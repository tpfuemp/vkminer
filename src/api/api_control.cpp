/*
 * Run-state control: pause, resume and stop, from outside the process.
 *
 * Copyright 2026 vkminer contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "api/api_control.h"

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

extern "C" {
#include "core/miner.h"
}

namespace vkminer {

namespace {

std::mutex              g_lock;
std::condition_variable g_cv;

// The whole of what a mining thread reads outside the lock. Everything else
// here is behind g_lock, which a worker takes only once it has stopped mining.
std::atomic<bool> g_park_requested{false};
std::atomic<bool> g_retain_shared{false};

ControlState g_state = ControlState::kRunning;
ControlState g_pending = ControlState::kRunning;
ControlState g_previous = ControlState::kRunning;

uint64_t    g_epoch = 0;
uint64_t    g_switches = 0;
int         g_workers = 0;
int         g_parked = 0;
bool        g_mutating = false;
bool        g_shutdown = false;
std::string g_last_error;

// Which park the workers now inside control_park() are serving. A pause that
// becomes a stop is a second park with different terms -- the shared table has
// to go this time -- so the workers have to leave and come back rather than
// have the change land on them where they stand.
uint64_t g_park_gen = 0;
int      g_parked_gen = 0;  // of g_parked, how many arrived under g_park_gen

std::chrono::steady_clock::time_point g_deadline;

// When the miner last entered the state it is in. Every assignment to g_state
// goes through set_state_locked(), because this is a field a manager polls to
// tell one switch from the next, and a state change that forgot to move the
// clock reads as a change that never happened.
std::chrono::steady_clock::time_point g_state_since =
    std::chrono::steady_clock::now();

// When the miner was last moved to a different pool, and whether it ever has
// been. The clock starts when a re-target is accepted rather than when it
// lands: one that is still in flight, or that changed the pool and is waiting
// on it to answer, is exactly the state a manager must not be allowed to
// re-target out of at once.
std::chrono::steady_clock::time_point g_last_switch;
bool g_ever_switched = false;

// A posted pool change, and the whole of what the two threads say to each other
// about it.
struct PoolRequest {
    std::string url;
    std::string user;
    std::string pass;

    // The algorithm to mine there, empty for a plain re-target. A pool change
    // that carries one is the change this whole barrier exists for.
    std::string algo;

    // Written under g_lock and read outside it, because the stratum thread asks
    // whether to stop waiting on a quiet socket and a socket wait that can be
    // held up by a control caller is one a control caller can hang.
    std::atomic<bool> pending{false};

    bool applied = false;  // taken: rpc_url names the pool that was asked for
    bool done = false;     // answered, one way or the other
    bool ok = false;       // and this is which

    // Refused by the far side before anything changed, which is a different
    // answer from a change that was made and did not work out: the first is
    // the request's fault and the second is the pool's.
    bool refused = false;
};

PoolRequest g_pool;

// Whether the change in flight is a pool change. Its park is not a state change
// and must not be committed as one, so the two are told apart here rather than
// inferred from a state that looks identical either side.
bool g_pool_switch = false;

// What the far side of the park does about an algorithm. This file is compiled
// without the registry, the backend or the self-test: a barrier that could
// build a kernel would be one nobody could test without a device.
ControlSwitchHook g_switch_hook = nullptr;

// The profile to go back to when a rebuild fails after a switch, captured
// before the switch rather than after -- afterwards the globals describe the
// profile that did not work.
std::string g_prev_algo;
std::string g_prev_url;
std::string g_prev_user;
std::string g_prev_pass;
bool        g_can_restore = false;

// Whether what is in force now is itself a restore. A rebuild that fails under
// one has nowhere left to go, and saying so is what stops a device that will
// build neither profile from moving between them for the life of the process.
bool g_restore_in_force = false;

std::atomic<bool> g_in_flight{false};
std::atomic<bool> g_hold_connection{false};

unsigned park_timeout_ms()
{
    // Below one dispatch plus a drain there is no park to wait for, only a
    // rollback: refuse to be configured into never succeeding.
    const int ms = opt_api_control_park_timeout;
    return ms < 250 ? 250u : static_cast<unsigned>(ms);
}

std::string park_timed_out()
{
    return "workers did not park within " + std::to_string(park_timeout_ms()) +
           " ms";
}

int min_interval_s()
{
    const int s = opt_api_control_min_interval;
    return s > 0 ? s : 0;
}

// How long a re-target still has to wait, and 0 when it may go ahead. Seconds
// rounded up, because a caller told to retry in 0 s that is then refused again
// has been told nothing.
int retry_after_s_locked()
{
    if (!g_ever_switched || !min_interval_s())
        return 0;

    const auto waited = std::chrono::steady_clock::now() - g_last_switch;
    const auto left = std::chrono::seconds(min_interval_s()) - waited;
    if (left <= std::chrono::seconds::zero())
        return 0;

    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::seconds>(left).count() + 1);
}

std::string pool_not_taken()
{
    return "the pool change was not taken up within " +
           std::to_string(park_timeout_ms()) + " ms";
}

std::string pool_not_answered()
{
    return "the pool was changed but did not answer within " +
           std::to_string(park_timeout_ms()) + " ms";
}

// Owned the way the option parser leaves these globals: one plain allocation,
// freed by whoever replaces it.
char *dup_string(const std::string &from)
{
    char *out = static_cast<char *>(std::malloc(from.size() + 1));

    if (out)
        std::memcpy(out, from.c_str(), from.size() + 1);
    return out;
}

// How much of the url is the scheme, and 0 for one this miner cannot be moved
// to. The dialect the connection speaks is chosen from the algorithm before the
// socket opens, so what can change here is which host, not which protocol.
size_t scheme_length(const std::string &url)
{
    static const char *const kSchemes[] = { "stratum+tcp://", "stratum+ssl://",
                                            "stratum+tcps://" };

    for (const char *scheme : kSchemes) {
        const size_t n = std::strlen(scheme);
        size_t i = 0;

        if (url.size() <= n)
            continue;
        while (i < n && std::tolower(static_cast<unsigned char>(url[i])) ==
                            scheme[i])
            i++;
        if (i == n)
            return n;
    }
    return 0;
}

// Everything that can be refused before anything is parked. The option parser's
// answer to a url it does not understand is to print the usage and exit, which
// is not an answer a request may have.
bool pool_url_usable(const std::string &url, std::string *why)
{
    if (!have_stratum) {
        *why = "this miner is not mining against a stratum pool";
        return false;
    }
    if (url.size() > 512) {
        *why = "the url is too long";
        return false;
    }
    if (!scheme_length(url)) {
        *why = "expected a stratum+tcp://, stratum+ssl:// or stratum+tcps:// url";
        return false;
    }

    const std::string host = url.substr(scheme_length(url));
    if (host[0] == '/' || host[0] == ':') {
        *why = "the url names no host";
        return false;
    }
    if (host.find('@') != std::string::npos) {
        *why = "credentials go in user and pass, not in the url";
        return false;
    }
    if (host.find_first_of(" \t\r\n") != std::string::npos) {
        *why = "the url has whitespace in it";
        return false;
    }
    return true;
}

// Whether the change in flight has happened yet. A park is done when every
// worker is counted in under the current generation; a resume when none is
// counted in at all.
bool all_parked_locked()
{
    return g_parked_gen >= g_workers;
}

bool landed_locked()
{
    if (g_pending == ControlState::kRunning)
        return g_parked == 0;
    return all_parked_locked();
}

void set_state_locked(ControlState want)
{
    if (g_state == want)
        return;
    g_state = want;
    g_state_since = std::chrono::steady_clock::now();
}

// Commits a change whose workers have arrived. Called from both sides, because
// the last worker to park is usually the one that lands it rather than the
// request that asked for it.
bool settle_locked()
{
    if (g_state != ControlState::kSwitching)
        return false;

    if (g_pool_switch) {
        // The park is not the change here, so it commits nothing: it is what
        // makes the change safe to make. The stratum thread is handed the new
        // pool once the last worker is in -- a dispatch still running against
        // the old pool's job finds shares the new one never issued, and pays
        // for them in rejects -- and the barrier is held until it answers,
        // whether or not the caller that asked is still waiting.
        if (!g_pool.pending.load(std::memory_order_relaxed) && !g_pool.applied) {
            if (!all_parked_locked())
                return false;
            g_pool.pending.store(true, std::memory_order_relaxed);
            g_in_flight.store(true, std::memory_order_relaxed);
        }
        if (!g_pool.done)
            return false;

        g_pool_switch = false;
        g_pool.pending.store(false, std::memory_order_relaxed);
        g_in_flight.store(false, std::memory_order_relaxed);
    } else if (!landed_locked())
        return false;

    set_state_locked(g_pending);
    g_epoch++;
    g_switches++;
    g_mutating = false;

    // Kept across a restore, and only across a restore: it is the reason the
    // miner is back on the previous profile, and a manager reading state after
    // the change has landed is exactly who needs it.
    if (!g_restore_in_force)
        g_last_error.clear();

    // The terms of the state being landed in, which for a re-target is the one
    // the workers were parked out of: they are what releases them.
    g_park_requested.store(g_state != ControlState::kRunning,
                           std::memory_order_relaxed);
    g_retain_shared.store(g_state == ControlState::kPaused,
                          std::memory_order_relaxed);
    g_hold_connection.store(g_state == ControlState::kStopped,
                            std::memory_order_relaxed);

    if (g_state == g_previous)
        applog(LOG_INFO, "control: pool changed, still %s (epoch %llu)",
               control_state_name(g_state),
               static_cast<unsigned long long>(g_epoch));
    else
        applog(LOG_INFO, "control: %s -> %s (epoch %llu)",
               control_state_name(g_previous), control_state_name(g_state),
               static_cast<unsigned long long>(g_epoch));
    return true;
}

void rollback_locked(std::string why)
{
    g_pool_switch = false;
    g_pool.pending.store(false, std::memory_order_relaxed);
    g_in_flight.store(false, std::memory_order_relaxed);

    g_park_requested.store(g_previous != ControlState::kRunning,
                           std::memory_order_relaxed);
    g_retain_shared.store(g_previous == ControlState::kPaused,
                          std::memory_order_relaxed);
    g_hold_connection.store(g_previous == ControlState::kStopped,
                            std::memory_order_relaxed);

    set_state_locked(g_previous);
    g_pending = g_previous;
    g_mutating = false;
    g_last_error = std::move(why);
    g_cv.notify_all();

    applog(LOG_WARNING, "control: rolled back to %s -- %s",
           control_state_name(g_state), g_last_error.c_str());
}

// A change nobody is waiting on any more. Without this a request answered
// kAccepted whose caller never came back would leave the miner reporting
// kSwitching, and half parked, for the life of the process.
void expire_locked()
{
    if (g_state != ControlState::kSwitching)
        return;
    if (std::chrono::steady_clock::now() < g_deadline)
        return;

    // A pool that has been changed and has not answered is not put back: doing
    // that is a second switch, to a pool nobody asked for, and the miner may
    // yet be one retry away from the one that was. So the barrier lets go, the
    // change stands, and last_error is what says the connection is missing.
    if (g_pool_switch && g_pool.applied) {
        g_pool.done = true;
        g_pool.ok = false;
        settle_locked();
        g_last_error = pool_not_answered();
        applog(LOG_WARNING, "control: %s", g_last_error.c_str());
        return;
    }

    if (g_pool_switch)
        rollback_locked(g_pool.pending.load(std::memory_order_relaxed)
                            ? pool_not_taken() : park_timed_out());
    else
        rollback_locked(park_timed_out());
}

// Posts a pool change, with or without an algorithm, and asks for the park it
// needs. Shared by the two requests and the restore: three callers arranging
// the same eight fields is three chances to leave one out.
void post_pool_locked(const std::string &url, const std::string &user,
                      const std::string &pass, const std::string &algo,
                      bool restore, const ControlState *want)
{
    if (!algo.empty() && !restore) {
        g_prev_algo = opt_algo ? opt_algo : "";
        g_prev_url = rpc_url ? rpc_url : "";
        g_prev_user = rpc_user ? rpc_user : "";
        g_prev_pass = rpc_pass ? rpc_pass : "";
        g_can_restore = !g_prev_algo.empty() && !g_prev_url.empty();
    }
    g_restore_in_force = restore;

    // The state either side is the same one unless a caller named another: a
    // change of pool or algorithm is a change to what the miner works on, not
    // to whether it is working. So there is no verb to be a no-op of, and every
    // request costs an epoch -- a run state named as well lands in this same
    // settle, which is what makes the two one change.
    g_last_switch = std::chrono::steady_clock::now();
    g_ever_switched = true;
    g_previous = g_state;
    g_pending = want ? *want : g_state;
    set_state_locked(ControlState::kSwitching);
    g_mutating = true;
    g_pool_switch = true;
    if (!restore)
        g_last_error.clear();
    g_deadline = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(park_timeout_ms());

    g_pool.url = url;
    g_pool.user = user;
    g_pool.pass = pass;
    g_pool.algo = algo;
    g_pool.pending.store(false, std::memory_order_relaxed);
    g_pool.applied = false;
    g_pool.done = false;
    g_pool.ok = false;
    g_pool.refused = false;

    // Parked on the terms of the state they are already in: a re-target does
    // not change the algorithm, so whatever a worker was keeping it keeps. An
    // algorithm change leaves a table that is no use -- but the switch hook is
    // what drops it, once the workers are in and nothing is reading it.
    g_retain_shared.store(g_previous != ControlState::kStopped,
                          std::memory_order_relaxed);
    g_park_requested.store(true, std::memory_order_relaxed);

    // Given up here rather than at the settle, for the profile that starts a
    // stopped miner on a new pool: this barrier waits for a subscribe, and the
    // stratum thread will not open a socket while the hold is on -- so holding
    // it to the settle waits for an ack the miner is itself forbidding.
    g_hold_connection.store(g_pending == ControlState::kStopped,
                            std::memory_order_relaxed);

    // Anyone already parked is parked on the previous verb's terms and is not
    // counted towards this park until it has come round and read these.
    g_park_gen++;
    g_parked_gen = 0;
    g_cv.notify_all();
}

// Waits out a posted change and says how it ended. The two requests answer
// identically because they are the same barrier.
ControlResult wait_for_pool_locked(std::unique_lock<std::mutex> &held,
                                   unsigned wait_ms, std::string *why)
{
    std::chrono::steady_clock::time_point answer_by =
        wait_ms ? std::chrono::steady_clock::now() +
                      std::chrono::milliseconds(wait_ms)
                : g_deadline;
    if (answer_by > g_deadline)
        answer_by = g_deadline;

    while (g_state == ControlState::kSwitching && !settle_locked() &&
           std::chrono::steady_clock::now() < answer_by)
        g_cv.wait_until(held, answer_by);

    if (g_state != ControlState::kSwitching) {
        if (g_pool.ok)
            return ControlResult::kOk;
        if (why)
            *why = g_last_error;

        // Refused by the far side, having changed nothing -- an algorithm this
        // build does not have, or a dataset the device cannot hold. A bad
        // request and not a slow one; "timeout" would be retried forever.
        return g_pool.refused ? ControlResult::kInvalid : ControlResult::kTimeout;
    }

    if (std::chrono::steady_clock::now() >= g_deadline) {
        expire_locked();
        if (why)
            *why = g_last_error;
        return ControlResult::kTimeout;
    }

    return ControlResult::kAccepted;
}

}  // namespace

const char *control_state_name(ControlState state)
{
    switch (state) {
    case ControlState::kRunning:   return "running";
    case ControlState::kPaused:    return "paused";
    case ControlState::kStopped:   return "stopped";
    case ControlState::kSwitching: return "switching";
    }
    return "running";
}

void control_init(int workers)
{
    std::lock_guard<std::mutex> held(g_lock);
    g_workers = workers > 0 ? workers : 0;

    // The miner has been running since here, not since the process started
    // linking itself together.
    g_state_since = std::chrono::steady_clock::now();
}

bool control_enabled()
{
    return opt_api_control;
}

bool control_wants_park()
{
    // Deliberately not gated on control_enabled(): nothing sets this flag while
    // the control API is off, so the test would cost a second load to say what
    // the first has already said.
    return g_park_requested.load(std::memory_order_relaxed);
}

bool control_park_retains_shared()
{
    return g_retain_shared.load(std::memory_order_relaxed);
}

void control_park(int thr_id)
{
    (void)thr_id;

    std::unique_lock<std::mutex> held(g_lock);
    if (g_shutdown)
        return;

    const uint64_t gen = g_park_gen;
    g_parked++;
    g_parked_gen++;
    settle_locked();
    g_cv.notify_all();

    // Woken by a resume, by a shutdown, or by a second park that needs this
    // worker to come round the mining loop and read its terms again. In slices
    // rather than on the predicate alone so that a wake lost to a race costs a
    // tenth of a second rather than the run.
    while (g_park_requested.load(std::memory_order_relaxed) &&
           g_park_gen == gen && !g_shutdown)
        g_cv.wait_for(held, std::chrono::milliseconds(100));

    g_parked--;
    if (g_park_gen == gen)
        g_parked_gen--;
    settle_locked();
    g_cv.notify_all();
}

ControlResult control_request(ControlState want, unsigned wait_ms,
                              std::string *why)
{
    if (why)
        why->clear();

    if (!control_enabled()) {
        if (why)
            *why = "the control API is not enabled";
        return ControlResult::kDisabled;
    }
    if (want == ControlState::kSwitching) {
        if (why)
            *why = "'switching' is not a state that can be asked for";
        return ControlResult::kBusy;
    }

    std::unique_lock<std::mutex> held(g_lock);

    // Judge this request against what has happened since, not against what was
    // true when the last one returned.
    settle_locked();
    expire_locked();

    if (g_mutating) {
        if (why)
            *why = "another change is already in progress";
        return ControlResult::kBusy;
    }
    if (g_state == want)
        return ControlResult::kOk;  // a no-op is answered, but spends no epoch

    g_previous = g_state;
    g_pending = want;
    set_state_locked(ControlState::kSwitching);
    g_mutating = true;
    g_last_error.clear();
    g_deadline = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(park_timeout_ms());

    if (want == ControlState::kRunning) {
        g_park_requested.store(false, std::memory_order_relaxed);
        g_retain_shared.store(false, std::memory_order_relaxed);
    } else {
        // The terms first and the request second: a worker that read the flags
        // between the two stores would park a pause on a stop's terms and drop
        // a shared table the resume was counting on.
        g_retain_shared.store(want == ControlState::kPaused,
                              std::memory_order_relaxed);
        g_park_requested.store(true, std::memory_order_relaxed);

        // Anyone already parked is parked on the previous verb's terms and has
        // to come round again. Nobody counts towards this park until they do.
        g_park_gen++;
        g_parked_gen = 0;
    }
    g_cv.notify_all();

    std::chrono::steady_clock::time_point answer_by =
        wait_ms ? std::chrono::steady_clock::now() +
                      std::chrono::milliseconds(wait_ms)
                : g_deadline;
    if (answer_by > g_deadline)
        answer_by = g_deadline;

    // On the state and not on settle_locked() alone: the worker that parks last
    // usually commits the change from its own side, and then this side's call
    // has nothing left to commit and would answer false to a change that has
    // already happened -- waiting out the whole of wait_ms for it.
    while (g_state == ControlState::kSwitching && !settle_locked() &&
           std::chrono::steady_clock::now() < answer_by)
        g_cv.wait_until(held, answer_by);

    if (g_state == want)
        return ControlResult::kOk;

    if (std::chrono::steady_clock::now() >= g_deadline) {
        const std::string message = park_timed_out();
        if (why)
            *why = message;
        rollback_locked(message);
        return ControlResult::kTimeout;
    }

    return ControlResult::kAccepted;
}

ControlResult control_pool_request(const std::string &url,
                                   const std::string &user,
                                   const std::string &pass, unsigned wait_ms,
                                   std::string *why, const ControlState *want)
{
    std::string complaint;

    if (why)
        why->clear();

    if (!control_enabled()) {
        if (why)
            *why = "the control API is not enabled";
        return ControlResult::kDisabled;
    }
    if (!pool_url_usable(url, &complaint)) {
        if (why)
            *why = complaint;
        return ControlResult::kInvalid;
    }

    std::unique_lock<std::mutex> held(g_lock);

    settle_locked();
    expire_locked();

    if (g_mutating) {
        if (why)
            *why = "another change is already in progress";
        return ControlResult::kBusy;
    }

    // Answered after "a change is in progress" and not before it: both refuse,
    // but the two are answers to different questions -- one says poll, the
    // other says back off -- and the more specific one is the more useful.
    const int retry_in = retry_after_s_locked();
    if (retry_in) {
        if (why)
            *why = "the pool was changed less than " +
                   std::to_string(min_interval_s()) + " s ago, retry in " +
                   std::to_string(retry_in) + " s";
        return ControlResult::kThrottled;
    }

    post_pool_locked(url, user, pass, std::string(), false, want);
    return wait_for_pool_locked(held, wait_ms, why);
}

void control_set_switch_hook(ControlSwitchHook hook)
{
    std::lock_guard<std::mutex> held(g_lock);
    g_switch_hook = hook;
}

ControlResult control_algo_request(const std::string &algo,
                                   const std::string &url,
                                   const std::string &user,
                                   const std::string &pass, unsigned wait_ms,
                                   std::string *why, const ControlState *want)
{
    std::string complaint;

    if (why)
        why->clear();

    if (!control_enabled()) {
        if (why)
            *why = "the control API is not enabled";
        return ControlResult::kDisabled;
    }
    if (algo.empty()) {
        if (why)
            *why = "no algorithm was named";
        return ControlResult::kInvalid;
    }

    // A pool is not optional here. The dialect is derived from the algorithm
    // before the socket opens, so the connection this miner is holding was
    // built to speak for the algorithm it is leaving.
    if (!pool_url_usable(url, &complaint)) {
        if (why)
            *why = complaint;
        return ControlResult::kInvalid;
    }

    // Whether the name resolves is the switch hook's to answer: the registry is
    // deliberately not linked into this file. It refuses before anything has
    // changed, so the answer is the same one turn later.

    std::unique_lock<std::mutex> held(g_lock);

    settle_locked();
    expire_locked();

    if (g_mutating) {
        if (why)
            *why = "another change is already in progress";
        return ControlResult::kBusy;
    }

    const int retry_in = retry_after_s_locked();
    if (retry_in) {
        if (why)
            *why = "the miner was switched less than " +
                   std::to_string(min_interval_s()) + " s ago, retry in " +
                   std::to_string(retry_in) + " s";
        return ControlResult::kThrottled;
    }

    post_pool_locked(url, user, pass, algo, false, want);
    return wait_for_pool_locked(held, wait_ms, why);
}

bool control_switch_recoverable()
{
    std::lock_guard<std::mutex> held(g_lock);
    return g_can_restore && !g_restore_in_force;
}

void control_switch_failed(const std::string &why)
{
    std::lock_guard<std::mutex> held(g_lock);

    settle_locked();
    expire_locked();

    // Nothing to go back to, or the thing to go back to is what just failed.
    // Either way this is not recoverable and the caller has already been told
    // as much; recording why is all that is left to do.
    if (!g_can_restore || g_restore_in_force || g_mutating) {
        g_last_error = why;
        return;
    }

    applog(LOG_WARNING, "control: %s -- going back to '%s'", why.c_str(),
           g_prev_algo.c_str());

    // Back to the profile, not to a run state: a restore puts right what the
    // failed switch changed, and the miner is doing whatever it was doing.
    post_pool_locked(g_prev_url, g_prev_user, g_prev_pass, g_prev_algo, true,
                     nullptr);
    g_last_error = why;
}

bool control_pool_apply()
{
    std::string       url, user, pass, algo;
    ControlSwitchHook hook = nullptr;

    {
        std::lock_guard<std::mutex> held(g_lock);
        if (!g_pool.pending.load(std::memory_order_relaxed))
            return false;

        url = g_pool.url;
        user = g_pool.user;
        pass = g_pool.pass;
        algo = g_pool.algo;
        hook = g_switch_hook;

        // Taken in the same breath as the pending flag is cleared, and not once
        // the work below is done: settle_locked() reads both, and a moment in
        // which the change is neither pending nor applied posts it twice.
        g_pool.pending.store(false, std::memory_order_relaxed);
        g_pool.applied = true;
    }

    // The algorithm first and outside the lock: on a DAG algorithm this drops a
    // table, sizes another, self-tests and tunes -- seconds, during which a
    // polling caller must not be stuck on a mutex. Every worker is parked.
    if (!algo.empty()) {
        std::string refusal;

        if (!hook)
            refusal = "this miner cannot change algorithm at runtime";
        else if (!hook(algo.c_str(), &refusal) && refusal.empty())
            refusal = "the switch was refused";

        if (!refusal.empty() || !hook) {
            std::lock_guard<std::mutex> held(g_lock);

            // Nothing was changed, so there is nothing to put back: the pool
            // below was never touched. Rolled back rather than settled, because
            // a refusal is not a switch that happened badly.
            g_pool.refused = true;
            rollback_locked(refusal);
            return false;
        }
    }

    // Freeing what the whole process has been reading all session is safe here
    // and nowhere else: report_summary_log() prints rpc_url from a mining
    // thread, and every one is parked at the barrier for as long as this takes.
    // Moving it out from between the park and the commit is a use-after-free.
    char *replaced = rpc_url;
    rpc_url = dup_string(url);
    short_url = rpc_url + scheme_length(url);
    std::free(replaced);

    if (!user.empty()) {
        replaced = rpc_user;
        rpc_user = dup_string(user);
        std::free(replaced);
    }
    if (!pass.empty()) {
        replaced = rpc_pass;
        rpc_pass = dup_string(pass);
        std::free(replaced);
    }

    // rpc_userpass is deliberately left as it was: it is the HTTP credential,
    // and a url this call accepted is a stratum one. Re-targeting a getwork
    // miner would have to rebuild it.
    applog(LOG_BLUE, "control: mining for %s", short_url);

    // A stopped miner has no connection to bring up, so the change is finished
    // by being recorded; the next start is what acts on it.
    if (g_hold_connection.load(std::memory_order_relaxed))
        control_pool_connected();
    return true;
}

void control_pool_connected()
{
    std::lock_guard<std::mutex> held(g_lock);

    if (!g_pool_switch || !g_pool.applied || g_pool.done)
        return;

    g_pool.done = true;
    g_pool.ok = true;
    settle_locked();
    g_cv.notify_all();
}

bool control_pool_pending()
{
    return g_pool.pending.load(std::memory_order_relaxed);
}

bool control_switch_in_flight()
{
    return g_in_flight.load(std::memory_order_relaxed);
}

bool control_holds_connection()
{
    return g_hold_connection.load(std::memory_order_relaxed);
}

ControlStatus control_status()
{
    std::lock_guard<std::mutex> held(g_lock);
    settle_locked();
    expire_locked();

    ControlStatus out;
    out.state = g_state;
    out.epoch = g_epoch;
    out.switch_count = g_switches;
    out.workers = g_workers;
    out.parked = g_parked;
    out.min_interval_s = min_interval_s();
    out.state_age_s = static_cast<int>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - g_state_since).count());
    out.retry_after_s = retry_after_s_locked();
    out.ready_for_switch = out.retry_after_s == 0;
    if (g_ever_switched)
        out.last_switch_age_s = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - g_last_switch).count());
    out.last_error = g_last_error;
    return out;
}

void control_release_all()
{
    std::lock_guard<std::mutex> held(g_lock);
    g_shutdown = true;
    g_park_requested.store(false, std::memory_order_relaxed);
    g_retain_shared.store(false, std::memory_order_relaxed);

    // A miner on its way out connects to nobody and waits for nothing: leaving
    // either of these set would hold the stratum thread off the socket it has
    // to close, or off the exit it has to take.
    g_pool.pending.store(false, std::memory_order_relaxed);
    g_in_flight.store(false, std::memory_order_relaxed);
    g_hold_connection.store(false, std::memory_order_relaxed);
    g_cv.notify_all();
}

}  // namespace vkminer

/* The stratum thread's entry points. It is inherited C and this is C++, so the
   five below are the whole of the boundary; the work is in the namespace. */

extern "C" bool control_pool_apply(void)
{
    return vkminer::control_pool_apply();
}

extern "C" void control_pool_connected(void)
{
    vkminer::control_pool_connected();
}

extern "C" bool control_pool_pending(void)
{
    return vkminer::control_pool_pending();
}

extern "C" bool control_switch_in_flight(void)
{
    return vkminer::control_switch_in_flight();
}

extern "C" bool control_holds_connection(void)
{
    return vkminer::control_holds_connection();
}
