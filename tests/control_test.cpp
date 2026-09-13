// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The run-state barrier, on its own. No device, no socket and no HTTP: what is
// under test is the state machine a control request, a mining thread and the
// stratum thread meet in, and every failure it has is a failure of agreement
// between threads.
//
// The workers here are the smallest thing that can stand in for a real one:
// a loop that asks whether it should park and parks. They can be told to stop
// asking, which is how a device that has gone away is modelled -- a park that
// never completes is the case the timeout exists for, and the case a real
// device only reaches by hanging. The stratum thread is the same idea: a loop
// that takes a pool change and says it connected, and can be told to say
// nothing, which is a pool that will not have this miner.

#include "api/api_control.h"

extern "C" {
#include "core/miner.h"
}

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

// The three options the barrier reads, and the log it writes to. Defined here
// rather than linked from the inherited C, which would bring the option parser
// and the network stack in with them.
extern "C" {
bool opt_api_control = false;
bool opt_debug = false;
int  opt_api_control_park_timeout = 30000;

// Off for most of what follows: this test re-targets as fast as it can, which
// is exactly what the interval exists to stop, so the anti-flap rule gets a
// section of its own rather than a say in every other assertion.
int  opt_api_control_min_interval = 0;

// The pool. Owned the way the option parser leaves these, because a change
// frees what it replaces -- a string literal here would be a crash, not a
// failure, which is the whole reason they are seeded through malloc below.
char *rpc_url = nullptr;
char *short_url = nullptr;
char *rpc_user = nullptr;
char *rpc_pass = nullptr;
bool  have_stratum = true;

// Owned the same way, and read by the barrier for the same reason: it is half
// of the profile a failed switch is put back to.
char *opt_algo = nullptr;

void applog(int prio, const char *fmt, ...)
{
    va_list ap;

    (void)prio;
    if (!opt_debug)
        return;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
}
}

namespace {

using vkminer::ControlResult;
using vkminer::ControlState;

int failures = 0;

void fail(const char *fmt, ...)
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

const char *result_name(ControlResult r)
{
    switch (r) {
    case ControlResult::kOk:       return "ok";
    case ControlResult::kAccepted: return "accepted";
    case ControlResult::kBusy:     return "busy";
    case ControlResult::kThrottled: return "throttled";
    case ControlResult::kTimeout:  return "timeout";
    case ControlResult::kDisabled: return "disabled";
    case ControlResult::kInvalid:  return "invalid";
    }
    return "?";
}

void expect_result(const char *what, ControlResult got, ControlResult want)
{
    if (got != want)
        fail("%s: %s, expected %s", what, result_name(got), result_name(want));
}

void expect_state(const char *what, ControlState got, ControlState want)
{
    if (got != want)
        fail("%s: %s, expected %s", what, vkminer::control_state_name(got),
             vkminer::control_state_name(want));
}

void expect_int(const char *what, long long got, long long want)
{
    if (got != want)
        fail("%s: %lld, expected %lld", what, got, want);
}

// How long the last request through request() took to be answered.
long long last_ms = 0;

ControlResult request(ControlState want, unsigned wait_ms, std::string *why)
{
    const auto start = std::chrono::steady_clock::now();
    const ControlResult got = vkminer::control_request(want, wait_ms, why);

    last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - start).count();
    return got;
}

// A request is answered when the change lands, not when its own timeout runs
// out. Nothing but the clock can see the difference: the state, the epoch and
// the result are all correct either way, and a pause that takes as long as the
// caller was willing to wait for it is a control API nobody can drive.
void expect_prompt(const char *what, long long budget_ms)
{
    if (last_ms > budget_ms)
        fail("%s was answered after %lld ms, over a budget of %lld", what,
             last_ms, budget_ms);
}

// One stand-in worker. `parks` counts arrivals rather than states, because a
// pause that becomes a stop is two parks for one worker and that is the point
// of the generation counter it goes round.
struct FakeWorker {
    std::thread       thread;
    std::atomic<int>  parks{0};
    std::atomic<bool> retained{false};  // what the last park was told to do
};

std::atomic<bool> g_running{true};
std::atomic<bool> g_ignore_park{false};

void fake_worker(FakeWorker *self, int thr_id)
{
    while (g_running.load(std::memory_order_relaxed)) {
        if (vkminer::control_wants_park() &&
            !g_ignore_park.load(std::memory_order_relaxed)) {
            // The order a real worker uses: read the terms of the park with
            // the pipeline already empty, then count in.
            self->retained.store(vkminer::control_park_retains_shared(),
                                 std::memory_order_relaxed);
            self->parks.fetch_add(1, std::memory_order_relaxed);
            vkminer::control_park(thr_id);
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// The stratum thread's half of a pool change. `answers` is the pool: with it
// false the url changes and nothing ever connects to it, which is the case the
// miner must not undo and must not wedge on.
std::atomic<bool> g_pool_answers{true};
std::atomic<int>  g_applied{0};

void fake_stratum()
{
    while (g_running.load(std::memory_order_relaxed)) {
        if (control_pool_apply()) {
            g_applied.fetch_add(1, std::memory_order_relaxed);
            if (g_pool_answers.load(std::memory_order_relaxed))
                control_pool_connected();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

char *own(const char *text)
{
    const size_t n = std::strlen(text) + 1;
    char *out = static_cast<char *>(std::malloc(n));

    std::memcpy(out, text, n);
    return out;
}

void expect_text(const char *what, const char *got, const char *want)
{
    if (std::strcmp(got, want))
        fail("%s: '%s', expected '%s'", what, got, want);
}

// The far side of an algorithm change with the algorithm taken out of it. What
// the barrier is entitled to assume is only this much: the hook either succeeds
// having moved opt_algo, or fails having moved nothing at all -- and it is
// called with the workers already parked, which is what the counts below check.
std::atomic<bool> g_hook_accepts{true};
std::atomic<int>  g_hook_calls{0};
std::atomic<int>  g_hook_parked{-1};

bool fake_switch(const char *algo, std::string *why)
{
    g_hook_calls.fetch_add(1, std::memory_order_relaxed);
    g_hook_parked.store(vkminer::control_status().parked,
                        std::memory_order_relaxed);

    if (!g_hook_accepts.load(std::memory_order_relaxed)) {
        *why = std::string("device 0: '") + algo +
               " needs more memory than this device has";
        return false;
    }
    std::free(opt_algo);
    opt_algo = own(algo);
    return true;
}

// Waits for a condition the workers have to reach on their own. Every use has a
// deadline well beyond what the loop above needs, so a failure here is a
// deadlock and not a slow machine.
template <typename Fn>
bool wait_for(Fn done, int ms)
{
    const auto until =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < until) {
        if (done())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return done();
}

}  // namespace

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (std::strcmp(argv[i], "-D") == 0)
            opt_debug = true;

    const int kWorkers = 3;

    // Before anything else, and with the option still off: a build that answers
    // a control request without --api-control has opened a write path the
    // command line said no to.
    vkminer::control_init(kWorkers);
    expect_result("disabled pause",
                  request(ControlState::kPaused, 100, nullptr),
                  ControlResult::kDisabled);
    expect_prompt("a refused request", 50);
    if (vkminer::control_wants_park())
        fail("a refused request still asked the workers to park");
    expect_int("disabled epoch", (long long)vkminer::control_status().epoch, 0);

    opt_api_control = true;

    rpc_url = own("stratum+tcp://first.example:1111");
    short_url = rpc_url + sizeof("stratum+tcp://") - 1;
    rpc_user = own("first");
    rpc_pass = own("x");
    opt_algo = own("scrypt");
    vkminer::control_set_switch_hook(fake_switch);

    std::vector<FakeWorker> workers(kWorkers);
    for (int i = 0; i < kWorkers; i++)
        workers[(size_t)i].thread =
            std::thread(fake_worker, &workers[(size_t)i], i);
    std::thread pool(fake_stratum);

    // --- pause ------------------------------------------------------------
    expect_result("pause", request(ControlState::kPaused, 5000, nullptr),
                  ControlResult::kOk);
    expect_prompt("pause", 1000);
    vkminer::ControlStatus st = vkminer::control_status();
    expect_state("after pause", st.state, ControlState::kPaused);
    expect_int("epoch after pause", (long long)st.epoch, 1);
    expect_int("parked after pause", st.parked, kWorkers);
    expect_int("workers", st.workers, kWorkers);
    for (int i = 0; i < kWorkers; i++) {
        expect_int("parks", workers[(size_t)i].parks.load(), 1);
        if (!workers[(size_t)i].retained.load())
            fail("worker %d parked a pause without keeping its shared table", i);
    }

    // A verb the miner is already obeying is answered, and spends nothing: a
    // manager polling pause must not walk the epoch a conditional request is
    // keyed on.
    expect_result("pause again", request(ControlState::kPaused, 100, nullptr),
                  ControlResult::kOk);
    expect_prompt("a no-op", 50);
    expect_int("epoch after a no-op", (long long)vkminer::control_status().epoch,
               1);

    // --- pause -> stop ----------------------------------------------------
    //
    // The workers are already parked, on terms that keep the table. Stop is a
    // stricter park, so each of them has to leave and come back for it.
    expect_result("stop", request(ControlState::kStopped, 5000, nullptr),
                  ControlResult::kOk);
    expect_prompt("stop", 1000);
    st = vkminer::control_status();
    expect_state("after stop", st.state, ControlState::kStopped);
    expect_int("epoch after stop", (long long)st.epoch, 2);
    expect_int("parked after stop", st.parked, kWorkers);
    for (int i = 0; i < kWorkers; i++) {
        expect_int("parks after stop", workers[(size_t)i].parks.load(), 2);
        if (workers[(size_t)i].retained.load())
            fail("worker %d parked a stop still holding its shared table", i);
    }
    if (!control_holds_connection())
        fail("a stopped miner is still holding its pool connection open");

    // --- resume -----------------------------------------------------------
    expect_result("start", request(ControlState::kRunning, 5000, nullptr),
                  ControlResult::kOk);
    expect_prompt("start", 1000);
    st = vkminer::control_status();
    expect_state("after start", st.state, ControlState::kRunning);
    expect_int("epoch after start", (long long)st.epoch, 3);
    expect_int("parked after start", st.parked, 0);
    if (control_holds_connection())
        fail("a started miner is still refusing a pool connection");

    // --- the pool ---------------------------------------------------------
    //
    // Refused with nothing parked and nothing disconnected. The option parser's
    // answer to each of these is to print the usage and exit, which is not an
    // answer a request may have.
    std::string complaint;
    const struct { const char *url; const char *what; } kRefused[] = {
        { "",                                "an empty url" },
        { "ftp://pool.example:3333",         "a scheme nothing here speaks" },
        { "http://pool.example:3333",        "a url this miner cannot mine over" },
        { "stratum+tcp://",                  "a url naming no host" },
        { "stratum+tcp:///nothing",          "a url that is only a path" },
        { "stratum+tcp://u:x@pool.example:3333", "credentials inside the url" },
    };
    for (const auto &refused : kRefused)
        expect_result(refused.what,
                      vkminer::control_pool_request(refused.url, "", "", 100,
                                                    &complaint),
                      ControlResult::kInvalid);
    if (vkminer::control_wants_park())
        fail("a refused pool change still asked the workers to park");
    expect_int("epoch after refused pool changes",
               (long long)vkminer::control_status().epoch, 3);

    // A change that is taken and answered. The workers park for it -- a
    // dispatch still running against the old pool's job finds shares the new
    // pool never issued -- and come back to the state they were parked out of,
    // because a re-target is not a verb about what the miner is doing.
    const int parks_before = workers[0].parks.load();
    expect_result("a pool change",
                  vkminer::control_pool_request(
                      "stratum+tcp://second.example:2222", "second", "y", 5000,
                      &complaint),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_state("after a pool change", st.state, ControlState::kRunning);
    expect_int("epoch after a pool change", (long long)st.epoch, 4);
    expect_int("times the change was taken", g_applied.load(), 1);
    expect_text("rpc_url", rpc_url, "stratum+tcp://second.example:2222");
    expect_text("short_url", short_url, "second.example:2222");
    expect_text("rpc_user", rpc_user, "second");
    expect_text("rpc_pass", rpc_pass, "y");
    expect_int("parks for a pool change", workers[0].parks.load(),
               parks_before + 1);
    if (!wait_for([]() { return vkminer::control_status().parked == 0; }, 2000))
        fail("a finished pool change left the workers parked");
    if (control_switch_in_flight())
        fail("a finished pool change is still in flight");

    // An empty credential keeps the one in force: moving a rig between two
    // ports of the same pool should not mean re-sending them.
    expect_result("a pool change carrying no credentials",
                  vkminer::control_pool_request(
                      "stratum+tcp://third.example:3333", "", "", 5000,
                      &complaint),
                  ControlResult::kOk);
    expect_text("rpc_url", rpc_url, "stratum+tcp://third.example:3333");
    expect_text("rpc_user after an empty one", rpc_user, "second");
    expect_text("rpc_pass after an empty one", rpc_pass, "y");
    expect_int("epoch", (long long)vkminer::control_status().epoch, 5);

    // A pool that takes the change and never answers. Putting it back would be
    // a second switch, to a pool nobody asked for, so the change stands, the
    // miner is released to go on trying, and the reason is on the record.
    g_pool_answers.store(false);
    opt_api_control_park_timeout = 400;
    expect_result("a pool that never answers",
                  vkminer::control_pool_request(
                      "stratum+tcp://silent.example:4444", "", "", 0,
                      &complaint),
                  ControlResult::kTimeout);
    if (complaint.empty())
        fail("a pool that never answered gave no reason");
    st = vkminer::control_status();
    expect_state("after a pool that never answers", st.state,
                 ControlState::kRunning);
    expect_int("epoch after a pool that never answers", (long long)st.epoch, 6);
    expect_text("rpc_url after a pool that never answers", rpc_url,
                "stratum+tcp://silent.example:4444");
    if (st.last_error.empty())
        fail("a pool that never answered left no last_error");
    if (!wait_for([]() { return vkminer::control_status().parked == 0; }, 2000))
        fail("a pool change that timed out left the workers parked");
    if (control_switch_in_flight())
        fail("a pool change that timed out is still in flight");
    g_pool_answers.store(true);
    opt_api_control_park_timeout = 30000;

    // --- a park that never happens ----------------------------------------
    //
    // A miner left in `switching` is worse than one that refused: it mines
    // nothing and answers nothing. Both ways out are checked -- the request
    // that waits it out, and the request that was answered early and abandoned.
    opt_api_control_park_timeout = 400;
    g_ignore_park.store(true);

    std::string why;
    expect_result("pause with the workers gone",
                  request(ControlState::kPaused, 0, &why),
                  ControlResult::kTimeout);
    if (why.empty())
        fail("a timeout gave no reason");
    st = vkminer::control_status();
    expect_state("after a timeout", st.state, ControlState::kRunning);
    expect_int("epoch after a timeout", (long long)st.epoch, 6);
    if (st.last_error.empty())
        fail("a timeout left no last_error");
    if (vkminer::control_wants_park())
        fail("a rolled-back park is still asking the workers to park");

    // Answered before the park could finish. It is still in flight until the
    // timeout, and nothing but a later status call is left to end it.
    expect_result("pause answered early",
                  request(ControlState::kPaused, 1, &why),
                  ControlResult::kAccepted);
    expect_prompt("a request answered early", 100);
    expect_state("while in flight", vkminer::control_status().state,
                 ControlState::kSwitching);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    st = vkminer::control_status();
    expect_state("an abandoned change", st.state, ControlState::kRunning);
    expect_int("epoch after an abandoned change", (long long)st.epoch, 6);

    // --- and one that does, so the barrier still works afterwards ---------
    g_ignore_park.store(false);
    opt_api_control_park_timeout = 30000;
    expect_result("pause after a timeout",
                  request(ControlState::kPaused, 5000, nullptr),
                  ControlResult::kOk);
    expect_prompt("pause after a timeout", 1000);
    expect_int("epoch", (long long)vkminer::control_status().epoch, 7);

    // A pool change with the miner paused. It parks again on the same terms and
    // stays parked: what the change moves is the pool, and the miner is doing
    // what it was doing either side of it.
    expect_result("a pool change while paused",
                  vkminer::control_pool_request(
                      "stratum+tcp://fourth.example:5555", "", "", 5000,
                      &complaint),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_state("after a pool change while paused", st.state,
                 ControlState::kPaused);
    expect_int("epoch after a pool change while paused", (long long)st.epoch, 8);
    expect_int("parked after a pool change while paused", st.parked, kWorkers);
    expect_text("rpc_url", rpc_url, "stratum+tcp://fourth.example:5555");

    // --- the anti-flap interval -------------------------------------------
    //
    // Everything above ran with it off. Turning it on now is the whole test: a
    // re-target was accepted moments ago, so the interval is already running
    // and the next one is due to be refused without the clock having to be
    // waited out. An hour is chosen so that a machine slow enough to fail every
    // other assertion here still cannot walk out of the window by accident.
    opt_api_control_min_interval = 3600;
    st = vkminer::control_status();
    expect_int("min_interval_s", st.min_interval_s, 3600);
    if (st.ready_for_switch)
        fail("ready for a switch inside the interval");
    if (st.last_switch_age_s < 0)
        fail("last_switch_age_s is unset after a switch");

    const int applied_before = g_applied.load();
    const int parks_before_throttle = workers[0].parks.load();

    complaint.clear();
    expect_result("a second pool change inside the interval",
                  vkminer::control_pool_request(
                      "stratum+tcp://fifth.example:6666", "", "", 5000,
                      &complaint),
                  ControlResult::kThrottled);
    if (complaint.empty())
        fail("a throttled pool change gave no reason");

    // Refused the way an invalid url is refused: nothing parked, nothing taken
    // and nothing changed. A throttle that costs a park has moved the miner for
    // a request it then declined.
    st = vkminer::control_status();
    expect_int("epoch after a throttled pool change", (long long)st.epoch, 8);
    expect_int("times a throttled change was taken", g_applied.load(),
               applied_before);
    expect_int("parks for a throttled change", workers[0].parks.load(),
               parks_before_throttle);
    expect_text("rpc_url after a throttled pool change", rpc_url,
                "stratum+tcp://fourth.example:5555");
    expect_state("after a throttled pool change", st.state,
                 ControlState::kPaused);
    expect_int("parked after a throttled pool change", st.parked, kWorkers);

    // The reason is prose, and a client is told never to parse it; the seconds
    // are the field it reads instead. The interval here is an hour, so a
    // throttle reporting a second or two is reading the wrong clock.
    if (st.retry_after_s <= 0)
        fail("a throttled pool change reported no retry_after_s");
    if (st.retry_after_s > 3600)
        fail("retry_after_s is longer than the interval it is measured against");
    if (st.ready_for_switch)
        fail("ready_for_switch is true while retry_after_s is nonzero");

    // The run-state verbs are not throttled, and do not start the clock either.
    // A stop that answers "too soon" is not a stop, and a miner that has been
    // paused and resumed has not been moved anywhere.
    expect_result("start inside the interval",
                  request(ControlState::kRunning, 5000, nullptr),
                  ControlResult::kOk);
    expect_result("pause inside the interval",
                  request(ControlState::kPaused, 5000, nullptr),
                  ControlResult::kOk);
    expect_int("epoch after two run-state verbs inside the interval",
               (long long)vkminer::control_status().epoch, 10);
    if (vkminer::control_status().ready_for_switch)
        fail("a run-state verb ended the interval");

    // And with it off, the same request the interval refused goes through. Zero
    // is the harness setting and it has to mean nothing rather than something
    // very short.
    opt_api_control_min_interval = 0;
    st = vkminer::control_status();
    expect_int("min_interval_s with the interval off", st.min_interval_s, 0);
    if (!st.ready_for_switch)
        fail("not ready for a switch with the interval off");
    expect_result("a pool change with the interval off",
                  vkminer::control_pool_request(
                      "stratum+tcp://fifth.example:6666", "", "", 5000,
                      &complaint),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_int("epoch after a pool change with the interval off",
               (long long)st.epoch, 11);
    expect_text("rpc_url", rpc_url, "stratum+tcp://fifth.example:6666");
    expect_state("after a pool change with the interval off", st.state,
                 ControlState::kPaused);
    expect_int("parked after a pool change with the interval off", st.parked,
               kWorkers);

    // --- the algorithm change ---------------------------------------------
    //
    // The pool half of this is the section above. What is added is a name that
    // can only be judged on the far side of the park, by the thing fake_switch
    // stands in for -- and the order that judgement happens in: a refusal that
    // had already moved the pool would leave the miner mining the algorithm it
    // was for a pool that wants the other one.
    const int calls_before = g_hook_calls.load();

    expect_result("an empty algorithm",
                  vkminer::control_algo_request(
                      "", "stratum+tcp://sixth.example:7777", "", "", 100,
                      &complaint),
                  ControlResult::kInvalid);
    expect_result("an algorithm with a url this miner cannot mine over",
                  vkminer::control_algo_request(
                      "kawpow", "http://pool.example:3333", "", "", 100,
                      &complaint),
                  ControlResult::kInvalid);
    expect_int("times the hook was asked about a refused request",
               g_hook_calls.load(), calls_before);
    expect_int("epoch after refused algorithm requests",
               (long long)vkminer::control_status().epoch, 11);
    expect_text("opt_algo after refused algorithm requests", opt_algo, "scrypt");

    // Refused by the far side, which is the answer a device without the memory
    // for the new algorithm's table produces. Nothing moves: not the algorithm,
    // not the pool, not the epoch -- and the miner is left running.
    g_hook_accepts.store(false);
    complaint.clear();
    expect_result("an algorithm this device cannot hold",
                  vkminer::control_algo_request(
                      "meowpow", "stratum+tcp://sixth.example:7777", "", "",
                      5000, &complaint),
                  ControlResult::kInvalid);
    if (complaint.empty())
        fail("a refused algorithm change gave no reason");
    st = vkminer::control_status();
    expect_int("epoch after a refused algorithm change", (long long)st.epoch, 11);
    expect_text("opt_algo after a refused algorithm change", opt_algo, "scrypt");
    expect_text("rpc_url after a refused algorithm change", rpc_url,
                "stratum+tcp://fifth.example:6666");
    expect_state("after a refused algorithm change", st.state,
                 ControlState::kPaused);
    if (st.last_error.empty())
        fail("a refused algorithm change left no last_error");
    if (!wait_for([&]() {
            return vkminer::control_status().parked == kWorkers;
        }, 2000))
        fail("a refused algorithm change left the workers out of their park");
    g_hook_accepts.store(true);

    // Taken. The hook runs with every worker parked -- it is about to free the
    // memory they were mining out of -- and the algorithm and the pool move
    // together, because the dialect is chosen from the algorithm before the
    // socket opens.
    g_hook_parked.store(-1);
    expect_result("an algorithm change",
                  vkminer::control_algo_request(
                      "kawpow", "stratum+tcp://sixth.example:7777", "sixth", "z",
                      5000, &complaint),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_int("epoch after an algorithm change", (long long)st.epoch, 12);
    expect_text("opt_algo after an algorithm change", opt_algo, "kawpow");
    expect_text("rpc_url after an algorithm change", rpc_url,
                "stratum+tcp://sixth.example:7777");
    expect_text("rpc_user after an algorithm change", rpc_user, "sixth");
    expect_int("workers parked while the hook ran", g_hook_parked.load(),
               kWorkers);
    expect_state("after an algorithm change", st.state, ControlState::kPaused);

    // --- a build that failed on the far side of one -----------------------
    //
    // The worker has given up the old algorithm's device state by the time it
    // finds out, so there is nothing for it to carry on with. Recoverable
    // because there is a profile behind it, and posted rather than waited on:
    // the caller is a mining thread whose own park is part of what the restore
    // needs, so what proves it happened is the state it leaves behind.
    if (!vkminer::control_switch_recoverable())
        fail("a switch with a profile behind it is not recoverable");

    vkminer::control_switch_failed("device 0 has no kernel for 'kawpow'");
    if (!wait_for([&]() {
            return std::strcmp(opt_algo, "scrypt") == 0 &&
                   vkminer::control_status().state == ControlState::kPaused;
        }, 5000))
        fail("a failed build did not put the previous algorithm back");
    st = vkminer::control_status();
    expect_int("epoch after a restore", (long long)st.epoch, 13);
    expect_text("rpc_url after a restore", rpc_url,
                "stratum+tcp://fifth.example:6666");
    expect_text("rpc_user after a restore", rpc_user, "second");
    if (st.last_error.empty())
        fail("a restore cleared the reason the switch failed");

    // And the restore is not itself recoverable, which is what stops a card
    // that will build neither profile from switching between them for the life
    // of the process.
    if (vkminer::control_switch_recoverable())
        fail("a restore is recoverable, so a failure under one would flap");

    // --- a whole profile: pool, algorithm and run state as one change -----
    //
    // The workers park once, what they were mining for is replaced on the far
    // side of that park, and the state they are released into is the one the
    // profile asked for. Two changes and one epoch: there is no moment at
    // which a manager can observe the new pool under the old run state.
    const ControlState running = ControlState::kRunning;
    const ControlState paused = ControlState::kPaused;

    expect_result("a pool change that also starts the miner",
                  vkminer::control_pool_request(
                      "stratum+tcp://seventh.example:8888", "seventh", "z",
                      5000, &complaint, &running),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_int("epoch after a pool change that also started the miner",
               (long long)st.epoch, 14);
    expect_state("after a pool change that also started the miner", st.state,
                 ControlState::kRunning);
    expect_text("rpc_url after a pool change that also started the miner",
                rpc_url, "stratum+tcp://seventh.example:8888");
    if (!wait_for([&]() { return vkminer::control_status().parked == 0; }, 5000))
        fail("a profile that started the miner left the workers parked");

    // Refused at its algorithm step, with a run-state change in it as well.
    // The refusal comes from the far side before anything has been moved, and
    // what it leaves behind is the whole pre-call profile -- algorithm, pool
    // and run state, and an epoch that did not advance. A half-switched miner
    // is never an outcome.
    g_hook_accepts.store(false);
    complaint.clear();
    expect_result("a profile whose algorithm the device refuses",
                  vkminer::control_algo_request(
                      "meowpow", "stratum+tcp://eighth.example:9999", "eighth",
                      "z", 5000, &complaint, &paused),
                  ControlResult::kInvalid);
    st = vkminer::control_status();
    expect_int("epoch after a refused profile", (long long)st.epoch, 14);
    expect_text("opt_algo after a refused profile", opt_algo, "scrypt");
    expect_text("rpc_url after a refused profile", rpc_url,
                "stratum+tcp://seventh.example:8888");
    expect_text("rpc_user after a refused profile", rpc_user, "seventh");
    expect_state("after a refused profile", st.state, ControlState::kRunning);
    if (!wait_for([&]() { return vkminer::control_status().parked == 0; }, 5000))
        fail("a refused profile left the workers out of the state it found");
    g_hook_accepts.store(true);

    // And accepted: algorithm, pool and run state all move, and between them
    // they spend one epoch rather than three.
    g_hook_parked.store(-1);
    expect_result("a profile that changes algorithm, pool and run state",
                  vkminer::control_algo_request(
                      "kawpow", "stratum+tcp://eighth.example:9999", "eighth",
                      "z", 5000, &complaint, &paused),
                  ControlResult::kOk);
    st = vkminer::control_status();
    expect_int("epoch after a whole profile", (long long)st.epoch, 15);
    expect_text("opt_algo after a whole profile", opt_algo, "kawpow");
    expect_text("rpc_url after a whole profile", rpc_url,
                "stratum+tcp://eighth.example:9999");
    expect_text("rpc_user after a whole profile", rpc_user, "eighth");
    expect_int("workers parked while the profile's hook ran",
               g_hook_parked.load(), kWorkers);
    expect_state("after a whole profile", st.state, ControlState::kPaused);
    if (!wait_for([&]() {
            return vkminer::control_status().parked == kWorkers;
        }, 5000))
        fail("a profile that paused the miner did not park the workers");

    // --- shutting down a paused miner -------------------------------------
    //
    // The workers are parked and not looking at anything else. Nothing releases
    // them but this, so without it a paused miner is one that cannot be told to
    // exit.
    vkminer::control_release_all();
    g_running.store(false);
    if (!wait_for([&]() { return vkminer::control_status().parked == 0; }, 5000))
        fail("workers were still parked after control_release_all()");
    for (int i = 0; i < kWorkers; i++)
        workers[(size_t)i].thread.join();
    pool.join();

    std::printf("%s\n", failures ? "control_test FAILED" : "control_test ok");
    return failures ? 1 : 0;
}
