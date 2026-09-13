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

#ifndef VKMINER_API_CONTROL_H
#define VKMINER_API_CONTROL_H

#include <cstdint>
#include <string>

namespace vkminer {

// What the miner is doing. Every accepted mutation moves through kSwitching and
// lands in one of the other three.
enum class ControlState { kRunning, kPaused, kStopped, kSwitching };

// Why a request was answered the way it was. What that becomes on the wire is
// the HTTP layer's business; nothing here knows about status codes.
enum class ControlResult {
    kOk,
    kAccepted,
    kBusy,
    kThrottled,  // too soon after the last one; the anti-flap interval
    kTimeout,
    kDisabled,
    kInvalid  // nothing was attempted: the request could not be carried out
};

struct ControlStatus {
    ControlState state = ControlState::kRunning;
    uint64_t     epoch = 0;  // advanced once per accepted mutation, never by a no-op
    uint64_t     switch_count = 0;
    int          workers = 0;
    int          parked = 0;

    // The anti-flap interval, and where this miner is in it. `last_switch_age_s`
    // is -1 until something has been switched; `ready_for_switch` is what a
    // manager polls to avoid asking for a re-target that will be refused, and
    // `retry_after_s` is how long that refusal has left to run -- 0 exactly when
    // ready_for_switch is true, and otherwise rounded up, so a caller that waits
    // it out is not refused a second time.
    int  min_interval_s = 0;
    int  last_switch_age_s = -1;
    int  retry_after_s = 0;
    bool ready_for_switch = true;

    // Seconds since the miner entered `state`. Counted from control_init, so a
    // miner nobody has controlled reports its uptime here rather than zero.
    int  state_age_s = 0;

    std::string  last_error;
};

const char *control_state_name(ControlState state);

// Called by main once opt_n_threads is settled and before any worker starts.
void control_init(int workers);

// True when --api-control was given. With it off every request is kDisabled and
// the two hooks below are constant.
bool control_enabled();

/* ---------------------------------------------------------- mining hooks --
 *
 * Read by every worker on every idle iteration, so they are one relaxed load
 * and take no lock: a mining thread blocking on a mutex that a stalled request
 * handler holds is a stopped miner. control_park() does take the lock, but only
 * once the caller has already decided to stop mining.
 */

bool control_wants_park();

// True while the state being parked into is one a worker should keep its
// device's shared table alive across. A pause is resumed from; a stop is not.
bool control_park_retains_shared();

// Counts this worker as parked and returns when it may mine again, when the
// process is winding up, or when a second request needs this worker to come
// round the loop and read the terms of the park again -- a pause that becomes a
// stop is parked on different terms, because the second one gives up the shared
// table. So a return is not by itself permission to mine: the caller's own loop
// re-tests control_wants_park().
//
// Call it with the pipeline drained and the kernel released. A worker that
// counts itself in while the device still holds a dispatch parks a miner that
// is still writing to buffers a switch is about to free.
void control_park(int thr_id);

/* --------------------------------------------------------- control side -- */

// Asks for a run state.
//
// kOk once every worker has parked, or resumed. kAccepted if `wait_ms` ran out
// with the change still in flight -- it is still in flight, and a later
// control_status() sees it land. kTimeout if no park completed within
// --api-control-park-timeout, in which case the request is rolled back and the
// miner is left mining. kBusy if another mutation holds the barrier.
//
// `why` takes the message last_error will also carry. Pass 0 for `wait_ms` to
// wait out the park timeout rather than answering early.
ControlResult control_request(ControlState want, unsigned wait_ms,
                              std::string *why);

// Also completes a request that was answered kAccepted, and rolls one back that
// has since run past the park timeout, so an abandoned mutation does not leave
// the miner in kSwitching for the life of the process.
ControlStatus control_status();

// Releases every parked worker without recording a state change, so that a
// paused miner can still be shut down.
void control_release_all();

/* ------------------------------------------------------ the pool re-target --
 *
 * A pool change runs on the stratum thread and nowhere else: rpc_url is what
 * the next connection is built from, short_url points into it, and the
 * connection itself is read under no lock. So the control side posts what it
 * wants and waits, and the stratum thread is what carries it out.
 */

// Asks the miner to mine for a different pool. An empty user or pass keeps the
// credential in force.
//
// The workers park before the socket is replaced and resume into the state they
// were parked out of: a re-target changes who the miner works for, not what it
// is doing. So it costs one epoch and leaves the run state alone.
//
// kInvalid for a url this miner cannot mine against, kThrottled for one asked
// less than --api-control-min-interval after the last accepted change; both
// answer with nothing parked and nothing disconnected. The run-state verbs are
// exempt from the interval -- an emergency stop that answers "too soon" is not
// a stop. kTimeout means either that the change was never taken up, and then
// nothing happened at all, or that it was taken and the new pool has not
// answered, and then it stands and the miner goes on trying; last_error says
// which. A pool is never put back: that would be a second switch, to one
// nobody asked for.
//
// `want` is the run state to leave the miner in, or null to come back to the
// one the workers were parked out of. It is what makes a pool change and a
// run-state change one change: one settle, one epoch, and no moment at which a
// manager can observe the new pool under the old run state.
ControlResult control_pool_request(const std::string &url,
                                   const std::string &user,
                                   const std::string &pass, unsigned wait_ms,
                                   std::string *why,
                                   const ControlState *want = nullptr);

/* -------------------------------------------------- the algorithm change --
 *
 * An algorithm and a pool are one change and arrive together. The Stratum this
 * miner speaks is chosen from the algorithm before the socket opens and cannot
 * be revised by a method that arrives later, so a switch that kept its
 * connection would be reading the new algorithm's jobs through the old one's
 * parser. The session is dropped and re-opened instead.
 */

// What has to happen on the far side of the park, while every worker is parked
// and before the new socket opens: the old algorithm's shared table dropped,
// the new one's memory checked against the device, its self-test run, and the
// device tuned for it. Registered by main, and run on the stratum thread with
// no lock held -- on a DAG algorithm it takes seconds and a manager is polling
// meanwhile.
//
// Returning false, with a reason and having changed nothing, refuses the
// switch: the barrier rolls back and the miner goes on mining what it was.
typedef bool (*ControlSwitchHook)(const char *algo, std::string *why);

void control_set_switch_hook(ControlSwitchHook hook);

// Asks the miner to mine a different algorithm, for a different pool.
//
// The answers are the pool request's, and so is the epoch it spends: what is
// added is that the workers rebind to the new algorithm as they leave the park,
// and that the far side may refuse before anything has changed -- an algorithm
// this build does not have, or one whose dataset will not fit the device.
ControlResult control_algo_request(const std::string &algo,
                                   const std::string &url,
                                   const std::string &user,
                                   const std::string &pass, unsigned wait_ms,
                                   std::string *why,
                                   const ControlState *want = nullptr);

// Whether a build that has just failed can be answered by putting the previous
// profile back rather than by ending the run.
//
// False at startup, where there is nothing to go back to and a device that will
// not build is a miner that should not start. False again while a restore is
// the thing in force, which is what stops a card that will build neither
// profile from switching between them for the life of the process.
bool control_switch_recoverable();

// Puts the previous profile back, after a rebuild failed on the far side of a
// switch. Posted and not waited on: the caller is a mining thread, and its own
// park is part of what this needs in order to complete.
void control_switch_failed(const std::string &why);

/* --------------------------------------------- what the stratum thread calls
 *
 * Through the C entry points of the same name in miner.h, because the thread
 * that owns the connection is inherited C. Nothing else should call these.
 */

// Takes a posted change and puts it into rpc_url, rpc_user and rpc_pass. True
// if there was one. What to do about it afterwards is the caller's: it knows
// whether it is holding a connection that now points at the wrong pool.
bool control_pool_apply();

// The ack. A re-target is done when the pool it named has this miner
// subscribed and authorized, not when the url changed.
void control_pool_connected();

// A change is posted and not yet taken -- which is a reason to stop waiting on
// a quiet socket.
bool control_pool_pending();

// Posted and not yet acked. The reconnect in that window is the one that was
// asked for: it is not a pool fault, does not count as one, and must not
// escalate to anything that gives up on the pool the manager chose.
bool control_switch_in_flight();

// The miner is stopped, so the connection is deliberately down and is not to be
// re-opened. Not a fault either.
bool control_holds_connection();

}  // namespace vkminer

#endif  // VKMINER_API_CONTROL_H
