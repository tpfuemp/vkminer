// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_SCHEDULER_WORKER_H__
#define VKMINER_SCHEDULER_WORKER_H__

#include <cstdint>

#include "backends/backend.h"

// Called by main before any worker starts. `device_map` has one entry per
// worker, holding the index into backend->devices() that worker mines on; it
// must outlive the workers.
void worker_set_backend(vkminer::ComputeBackend *backend, const int *device_map);

// The worker entry point, as pthread_create wants it.
extern "C" void *miner_thread(void *userdata);

// Asks every worker to finish the dispatch it is in and return.
//
// A dispatch cannot be cancelled, so this is a request and not an order: a
// worker notices it between batches. worker_count() reports how many are still
// running, and reaches zero only after the last one has handed its kernel back
// -- which is the point before which nothing owning a device may be destroyed.
void worker_request_stop();
int worker_count();

// -1 unless a worker has hit something the run cannot continue past, in which
// case it is the code to end the process with. That worker has already logged
// why and left its loop; it does not end the process itself, because the
// teardown that follows waits for it to let go of its device first.
int worker_exit_code();

// What --benchmark-target is for: candidates the devices emitted and the host
// re-hashed, confirmed and not. Zero and zero at the default target is the
// expected answer and says nothing; only a loosened target makes these
// evidence.
void worker_candidate_counts(uint64_t *confirmed, uint64_t *rejected);

#endif  // VKMINER_SCHEDULER_WORKER_H__
