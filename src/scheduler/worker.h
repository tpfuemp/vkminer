// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_SCHEDULER_WORKER_H__
#define VKMINER_SCHEDULER_WORKER_H__

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

#endif  // VKMINER_SCHEDULER_WORKER_H__
