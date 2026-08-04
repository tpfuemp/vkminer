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

#endif  // VKMINER_SCHEDULER_WORKER_H__
