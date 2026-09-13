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

// Which device a worker mines on, as an index into backend->devices(), or -1
// before worker_set_backend has run. Two workers may answer the same: what a
// worker is on a GPU is a queue to keep fed, so a reader comparing devices has
// to fold the workers on each one together itself.
int worker_device_index(int thr_id);

// Dispatches this worker has completed, and how many of them came back after
// the pool had replaced the job they were launched under. Zero and zero before
// the first dispatch, which is not the same claim as none of them being late --
// a caller with no batches yet has nothing to report a rate from.
void worker_batch_counts(int thr_id, uint64_t *total, uint64_t *stale);

// Bytes of epoch-scoped table the backend is holding on `device_index`, which
// is an index into backend->devices() and not a worker id. Zero before
// worker_set_backend has run, and on a device holding nothing.
//
// A park keeps the table, so this stays non-zero across one; only a stop gives
// the memory back.
uint64_t worker_shared_table_bytes(int device_index);

#endif  // VKMINER_SCHEDULER_WORKER_H__
