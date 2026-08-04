// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One worker per device. It takes whatever job the Stratum thread last
// published, hands nonce ranges to a Kernel, and submits whatever comes back.
//
// Upstream this loop was miner_thread, and it both scheduled and hashed. Here
// it only schedules: the hashing is a dispatch to a device that runs whether
// this thread is looking or not, so the loop is written around the latency of
// a dispatch rather than around the cost of a hash.

#include "algorithms/registry.h"
#include "backends/backend.h"

extern "C" {
#include "core/miner.h"
}

#include <chrono>
#include <cstring>
#include <memory>
#include <thread>

namespace {

// Set once by main before any worker starts, read by all of them.
vkminer::ComputeBackend *g_backend = nullptr;
const int *g_worker_device = nullptr;

// Nonces are split into one contiguous range per worker so that two workers
// never test the same nonce. The tail margin is for the batch that straddles
// the end of a range.
constexpr uint32_t kRangeMargin = 0x20;

void update_hashrate(int thr_id, double hashes, double seconds)
{
    pthread_mutex_lock(&stats_lock);
    thr_hashrates[thr_id] = safe_div(hashes, seconds, 0.);
    total_hashes += hashes;
    gettimeofday(&total_hashes_time, nullptr);

    double sum = 0.;
    for (int i = 0; i < opt_n_threads; i++)
        sum += thr_hashrates[i];
    global_hashrate = sum;
    pthread_mutex_unlock(&stats_lock);
}

}  // namespace

void worker_set_backend(vkminer::ComputeBackend *backend, const int *device_map)
{
    g_backend = backend;
    g_worker_device = device_map;
}

extern "C" void *miner_thread(void *userdata)
{
    struct thr_info *mythr = static_cast<struct thr_info *>(userdata);
    const int thr_id = mythr->id;
    const int device_index = g_worker_device[thr_id];

    // One instance per worker rather than one shared between them. An
    // algorithm holds no per-job state, so sharing would work today; a worker
    // that owns its own cannot be the thing that stops being true.
    std::unique_ptr<vkminer::Algorithm> algo = vkminer::create_algorithm(opt_algo);
    if (!algo) {
        applog(LOG_ERR, "Worker %d: no algorithm called '%s'", thr_id, opt_algo);
        return nullptr;
    }

    // The algorithm chooses what to run from what the device can do; the
    // backend reads the result without asking what it computes.
    const vkminer::KernelSpec spec =
        algo->kernel(g_backend->devices()[device_index]);

    std::unique_ptr<vkminer::Kernel> kernel =
        g_backend->create_kernel(device_index, spec);
    if (!kernel) {
        applog(LOG_ERR, "Worker %d: backend '%s' has no kernel for '%s'",
               thr_id, g_backend->name(), opt_algo);
        return nullptr;
    }

    const uint32_t range = 0xffffffffU / static_cast<uint32_t>(opt_n_threads);
    const uint32_t first_nonce = range * static_cast<uint32_t>(thr_id);
    const uint32_t end_nonce = first_nonce + range - kRangeMargin;

    struct work work;
    memset(&work, 0, sizeof work);
    uint32_t nonce = first_nonce;

    while (true) {
        // No job to mine: the connection is down, or the first notify has not
        // arrived yet. Nothing to do but wait for one, cheaply.
        if (stratum_down || !g_work_time) {
            work_restart[thr_id].restart = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        pthread_rwlock_rdlock(&g_work_lock);
        const bool new_job = work.job_epoch != g_work.job_epoch;
        if (new_job) {
            work_free(&work);
            work_copy(&work, &g_work);
        }
        pthread_rwlock_unlock(&g_work_lock);

        if (new_job) {
            nonce = first_nonce;
            work_restart[thr_id].restart = 0;
        }

        uint32_t batch = kernel->preferred_batch();
        if (nonce > end_nonce - batch)
            batch = end_nonce - nonce;
        if (!batch) {
            // The range is exhausted before the pool sent a new job. Waiting
            // costs nothing; wrapping would retest nonces already rejected.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        struct timeval start, stop, elapsed;
        gettimeofday(&start, nullptr);

        if (!kernel->dispatch(work.data, work.target, nonce, batch)) {
            applog(LOG_ERR, "Worker %d: dispatch failed", thr_id);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        vkminer::Solution found[16];
        const int count = kernel->collect(found, 16);
        if (count < 0) {
            applog(LOG_ERR, "Worker %d: device failed", thr_id);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        gettimeofday(&stop, nullptr);
        timeval_subtract(&elapsed, &stop, &start);
        update_hashrate(thr_id, batch,
                        elapsed.tv_sec + elapsed.tv_usec * 1e-6);

        // A dispatch cannot be recalled, so a result that arrives after a new
        // job is checked against the job it was launched under, not the
        // current one. submit_solution drops it if the epoch has moved on.
        for (int i = 0; i < count; i++) {
            // Every candidate is hashed again on the host before it is
            // submitted. There is no fast path around this and there will not
            // be one: a device that reports a share it did not find costs the
            // pool's trust in this miner, and the cost of re-hashing one nonce
            // is invisible next to the batch that produced it.
            uint32_t hash[8];
            if (!algo->verify(work.data, found[i].nonce, work.target, hash)) {
                applog(LOG_WARNING,
                       "Worker %d: device %d reported nonce %08x, which does "
                       "not meet the target -- share dropped",
                       thr_id, device_index, found[i].nonce);
                continue;
            }

            // It is a real share, but the device's own arithmetic disagrees
            // with the host's. The share is still submitted, because the host
            // just proved it; the mismatch is logged because it means the
            // kernel is wrong in a way that happened not to matter this time.
            if (memcmp(hash, found[i].hash, sizeof hash) != 0)
                applog(LOG_WARNING,
                       "Worker %d: device %d returned a different hash for "
                       "nonce %08x than the host computes",
                       thr_id, device_index, found[i].nonce);

            work.data[STD_NONCE_INDEX] = found[i].nonce;
            submit_solution(&work, hash, mythr);
        }

        nonce += batch;

        if (thr_id == 0)
            report_summary_log(false);
    }

    return nullptr;
}
