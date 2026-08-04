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

    std::unique_ptr<vkminer::Kernel> kernel =
        g_backend->create_kernel(g_worker_device[thr_id], opt_algo);
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
            work.data[STD_NONCE_INDEX] = found[i].nonce;
            submit_solution(&work, found[i].hash, mythr);
        }

        nonce += batch;

        if (thr_id == 0)
            report_summary_log(false);
    }

    return nullptr;
}
