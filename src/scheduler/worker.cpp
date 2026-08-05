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

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace {

// Set once by main before any worker starts, read by all of them.
vkminer::ComputeBackend *g_backend = nullptr;
const int *g_worker_device = nullptr;

// Shutdown. The flag is set from whichever thread is winding the process up;
// the count is how many workers are still holding device objects.
std::atomic<bool> g_stop{false};
std::atomic<int> g_live{0};

// Counts a worker as running for exactly as long as it might touch a device.
// Declared first in miner_thread so that it is destroyed last -- after the
// kernel, whose own destructor waits on the device it was created from.
struct WorkerLifetime {
    WorkerLifetime() { g_live.fetch_add(1, std::memory_order_relaxed); }
    ~WorkerLifetime() { g_live.fetch_sub(1, std::memory_order_release); }
};

// Nonces are split into one contiguous range per worker so that two workers
// never test the same nonce. The tail margin is for the batch that straddles
// the end of a range.
constexpr uint32_t kRangeMargin = 0x20;

// How often --benchmark prints. The periodic report is on a five minute cycle
// aimed at an unattended miner; a benchmark is something somebody is standing
// in front of.
constexpr auto kBenchmarkInterval = std::chrono::seconds(5);

// A job that never came from a pool. --benchmark measures how fast this machine
// hashes, which needs a header and a target and nothing else.
//
// The header is one of the algorithm's own published vectors, so the words the
// kernel schedules are the shape of the thing it will be given in earnest
// rather than a pattern that might optimize differently.
bool benchmark_work(const vkminer::Algorithm &algo, struct work *work)
{
    const vkminer::KnownAnswer *answers = nullptr;
    if (!algo.known_answers(&answers))
        return false;

    memset(work, 0, sizeof *work);

    const size_t words = algo.header_bytes() / 4;
    for (size_t i = 0; i < words && i < sizeof work->data / sizeof *work->data;
         i++)
        work->data[i] = be32dec(answers[0].header + i * 4);

    // One bit off the published header, because the published header is a
    // solved one. A GPU covers the whole nonce space in seconds, so the block's
    // own nonce would be rediscovered on every pass -- correct, useless, and a
    // line of log every few seconds. Word 15 is inside the merkle root, which
    // is a field a pool rewrites constantly anyway.
    if (words > 15)
        work->data[15] ^= 1u;

    // 0x000000000000ffff0000...0000, most significant word last, which is the
    // order fulltest() compares in: an ordinary pool share target, met about
    // once in 2^48 nonces. Not a target the benchmark is expected to meet --
    // it is here because a dispatch needs one, and a realistic one keeps the
    // comparison doing the work it does when mining.
    work->target[7] = 0x00000000;
    work->target[6] = 0x0000ffff;
    return true;
}

void report_benchmark(const double *rates, int workers, double total)
{
    char scaled[32];
    format_hashrate(total, scaled);
    applog(LOG_NOTICE, "Benchmark: %s", scaled);

    // Per worker only when there is more than one, because with a single
    // device the second line would repeat the first.
    if (workers > 1)
        for (int i = 0; i < workers; i++) {
            format_hashrate(rates[i], scaled);
            applog2(LOG_INFO, "worker %d   %s", i, scaled);
        }
}

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

void worker_request_stop()
{
    g_stop.store(true, std::memory_order_relaxed);
}

int worker_count()
{
    return g_live.load(std::memory_order_acquire);
}

extern "C" void *miner_thread(void *userdata)
{
    struct thr_info *mythr = static_cast<struct thr_info *>(userdata);
    const int thr_id = mythr->id;
    const int device_index = g_worker_device[thr_id];

    WorkerLifetime live;

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
    bool have_job = false;
    auto last_report = std::chrono::steady_clock::now();

    while (!g_stop.load(std::memory_order_relaxed)) {
        bool new_job = false;

        if (opt_benchmark) {
            // One synthetic job for the whole run: there is no pool to send a
            // second one, and restarting the range would remeasure the same
            // nonces.
            if (!have_job) {
                if (!benchmark_work(*algo, &work)) {
                    applog(LOG_ERR, "Worker %d: '%s' has no header to "
                                    "benchmark with", thr_id, opt_algo);
                    return nullptr;
                }
                have_job = true;
                new_job = true;
            }
        } else {
            // No job to mine: the connection is down, or the first notify has
            // not arrived yet. Nothing to do but wait for one, cheaply.
            if (stratum_down || !g_work_time) {
                work_restart[thr_id].restart = 0;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            pthread_rwlock_rdlock(&g_work_lock);
            new_job = work.job_epoch != g_work.job_epoch;
            if (new_job) {
                work_free(&work);
                work_copy(&work, &g_work);
            }
            pthread_rwlock_unlock(&g_work_lock);
        }

        if (new_job) {
            nonce = first_nonce;
            work_restart[thr_id].restart = 0;
        }

        uint32_t batch = kernel->preferred_batch();
        if (nonce > end_nonce - batch)
            batch = end_nonce - nonce;
        if (!batch) {
            // A benchmark has no pool to send a new job, so the only way to
            // keep measuring is to go round again. Retesting nonces is the
            // point of a benchmark and a bug in a miner, which is why the two
            // cases are written out separately.
            if (opt_benchmark) {
                nonce = first_nonce;
                continue;
            }
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

            // A benchmark is not connected to anything and its target is not
            // anybody's. Finding a nonce that meets it says the kernel and the
            // comparison work, which is worth a line, and submitting it would
            // be an error.
            if (opt_benchmark) {
                applog(LOG_INFO, "Benchmark: nonce %08x meets the synthetic "
                                 "target; nothing is submitted",
                       found[i].nonce);
                continue;
            }

            work.data[STD_NONCE_INDEX] = found[i].nonce;
            submit_solution(&work, hash, mythr);
        }

        nonce += batch;

        if (thr_id != 0)
            continue;

        if (!opt_benchmark) {
            report_summary_log(false);
            continue;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_report < kBenchmarkInterval)
            continue;
        last_report = now;

        // Copied out under the lock and printed outside it: applog takes a
        // lock of its own, and holding two in one order here and the other
        // order anywhere else is how a miner stops for good.
        std::vector<double> rates(static_cast<size_t>(opt_n_threads));
        double total;
        pthread_mutex_lock(&stats_lock);
        for (int i = 0; i < opt_n_threads; i++)
            rates[static_cast<size_t>(i)] = thr_hashrates[i];
        total = global_hashrate;
        pthread_mutex_unlock(&stats_lock);

        report_benchmark(rates.data(), opt_n_threads, total);
    }

    // The kernel goes here rather than at the end of the enclosing scope, so
    // that the device is given up before this worker stops being counted.
    kernel.reset();
    work_free(&work);
    return nullptr;
}
