// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One worker per device. It takes whatever job the Stratum thread last
// published, hands nonce ranges to a Kernel, and submits whatever comes back.
//
// Upstream this loop was miner_thread, and it both scheduled and hashed. Here
// it only schedules: the hashing is a dispatch to a device that runs whether
// this thread is looking or not, so the loop is written around the latency of
// a dispatch rather than the cost of a hash. Hence the queue: a device with
// nothing behind what it is finishing goes idle until this thread notices.

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "tune.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <deque>
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

// The exit code a worker has asked the process to end with, -1 for none.
//
// A worker cannot end the process itself. proper_exit waits for every worker to
// hand its device back, so one that calls it from inside its own loop waits for
// itself: it sits out the grace period, warns that it is stuck, and leaks the
// device. Recording the code and leaving by the ordinary route lets main call
// proper_exit from a thread that owns nothing.
std::atomic<int> g_fatal{-1};

// Ends the run because of something this worker cannot continue past. The
// caller logs what happened; this only decides that it is fatal, and the first
// worker to say so is the one whose code is used.
void fail_run(int code)
{
    int none = -1;
    g_fatal.compare_exchange_strong(none, code, std::memory_order_relaxed);
    g_stop.store(true, std::memory_order_relaxed);
}

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

// How much wall clock a published hash rate is averaged over. Long enough that
// the boundaries between dispatches do not show through it, short enough that a
// device which has stopped reads as slowing down rather than staying fast.
constexpr auto kRateWindow = std::chrono::seconds(2);

// Per worker, for the periodic report. `stale` counts batches that came back
// after the pool had replaced the job they were launched under: not work thrown
// away -- a share found in one is still submitted against its own job -- but
// the number that says whether dispatches are sized for how fast jobs change.
struct BatchCount {
    std::atomic<uint64_t> total{0};
    std::atomic<uint64_t> stale{0};
};

// One entry per worker, allocated before any of them starts. Null in a build
// that never calls worker_set_backend.
std::unique_ptr<BatchCount[]> g_batches;

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

// Publishes what one worker managed over one window of wall clock.
//
// Upstream divided a batch by the time that batch took, answering "how fast is
// this device while hashing" -- the same number whether the miner is mining or
// waiting on a pool that stopped sending jobs. A device is idle between
// dispatches, between jobs and for a whole reconnect, and none of that shows
// unless the divisor is wall clock.
void publish_hashrate(int thr_id, double hashes, double seconds)
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

// The per-device lines of the periodic report, printed from inside it.
//
// With one device this repeats the aggregate above it and is worth printing
// anyway: the aggregate cannot say which of two GPUs is the slow one.
void report_devices()
{
    if (!g_batches || !g_backend)
        return;

    // Copied out under the lock and printed outside it, because applog takes a
    // lock of its own.
    std::vector<double> rates(static_cast<size_t>(opt_n_threads));
    pthread_mutex_lock(&stats_lock);
    for (int i = 0; i < opt_n_threads; i++)
        rates[static_cast<size_t>(i)] = thr_hashrates[i];
    pthread_mutex_unlock(&stats_lock);

    // One line per device, not per worker. Two workers on one GPU are two ways
    // of keeping the same queue busy; the line compares devices.
    std::vector<int> seen;
    for (int i = 0; i < opt_n_threads; i++) {
        const int dev = g_worker_device[i];
        if (std::find(seen.begin(), seen.end(), dev) != seen.end())
            continue;
        seen.push_back(dev);

        double rate = 0.;
        uint64_t total = 0, stale = 0;
        int workers = 0;
        for (int j = i; j < opt_n_threads; j++) {
            if (g_worker_device[j] != dev)
                continue;
            rate += rates[static_cast<size_t>(j)];
            total += g_batches[j].total.load(std::memory_order_relaxed);
            stale += g_batches[j].stale.load(std::memory_order_relaxed);
            workers++;
        }

        char units[4] = {0};
        scale_hash_for_display(&rate, units);

        // Nothing dispatched yet would read as 0.0% late, which is a claim this
        // line is not in a position to make.
        char late[64];
        if (total)
            snprintf(late, sizeof late, "%.1f%% of %" PRIu64 " batches late",
                     100. * safe_div(static_cast<double>(stale),
                                     static_cast<double>(total), 0.),
                     total);
        else
            snprintf(late, sizeof late, "no batches yet");

        // The worker count only appears when it is not one, because on the
        // ordinary setup it would be the same "x1" on every line forever.
        char sharing[16] = {0};
        if (workers > 1)
            snprintf(sharing, sizeof sharing, " x%d", workers);

        applog2(LOG_INFO, "Device %-2d %7.2f%sh/s%s   %s  (%s)",
                dev, rate, units, sharing, late,
                g_backend->devices()[static_cast<size_t>(dev)].name.c_str());
    }
}

}  // namespace

void worker_set_backend(vkminer::ComputeBackend *backend, const int *device_map)
{
    g_backend = backend;
    g_worker_device = device_map;

    // opt_n_threads is settled by the time main gets here, and no worker has
    // started, so this is the last moment at which the array can be sized
    // without anybody racing for it.
    g_batches.reset(new BatchCount[static_cast<size_t>(opt_n_threads)]);
    report_devices_hook = report_devices;
}

void worker_request_stop()
{
    g_stop.store(true, std::memory_order_relaxed);
}

int worker_count()
{
    return g_live.load(std::memory_order_acquire);
}

int worker_exit_code()
{
    return g_fatal.load(std::memory_order_relaxed);
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
        fail_run(1);
        return nullptr;
    }

    // The algorithm chooses what to run from what the device can do; the
    // backend reads the result without asking what it computes. Then the
    // tuning, which is neither's business: what this device was measured to
    // like, overriding the width the algorithm would have accepted and the
    // depth the backend would have picked.
    vkminer::KernelSpec spec =
        algo->kernel(g_backend->devices()[device_index]);
    vkminer::apply_tuning(device_index, &spec);

    std::unique_ptr<vkminer::Kernel> kernel =
        g_backend->create_kernel(device_index, spec);
    if (!kernel) {
        // Fatal rather than one worker quietly leaving. With more than one
        // device this is how a GPU that failed to open would show up: the miner
        // carrying on at half its hashrate with one line in the scrollback,
        // which is exactly the failure nobody notices for a week.
        applog(LOG_ERR, "Worker %d: backend '%s' has no kernel for '%s' on "
                        "device %d", thr_id, g_backend->name(), opt_algo,
               device_index);
        fail_run(1);
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

    // This worker's own extranonce2 sequence. It starts at the worker's index
    // and strides by the number of workers, so no two of them ever build the
    // same coinbase, and it is re-armed rather than reused whenever the header
    // it belongs to changes.
    uint64_t xnonce2 = 0;
    bool xnonce2_armed = false;

    // The rate window. `account` is called with the hashes a dispatch covered,
    // and with none for time the worker spent waiting rather than hashing --
    // which is the whole reason the window exists, so every path that sleeps
    // has to go through it.
    auto window_start = std::chrono::steady_clock::now();
    double window_hashes = 0.;
    auto account = [&](double hashes) {
        window_hashes += hashes;
        const auto now = std::chrono::steady_clock::now();
        if (now - window_start < kRateWindow)
            return;
        publish_hashrate(thr_id, window_hashes,
                         std::chrono::duration<double>(now - window_start).count());
        window_start = now;
        window_hashes = 0.;
    };

    // How many dispatches the device will hold at once, and how many nonces
    // each outstanding one covers, oldest first. A device with the next
    // dispatch already queued starts it the moment it finishes one, instead of
    // waiting out a round trip through this thread.
    //
    // The deque deliberately holds no header: everything in flight was launched
    // under the one in `work`, because every point that changes `work` drains
    // this first -- see drain().
    const size_t depth = std::max<uint32_t>(1, kernel->queue_depth());
    std::deque<uint32_t> inflight;

    // Takes the oldest outstanding dispatch and does whatever its results
    // deserve. False means the device failed -- that dispatch is retired
    // either way, so a caller emptying the rest keeps making progress.
    auto reap = [&]() -> bool {
        if (inflight.empty())
            return true;

        vkminer::Solution found[16];
        const int count = kernel->collect(found, 16);
        const uint32_t nonces = inflight.front();
        inflight.pop_front();

        if (count < 0) {
            applog(LOG_ERR, "Worker %d: device failed", thr_id);
            account(0.);
            return false;
        }

        // Counted where the hashes were finished rather than where they were
        // asked for, so that a dispatch which took twice as long as the one
        // before it shows up as half the rate and not as a rate at all.
        account(nonces);

        // Whether the pool moved on while this batch was in flight. Read after
        // the fact because there is nothing to be done about it in advance: a
        // dispatch cannot be recalled, and this is the measurement that says
        // whether they are being sized to finish inside a job.
        if (g_batches) {
            bool late = false;
            if (!opt_benchmark) {
                pthread_rwlock_rdlock(&g_work_lock);
                late = work.job_epoch != g_work.job_epoch;
                pthread_rwlock_unlock(&g_work_lock);
            }
            g_batches[thr_id].total.fetch_add(1, std::memory_order_relaxed);
            if (late)
                g_batches[thr_id].stale.fetch_add(1, std::memory_order_relaxed);
        }

        // A late result is still submitted, and submitted against the job it
        // was launched under: the id, the ntime and the extranonce2 all come
        // from this worker's own copy, so a pool still holding that job credits
        // it. Dropping it would throw away a share the pool would have taken.
        for (int i = 0; i < count; i++) {
            // Every candidate is re-hashed on the host first, and there will be
            // no fast path around it: a device that reports a share it did not
            // find costs the pool's trust in this miner, and one nonce is
            // invisible next to the batch that produced it.
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

        return true;
    };

    // Empties the pipeline and accounts for everything in it. Every point where
    // `work` is about to change goes through this first, because what the
    // device is still holding was launched under the header that is there now.
    auto drain = [&]() {
        // Each call retires one dispatch whether it succeeded or not, so a
        // device that has stopped answering empties this rather than spinning
        // in it.
        while (!inflight.empty())
            reap();
    };

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
                    fail_run(1);
                    break;
                }
                have_job = true;
                new_job = true;
            }
        } else {
            // No job to mine: the connection is down, or the first notify has
            // not arrived yet. Nothing to do but wait for one, cheaply.
            if (stratum_down || !g_work_time) {
                // Nothing more will be launched until this clears, so the
                // device may as well finish what it has and be counted for it.
                drain();
                work_restart[thr_id].restart = 0;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                account(0.);
                continue;
            }

            pthread_rwlock_rdlock(&g_work_lock);
            new_job = work.job_epoch != g_work.job_epoch;
            pthread_rwlock_unlock(&g_work_lock);

            if (new_job) {
                // Before the copy, not after. What the device is still holding
                // was launched under the header `work` has at this moment, and
                // the copy is about to replace it. A job that arrives in the
                // gap costs nothing: the copy below takes whatever is newest.
                drain();

                pthread_rwlock_rdlock(&g_work_lock);
                work_free(&work);
                work_copy(&work, &g_work);
                pthread_rwlock_unlock(&g_work_lock);
            }
        }

        if (new_job) {
            nonce = first_nonce;
            xnonce2 = static_cast<uint64_t>(thr_id);
            xnonce2_armed = false;
            work_restart[thr_id].restart = 0;

            // Without room to move the coinbase there is one nonce range per
            // job, which a device finishes in seconds and cannot extend. That
            // is a pool this miner cannot work with; saying so once beats a
            // warning every few seconds for the rest of the session.
            if (!opt_benchmark && !work.xnonce2_len) {
                applog(LOG_ERR, "This pool gave the miner no extranonce2 "
                                "field. A device covers a whole nonce range "
                                "in seconds and would have nowhere to go from "
                                "there.");
                fail_run(1);
                break;
            }
        }

        // The header this worker mines is its own: same job as everyone else's,
        // different coinbase. Re-derived here rather than at the point it
        // changes, so that a job arriving in between is picked up first.
        if (!opt_benchmark && !xnonce2_armed) {
            // Arming rewrites the merkle root, which is the header the device
            // is mining. Every path that reaches here has drained already; this
            // is what keeps that a fact rather than an assumption, and it costs
            // a branch when it is one.
            drain();

            if (!stratum_set_extranonce2(&work, &stratum, xnonce2)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                account(0.);
                continue;
            }
            xnonce2_armed = true;
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
            // The range is exhausted, which at device speed happens seconds
            // into a job with tens of seconds left. Moving the extranonce2 on
            // gives a different coinbase and a fresh range on the same job --
            // the difference between mining continuously and mining for the
            // first few seconds after every notify.
            xnonce2 += static_cast<uint64_t>(opt_n_threads);
            xnonce2_armed = false;
            nonce = first_nonce;
            continue;
        }

        if (!kernel->dispatch(work.data, work.target, nonce, batch)) {
            applog(LOG_ERR, "Worker %d: dispatch failed", thr_id);
            drain();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            account(0.);
            continue;
        }
        inflight.push_back(batch);
        nonce += batch;

        // Only once the device has as much queued as it will take. Collecting
        // any sooner is exactly what this is here to stop: the device would
        // finish a dispatch and then sit idle until this thread got round to
        // handing it the next one.
        if (inflight.size() >= depth && !reap()) {
            drain();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            account(0.);
            continue;
        }

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

    // The device has already been paid for whatever is still queued on it, and
    // a share in there is a share. Waiting the last few dispatches out costs a
    // fraction of a second of a shutdown that is about to wait on a pool.
    drain();

    // The kernel goes here rather than at the end of the enclosing scope, so
    // that the device is given up before this worker stops being counted.
    kernel.reset();
    work_free(&work);
    return nullptr;
}
