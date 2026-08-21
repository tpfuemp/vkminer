// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One worker per device. It takes whatever job the Stratum thread last
// published, hands nonce ranges to a Kernel, and submits whatever comes back.
//
// This loop only schedules. The hashing is a dispatch to a device that runs
// whether this thread is looking or not, so the loop is written around the
// latency of a dispatch rather than the cost of a hash -- hence the queue: a
// device with nothing behind what it is finishing goes idle until this thread
// notices.

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "scheduler/candidate_log.h"
#include "tune.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
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
//
// `best_ratio_sum` and `best_samples` are the --vk-probe-best pair, copied out
// of the kernel so the reporting thread can read them without touching it.
// `hashes` is carried alongside only so a line about the probe can say how much
// work is behind it; the kernel's terms are already scaled per dispatch.
struct BatchCount {
    std::atomic<uint64_t> total{0};
    std::atomic<uint64_t> stale{0};
    std::atomic<double> best_ratio_sum{0.};
    std::atomic<uint64_t> best_samples{0};
    std::atomic<uint64_t> hashes{0};
};

// One entry per worker, allocated before any of them starts. Null in a build
// that never calls worker_set_backend.
std::unique_ptr<BatchCount[]> g_batches;

// Candidates across every worker: the ones the host re-hashed and confirmed,
// and the ones it refused. Not per worker, because the question these answer is
// whether the emit-and-verify path runs at all, which is not a property of a
// device. Counted whether mining or benchmarking; only --benchmark-target makes
// the totals large enough to compare against a prediction.
std::atomic<uint64_t> g_candidates_confirmed{0};
std::atomic<uint64_t> g_candidates_rejected{0};

// Which header word a benchmark moves to stop remeasuring the same nonces.
// Word 15 for a Bitcoin header, which is inside the merkle root -- a field a
// pool rewrites constantly anyway. Word 0 for anything shorter, which for the
// one such algorithm is the head of the header hash and is exactly as free.
//
// Never a word the algorithm reads structurally. KawPoW's word 8 is the block
// height, and moving that would step the epoch and the program rather than the
// header, which is a benchmark measuring a DAG rebuild.
size_t benchmark_word(const vkminer::Algorithm &algo)
{
    return algo.header_bytes() / 4 > 15 ? 15 : 0;
}

// A job that never came from a pool: --benchmark needs a header and a target
// and nothing else. The header is one of the algorithm's own published vectors,
// so the kernel schedules the shape of thing it will be given in earnest rather
// than a pattern that might optimize differently.
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
    // line of log every few seconds.
    work->data[benchmark_word(algo)] ^= 1u;

    // 0x000000000000ffff0000...0000, most significant word last, which is the
    // order fulltest() compares in: an ordinary pool share target, met about
    // once in 2^48 nonces. Not a target the benchmark is expected to meet --
    // it is here because a dispatch needs one, and a realistic one keeps the
    // comparison doing the work it does when mining.
    work->target[7] = 0x00000000;
    work->target[6] = 0x0000ffff;

    // ...which is why a plain benchmark proves nothing about the path a
    // candidate takes: at 2^-48 the emit, the readback and the host's
    // re-verification never run, and a run that finds nothing looks the same
    // whether they work or are broken. --benchmark-target says how often to
    // find one, and nothing is submitted either way.
    //
    // The lower words are all ones so that the device's cheap screen -- top
    // digest word against target[7] -- and the host's full 256-bit compare
    // accept exactly the same nonces. The expected count is then one term,
    // (t+1)/2^32 per nonce: a gap between prediction and count is the path
    // itself and not the arithmetic.
    if (opt_benchmark_target >= 0) {
        work->target[7] = static_cast<uint32_t>(opt_benchmark_target);
        for (int i = 0; i < 7; i++)
            work->target[i] = 0xffffffffu;
    }
    return true;
}

// What --vk-probe-best is for, said in one line per device. The kernel has
// already done the arithmetic; this divides and prints it. 1.00 for a kernel
// that searches every nonce it was handed, 2.00 for one that quietly searches
// half of them, and it goes on reading 2.00 for as long as the run lasts.
//
// Noisy at first: each dispatch contributes a term distributed like an
// exponential with mean one, so the reading is within about one over the square
// root of the dispatch count -- ten percent at a hundred, one at ten thousand.
// Hence the count printed beside it.
void report_probe()
{
    if (!opt_vk_probe_best || !g_batches)
        return;

    for (int i = 0; i < opt_n_threads; i++) {
        const uint64_t hashes = g_batches[i].hashes.load(std::memory_order_relaxed);
        const uint64_t samples =
            g_batches[i].best_samples.load(std::memory_order_relaxed);
        const double sum =
            g_batches[i].best_ratio_sum.load(std::memory_order_relaxed);
        if (!hashes)
            continue;

        if (!samples) {
            applog2(LOG_ERR, "worker %d   the probe reported nothing after %.2f "
                             "Ghash -- the shader was built without it, or it "
                             "is not reaching the probe at all",
                    i, static_cast<double>(hashes) / 1e9);
            continue;
        }

        const double observed = sum / static_cast<double>(samples);

        applog2(LOG_INFO, "worker %d   probe %.2fx expected, over %llu "
                          "dispatch(es) and %.2f Ghash (+/- %.0f%%)",
                i, observed, static_cast<unsigned long long>(samples),
                static_cast<double>(hashes) / 1e9,
                100. / std::sqrt(static_cast<double>(samples)));
    }
}

// The two counters that should read zero for the life of a run. Printed only
// when they do not, and at an error priority, because this is the miner saying
// its own device is computing the wrong thing -- see candidate_log.h for why
// that is otherwise so easy to miss.
void report_disagreements()
{
    const uint64_t below = vkminer::candidates_below_target();
    const uint64_t wrong = vkminer::candidates_wrong_digest();
    if (!below && !wrong)
        return;

    applog2(LOG_ERR, "Device disagreed with the host %" PRIu64 " time(s): "
                     "%" PRIu64 " candidate(s) that did not meet the target, "
                     "%" PRIu64 " with a digest the host does not compute",
            below + wrong, below, wrong);
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

    // Here as well as in the periodic report: a benchmark never reaches that
    // one, and a benchmark is where these two are usually switched on.
    report_probe();
    report_disagreements();
}

// Publishes what one worker managed over one window of wall clock.
//
// The divisor is wall clock, not the time a batch took. A device is idle
// between dispatches, between jobs and for a whole reconnect, and none of that
// shows in a rate that only counts the hashing.
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

    report_probe();
    report_disagreements();
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

void worker_candidate_counts(uint64_t *confirmed, uint64_t *rejected)
{
    if (confirmed)
        *confirmed = g_candidates_confirmed.load(std::memory_order_relaxed);
    if (rejected)
        *rejected = g_candidates_rejected.load(std::memory_order_relaxed);
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

    // How many of us are on this card, which matters only to a kernel wanting
    // memory per invocation: two workers each sizing a scratchpad as though
    // they were alone is how the second fails to start.
    uint32_t sharing = 0;
    for (int i = 0; i < opt_n_threads; i++)
        if (g_worker_device[i] == device_index)
            sharing++;

    // How many dispatches the device will hold at once. A device with the next
    // dispatch already queued starts it the moment it finishes one, instead of
    // waiting out a round trip through this thread.
    std::unique_ptr<vkminer::Kernel> kernel;
    size_t depth = 1;

    // The algorithm chooses what to run from what the device can do; the
    // backend reads the result without asking what it computes. Through the
    // tuning, which is neither's business: where this device was measured, its
    // answer stands in for the algorithm's guess at which kernel and for the
    // width and depth the two of them would have settled on unaided.
    //
    // Called again whenever retarget() says this algorithm has been resized --
    // the spec is where the size of a shared table is stated, and the kernel is
    // where that becomes descriptor sets that cannot be rewritten.
    auto build_kernel = [&]() -> bool {
        vkminer::KernelSpec spec = vkminer::tuned_kernel(
            *algo, device_index, g_backend->devices()[device_index]);
        spec.concurrent_kernels = sharing;

        kernel = g_backend->create_kernel(device_index, spec);
        if (!kernel) {
            // Fatal rather than one worker quietly leaving. With more than one
            // device this is how a GPU that failed to open would show up: the
            // miner carrying on at half its hashrate with one line in the
            // scrollback, which is exactly the failure nobody notices for a
            // week.
            applog(LOG_ERR, "Worker %d: backend '%s' has no kernel for '%s' on "
                            "device %d", thr_id, g_backend->name(), opt_algo,
                   device_index);
            fail_run(1);
            return false;
        }
        depth = std::max<uint32_t>(1, kernel->queue_depth());
        return true;
    };

    // The nonce space this worker walks, split evenly between the workers so
    // that no two of them ever test the same one. Thirty-two bits for every
    // algorithm whose nonce is a header word; a KawPoW pool hands out the top
    // sixteen of a 64-bit field and leaves 48.
    //
    // The width decides whether there is an extranonce2 roll at all: 32 bits is
    // seconds of a device, and a fresh coinbase on the same job is what covers
    // that. Anything wider needs none -- and the dialect that is wider has no
    // coinbase, so rolling one would build a header the pool never sent.
    const uint32_t walk_bits = std::min<uint32_t>(algo->nonce_bits(), 64);
    const bool roll_xnonce2 = walk_bits <= 32;
    const uint64_t space = walk_bits >= 64 ? ~UINT64_C(0)
                                           : UINT64_C(1) << walk_bits;
    const uint64_t range = space / static_cast<uint64_t>(opt_n_threads);
    const uint64_t first_nonce = range * static_cast<uint64_t>(thr_id);
    const uint64_t end_nonce = first_nonce + range - kRangeMargin;

    struct work work;
    memset(&work, 0, sizeof work);
    uint64_t nonce = first_nonce;
    bool have_job = false;
    auto last_report = std::chrono::steady_clock::now();

    // This worker's own extranonce2 sequence. It starts at the worker's index
    // and strides by the number of workers, so no two of them ever build the
    // same coinbase, and it is re-armed rather than reused whenever the header
    // it belongs to changes.
    //
    // It only ever counts up -- see the new-job path below for why it must not
    // restart.
    uint64_t xnonce2 = static_cast<uint64_t>(thr_id);
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

    // How many nonces each outstanding dispatch covers, oldest first.
    //
    // The deque deliberately holds no header: everything in flight was launched
    // under the one in `work`, because every point that changes `work` drains
    // this first -- see drain().
    std::deque<uint32_t> inflight;

    // How many benchmark candidates this worker has spelled out in the log
    // before falling back to counting them; see where it is used.
    int bench_logged = 0;

    // Writes down a candidate the host would not confirm, and returns what to
    // put at the end of the warning about it: the file it went into, or nothing
    // at all when it could not be kept. The header comes from this worker's own
    // copy, which is the one the dispatch was launched under -- taking it from
    // g_work would capture whatever the pool has sent since.
    auto capture = [&](vkminer::CandidateFault fault,
                       const vkminer::Solution &got,
                       const uint32_t host_hash[8]) -> std::string {
        vkminer::CapturedCandidate bad;
        bad.fault = fault;
        bad.device = device_index;
        bad.nonce = got.nonce;
        memcpy(bad.header, work.data, sizeof bad.header);
        memcpy(bad.target, work.target, sizeof bad.target);
        memcpy(bad.device_hash, got.hash, sizeof bad.device_hash);
        memcpy(bad.host_hash, host_hash, sizeof bad.host_hash);

        const std::string path = vkminer::capture_candidate(bad);
        return path.empty() ? std::string() : ". Captured in " + path;
    };

    // Takes the oldest outstanding dispatch and does whatever its results
    // deserve. False means the device failed -- that dispatch is retired
    // either way, so a caller emptying the rest keeps making progress.
    auto reap = [&]() -> bool {
        if (inflight.empty())
            return true;

        // Sized by the device's own capacity, not by a number of its own: a
        // smaller array here would drop candidates the device stored and the
        // host would confirm, and nothing would say so -- the kernel's overflow
        // warning only covers the ones that did not fit in the device buffer.
        vkminer::Solution found[vkminer::kMaxCandidates];
        const int count = kernel->collect(found, vkminer::kMaxCandidates);
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
            // Every part of the probe, updated together: what the kernel has
            // accumulated, and the hashes it had to find it in. The kernel's
            // pair is copied rather than added to, because it is keeping the
            // running totals itself and this is only publishing them.
            const vkminer::Kernel::BestDigest probe = kernel->best_digest();
            g_batches[thr_id].hashes.fetch_add(nonces, std::memory_order_relaxed);
            g_batches[thr_id].best_ratio_sum.store(probe.ratio_sum,
                                                   std::memory_order_relaxed);
            g_batches[thr_id].best_samples.store(probe.samples,
                                                 std::memory_order_relaxed);

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
                g_candidates_rejected.fetch_add(1, std::memory_order_relaxed);
                applog(LOG_WARNING,
                       "Worker %d: device %d reported nonce %s, which does "
                       "not meet the target -- share dropped%s",
                       thr_id, device_index,
                       vkminer::nonce_hex(found[i].nonce).c_str(),
                       capture(vkminer::CandidateFault::BelowTarget, found[i],
                               hash).c_str());
                continue;
            }
            g_candidates_confirmed.fetch_add(1, std::memory_order_relaxed);

            // It is a real share, but the device's own arithmetic disagrees
            // with the host's. The share is still submitted, because the host
            // just proved it; the mismatch is logged because it means the
            // kernel is wrong in a way that happened not to matter this time.
            if (memcmp(hash, found[i].hash, sizeof hash) != 0)
                applog(LOG_WARNING,
                       "Worker %d: device %d returned a different hash for "
                       "nonce %s than the host computes%s",
                       thr_id, device_index,
                       vkminer::nonce_hex(found[i].nonce).c_str(),
                       capture(vkminer::CandidateFault::WrongDigest, found[i],
                               hash).c_str());

            // A benchmark is not connected to anything and its target is not
            // anybody's. Finding a nonce that meets it says the kernel and the
            // comparison work, which is worth a line, and submitting it would
            // be an error.
            if (opt_benchmark) {
                // A loosened target can produce these by the thousand, and a
                // line each would bury the run they are evidence about. The
                // first few show what "a candidate came back and the host
                // confirmed it" looks like; the total at the end is the number
                // to compare against the prediction.
                if (bench_logged < 8) {
                    bench_logged++;
                    applog(LOG_INFO, "Benchmark: nonce %s meets the "
                                     "synthetic target; nothing is submitted",
                           vkminer::nonce_hex(found[i].nonce).c_str());
                } else if (bench_logged == 8) {
                    bench_logged++;
                    applog(LOG_INFO, "Benchmark: further candidates are "
                                     "counted rather than logged");
                }
                continue;
            }

            // Where the nonce goes depends on whether the header has a word for
            // it. Every Bitcoin-descended one does, and that word is what the
            // submit is built from. KawPoW's has not -- the pool sent a hash
            // and nothing may be written into it -- so the whole 64 bits travel
            // beside the header instead.
            work.nonce = found[i].nonce;
            if (algo->nonce_word() * 4 < algo->header_bytes())
                work.data[algo->nonce_word()] =
                    static_cast<uint32_t>(found[i].nonce);

            // And the mix hash, for the dialect whose share is the nonce and
            // the mix together. False, and left false, for every algorithm
            // whose submit says nothing but which header and which nonce.
            work.have_mixhash =
                algo->submit_mix(work.data, found[i].nonce, work.mixhash);

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

            // Is this job for the same table the kernel was built around? For
            // almost every algorithm the answer is always yes and this costs a
            // call; for KawPoW it is no once every 7500 blocks, and the answer
            // is a new kernel, because the DAG's size reached the descriptor
            // sets when the old one was built.
            //
            // Also how the first kernel gets built at all: an algorithm sized
            // by the job cannot be given one before there is a job, and a
            // guessed epoch would generate a gigabyte the first notify throws
            // away.
            if (algo->retarget(work.data) || !kernel) {
                if (kernel) {
                    drain();
                    kernel.reset();
                    applog(LOG_NOTICE, "Worker %d: this job needs different "
                                       "device state; rebuilding the kernel",
                           thr_id);
                }
                if (!build_kernel())
                    break;
            }

            // Advanced, never restarted: a job id is not unique. A pool
            // switching between coins re-sends one it has already sent, and a
            // worker that answered by resetting this counter and the nonce
            // would rebuild the same coinbase, rescan the same range, re-find
            // the nonce it already submitted and be rejected as a duplicate.
            // Counting on costs nothing -- any value of this field is valid,
            // and the stride keeps the workers apart either way.
            xnonce2 += static_cast<uint64_t>(opt_n_threads);
            xnonce2_armed = false;
            work_restart[thr_id].restart = 0;

            // Without room to move the coinbase there is one nonce range per
            // job, which a device finishes in seconds and cannot extend. That
            // is a pool this miner cannot work with; saying so once beats a
            // warning every few seconds for the rest of the session.
            //
            // Only for an algorithm that would run out. One with 48 bits of its
            // own has nowhere it needs to go, and for that dialect an
            // extranonce2 is not a field the pool forgot -- there is no
            // coinbase for it to be part of.
            if (!opt_benchmark && roll_xnonce2 && !work.xnonce2_len) {
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
        if (!opt_benchmark && roll_xnonce2 && !xnonce2_armed) {
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
            batch = static_cast<uint32_t>(end_nonce - nonce);
        if (!batch) {
            // A benchmark has no pool to send a new job, so the only way to
            // keep measuring is to go round again. Retesting nonces is the
            // point of a benchmark and a bug in a miner, which is why the two
            // cases are written out separately.
            //
            // The header moves on rather than repeating: a device covers the
            // whole nonce space in seconds, so a minute-long run would
            // otherwise be the same few dozen dispatches over and over. It
            // costs the rate nothing, and it is what makes --vk-probe-best mean
            // anything here -- its reading averages over
            // dispatches, and averaging the same one twenty times buys no
            // precision while looking exactly as though it had.
            if (opt_benchmark) {
                // Drained before the header is touched, for the same reason
                // the job-change path above drains: what the device is still
                // holding was launched under the header `work` has right now,
                // and every candidate that comes back is re-verified against
                // whatever `work` holds by then. Changing it underneath them
                // makes the host hash a different header from the device and
                // report the disagreement as a fault in the kernel.
                drain();
                nonce = first_nonce;
                work.data[benchmark_word(*algo)]++;
                continue;
            }
            // The range is exhausted, which at device speed happens seconds
            // into a job with tens of seconds left. Moving the extranonce2 on
            // gives a different coinbase and a fresh range on the same job --
            // the difference between mining continuously and mining for the
            // first few seconds after every notify.
            //
            // For a 48-bit range this is weeks of one device rather than
            // seconds, and it takes a job change long before it takes this. The
            // range restarts, which is what a job change would have done to it
            // anyway; there is nothing else it could correctly do, because
            // there is no coinbase to move.
            if (roll_xnonce2) {
                xnonce2 += static_cast<uint64_t>(opt_n_threads);
                xnonce2_armed = false;
            }
            nonce = first_nonce;
            continue;
        }

        // What the device hashes against, for an algorithm that keeps such a
        // thing: nothing for the ones that do not, a comparison for the ones
        // that do, and a rebuild only where this header names something the
        // device is not already holding. Here rather than in the job-change
        // path above because the extranonce2 and a benchmark's own counter
        // move the header too, and the header is what decides.
        if (!kernel->prepare_state(algo->state_key(work.data))) {
            applog(LOG_ERR, "Worker %d: could not prepare the state this job "
                            "hashes against", thr_id);
            drain();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            account(0.);
            continue;
        }

        // And the other half of the same idea, for a kernel whose instructions
        // are part of the pipeline: this header's program, built if it is not
        // the one already loaded. Usually free -- the backend was told the next
        // key when it took this one and has been building it on another thread
        // ever since -- and the cost when it is not is a compile, once every
        // few blocks, against a job that lasts far longer.
        if (!kernel->prepare_program(algo->program_key(work.data))) {
            applog(LOG_ERR, "Worker %d: could not build the kernel this job's "
                            "program needs", thr_id);
            drain();
            std::this_thread::sleep_for(std::chrono::seconds(1));
            account(0.);
            continue;
        }

        // The pool's prefix and this worker's offset into what it left. Zero
        // for every algorithm whose nonce is a header word, so this is the
        // worker's own range and nothing else.
        if (!kernel->dispatch(work.data, work.target, work.nonce_base | nonce,
                              batch)) {
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
