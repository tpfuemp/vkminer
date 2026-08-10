// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "tune.h"

#include "algorithms/algorithm.h"
#include "algorithms/registry.h"
#include "self_test.h"
#include "tune_cache.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace vkminer {
namespace {

// Three rounds is the fewest that has a median; a quarter-second round is
// several dispatches, and long enough that one descheduled host thread does not
// decide it. The warm-up is thrown away so the rounds see a batch size the
// kernel has settled on rather than its opening guess.
constexpr int kRounds = 3;
constexpr double kRoundSeconds = 0.25;
constexpr double kWarmupSeconds = 0.25;

// How much better than the backend's default a candidate must be to be worth
// moving to. Clocks decaying across a sweep separate identical configurations
// by a few percent, so a winner inside this is a measurement of the weather.
constexpr double kMargin = 0.02;

// Wider groups are legal on desktop parts and useful on none: a dispatch is
// already millions of invocations, so width past this only costs occupancy.
constexpr uint32_t kMaxLocalSize = 1024;

// A target no hash meets, so the sweep measures hashing and nothing else. The
// candidate path is covered by the vector each kernel is checked against first.
constexpr uint32_t kUnreachableTarget[8] = {0, 0, 0, 0, 0, 0, 0, 0};

constexpr int kMaxSolutions = 8;

// Written once before any worker exists and only read after, which is what
// makes a bare map safe and would stop being true if anything re-tuned midrun.
std::map<int, Tuning> g_tuning;

// The header as struct work carries it, from a published vector: one host-order
// word per big-endian read of the wire, nonce word cleared because it is
// supplied per dispatch.
void header_words(const Algorithm &algo, const KnownAnswer &answer,
                  std::vector<uint32_t> *out)
{
    const size_t words = algo.header_bytes() / 4;
    out->assign(words, 0);
    for (size_t i = 0; i < words; i++)
        (*out)[i] = be32dec(answer.header + i * 4);
    if (algo.nonce_word() < words)
        (*out)[algo.nonce_word()] = 0;
}

// Run `kernel` flat out for `seconds` and return the hash rate, or -1 if the
// device failed. The queue is filled before the clock starts and kept full
// throughout: a device with nothing queued behind what it is finishing measures
// how quickly this thread noticed.
double burst(Kernel &kernel, const uint32_t *header, uint32_t *nonce,
             double seconds)
{
    const uint32_t depth = kernel.queue_depth();
    Solution found[kMaxSolutions];

    // Nonces per outstanding dispatch, oldest first. The size is asked for anew
    // each time because the kernel is still converging on one; pinning it would
    // measure a size no run ever uses.
    std::deque<uint32_t> outstanding;

    auto launch = [&]() {
        const uint32_t count = kernel.preferred_batch();
        if (!kernel.dispatch(header, kUnreachableTarget, *nonce, count))
            return false;
        *nonce += count;
        outstanding.push_back(count);
        return true;
    };

    auto retire = [&](uint64_t *hashes) {
        const int n = kernel.collect(found, kMaxSolutions);
        if (n < 0)
            return false;
        if (hashes)
            *hashes += outstanding.front();
        outstanding.pop_front();
        return true;
    };

    auto drain = [&]() {
        while (!outstanding.empty())
            if (!retire(nullptr))
                return;
    };

    for (uint32_t i = 0; i < depth; i++)
        if (!launch()) {
            drain();
            return -1.;
        }

    const auto start = std::chrono::steady_clock::now();
    uint64_t hashes = 0;
    double elapsed = 0.;

    while (elapsed < seconds) {
        if (!retire(&hashes) || !launch()) {
            drain();
            return -1.;
        }
        elapsed = std::chrono::duration<double>(
                      std::chrono::steady_clock::now() - start).count();
    }

    drain();
    return elapsed > 0. ? static_cast<double>(hashes) / elapsed : -1.;
}

struct Candidate {
    uint32_t local = 0;
    uint32_t depth = 0;
    std::unique_ptr<Kernel> kernel;
    std::vector<double> rate;

    // The configuration the backend would have used unaided. It wins ties, and
    // it wins anything closer than kMargin.
    bool is_default = false;

    // The middle round, not the mean: a cold card's first round is its fastest
    // and its last its slowest, and neither describes the rest of the run.
    double score() const
    {
        if (rate.empty())
            return -1.;
        std::vector<double> sorted = rate;
        std::sort(sorted.begin(), sorted.end());
        if (sorted.front() < 0.)
            return -1.;       // a failed round disqualifies the candidate
        return sorted[sorted.size() / 2];
    }
};

// Build one candidate and prove it still hashes correctly. A width is a
// specialization constant, so every candidate is a differently compiled shader;
// one wrong at 64 and right at 256 would otherwise be found by a pool rejecting
// everything. The self-test covered one configuration, not these.
std::unique_ptr<Kernel> build(ComputeBackend &backend, int device_index,
                              const Algorithm &algo, KernelSpec spec,
                              uint32_t local, uint32_t depth,
                              uint32_t concurrent,
                              const KnownAnswer *answers, size_t answer_count)
{
    spec.local_size_x = local;
    spec.queue_depth = depth;
    spec.concurrent_kernels = concurrent;

    std::unique_ptr<Kernel> kernel = backend.create_kernel(device_index, spec);
    if (!kernel)
        return nullptr;

    char label[96];
    std::snprintf(label, sizeof label, "device %d at workgroup %u, depth %u",
                  device_index, kernel->local_size(), kernel->queue_depth());

    for (size_t i = 0; i < answer_count; i++)
        if (!kernel_reproduces(*kernel, algo, answers[i], label)) {
            applog(LOG_ERR, "Tuning: %s hashes wrongly and will not be used. "
                            "This is a shader bug, not a tuning one.", label);
            return nullptr;
        }

    return kernel;
}

// Measure every candidate against every other, then say which won.
//
// Interleaved rather than one block each, with the order reversed every round:
// a card that reads 20% faster cold than hot would otherwise favour whatever
// was tried first. That is bias, not noise -- more samples do not remove it and
// only ordering does.
int race(std::vector<Candidate> &candidates, const uint32_t *header,
         uint32_t *nonce)
{
    for (Candidate &c : candidates)
        if (burst(*c.kernel, header, nonce, kWarmupSeconds) < 0.)
            c.rate.push_back(-1.);

    for (int round = 0; round < kRounds; round++) {
        for (size_t i = 0; i < candidates.size(); i++) {
            Candidate &c = candidates[round % 2 ? candidates.size() - 1 - i : i];
            c.rate.push_back(burst(*c.kernel, header, nonce, kRoundSeconds));
        }
    }

    int best = -1;
    int fallback = -1;
    for (size_t i = 0; i < candidates.size(); i++) {
        const double score = candidates[i].score();
        if (score < 0.)
            continue;
        if (candidates[i].is_default)
            fallback = static_cast<int>(i);
        if (best < 0 || score > candidates[static_cast<size_t>(best)].score())
            best = static_cast<int>(i);
    }

    if (best < 0 || fallback < 0 || best == fallback)
        return best;

    const double gain = candidates[static_cast<size_t>(best)].score()
                      / candidates[static_cast<size_t>(fallback)].score() - 1.;
    return gain > kMargin ? best : fallback;
}

// Widths worth trying: whole subgroups, doubling, up to what the device allows.
// A partial subgroup wastes its remainder in every workgroup, so those are not
// candidates at all.
std::vector<uint32_t> local_sizes(const DeviceInfo &info)
{
    uint32_t limit = kMaxLocalSize;
    if (info.max_workgroup_size && info.max_workgroup_size < limit)
        limit = info.max_workgroup_size;
    if (info.max_invocations && info.max_invocations < limit)
        limit = info.max_invocations;

    const uint32_t step = info.subgroup_size > 1 ? info.subgroup_size : 32;

    std::vector<uint32_t> sizes;
    for (uint32_t size = step; size <= limit; size *= 2)
        sizes.push_back(size);
    if (sizes.empty() && limit)
        sizes.push_back(limit);
    return sizes;
}

// Kept short: the whole range is a fifth of a second of latency at a job
// change, and pipelining's gain turned out to be under one percent -- inside
// kMargin, so this pass mostly confirms the default.
std::vector<uint32_t> queue_depths()
{
    return {1, 2, 3, 4};
}

bool sweep(ComputeBackend &backend, int device_index, const Algorithm &algo,
           const KernelSpec &base, const KnownAnswer *answers,
           size_t answer_count, Tuning *out)
{
    const DeviceInfo &info = backend.devices()[static_cast<size_t>(device_index)];

    std::vector<uint32_t> header;
    header_words(algo, answers[0], &header);
    uint32_t nonce = 0;

    const auto started = std::chrono::steady_clock::now();

    // race() runs the candidates interleaved, so all of them are alive at once
    // and a kernel wanting memory per invocation has to be told how many that
    // is. The default is included: it must be measured on the same terms as
    // what it is compared against.
    //
    // An upper bound, not a count -- local_sizes may or may not contain the
    // default, and a width that fails to build leaves its share unclaimed.
    // Over-declaring costs a smaller batch during the sweep and nothing else.
    const uint32_t width_share =
        static_cast<uint32_t>(local_sizes(info).size()) + 1;

    // The default first, everything else measured against it. Asking for no
    // width and no depth gets exactly what this device would run untuned, read
    // back off the kernel because the rule that picks it is the backend's.
    std::vector<Candidate> candidates;
    {
        Candidate c;
        c.kernel = build(backend, device_index, algo, base, 0, 0, width_share,
                         answers, answer_count);
        if (!c.kernel) {
            // Two different failures, and the difference is worth printing: a
            // device with room to run this kernel and none to hold a field of
            // them is not a broken kernel and does not stop the run.
            if (base.scratch_bytes && width_share > 1)
                applog(LOG_WARNING, "Tuning: device %d cannot hold %u "
                                    "candidates of '%s' at once, and a sweep is "
                                    "candidates raced against each other; "
                                    "mining untuned", device_index, width_share,
                       algo.name());
            else
                applog(LOG_WARNING, "Tuning: device %d would not build its own "
                                    "default; mining untuned", device_index);
            return false;
        }
        c.local = c.kernel->local_size();
        c.depth = c.kernel->queue_depth();
        c.is_default = true;
        candidates.push_back(std::move(c));
    }

    const uint32_t default_local = candidates[0].local;
    const uint32_t default_depth = candidates[0].depth;

    for (const uint32_t local : local_sizes(info)) {
        if (local == default_local)
            continue;
        Candidate c;
        c.kernel = build(backend, device_index, algo, base, local,
                         default_depth, width_share, answers, answer_count);
        if (!c.kernel)
            continue;   // build() said why; a width that will not build is not
        c.local = local;   // a failure of the sweep
        c.depth = default_depth;
        candidates.push_back(std::move(c));
    }

    applog(LOG_INFO, "Tuning: device %d (%s), %u workgroup size(s), about %.0f "
                     "seconds", device_index, info.name.c_str(),
           static_cast<unsigned>(candidates.size()),
           candidates.size() * (kWarmupSeconds + kRounds * kRoundSeconds));

    int winner = race(candidates, header.data(), &nonce);
    if (winner < 0) {
        applog(LOG_WARNING, "Tuning: device %d failed every configuration; "
                            "mining untuned", device_index);
        return false;
    }

    out->local_size_x = candidates[static_cast<size_t>(winner)].local;
    out->queue_depth = candidates[static_cast<size_t>(winner)].depth;
    out->rate = candidates[static_cast<size_t>(winner)].score();

    // Released before the depth pass builds anything: the winner is three
    // numbers, and holding the kernels that produced them would make the two
    // passes share the device as well.
    candidates.clear();

    // The depth pass, at the width that just won. Skipped when --queue-depth
    // named one: that option exists to compare runs at a depth of the user's
    // choosing, and a tuner overruling it would make them the same run.
    if (opt_queue_depth <= 0) {
        const uint32_t depth_share =
            static_cast<uint32_t>(queue_depths().size());

        std::vector<Candidate> depths;
        for (const uint32_t depth : queue_depths()) {
            Candidate c;
            c.kernel = build(backend, device_index, algo, base,
                             out->local_size_x, depth, depth_share, answers,
                             answer_count);
            if (!c.kernel)
                continue;
            c.local = out->local_size_x;
            c.depth = depth;
            c.is_default = depth == default_depth;
            depths.push_back(std::move(c));
        }

        const int best = race(depths, header.data(), &nonce);
        if (best >= 0) {
            out->queue_depth = depths[static_cast<size_t>(best)].depth;
            out->rate = depths[static_cast<size_t>(best)].score();
        }
    }

    out->soak_seconds = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - started).count();

    applog(LOG_INFO, "Tuning: device %d chose workgroup %u, depth %u -- "
                     "%.2f MH/s after %.0f seconds under load",
           device_index, out->local_size_x, out->queue_depth,
           out->rate / 1e6, out->soak_seconds);

    // Said plainly: a sweep is the first seconds of load a card sees, which on
    // a thermally capped part is its best, so the rate above will not hold.
    if (out->local_size_x != default_local || out->queue_depth != default_depth)
        applog(LOG_INFO, "Tuning: that is not the default (%u, %u). The rate "
                         "was measured while the device was still cold and is "
                         "a ranking, not a benchmark.",
               default_local, default_depth);

    // A second reason the rate is not a benchmark, where there is a scratchpad:
    // the candidates raced on a share of the device each, so all of them ran at
    // a fraction of the batch a mining run gets. The *same* fraction, which is
    // what keeps the ranking sound and the number unusable.
    if (base.scratch_bytes)
        applog(LOG_INFO, "Tuning: '%s' keeps %llu KiB per hash, so the "
                         "candidates split the device's memory between them "
                         "and each hashed a smaller batch than mining will.",
               algo.name(),
               static_cast<unsigned long long>(base.scratch_bytes >> 10));

    return true;
}

}  // namespace

void tune_devices(ComputeBackend &backend,
                  const std::vector<int> &device_indices,
                  const char *algo_name)
{
    if (opt_no_tune)
        return;

    std::unique_ptr<Algorithm> algo = create_algorithm(algo_name);
    if (!algo)
        return;

    const KnownAnswer *answers = nullptr;
    const size_t answer_count = algo->known_answers(&answers);
    if (!answer_count)
        return;   // nothing to sweep against, and the self-test already said so

    const std::string path = tune_cache_path();
    if (path.empty())
        applog(LOG_DEBUG, "Tuning: no config directory, so nothing will be "
                          "remembered between runs");

    const std::vector<DeviceInfo> &devices = backend.devices();

    for (const int index : device_indices) {
        if (index < 0 || index >= static_cast<int>(devices.size()))
            continue;
        const DeviceInfo &info = devices[static_cast<size_t>(index)];

        const KernelSpec base = algo->kernel(info);
        if (!base.spirv)
            continue;   // no shader for this device; nothing to tune about it

        const std::string key = tune_key(info, algo->name(), base.spirv,
                                         base.spirv_words);

        Tuning tuning;
        if (!opt_retune && tune_cache_load(path, key, &tuning)) {
            // The depth as it will be, not as it was filed: apply_tuning leaves
            // --queue-depth alone, so the stored one would be a number the run
            // is not using.
            applog(LOG_INFO, "Tuning: device %d (%s) uses workgroup %u, depth "
                             "%u, measured earlier at %.2f MH/s", index,
                   info.name.c_str(), tuning.local_size_x,
                   opt_queue_depth > 0 ? static_cast<uint32_t>(opt_queue_depth)
                                       : tuning.queue_depth,
                   tuning.rate / 1e6);
            g_tuning[index] = tuning;
            continue;
        }

        if (!sweep(backend, index, *algo, base, answers, answer_count, &tuning))
            continue;

        g_tuning[index] = tuning;

        // Used for this run but not filed, because half of it was not measured:
        // --queue-depth skipped the depth pass. The key says nothing about the
        // option, so writing it would make a one-off experiment permanent.
        if (opt_queue_depth > 0)
            continue;

        const std::string description = info.name + " (" + info.driver + "), "
                                      + algo->name();
        if (!path.empty() && !tune_cache_store(path, key, description, tuning))
            applog(LOG_WARNING, "Tuning: could not write %s, so this sweep "
                                "will be run again next time", path.c_str());
    }
}

void apply_tuning(int device_index, KernelSpec *spec)
{
    const std::map<int, Tuning>::const_iterator found = g_tuning.find(device_index);
    if (found == g_tuning.end())
        return;

    spec->local_size_x = found->second.local_size_x;

    // Not the depth when the user named one: the kernel prefers the spec over
    // the option, which is right for the sweep and wrong here.
    if (opt_queue_depth <= 0)
        spec->queue_depth = found->second.queue_depth;
}

}  // namespace vkminer
