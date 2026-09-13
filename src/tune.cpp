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
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
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

// The floor under how much better than the backend's default a candidate must
// be to be worth moving to. Only the floor: what it really has to clear is
// whatever its own rounds said the noise was, and this is what is asked of a
// device quiet enough to have said nothing.
constexpr double kMargin = 0.02;

// Kernels one algorithm may offer for one device. Fixed, so an algorithm
// cannot make the tuner allocate.
constexpr size_t kMaxVariants = 4;

// Wider groups are legal on desktop parts and useful on none: a dispatch is
// already millions of invocations, so width past this only costs occupancy.
constexpr uint32_t kMaxLocalSize = 1024;

// A target no hash meets, so the sweep measures hashing and nothing else. The
// candidate path is covered by the vector each kernel is checked against first.
constexpr uint32_t kUnreachableTarget[8] = {0, 0, 0, 0, 0, 0, 0, 0};

constexpr int kMaxSolutions = 8;

// What each device was measured at, per algorithm.
//
// Keyed by algorithm as well as device because tuned_kernel() applies a stored
// width and depth without checking what they were measured on: keyed by device
// alone it would build the new algorithm at the old one's numbers, and scrypt's
// depth cliff between 2 and 3 is 6x.
//
// Behind a lock because a switch re-tunes while parked workers are about to
// read this.
std::map<std::pair<int, std::string>, Tuning> g_tuning;
std::mutex g_tuning_lock;

void remember_tuning(int index, const char *algo_name, const Tuning &tuning)
{
    std::lock_guard<std::mutex> held(g_tuning_lock);
    g_tuning[std::make_pair(index, std::string(algo_name ? algo_name : ""))] =
        tuning;
}

bool recall_tuning(int index, const char *algo_name, Tuning *out)
{
    std::lock_guard<std::mutex> held(g_tuning_lock);
    const std::map<std::pair<int, std::string>, Tuning>::const_iterator found =
        g_tuning.find(
            std::make_pair(index, std::string(algo_name ? algo_name : "")));

    if (found == g_tuning.end())
        return false;
    *out = found->second;
    return true;
}

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
double burst(Kernel &kernel, const uint32_t *header, uint64_t *nonce,
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
    const char *variant = "";   // set only where the pass is about kernels
    std::unique_ptr<Kernel> kernel;
    std::vector<double> rate;

    // What it was built from, so a race holding one at a time can build it
    // again, and what it dispatched -- the kernel that could be asked for that
    // is gone by the time the report is written.
    KernelSpec spec;
    uint32_t batch = 0;

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

    // How far the rounds disagreed, as a fraction of the score: half the range,
    // so it reads as the +/- either side of the median. A coarse estimate of
    // this device's noise, and the alternative is a constant that estimates
    // some other machine's.
    double spread() const
    {
        const double middle = score();
        if (middle <= 0.)
            return 0.;
        std::vector<double> sorted = rate;
        std::sort(sorted.begin(), sorted.end());
        return (sorted.back() - sorted.front()) / (2. * middle);
    }

    // What this candidate varies, for a log line: a pass sweeps one axis, so
    // naming the other two would be naming what every candidate shares.
    std::string describe() const
    {
        char buf[64];
        if (variant[0])
            std::snprintf(buf, sizeof buf, "kernel '%s'", variant);
        else
            std::snprintf(buf, sizeof buf, "workgroup %u, depth %u", local,
                          depth);
        return buf;
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

    // Named down to the module: a candidate that hashes wrongly is a shader
    // bug, and this label is the whole report of it.
    char label[128];
    std::snprintf(label, sizeof label, "device %d at workgroup %u, depth %u%s%s",
                  device_index, kernel->local_size(), kernel->queue_depth(),
                  spec.variant && spec.variant[0] ? ", kernel " : "",
                  spec.variant ? spec.variant : "");

    for (size_t i = 0; i < answer_count; i++)
        if (!kernel_reproduces(*kernel, algo, answers[i], label)) {
            applog(LOG_ERR, "Tuning: %s hashes wrongly and will not be used. "
                            "This is a shader bug, not a tuning one.", label);
            return nullptr;
        }

    // The vectors may each have named a different shared state, and the one
    // left loaded is the last vector's. The race that follows hashes the first
    // vector's header, so the kernel is pointed back at that one -- otherwise
    // every candidate would spend its first dispatch rebuilding.
    if (answer_count) {
        std::vector<uint32_t> header;
        header_words(algo, answers[0], &header);
        if (!kernel->prepare_state(algo.state_key(header.data()))) {
            applog(LOG_ERR, "Tuning: %s could not prepare the state its "
                            "measurement needs", label);
            return nullptr;
        }

        // Likewise the program: the race times dispatches, and a kernel that
        // had not been built yet would refuse every one of them.
        if (!kernel->prepare_program(algo.program_key(header.data()))) {
            applog(LOG_ERR, "Tuning: %s could not build the kernel its "
                            "measurement needs", label);
            return nullptr;
        }
    }

    return kernel;
}

// Every candidate, not just the winner: the rounds, the spread and the batch
// each one dispatched are what say whether a pick was noise, a fair loss, or a
// candidate measured under a handicap the winner did not carry.
void report(int device_index, const std::vector<Candidate> &candidates)
{
    if (!opt_debug)
        return;

    for (const Candidate &c : candidates) {
        std::string rounds;
        for (const double r : c.rate) {
            char buf[32];
            std::snprintf(buf, sizeof buf, " %.3f", r / 1e6);
            rounds += buf;
        }
        applog(LOG_DEBUG, "Tuning: device %d %s -- %.3f MH/s median, +/-%.1f%%, "
                          "batch %u, rounds%s", device_index,
               c.describe().c_str(), c.score() / 1e6, c.spread() * 100., c.batch,
               rounds.c_str());
    }
}

// Say which won, from rounds somebody else measured.
int pick(int device_index, const std::vector<Candidate> &candidates)
{
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

    const Candidate &winner = candidates[static_cast<size_t>(best)];
    const Candidate &standing = candidates[static_cast<size_t>(fallback)];
    const double gain = winner.score() / standing.score() - 1.;

    // What the candidate has to clear is the noise the rounds themselves
    // showed, both candidates' worth of it, with kMargin only as a floor. Two
    // configurations whose bands overlap have not been told apart, however the
    // medians came out.
    const double required = std::max(kMargin,
                                     winner.spread() + standing.spread());
    if (gain > required)
        return best;

    if (gain > 0.)
        applog(LOG_INFO, "Tuning: device %d measured %s %.1f%% above the "
                         "default, which is inside the %.1f%% its own rounds "
                         "varied by; keeping the default", device_index,
               winner.describe().c_str(), gain * 100., required * 100.);
    return fallback;
}

// Measure every candidate against every other, then say which won.
//
// Interleaved rather than one block each, with the order reversed every round:
// a card that reads 20% faster cold than hot would otherwise favour whatever
// was tried first. That is bias, not noise -- more samples do not remove it and
// only ordering does.
int race(int device_index, std::vector<Candidate> &candidates,
         const uint32_t *header, uint64_t *nonce)
{
    for (Candidate &c : candidates) {
        c.batch = c.kernel->preferred_batch();
        if (burst(*c.kernel, header, nonce, kWarmupSeconds) < 0.)
            c.rate.push_back(-1.);
    }

    for (int round = 0; round < kRounds; round++) {
        for (size_t i = 0; i < candidates.size(); i++) {
            Candidate &c = candidates[round % 2 ? candidates.size() - 1 - i : i];
            c.rate.push_back(burst(*c.kernel, header, nonce, kRoundSeconds));
        }
    }

    report(device_index, candidates);
    return pick(device_index, candidates);
}

// The same race, one candidate on the device at a time.
//
// A kernel that owns memory per invocation gets a share of the card when
// several are alive, and a share is not the regime it will mine in:
// configurations indistinguishable at a fraction of the memory can span several
// times at all of it, so an interleaved race of them ranks a regime that does
// not ship.
//
// Order bias is what interleaving bought and this gives up, so the list is
// walked once forwards and once backwards instead, and each candidate exists
// only while it is being measured. Nothing holds the algorithm's shared state
// either, so an algorithm with a scratchpad *and* a table would rebuild the
// table twice per candidate; scrypt has no table, and one that had both would
// need this to keep a kernel alive across the walk.
int race_alone(int device_index, std::vector<Candidate> &candidates,
               const std::function<bool(Candidate &)> &rebuild,
               const uint32_t *header, uint64_t *nonce)
{
    for (int pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < candidates.size(); i++) {
            Candidate &c =
                candidates[pass ? candidates.size() - 1 - i : i];
            if (c.score() < 0. && !c.rate.empty())
                continue;       // already failed; do not pay to build it twice

            if (!rebuild(c)) {
                c.rate.push_back(-1.);
                continue;
            }
            c.batch = c.kernel->preferred_batch();

            if (burst(*c.kernel, header, nonce, kWarmupSeconds) < 0.)
                c.rate.push_back(-1.);
            for (int round = 0; round < kRounds; round++)
                c.rate.push_back(burst(*c.kernel, header, nonce,
                                       kRoundSeconds));
            c.kernel.reset();
        }

    report(device_index, candidates);
    return pick(device_index, candidates);
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
// change, and deeper queues buy less than kMargin, so this pass mostly
// confirms the default.
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
    uint64_t nonce = 0;

    const auto started = std::chrono::steady_clock::now();

    // An algorithm that owns memory per invocation is raced one candidate at a
    // time; race_alone() says why.
    const bool alone = base.scratch_bytes != 0;

    auto rebuild = [&](Candidate &c) {
        c.kernel = build(backend, device_index, algo, c.spec, c.local, c.depth,
                         1, answers, answer_count);
        return c.kernel != nullptr;
    };

    // Which kernel first, where the algorithm has more than one: a different
    // module is the coarsest axis, and the width that suits one need not suit
    // the other, so the passes below run on whichever wins. At the default
    // width and depth, the only footing they share before either is known.
    KernelSpec chosen = base;
    {
        KernelSpec variants[kMaxVariants];
        const size_t count = algo.kernels(info, variants, kMaxVariants);

        std::vector<KernelSpec> specs;
        std::vector<Candidate> candidates;
        for (size_t i = 0; count > 1 && i < count; i++) {
            Candidate c;
            c.spec = variants[i];
            c.kernel = build(backend, device_index, algo, c.spec, 0, 0,
                             alone ? 1u : static_cast<uint32_t>(count), answers,
                             answer_count);
            if (!c.kernel)
                continue;
            c.local = c.kernel->local_size();
            c.depth = c.kernel->queue_depth();
            c.variant = variants[i].variant;
            if (alone)
                c.kernel.reset();

            // The one the algorithm would have handed out unaided. A second
            // module has to beat it, not merely differ from it.
            c.is_default = variants[i].spirv == base.spirv;
            specs.push_back(variants[i]);
            candidates.push_back(std::move(c));
        }

        if (candidates.size() > 1) {
            applog(LOG_INFO, "Tuning: device %d (%s) can run %u kernels of "
                             "'%s'", device_index, info.name.c_str(),
                   static_cast<unsigned>(candidates.size()), algo.name());

            const int best =
                alone ? race_alone(device_index, candidates, rebuild,
                                   header.data(), &nonce)
                      : race(device_index, candidates, header.data(), &nonce);
            if (best >= 0)
                chosen = specs[static_cast<size_t>(best)];
        }
    }

    // The widths to try, and none where --workgroup named one: that option
    // exists so two runs can be compared at two widths, and a tuner overruling
    // it would make them the same run. --queue-depth skips the depth pass the
    // same way.
    const std::vector<uint32_t> widths =
        opt_workgroup > 0 ? std::vector<uint32_t>() : local_sizes(info);

    // race() runs the candidates interleaved, so all of them are alive at once
    // and a kernel wanting memory per invocation has to be told how many that
    // is. The default is included: it must be measured on the same terms as
    // what it is compared against. Those kernels are exactly the ones raced one
    // at a time, so there the share is the whole card.
    //
    // An upper bound, not a count -- widths may or may not contain the default,
    // and a width that fails to build leaves its share unclaimed.
    // Over-declaring costs a smaller batch during the sweep and nothing else.
    const uint32_t width_share =
        alone ? 1u : static_cast<uint32_t>(widths.size()) + 1;

    // What the backend would run unaided, asked for by naming no width and no
    // depth; both passes below measure against it. The rule that picks it is
    // the backend's.
    //
    // Held past the first width pass rather than read and dropped: a build
    // prepares the algorithm's shared state, which the backend keeps only while
    // some kernel holds it, so releasing this early pays to rebuild a DAG-sized
    // table. Raced alone the opposite holds -- what it keeps is the memory each
    // candidate needs all of -- so there it goes at once.
    std::unique_ptr<Kernel> probe = build(backend, device_index, algo, chosen,
                                          0, 0, width_share, answers,
                                          answer_count);
    if (!probe) {
        // Two different failures, and the difference is worth printing: a
        // device with room to run this kernel and none to hold a field of them
        // is not a broken kernel and does not stop the run.
        if (chosen.scratch_bytes && width_share > 1)
            applog(LOG_WARNING, "Tuning: device %d cannot hold %u candidates of "
                                "'%s' at once, and a sweep is candidates raced "
                                "against each other; mining untuned",
                   device_index, width_share, algo.name());
        else
            applog(LOG_WARNING, "Tuning: device %d would not build its own "
                                "default; mining untuned", device_index);
        return false;
    }

    const uint32_t default_local = probe->local_size();
    const uint32_t default_depth = probe->queue_depth();
    if (alone)
        probe.reset();

    out->variant = chosen.variant ? chosen.variant : "";
    out->local_size_x = default_local;
    out->queue_depth = default_depth;

    // One pass over the widths, all at one depth, the default width first
    // because it is what the others are measured against.
    auto width_pass = [&](uint32_t depth) {
        std::vector<uint32_t> order{default_local};
        for (const uint32_t local : widths)
            if (local != default_local)
                order.push_back(local);

        std::vector<Candidate> candidates;
        for (const uint32_t local : order) {
            Candidate c;
            c.spec = chosen;
            c.local = local;
            c.depth = depth;
            c.is_default = local == default_local;
            if (!alone) {
                c.kernel = build(backend, device_index, algo, chosen, local,
                                 depth, width_share, answers, answer_count);
                if (!c.kernel)
                    continue;   // build() said why; a width that will not build
            }                   // is not a failure of the sweep
            candidates.push_back(std::move(c));
        }

        applog(LOG_INFO, "Tuning: device %d (%s), %u workgroup size(s) at depth "
                         "%u, about %.0f seconds", device_index,
               info.name.c_str(), static_cast<unsigned>(candidates.size()),
               depth, (alone ? 2 : 1) * candidates.size()
                          * (kWarmupSeconds + kRounds * kRoundSeconds));

        const int best = alone ? race_alone(device_index, candidates, rebuild,
                                            header.data(), &nonce)
                               : race(device_index, candidates, header.data(),
                                      &nonce);
        if (best < 0)
            return false;

        out->local_size_x = candidates[static_cast<size_t>(best)].local;
        out->queue_depth = candidates[static_cast<size_t>(best)].depth;
        out->rate = candidates[static_cast<size_t>(best)].score();
        return true;
    };

    const bool swept = width_pass(default_depth);
    probe.reset();
    if (!swept) {
        applog(LOG_WARNING, "Tuning: device %d failed every configuration; "
                            "mining untuned", device_index);
        return false;
    }

    // The depth pass, at the width that just won. Skipped when --queue-depth
    // named one: that option exists to compare runs at a depth of the user's
    // choosing, and a tuner overruling it would make them the same run.
    if (opt_queue_depth <= 0) {
        const uint32_t depth_share =
            alone ? 1u : static_cast<uint32_t>(queue_depths().size());

        std::vector<Candidate> depths;
        for (const uint32_t depth : queue_depths()) {
            Candidate c;
            c.spec = chosen;
            c.local = out->local_size_x;
            c.depth = depth;
            c.is_default = depth == default_depth;
            if (!alone) {
                c.kernel = build(backend, device_index, algo, chosen,
                                 out->local_size_x, depth, depth_share, answers,
                                 answer_count);
                if (!c.kernel)
                    continue;
            }
            depths.push_back(std::move(c));
        }

        const uint32_t before = out->queue_depth;
        const int best = alone ? race_alone(device_index, depths, rebuild,
                                            header.data(), &nonce)
                               : race(device_index, depths, header.data(),
                                      &nonce);
        if (best >= 0) {
            out->queue_depth = depths[static_cast<size_t>(best)].depth;
            out->rate = depths[static_cast<size_t>(best)].score();

            // The widths were told apart at the old depth. Where depth is the
            // axis carrying the difference, that ranking was made in a regime
            // the run will not use, so it is made again -- once: the same
            // argument applies to the depth pass, and taking it does not
            // terminate.
            if (out->queue_depth != before)
                width_pass(out->queue_depth);
        }
    }

    out->soak_seconds = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - started).count();

    applog(LOG_INFO, "Tuning: device %d chose %s%sworkgroup %u, depth %u -- "
                     "%.2f MH/s after %.0f seconds under load",
           device_index, out->variant.c_str(), out->variant.empty() ? "" : ", ",
           out->local_size_x, out->queue_depth, out->rate / 1e6,
           out->soak_seconds);

    // Said plainly: a sweep is the first seconds of load a card sees, which on
    // a thermally capped part is its best, so the rate above will not hold.
    if (out->local_size_x != default_local || out->queue_depth != default_depth)
        applog(LOG_INFO, "Tuning: that is not the default (%u, %u). The rate "
                         "was measured while the device was still cold and is "
                         "a ranking, not a benchmark.",
               default_local, default_depth);

    // Where there is a scratchpad the candidates were raced one at a time, so
    // the batch each of them hashed is the batch a mining run gets. That is
    // what makes the rate above comparable to one at all, and it is why this
    // sweep took twice as long as an algorithm without a scratchpad.
    if (chosen.scratch_bytes)
        applog(LOG_INFO, "Tuning: '%s' keeps %llu KiB per hash, so its "
                         "candidates were raced one at a time, each with the "
                         "whole device rather than a share of it.",
               algo.name(),
               static_cast<unsigned long long>(chosen.scratch_bytes >> 10));

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
    const size_t answer_count = startup_answers(*algo, &answers, nullptr);
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
            // The sizes as they will be, not as they were filed: tuned_kernel
            // leaves --workgroup and --queue-depth alone, so the stored ones
            // would be numbers the run is not using.
            applog(LOG_INFO, "Tuning: device %d (%s) uses %s%sworkgroup %u, "
                             "depth %u, measured earlier at %.2f MH/s", index,
                   info.name.c_str(), tuning.variant.c_str(),
                   tuning.variant.empty() ? "" : ", ",
                   opt_workgroup > 0 ? static_cast<uint32_t>(opt_workgroup)
                                     : tuning.local_size_x,
                   opt_queue_depth > 0 ? static_cast<uint32_t>(opt_queue_depth)
                                       : tuning.queue_depth,
                   tuning.rate / 1e6);
            remember_tuning(index, algo->name(), tuning);
            continue;
        }

        if (!sweep(backend, index, *algo, base, answers, answer_count, &tuning))
            continue;

        remember_tuning(index, algo->name(), tuning);

        // Used for this run but not filed, because part of it was not measured:
        // --workgroup and --queue-depth each skip a pass. The key says nothing
        // about either option, so writing it would make a one-off experiment
        // permanent.
        if (opt_workgroup > 0 || opt_queue_depth > 0)
            continue;

        const std::string description = info.name + " (" + info.driver + "), "
                                      + algo->name();
        if (!path.empty() && !tune_cache_store(path, key, description, tuning))
            applog(LOG_WARNING, "Tuning: could not write %s, so this sweep "
                                "will be run again next time", path.c_str());
    }
}

KernelSpec tuned_kernel(const Algorithm &algo, int device_index,
                        const DeviceInfo &device)
{
    KernelSpec spec = algo.kernel(device);

    // The user's choice first and unconditionally, because the case it exists
    // for is --no-tune, where there is no entry below to read. Refused rather
    // than fallen back from: a run that quietly measured some other kernel than
    // the one named is worse than a run that does not start.
    if (opt_kernel && opt_kernel[0]) {
        KernelSpec variants[kMaxVariants];
        const size_t count = algo.kernels(device, variants, kMaxVariants);
        bool named = false;
        for (size_t i = 0; i < count && !named; i++)
            if (variants[i].variant
                && std::strcmp(variants[i].variant, opt_kernel) == 0) {
                spec = variants[i];
                named = true;
            }
        if (!named) {
            applog(LOG_ERR, "device %d (%s) has no '%s' kernel for %s",
                   device_index, device.name.c_str(), opt_kernel, algo.name());
            spec.spirv = nullptr;
            return spec;
        }
    }

    // This algorithm's entry and no other's. A worker that has just been
    // switched asks for the one it is about to mine, not the one the device was
    // last measured on.
    Tuning tuning;
    if (!recall_tuning(device_index, algo.name(), &tuning))
        return spec;

    // A named kernel is looked up, not trusted: the entry may name one this
    // build no longer offers. Not finding it leaves the algorithm's own choice
    // carrying sizes measured on a different module -- a slower start, not a
    // wrong one. Skipped where the user named one, which outranks a cache.
    if (!tuning.variant.empty() && !(opt_kernel && opt_kernel[0])) {
        KernelSpec variants[kMaxVariants];
        const size_t count = algo.kernels(device, variants, kMaxVariants);
        for (size_t i = 0; i < count; i++)
            if (variants[i].variant && tuning.variant == variants[i].variant) {
                spec = variants[i];
                break;
            }
    }

    // Neither size when the user named one: the kernel prefers the spec over
    // the option, which is right for the sweep and wrong here.
    if (opt_workgroup <= 0)
        spec.local_size_x = tuning.local_size_x;
    if (opt_queue_depth <= 0)
        spec.queue_depth = tuning.queue_depth;
    return spec;
}

bool device_tuning(int device_index, Tuning *out)
{
    // For the algorithm the miner is on right now, which is what an API asking
    // "how is this device set up" means by the question.
    if (!recall_tuning(device_index, opt_algo, out))
        return false;

    return true;
}

}  // namespace vkminer
