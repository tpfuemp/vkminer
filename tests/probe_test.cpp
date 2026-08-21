// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The calibration for --vk-probe-best. That probe is relied on to say something
// no other test can -- whether the kernel is quietly failing to search nonces it
// was handed -- and a kernel that misses them produces no rejects and no wrong
// shares, only worse luck. So the probe itself has to be checked against a known
// answer; "the number looked plausible" is not evidence.
//
// Three checks, because they fail for different reasons and each reaches a size
// the one before it cannot.
//
//   Exactness, at a size the host can also compute. The probe reports the
//   smallest most significant digest word in the dispatch; the reference
//   computes the same minimum over the same nonces, and the two must be equal.
//   Not close -- equal. Both are minima over the same integers.
//
//   Repeatability, at the size the device really runs. The host cannot hash a
//   hundred million nonces in a test, but it does not have to: the same
//   dispatch has one minimum, so running it repeatedly and getting two answers
//   proves a fault without any reference at all. This is what reaches the full
//   occupancy that the first check cannot afford.
//
//   Calibration, over many dispatches that share nothing. The two checks above
//   ask whether one reading is right; this asks whether the average of them is
//   the number the miner prints it as. It is a separate question because the
//   quantity is a minimum over a random-looking set: one dispatch's reading is
//   an exponential deviate with a mean of one and a spread of one, so a single
//   dispatch -- or a hundred of the same dispatch -- says nothing at all about
//   the mean, however tight the error bar printed beside it looks.

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "backends/vulkan/vulkan_common.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

extern "C" {
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
struct thr_info *thr_info = nullptr;
double *thr_hashrates = nullptr;
struct work_restart *work_restart = nullptr;
int work_thr_id = 0;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
}

namespace {

int failures = 0;

void fail(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::printf("FAIL ");
    std::vprintf(fmt, args);
    std::printf("\n");
    va_end(args);
    failures++;
}

// Nonces for the exact check. The host hashes every one of them twice over, so
// this is bounded by what a build machine will sit through rather than by
// anything about the device -- a couple of million is a few seconds, and the
// expected minimum over them is around two thousand, which is far enough from
// zero that an equality means something.
//
// It is also a single dispatch, and a memory-bound kernel cannot take one
// that large. The check runs at whichever of the two is smaller, which weakens
// it -- a shorter range has a larger expected minimum -- but does not empty it:
// an equality between two independently computed minima is still an equality
// between two 32-bit values.
constexpr uint32_t kExactNonces = 1u << 21;

constexpr uint32_t kNonceBase = 0x7fff0000u;
constexpr int kMaxSolutions = 64;

// Two targets, for two different jobs.
//
// The device gets a target nothing meets. The probe is reached before the
// screen, so it still sees every nonce in the dispatch, and no candidates come
// back -- which matters, because a target everything meets overflows the result
// buffer millions deep and turns a question about the probe into a page of
// warnings about capacity.
//
// The reference gets a target everything meets, because verify() fills in the
// digest for the nonces it accepts and this needs the digest for all of them.
const uint32_t kTargetNone[8] = {0, 0, 0, 0, 0, 0, 0, 0};
const uint32_t kTargetAll[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
};

const unsigned char kHeader[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b,
    0xcd, 0x93, 0x17, 0xe2, 0xfe, 0x99, 0xf2, 0xde,
    0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4,
    0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75,
    0x04, 0x23, 0xdb, 0x8b, 0x1e, 0xb9, 0x42, 0xae,
    0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf,
    0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b,
    0xc7, 0xf5, 0xd7, 0x4d,
    0xf2, 0xb9, 0x44, 0x1a,
    0x42, 0xa1, 0x46, 0x95,
};

// Dispatches to run before the batch size is read. The kernel aims each
// dispatch at a fixed wall time and corrects from what it measures, sitting out
// a queue's worth of completions after every change, so it needs a good few of
// them to arrive anywhere. Their readings are thrown away.
constexpr int kWarmup = 24;

void warm_up(vkminer::Kernel &kernel, const uint32_t *header)
{
    const uint32_t depth = std::max<uint32_t>(1, kernel.queue_depth());
    uint32_t inflight = 0;

    for (int i = 0; i < kWarmup; i++) {
        if (!kernel.dispatch(header, kTargetNone, kNonceBase,
                             kernel.preferred_batch()))
            break;
        inflight++;
        if (inflight < depth)
            continue;

        vkminer::Solution got[kMaxSolutions];
        if (kernel.collect(got, kMaxSolutions) < 0)
            break;
        inflight--;
    }

    while (inflight--) {
        vkminer::Solution got[kMaxSolutions];
        if (kernel.collect(got, kMaxSolutions) < 0)
            break;
    }
}

// One dispatch, and the smallest digest word the probe saw in it.
//
// The kernel keeps the probe's readings scaled and summed, because over a run
// that is the only form of them that means anything. Here there is exactly one
// dispatch, so the scaling is undone to recover the integer the shader actually
// wrote -- which is the thing that can be compared with a reference.
bool probe_dispatch(vkminer::Kernel &kernel, const uint32_t *header,
                    uint32_t start, uint32_t count, uint32_t *out,
                    double *scaled = nullptr)
{
    const vkminer::Kernel::BestDigest before = kernel.best_digest();

    if (!kernel.dispatch(header, kTargetNone, start, count)) {
        fail("dispatch of %u nonces from 0x%08x was refused", count, start);
        return false;
    }

    vkminer::Solution got[kMaxSolutions];
    if (kernel.collect(got, kMaxSolutions) < 0) {
        fail("the device failed while hashing %u nonces from 0x%08x", count,
             start);
        return false;
    }

    const vkminer::Kernel::BestDigest after = kernel.best_digest();
    if (after.samples != before.samples + 1) {
        // Counted as unsigned rather than with %llu: mingw's printf does not
        // take it, and this test has to build for Windows. One dispatch's worth
        // of readings fits either way.
        fail("the probe reported %u reading(s) for one dispatch -- the shader "
             "was built without it, or nothing reaches it",
             static_cast<unsigned>(after.samples - before.samples));
        return false;
    }

    const double term = after.ratio_sum - before.ratio_sum;
    *out = static_cast<uint32_t>(term * 4294967296. / static_cast<double>(count)
                                 + 0.5);
    if (scaled)
        *scaled = term;
    return true;
}

// The same minimum, computed by the algorithm's own scalar reference. The
// target is all ones so that verify() takes every nonce and fills in the
// digest; word 7 is the most significant, which is the word the shader screens
// on and the word the probe reports.
uint32_t reference_best(const vkminer::Algorithm &algo, const uint32_t *header,
                        uint32_t start, uint32_t count)
{
    uint32_t best = 0xffffffffu;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t hash[8];
        if (algo.verify(header, start + i, kTargetAll, hash) && hash[7] < best)
            best = hash[7];
    }
    return best;
}

// How far the mean may sit from its expectation before this is a fault, in
// multiples of the standard error the run measures for itself. Four, because
// the mean of a few hundred exponentials is near enough normal that four is a
// once-in-tens-of-thousands accident, and because the fault this is looking for
// -- a kernel searching some fraction of the nonces it was handed -- reads low
// by that whole fraction and not by a few per cent.
constexpr double kTolerance = 4.;

// What a correct probe averages over a dispatch of `count` nonces.
//
// Not one, quite. The smallest of `count` words drawn uniformly from 0..2^32-1
// has expectation 2^32/(count+1) - 1/2, so the scaled reading sits slightly
// below one -- by about a part in a hundred at the batch a GPU settles on,
// which is not negligible for a check trying to resolve a few per cent. The
// shortfall is a property of the estimator and not of the kernel.
double expected_term(uint32_t count)
{
    const double n = static_cast<double>(count);
    return n / (n + 1.) - n / (2. * 4294967296.);
}

// Whether the average of the readings is the number the miner prints it as.
//
// The two checks above establish that a reading is the true minimum over the
// nonces of that dispatch. They cannot ask the next question, because they only
// ever look at one dispatch: the scaled reading is an exponential deviate with
// a mean of one and a spread of one, and the miner reports the mean of a run's
// worth of them as a measurement. It is one -- to 1/sqrt(N), and only if the N
// readings are independent.
//
// They are not independent for free. A dispatch of `batch` nonces against a
// fixed header repeats after 2^32/batch of them -- forty-odd on a GPU -- and
// from there the average is re-averaging minima already counted: the error bar
// keeps shrinking while the estimate stops improving. So every round here gets
// its own header as well as its own nonce base, which is the substance of the
// check rather than a detail of it.
bool calibrate(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
               const uint32_t *header_in, int rounds)
{
    // Any word but the nonce, which the dispatch supplies and which must stay
    // where it is. The timestamp by preference, since a real miner stirs that
    // one too.
    const size_t stir = algo.nonce_word() == 17 ? 0 : 17;

    uint32_t header[20];
    std::memcpy(header, header_in, sizeof header);

    double sum = 0., sum_sq = 0., expect = 0.;

    for (int i = 0; i < rounds; i++) {
        const uint32_t batch = kernel.preferred_batch();

        // splitmix64 of the round number: a header and a base that share
        // nothing with the round before, and that depend on nothing but i, so
        // a round that fails can be run again.
        uint64_t x = 0x9e3779b97f4a7c15ull * static_cast<uint64_t>(i + 1);
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ull;
        x ^= x >> 27;

        header[stir] = static_cast<uint32_t>(x >> 32);

        // Kept clear of the top of the range, so that no dispatch wraps and
        // the question of what wrapping would mean stays out of this check.
        const uint32_t start = static_cast<uint32_t>(
            (x & 0xffffffffu) % (0x100000000ull - batch));

        uint32_t best = 0;
        double term = 0.;
        if (!probe_dispatch(kernel, header, start, batch, &best, &term))
            return false;

        sum += term;
        sum_sq += term * term;
        expect += expected_term(batch);
    }

    const double n = static_cast<double>(rounds);
    const double mean = sum / n;
    const double var = (sum_sq - n * mean * mean) / (n - 1.);
    const double spread = std::sqrt(var > 0. ? var : 0.);

    // Against the expectation rather than against one, and with the error bar
    // the readings themselves imply rather than an assumed 1/sqrt(N) -- the
    // spread is close to one for a working probe, but a broken one can be
    // narrow, and a check that assumed the spread would then quote an error
    // bar the data does not support. Which is the mistake being guarded here.
    const double ratio = sum / expect;
    const double error = spread / std::sqrt(n) / (expect / n);
    const double sigmas = error > 0. ? std::fabs(ratio - 1.) / error : 0.;

    if (sigmas > kTolerance) {
        fail("over %d dispatches of distinct headers the probe averages %.3f "
             "of what it should, which is %.1f standard errors out", rounds,
             ratio, sigmas);
        // Directional, like the checks above, and the direction is the useful
        // half: a kernel searching a fraction of the nonces it was given reads
        // low by exactly that fraction, and one seeing nonces it was not given
        // reads high.
        std::printf("  the probe is reading %s than it should on average -- "
                    "%s\n", ratio < 1. ? "lower" : "higher",
                    ratio < 1. ? "as a kernel searching only part of its "
                                 "dispatch would"
                               : "as a kernel seeing digests from outside its "
                                 "dispatch would");
        return false;
    }

    std::printf("ok   %d dispatch(es), each its own header and nonce base: "
                "mean %.3f of expected (+/- %.1f%%, spread %.2f)\n", rounds,
                ratio, 100. * error, spread);
    return true;
}

bool run_device(vkminer::ComputeBackend &backend, const vkminer::DeviceInfo &info,
                const vkminer::Algorithm &algo, int repetitions, int rounds)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    const vkminer::KernelSpec spec = algo.kernel(info);
    if (!spec.spirv || !spec.spirv_words) {
        std::printf("SKIP %s has no shader for this device\n", algo.name());
        return true;
    }

    std::unique_ptr<vkminer::Kernel> kernel =
        backend.create_kernel(info.index, spec);
    if (!kernel) {
        fail("could not build %s for this device", algo.name());
        return false;
    }

    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(kHeader + i * 4);

    const uint32_t exact = std::min(kExactNonces, kernel->max_batch());

    uint32_t device_best = 0;
    if (!probe_dispatch(*kernel, header, kNonceBase, exact, &device_best))
        return false;

    const uint32_t host_best =
        reference_best(algo, header, kNonceBase, exact);

    if (device_best != host_best) {
        fail("over %u nonces from 0x%08x the probe says the smallest digest "
             "word is %08x and the reference says %08x", exact,
             kNonceBase, device_best, host_best);
        // Which way it is wrong says which bug it is: below the reference means
        // the shader is seeing digests from nonces it was not given, and above
        // it means it is not seeing all the ones it was.
        std::printf("  the probe is reading %s than the truth\n",
                    device_best < host_best ? "lower" : "higher");
        return false;
    }
    std::printf("ok   %u nonces, smallest digest word %08x, probe and "
                "reference agree exactly\n", exact, device_best);

    // Everything from here runs at the size the device would really run, which
    // the host cannot follow -- so it is warmed up first, for the same reason
    // the race check is: a dispatch of the tuner's opening guess is not the
    // dispatch anybody mines with, and it is the large one that has the
    // occupancy a fault would need.
    warm_up(*kernel, header);
    const uint32_t batch = kernel->preferred_batch();

    // One dispatch has one minimum however many times it is run, so a
    // disagreement between repetitions is a fault on its own evidence, with no
    // reference needed.
    uint32_t first = 0;
    for (int i = 0; i < repetitions; i++) {
        uint32_t got = 0;
        if (!probe_dispatch(*kernel, header, kNonceBase, batch, &got))
            return false;
        if (i == 0) {
            first = got;
        } else if (got != first) {
            fail("the same dispatch of %u nonces gave a smallest digest word "
                 "of %08x and then %08x", batch, first, got);
            return false;
        }
    }
    std::printf("ok   %u nonces, smallest digest word %08x on all %d "
                "repetition(s)\n", batch, first, repetitions);

    // The exactness check again, at full size, with the reference replaced by
    // the device itself. The minimum over a set of nonces is the smallest of
    // the minima over any partition of it, so the same nonces split across
    // several dispatches must produce the same answer as one dispatch of all
    // of them. Nothing here is a hash the host computes, which is what lets it
    // run at a hundred million nonces instead of two.
    //
    // It is directional in the same way as the check above. A whole dispatch
    // reporting *lower* than its own parts is seeing digests the parts did not
    // -- from nonces it was not given, or from a neighbouring dispatch's buffer
    // -- and reporting *higher* means it is missing some of its own.
    constexpr uint32_t kParts = 8;
    const uint32_t chunk = batch / kParts;
    const uint32_t total = chunk * kParts;

    uint32_t whole = 0;
    if (!probe_dispatch(*kernel, header, kNonceBase, total, &whole))
        return false;

    uint32_t parts = 0xffffffffu;
    for (uint32_t i = 0; i < kParts; i++) {
        uint32_t got = 0;
        if (!probe_dispatch(*kernel, header, kNonceBase + i * chunk, chunk,
                            &got))
            return false;
        parts = std::min(parts, got);
    }

    if (whole != parts) {
        fail("%u nonces from 0x%08x give a smallest digest word of %08x in one "
             "dispatch and %08x in %u of them", total, kNonceBase, whole, parts,
             kParts);
        std::printf("  the whole dispatch is reading %s than its own parts\n",
                    whole < parts ? "lower" : "higher");
        return false;
    }
    std::printf("ok   %u nonces, smallest digest word %08x whole and in %u "
                "parts\n", total, whole, kParts);

    return calibrate(*kernel, algo, header, rounds);
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    const char *name = argc > 1 ? argv[1] : "sha256d";
    int repetitions = 4;
    if (argc > 2) {
        const long n = std::strtol(argv[2], nullptr, 0);
        if (n < 2) {
            std::printf("usage: %s [algo] [repetitions] [calibration rounds]\n",
                        argv[0]);
            return 2;
        }
        repetitions = static_cast<int>(n);
    }

    // A reading is worth 1/sqrt(rounds), so this is the resolution of the
    // calibration and not a run length to trim: 256 of them resolve six per
    // cent, and fewer than about sixty cannot tell a working probe from one
    // reading a third of the nonces. Each dispatch is aimed at a twentieth of a
    // second by the tuner, whatever the device, so the default costs a quarter
    // of a minute on a GPU and about the same on a software rasterizer.
    int rounds = 256;
    if (argc > 3) {
        const long n = std::strtol(argv[3], nullptr, 0);
        if (n < 2) {
            std::printf("usage: %s [algo] [repetitions] [calibration rounds]\n",
                        argv[0]);
            return 2;
        }
        rounds = static_cast<int>(n);
    }

    // The whole subject of this file. Without it the shader is built with the
    // probe folded out and every reading below is an absence.
    opt_vk_probe_best = true;

    std::unique_ptr<vkminer::Algorithm> algo = vkminer::create_algorithm(name);
    if (!algo) {
        std::printf("FAIL no algorithm called '%s'\n", name);
        return 1;
    }

    // The header below is one particular block of one particular chain, and
    // eighty bytes of it. An algorithm whose header is some other length would
    // be handed the first n bytes of it and asked about the digests -- a
    // question with an answer, and not the one this file claims to be asking.
    if (algo->header_bytes() != sizeof kHeader) {
        std::printf("FAIL '%s' reads a %u-byte header, and this test has an "
                    "80-byte block to give it\n",
                    algo->name(),
                    static_cast<unsigned>(algo->header_bytes()));
        return 1;
    }

    std::unique_ptr<vkminer::ComputeBackend> backend =
        vkminer::make_vulkan_backend();
    if (!backend || !backend->init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;
    }

    std::printf("%s: the best-digest probe against the reference, against "
                "itself, and against its own expectation\n", name);

    for (const vkminer::DeviceInfo &info : backend->devices())
        run_device(*backend, info, *algo, repetitions, rounds);

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
