// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The differential test: the same nonce range through the shader and through
// the algorithm's scalar reference, and the two answers must be the same
// answer. Not "the candidates the device returned are valid" -- that is a
// weaker claim which a kernel that finds one nonce in three would still pass --
// but set equality. Every nonce the reference says meets the target must come
// back, no nonce it rejects may come back, and the digest words must agree bit
// for bit.
//
// The target is chosen so that candidates are common: about one nonce in a
// thousand, rather than the one in billions a real difficulty asks for. At pool
// difficulty the interesting cases -- a hash just above the target, just below
// it, equal in the top word and decided by a lower one -- would never occur.
// Here they occur by the hundred.
//
// The range is run twice: once with a single dispatch outstanding, and once
// with the kernel's queue kept full, which is how the miner drives it. Both
// must produce the same answer, because a pipeline that mixes up which result
// buffer belongs to which dispatch is otherwise invisible -- it returns real
// hashes of real nonces, just not the ones it was asked about.
//
// It reports SKIP rather than failing where there is no Vulkan device, and
// where the algorithm under test has no shader yet: neither is a wrong result,
// and both are normal states for a build machine or a half-finished algorithm.

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "backends/vulkan/vulkan_common.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and fulltest reach for and no more.
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

// Nonces per dispatch. Small on purpose: with the target below it averages
// about eight candidates, which is well inside what any result buffer holds, so
// a run cannot fail because too many nonces qualified at once. It is also not a
// multiple of any plausible workgroup size, so the last workgroup of every
// dispatch is a partial one and a shader that forgets its bounds check hashes
// nonces the host never asked about.
constexpr uint32_t kChunk = 8000;

// ...but a kernel may not be able to take that many: a memory-bound one owns a
// scratchpad per invocation, so the device's memory decides how large a dispatch
// can be. The chunk is the smaller of what this test wants and what the kernel
// says it will take.
//
// That costs the partial-workgroup property above, because a capped batch is a
// whole number of workgroups. The last chunk of a run is still partial whenever
// the total is not a multiple of this, which is why the totals are not round.
uint32_t chunk_for(const vkminer::Kernel &kernel)
{
    return std::min(kChunk, kernel.max_batch());
}

// Where the range starts. Not zero: a kernel that ignores nonce_start, or that
// treats the nonce as signed, agrees with the reference at zero and nowhere
// else. This start also crosses 0x80000000 partway through a hundred thousand
// nonces, which is where a signed comparison would break.
constexpr uint64_t kNonceBase = 0x7fff0000u;

// How many candidates to ask for in one collect(). Larger than any backend's
// per-dispatch capacity, so that a device which found more than it can report
// shows up here as missing nonces rather than as a silent truncation by this
// test.
constexpr int kMaxSolutions = 256;

// The sweep's target: about one nonce in 2^10 meets it, which is what makes a
// hundred thousand nonces produce a hundred candidates instead of none.
//
// It decides every comparison in the **top word**, and cannot do otherwise.
// A 256-bit compare only reaches a lower word when the top words are exactly
// equal, which is a 2^-32 event -- so no sweep of any length this test could run
// will reach one, and with the lower words all ones no digest that got there
// could be rejected anyway. The screen and the full compare are therefore
// indistinguishable everywhere this range goes. That half is `compare_boundary`
// below, which constructs the equality instead of waiting for it.
const uint32_t kTarget[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0x003fffffu,
};

// Nonces per boundary dispatch, and the witness sits in the middle of them. Odd,
// so this dispatch is a partial workgroup too; small, because the range is here
// to carry one nonce past the device rather than to search.
//
// Bounded by the result buffer, and it has to be. A target built to be met at
// the *top* word is a target most of the range meets -- the witness's digest
// decides how loose, and that is a random 32-bit number -- so a span wider than
// the buffer would overflow it for some witnesses and not others, and read as a
// wrong answer from the device. Every nonce qualifying is then still a dispatch
// that fits.
constexpr uint32_t kBoundarySpan = 31;
static_assert(kBoundarySpan <= vkminer::kMaxCandidates,
              "a boundary dispatch must fit the device's result buffer even "
              "when every one of its nonces qualifies");

// Nonces to look at for a witness digest with no word at either extreme. One is
// almost always enough -- the chance a digest holds a 0x00000000 or 0xffffffff
// word is about 2^-28 -- and the loop is here so that "almost" is not load
// bearing.
constexpr uint32_t kWitnessSearch = 1000;

// Block 125552's header, as it went over the wire, with the nonce left in
// place -- the range below overwrites it anyway. A real header rather than a
// pattern, so that the words the shader schedules are the shape of the thing it
// will actually be given.
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

void print_hash(const char *label, const uint32_t hash[8])
{
    // Most significant word first, which is how the comparison reads it and
    // how a difference in the deciding word ends up at the left of the line.
    std::printf("  %-9s ", label);
    for (int i = 7; i >= 0; i--)
        std::printf("%08x", hash[i]);
    std::printf("\n");
}

struct Candidate {
    uint64_t nonce;
    uint32_t hash[8];
};

// Every nonce in [start, start + count) that the reference says meets the
// target, in increasing order. This is the answer; the device is measured
// against it.
void reference_candidates(const vkminer::Algorithm &algo,
                          const uint32_t *header, const uint32_t *target,
                          uint64_t start, uint32_t count,
                          std::vector<Candidate> *out)
{
    out->clear();
    for (uint32_t i = 0; i < count; i++) {
        Candidate c;
        c.nonce = start + i;
        if (algo.verify(header, c.nonce, target, c.hash))
            out->push_back(c);
    }
}

// What one dispatch came back with, against what the reference says that range
// holds. Returns false on the first disagreement: a kernel that is wrong is
// wrong about every dispatch after this one too, and printing a hundred
// thousand lines of it helps nobody.
bool compare_results(const vkminer::Algorithm &algo, const uint32_t *header,
                     const uint32_t *target, uint64_t start, uint32_t count,
                     vkminer::Solution *got, int n, size_t *candidates)
{
    std::vector<Candidate> want;
    reference_candidates(algo, header, target, start, count, &want);

    // The device emits candidates in whatever order its invocations reached
    // the counter, which is not an order at all. Sorting is not papering over
    // anything: nothing in the miner depends on the order, and a duplicate
    // survives a sort and is caught by the comparison below.
    std::sort(got, got + n, [](const vkminer::Solution &a,
                               const vkminer::Solution &b) {
        return a.nonce < b.nonce;
    });

    if (static_cast<size_t>(n) != want.size()) {
        // Sizes are printed as unsigned rather than with %zu: mingw's printf
        // does not accept it, and this test has to build for Windows.
        fail("%u nonces from 0x%s: the device reported %d candidate(s) and "
             "the reference found %u", count,
             vkminer::nonce_hex(start).c_str(), n,
             static_cast<unsigned>(want.size()));

        // Which ones, because "one too many" and "one too few" are different
        // bugs and the nonce says which.
        size_t i = 0;
        int j = 0;
        while (i < want.size() || j < n) {
            if (j >= n || (i < want.size() && want[i].nonce < got[j].nonce)) {
                std::printf("  missing   nonce 0x%s\n",
                            vkminer::nonce_hex(want[i].nonce).c_str());
                i++;
            } else if (i >= want.size() || got[j].nonce < want[i].nonce) {
                std::printf("  spurious  nonce 0x%s\n",
                            vkminer::nonce_hex(got[j].nonce).c_str());
                j++;
            } else {
                i++;
                j++;
            }
        }
        return false;
    }

    for (int i = 0; i < n; i++) {
        if (got[i].nonce != want[static_cast<size_t>(i)].nonce) {
            fail("candidate %d of the dispatch at 0x%s is nonce 0x%s, and "
                 "the reference says 0x%s", i,
                 vkminer::nonce_hex(start).c_str(),
                 vkminer::nonce_hex(got[i].nonce).c_str(),
                 vkminer::nonce_hex(want[static_cast<size_t>(i)].nonce).c_str());
            return false;
        }
        if (std::memcmp(got[i].hash, want[static_cast<size_t>(i)].hash,
                        sizeof got[i].hash) != 0) {
            fail("nonce 0x%s hashed to different digests",
                 vkminer::nonce_hex(got[i].nonce).c_str());
            print_hash("reference", want[static_cast<size_t>(i)].hash);
            print_hash("device", got[i].hash);
            return false;
        }
    }

    *candidates += want.size();
    return true;
}

// One dispatch, submitted and waited for before the next is asked about.
bool compare_chunk(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                   const uint32_t *header, const uint32_t *target,
                   uint64_t start, uint32_t count, size_t *candidates)
{
    if (!kernel.dispatch(header, target, start, count)) {
        fail("dispatch of %u nonces from 0x%s was refused", count,
             vkminer::nonce_hex(start).c_str());
        return false;
    }

    vkminer::Solution got[kMaxSolutions];
    const int n = kernel.collect(got, kMaxSolutions);
    if (n < 0) {
        fail("the device failed while hashing %u nonces from 0x%s",
             count, vkminer::nonce_hex(start).c_str());
        return false;
    }

    return compare_results(algo, header, target, start, count, got, n,
                           candidates);
}

// The same range again, with as many dispatches outstanding as the kernel will
// take -- the way the miner actually drives it.
//
// The same set-equality check, and that is the point. Each in-flight dispatch
// has its own result buffer and descriptor set, and a kernel that crossed two
// of them would answer for one dispatch with another's candidates -- nonces
// outside the range the reference was asked about, so the first chunk fails
// loudly rather than the run passing on plausible-looking numbers.
bool compare_pipelined(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                       const uint32_t *header, uint32_t total,
                       size_t *candidates)
{
    const size_t depth = std::max<uint32_t>(1, kernel.queue_depth());

    // What was launched, in the order it was launched, because that is the
    // order the results come back in and the only thing tying one to a range.
    struct Launched {
        uint64_t start;
        uint32_t count;
    };
    std::deque<Launched> inflight;

    const uint32_t chunk = chunk_for(kernel);

    uint32_t done = 0;
    while (done < total || !inflight.empty()) {
        while (done < total && inflight.size() < depth) {
            const uint32_t count = std::min(chunk, total - done);
            const uint64_t start = kNonceBase + done;
            if (!kernel.dispatch(header, kTarget, start, count)) {
                fail("dispatch of %u nonces from 0x%s was refused with %u "
                     "already in flight", count,
                     vkminer::nonce_hex(start).c_str(),
                     static_cast<unsigned>(inflight.size()));
                return false;
            }
            inflight.push_back(Launched{start, count});
            done += count;
        }

        vkminer::Solution got[kMaxSolutions];
        const int n = kernel.collect(got, kMaxSolutions);
        const Launched oldest = inflight.front();
        inflight.pop_front();

        if (n < 0) {
            fail("the device failed while hashing %u nonces from 0x%s",
                 oldest.count, vkminer::nonce_hex(oldest.start).c_str());
            return false;
        }
        if (!compare_results(algo, header, kTarget, oldest.start, oldest.count,
                             got, n, candidates))
            return false;
    }

    return true;
}

// A target that puts the decision on a chosen word of a known digest.
//
// The comparison walks from the top word down and stops at the first word that
// differs, so making every word above `word` equal to the digest's is what
// forces it to reach `word` at all. `above` then chooses which way it goes
// there: a target one larger than the digest is met (and the walk stops), one
// smaller is not. The words below are left equal to the digest, where nothing
// reads them.
void target_at(const uint32_t digest[8], int word, bool above, uint32_t out[8])
{
    std::memcpy(out, digest, 8 * sizeof(uint32_t));
    out[word] = above ? digest[word] + 1 : digest[word] - 1;
}

// The half of the comparison the sweep above cannot reach: the paths that only
// exist when a digest's top word is *exactly* the target's.
//
// The shader screens on one word and then re-compares all eight, and those two
// only ever disagree at that exact equality -- everywhere else the top
// word already decides, so the sweep runs the same branch a hundred thousand
// times. Waiting for the equality is not an option at 2^-32 a nonce; the way to
// it is to stop choosing the target first. Hash a nonce, and build the targets
// from what came back, so the boundary lands on a digest that exists.
//
// Sixteen of those, two per word: the one the digest just fails and the one it
// just meets. The eight below the top word are the interesting ones, because
// each is a nonce the screen lets through for the full compare to decide -- the
// path that is otherwise reached once in four billion. A seventeenth target is
// the digest itself, where every word is equal and the walk runs off the end,
// which is the case a compare written with `<` rather than `<=` gets wrong and
// no other case here would catch.
bool compare_boundary(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                      const uint32_t *header)
{
    // The witness. Any nonce would do -- the targets are built from its digest,
    // not the other way round -- except that a digest word of 0x00000000 has no
    // target below it and one of 0xffffffff none above, so a word at either
    // extreme would quietly drop a case instead of testing it.
    uint64_t witness = 0;
    uint32_t digest[8];
    bool usable = false;
    for (uint32_t i = 0; i < kWitnessSearch && !usable; i++) {
        witness = kNonceBase + i;
        algo.hash(header, witness, digest);
        usable = true;
        for (int w = 0; w < 8; w++)
            if (digest[w] == 0 || digest[w] == 0xffffffffu)
                usable = false;
    }
    if (!usable) {
        fail("no nonce in %u produced a digest with room either side of every "
             "word", kWitnessSearch);
        return false;
    }

    const uint64_t start = witness - kBoundarySpan / 2;

    struct Case {
        uint32_t target[8];
        bool     expect;   // whether the witness should meet it
        int      word;     // where the comparison should be decided, -1 for "nowhere"
    };
    std::vector<Case> cases;

    Case exact;
    std::memcpy(exact.target, digest, sizeof exact.target);
    exact.expect = true;                // hash == target is a share
    exact.word = -1;
    cases.push_back(exact);

    for (int w = 7; w >= 0; w--) {
        Case below, above;
        target_at(digest, w, false, below.target);
        below.expect = false;
        below.word = w;
        cases.push_back(below);

        target_at(digest, w, true, above.target);
        above.expect = true;
        above.word = w;
        cases.push_back(above);
    }

    unsigned survivors = 0;
    for (const Case &c : cases) {
        // What this case is worth is a property of the case, so it is checked
        // rather than assumed: a target built wrongly would agree with the
        // reference on both sides and pass while testing nothing. Ask the
        // reference what the witness does with this target and require it to be
        // what the construction claims.
        uint32_t ignored[8];
        const bool got = algo.verify(header, witness, c.target, ignored);
        if (got != c.expect) {
            fail("the reference says nonce 0x%s %s a target built to be %s "
                 "at word %d -- the construction is wrong, so this case tests "
                 "nothing", vkminer::nonce_hex(witness).c_str(),
                 got ? "meets" : "misses",
                 c.expect ? "met" : "missed", c.word);
            print_hash("digest", digest);
            print_hash("target", c.target);
            return false;
        }

        size_t candidates = 0;
        if (!compare_chunk(kernel, algo, header, c.target, start,
                           kBoundarySpan, &candidates))
            return false;

        // The screen passes on the top word alone, so every case that keeps the
        // top word equal is one the device carried into the full compare.
        if (c.word != 7)
            survivors++;
    }

    std::printf("ok   %u boundary target(s) at nonce 0x%s, %u of them decided "
                "below the top word\n", static_cast<unsigned>(cases.size()),
                vkminer::nonce_hex(witness).c_str(), survivors);
    return true;
}

bool run_device(vkminer::ComputeBackend &backend, const vkminer::DeviceInfo &info,
                const vkminer::Algorithm &algo, uint32_t total)
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

    // struct work's spelling of the header: one host-order word per big-endian
    // read of the wire. The same conversion the miner makes on the way in, so
    // that what is under test is the shader and not this file's idea of a
    // header.
    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(kHeader + i * 4);

    const uint32_t chunk = chunk_for(*kernel);

    size_t candidates = 0;
    for (uint32_t done = 0; done < total; done += chunk) {
        const uint32_t count = std::min(chunk, total - done);
        if (!compare_chunk(*kernel, algo, header, kTarget, kNonceBase + done,
                           count, &candidates))
            return false;
    }

    // A run that found nothing compared nothing. It would pass silently against
    // a kernel that never emits, which is the one failure this test exists to
    // catch, so it is a failure here rather than a pass.
    if (candidates == 0) {
        fail("%u nonces produced no candidates at all -- the target above is "
             "meant to be met about once in a thousand", total);
        return false;
    }

    std::printf("ok   %u nonces, %u candidate(s), one dispatch at a time\n",
                total, static_cast<unsigned>(candidates));

    size_t pipelined = 0;
    if (!compare_pipelined(*kernel, algo, header, total, &pipelined))
        return false;

    // The same nonces hashed both ways have to meet the target both ways.
    // Weaker than the per-dispatch comparison above, and here because it is the
    // one line that still catches a pipeline dropping a whole dispatch's
    // results -- reporting nothing rather than reporting wrongly.
    if (pipelined != candidates) {
        fail("%u candidate(s) with the pipeline full and %u with one dispatch "
             "at a time, over the same nonces",
             static_cast<unsigned>(pipelined), static_cast<unsigned>(candidates));
        return false;
    }

    const uint32_t depth = kernel->queue_depth();
    std::printf("ok   %u nonces, %u candidate(s), up to %u dispatch%s in "
                "flight\n", total, static_cast<unsigned>(pipelined), depth,
                depth == 1 ? "" : "es");

    return compare_boundary(*kernel, algo, header);
}

void usage(const char *program)
{
    std::printf("usage: %s [algo] [nonces] [queue-depth] [--no-int64]\n",
                program);
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    // --no-int64 is taken from anywhere among the arguments, so that a caller
    // who wants it need not spell out the three numbers before it. It is the
    // only way to point this test at an algorithm's 2x32 fallback on a device
    // that has shaderInt64, and it must be set before the backend exists.
    const char *args[4] = { argv[0], nullptr, nullptr, nullptr };
    int count = 1;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--no-int64") == 0) {
            opt_no_int64 = true;
        } else if (count < 4) {
            args[count++] = argv[i];
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    const char *name = count > 1 ? args[1] : "sha256d";
    uint32_t total = 100000;
    if (count > 2) {
        const long n = std::strtol(args[2], nullptr, 0);
        if (n <= 0) {
            usage(argv[0]);
            return 2;
        }
        total = static_cast<uint32_t>(n);
    }

    // The pipelined pass below runs at whatever depth the kernel reports, so
    // this is what lets the same check be pointed at a depth --queue-depth can
    // ask for. Without it every depth but the default ships untested.
    if (count > 3) {
        const long n = std::strtol(args[3], nullptr, 0);
        if (n < 1 || n > 16) {
            usage(argv[0]);
            return 2;
        }
        opt_queue_depth = static_cast<int>(n);
    }

    std::unique_ptr<vkminer::Algorithm> algo = vkminer::create_algorithm(name);
    if (!algo) {
        std::printf("FAIL no algorithm called '%s'\n", name);
        return 1;
    }

    // On, because a kernel that produces the right answers through undefined
    // behaviour is a kernel that will produce the wrong ones on a driver
    // nobody here has.
    opt_vk_validate = true;

    std::unique_ptr<vkminer::ComputeBackend> backend =
        vkminer::make_vulkan_backend();
    if (!backend || !backend->init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    std::printf("%s: %u nonces from 0x%s per device%s\n", name, total,
                vkminer::nonce_hex(kNonceBase).c_str(),
                opt_no_int64 ? ", shaderInt64 disabled" : "");

    for (const vkminer::DeviceInfo &info : backend->devices())
        run_device(*backend, info, *algo, total);

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (!vkminer::vk_validation_enabled) {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the answers matched\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
