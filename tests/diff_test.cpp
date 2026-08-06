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
// thousand, rather than the one in billions a real difficulty asks for. A test
// at pool difficulty would dispatch for an hour and prove nothing about the
// comparison, because the interesting cases -- a hash just above the target,
// just below it, equal in the top word and decided by a lower one -- would
// never occur. Here they occur by the hundred.
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

// Where the range starts. Not zero: a kernel that ignores nonce_start, or that
// treats the nonce as signed, agrees with the reference at zero and nowhere
// else. This start also crosses 0x80000000 partway through a hundred thousand
// nonces, which is where a signed comparison would break.
constexpr uint32_t kNonceBase = 0x7fff0000u;

// How many candidates to ask for in one collect(). Larger than any backend's
// per-dispatch capacity, so that a device which found more than it can report
// shows up here as missing nonces rather than as a silent truncation by this
// test.
constexpr int kMaxSolutions = 256;

// The target: about one nonce in 2^10 meets it. The upper words are all ones
// so that the comparison is decided in the top word most of the time and in a
// lower word the rest of the time -- both paths through a 256-bit compare get
// exercised, which a target of "top word zero" would not do.
const uint32_t kTarget[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0x003fffffu,
};

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
    uint32_t nonce;
    uint32_t hash[8];
};

// Every nonce in [start, start + count) that the reference says meets the
// target, in increasing order. This is the answer; the device is measured
// against it.
void reference_candidates(const vkminer::Algorithm &algo,
                          const uint32_t *header, uint32_t start,
                          uint32_t count, std::vector<Candidate> *out)
{
    out->clear();
    for (uint32_t i = 0; i < count; i++) {
        Candidate c;
        c.nonce = start + i;
        if (algo.verify(header, c.nonce, kTarget, c.hash))
            out->push_back(c);
    }
}

// What one dispatch came back with, against what the reference says that range
// holds. Returns false on the first disagreement: a kernel that is wrong is
// wrong about every dispatch after this one too, and printing a hundred
// thousand lines of it helps nobody.
bool compare_results(const vkminer::Algorithm &algo, const uint32_t *header,
                     uint32_t start, uint32_t count, vkminer::Solution *got,
                     int n, size_t *candidates)
{
    std::vector<Candidate> want;
    reference_candidates(algo, header, start, count, &want);

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
        fail("%u nonces from 0x%08x: the device reported %d candidate(s) and "
             "the reference found %u", count, start, n,
             static_cast<unsigned>(want.size()));

        // Which ones, because "one too many" and "one too few" are different
        // bugs and the nonce says which.
        size_t i = 0;
        int j = 0;
        while (i < want.size() || j < n) {
            if (j >= n || (i < want.size() && want[i].nonce < got[j].nonce)) {
                std::printf("  missing   nonce 0x%08x\n", want[i].nonce);
                i++;
            } else if (i >= want.size() || got[j].nonce < want[i].nonce) {
                std::printf("  spurious  nonce 0x%08x\n", got[j].nonce);
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
            fail("candidate %d of the dispatch at 0x%08x is nonce 0x%08x, and "
                 "the reference says 0x%08x", i, start, got[i].nonce,
                 want[static_cast<size_t>(i)].nonce);
            return false;
        }
        if (std::memcmp(got[i].hash, want[static_cast<size_t>(i)].hash,
                        sizeof got[i].hash) != 0) {
            fail("nonce 0x%08x hashed to different digests", got[i].nonce);
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
                   const uint32_t *header, uint32_t start, uint32_t count,
                   size_t *candidates)
{
    if (!kernel.dispatch(header, kTarget, start, count)) {
        fail("dispatch of %u nonces from 0x%08x was refused", count, start);
        return false;
    }

    vkminer::Solution got[kMaxSolutions];
    const int n = kernel.collect(got, kMaxSolutions);
    if (n < 0) {
        fail("the device failed while hashing %u nonces from 0x%08x",
             count, start);
        return false;
    }

    return compare_results(algo, header, start, count, got, n, candidates);
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
        uint32_t start;
        uint32_t count;
    };
    std::deque<Launched> inflight;

    uint32_t done = 0;
    while (done < total || !inflight.empty()) {
        while (done < total && inflight.size() < depth) {
            const uint32_t count = std::min(kChunk, total - done);
            const uint32_t start = kNonceBase + done;
            if (!kernel.dispatch(header, kTarget, start, count)) {
                fail("dispatch of %u nonces from 0x%08x was refused with %u "
                     "already in flight", count, start,
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
            fail("the device failed while hashing %u nonces from 0x%08x",
                 oldest.count, oldest.start);
            return false;
        }
        if (!compare_results(algo, header, oldest.start, oldest.count, got, n,
                             candidates))
            return false;
    }

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

    size_t candidates = 0;
    for (uint32_t done = 0; done < total; done += kChunk) {
        const uint32_t count = std::min(kChunk, total - done);
        if (!compare_chunk(*kernel, algo, header, kNonceBase + done, count,
                           &candidates))
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
    return true;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    const char *name = argc > 1 ? argv[1] : "sha256d";
    uint32_t total = 100000;
    if (argc > 2) {
        const long n = std::strtol(argv[2], nullptr, 0);
        if (n <= 0) {
            std::printf("usage: %s [algo] [nonces] [queue-depth]\n", argv[0]);
            return 2;
        }
        total = static_cast<uint32_t>(n);
    }

    // The pipelined pass below runs at whatever depth the kernel reports, so
    // this is what lets the same check be pointed at a depth --queue-depth can
    // ask for. Without it every depth but the default ships untested.
    if (argc > 3) {
        const long n = std::strtol(argv[3], nullptr, 0);
        if (n < 1 || n > 16) {
            std::printf("usage: %s [algo] [nonces] [queue-depth]\n", argv[0]);
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

    std::printf("%s: %u nonces from 0x%08x per device\n", name, total,
                kNonceBase);

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
