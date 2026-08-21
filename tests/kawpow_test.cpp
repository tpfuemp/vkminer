// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The KawPoW kernel against the host reference, digest word by digest word.
//
// This is the first kernel here where one nonce is not one invocation: sixteen
// cooperate on each, meeting at a barrier once a round to agree which line of
// the DAG to read and once at the end to fold their sixteen lane hashes into
// eight words. Nothing about that is visible in a hash rate. A kernel that got
// the lane exchange subtly wrong -- the wrong lane's register, the wrong
// quarter of the line, a barrier one invocation skipped -- produces digests
// that look exactly like digests, at full speed, forever.
//
// So every word of every digest is compared against the scalar reference, which
// is the same code the miner re-hashes candidates with and which the KAT tests
// have already measured against published vectors. What is under test here is
// the shader and only the shader.
//
// The DAG is built on the *host* and uploaded. A real epoch-0 table is 1023
// MiB the device would generate for itself in seconds, and generating it here
// would mean a test that fails for either of two reasons -- a wrong table or a
// wrong hash -- with one bit of information to tell them apart. dag_test already
// says the generation kernel is right. This one takes a small table the host
// built, so a disagreement has exactly one cause.

#include "algorithms/algorithm.h"
#include "algorithms/kawpow/kawpow.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_common.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and the option parser reach for and no more.
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

// The epoch, and how much of its DAG to upload. Epoch 0 because its light cache
// is the smallest there is; 8192 lines because 2 MiB is a second of host work
// and still four chunks of shared table, so the multi-binding path the kernel
// reads the DAG through is exercised on a device whose limits would never ask
// for it.
constexpr uint32_t kEpoch = 0;
constexpr uint64_t kLines = 8192;

// Nonces per dispatch. Every one of them is a candidate in the first phase --
// the target is wide open, so the device reports every digest it computes --
// which puts the ceiling at kMaxCandidates.
constexpr uint32_t kBatch = 16;

// Nonces per range, unless argv[1] says otherwise. Each is 64 rounds over 16
// lanes on the device and 256 DAG items recomputed from a light cache on the
// host, and the host is the slow half.
constexpr uint32_t kDefaultNonces = 256;

// How many of a batch the screening phase asks for. Enough that the answer is a
// set rather than a single nonce, and small enough to be most of a batch
// rejected.
constexpr uint32_t kWanted = 4;

int failures = 0;

// A nonce is a 64-bit quantity here and is printed as one, so the format string
// has to be checked against the printf that will read it rather than against
// the C library's default one. progpow_kat says the same thing at more length.
#if defined(__MINGW_PRINTF_FORMAT)
#define KAWPOW_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#elif defined(__GNUC__)
#define KAWPOW_PRINTF_FORMAT printf
#endif

void fail(const char *fmt, ...)
#if defined(KAWPOW_PRINTF_FORMAT)
    __attribute__((format(KAWPOW_PRINTF_FORMAT, 1, 2)))
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

// A header, as struct work carries one for this algorithm: the 32-byte header
// hash in the first eight words and the block height in the ninth. The hash is
// arbitrary -- nothing here checks it against a chain -- but it is fixed, so a
// failure is reproducible.
std::vector<uint32_t> header_for(uint32_t height)
{
    static const uint32_t kHash[8] = {
        0x11c1a3d4u, 0x1f2e3d4cu, 0x5b6a7988u, 0xc0ffee00u,
        0x0badf00du, 0xdeadbeefu, 0x13579bdfu, 0x2468ace0u,
    };
    std::vector<uint32_t> header(kHash, kHash + 8);
    header.push_back(height);
    return header;
}

// Every candidate, whatever it hashed to.
const uint32_t kOpen[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
};

// Two digests as 256-bit numbers, in the order fulltest() reads them: most
// significant word last. Negative, zero or positive, like memcmp.
int cmp256(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

// Every nonce of a range against the host, one dispatch at a time. `label`
// names the range in a failure, because the two this test runs fail for
// different reasons.
bool range_matches(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                   const std::vector<uint32_t> &header, uint64_t first,
                   uint32_t nonces, const char *label)
{
    for (uint32_t done = 0; done < nonces; done += kBatch) {
        const uint32_t count = std::min(kBatch, nonces - done);
        const uint64_t base = first + done;

        if (!kernel.dispatch(header.data(), kOpen, base, count)) {
            fail("%s: the kernel refused a dispatch at %s", label,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        vkminer::Solution got[vkminer::kMaxCandidates];
        const int n = kernel.collect(got, vkminer::kMaxCandidates);
        if (n < 0) {
            fail("%s: the device failed at %s", label,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        // Every invocation clears the target, so anything but all of them means
        // nonces went missing -- which on a kernel with sixteen invocations per
        // hash is most likely lanes that never reached the fold.
        if (n != static_cast<int>(count)) {
            fail("%s: %d of %u nonces came back at %s", label, n, count,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        for (int i = 0; i < n; i++) {
            const uint64_t nonce = got[i].nonce;
            if (nonce < base || nonce >= base + count) {
                fail("%s: nonce %s is outside the %u dispatched from %s", label,
                     vkminer::nonce_hex(nonce).c_str(), count,
                     vkminer::nonce_hex(base).c_str());
                return false;
            }

            uint32_t expect[8];
            algo.hash(header.data(), nonce, expect);
            for (uint32_t w = 0; w < 8; w++) {
                if (got[i].hash[w] == expect[w])
                    continue;
                fail("%s: nonce %s word %u came back 0x%08x, and the host says "
                     "0x%08x", label, vkminer::nonce_hex(nonce).c_str(), w,
                     got[i].hash[w], expect[w]);
                return false;
            }
        }
    }

    return true;
}

// The same nonces again at a target only some of them meet: the kernel has to
// return that set exactly. The phase above proves the digests are right and
// says nothing about the comparison that decides which of them is a share --
// a screen with a flipped inequality passes it perfectly.
bool screen_matches(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                    const std::vector<uint32_t> &header, uint64_t first)
{
    struct Scored {
        uint64_t nonce;
        uint32_t hash[8];
    };

    std::vector<Scored> scored(kBatch);
    for (uint32_t i = 0; i < kBatch; i++) {
        scored[i].nonce = first + i;
        algo.hash(header.data(), scored[i].nonce, scored[i].hash);
    }

    std::sort(scored.begin(), scored.end(),
              [](const Scored &a, const Scored &b) {
                  return cmp256(a.hash, b.hash) < 0;
              });

    // The kWanted-th smallest digest, so that nonce meets the target exactly
    // and the ones above it do not. The boundary case is the point: a
    // comparison that is strict where it should not be loses it.
    const uint32_t *target = scored[kWanted - 1].hash;

    std::vector<uint64_t> want;
    for (uint32_t i = 0; i < kWanted; i++)
        want.push_back(scored[i].nonce);
    std::sort(want.begin(), want.end());

    if (!kernel.dispatch(header.data(), target, first, kBatch)) {
        fail("screen: the kernel refused a dispatch at %s",
             vkminer::nonce_hex(first).c_str());
        return false;
    }

    vkminer::Solution got[vkminer::kMaxCandidates];
    const int n = kernel.collect(got, vkminer::kMaxCandidates);
    if (n < 0) {
        fail("screen: the device failed at %s",
             vkminer::nonce_hex(first).c_str());
        return false;
    }

    std::vector<uint64_t> have;
    for (int i = 0; i < n; i++)
        have.push_back(got[i].nonce);
    std::sort(have.begin(), have.end());

    if (have != want) {
        fail("screen: %u nonces meet the target and %d came back", kWanted, n);
        for (size_t i = 0; i < want.size(); i++)
            std::printf("     wanted %s\n",
                        vkminer::nonce_hex(want[i]).c_str());
        for (size_t i = 0; i < have.size(); i++)
            std::printf("     got    %s\n",
                        vkminer::nonce_hex(have[i]).c_str());
        return false;
    }

    return true;
}

bool run_device(vkminer::VulkanBackend &backend, const vkminer::DeviceInfo &info,
                uint32_t nonces)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::make_kawpow_host_dag(kEpoch, kLines);
    const vkminer::KernelSpec spec = algo->kernel(info);
    if (!spec.spirv) {
        fail("the kawpow module is not embedded in this build");
        return false;
    }

    std::unique_ptr<vkminer::Kernel> kernel =
        backend.create_kernel(info.index, spec);
    if (!kernel) {
        fail("could not create a kernel wanting %llu KiB of DAG in %u chunks",
             static_cast<unsigned long long>(spec.shared_bytes >> 10),
             spec.shared_chunks);
        return false;
    }

    std::printf("     epoch %u: %llu lines of DAG uploaded, %llu KiB to a "
                "binding\n", kEpoch, static_cast<unsigned long long>(kLines),
                static_cast<unsigned long long>(spec.shared_chunk_bytes >> 10));

    // The table, built here rather than on the device. Everything below hashes
    // against it, and it is the same bytes for both headers: the epoch decides
    // the table and the height decides only the program.
    const std::vector<uint32_t> low = header_for(3 * 1249);
    if (!kernel->prepare_state(algo->state_key(low.data()))) {
        fail("could not upload the DAG");
        return false;
    }

    // ---- an ordinary range
    //
    // Nonces from zero, at a height whose period is one the KAT vectors do not
    // cover: what is being checked is that the kernel draws the same program
    // the host draws, not that either matches a number written down somewhere.
    if (!range_matches(*kernel, *algo, low, 0, nonces, "low range"))
        return false;
    std::printf("ok   %u nonces at period %u\n", nonces, 1249u);

    // ---- and one that crosses 2^32
    //
    // A KawPoW nonce is 64 bits and the pool owns its top two bytes, so the
    // interesting arithmetic is the carry out of the low word -- which the
    // kernel does itself, once per invocation, because what it is handed is a
    // base and an index. This range starts eight nonces below the boundary.
    const uint64_t high_first = 0x00001234fffffff8ull;
    const std::vector<uint32_t> high = header_for(3 * 2499 + 2);
    if (!range_matches(*kernel, *algo, high, high_first, kBatch, "high range"))
        return false;
    std::printf("ok   %u nonces across 2^32, from %s\n", kBatch,
                vkminer::nonce_hex(high_first).c_str());

    // ---- and the comparison that turns a digest into a share
    if (!screen_matches(*kernel, *algo, low, 0))
        return false;
    std::printf("ok   %u of %u nonces returned at a target only they meet\n",
                kWanted, kBatch);

    return true;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    uint32_t nonces = kDefaultNonces;
    if (argc > 1) {
        const long asked = std::strtol(argv[1], nullptr, 10);
        if (asked <= 0) {
            std::printf("usage: %s [nonces]\n", argv[0]);
            return 2;
        }
        nonces = static_cast<uint32_t>(asked);
    }

    // Worth their cost here for the same reason as everywhere else the shared
    // table is involved, and one more: this is the first kernel with a barrier
    // in it, and a barrier some invocations of a workgroup do not reach is
    // undefined behaviour that a software rasterizer will happily execute.
    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    for (const vkminer::DeviceInfo &info : backend.devices())
        run_device(backend, info, nonces);

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (vkminer::vk_validation_enabled) {
        std::printf("\nok   no validation errors\n");
    } else {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the numbers came back right\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
