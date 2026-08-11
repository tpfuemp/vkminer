// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The negative half of the known-answer test, on the side that matters.
//
// The startup KAT drives a published header through a real device and checks
// the digest that comes back, which is the right shape for a positive test. The
// negative tests around it are not: they perturb a hash and confirm the *host*
// notices, which is a property of the scalar reference and holds no matter what
// the shader does. A self-test that cannot be made to fail is not a gate, and
// one whose failure mode lives entirely on the host is not a gate on the GPU.
//
// So this perturbs the device's input and requires the device's answer to move.
// For every word of the header: flip one bit, ask the same device for the same
// nonce again, and require both that the digest changed and that it changed to
// the value the reference says it should. The first catches a kernel that does
// not read the word at all; the second catches one that reads it wrongly.
//
// ⚠️ Perturbation is the only way to cover some of those words, which is what
// motivated the file. A valid block hash has leading zeros, and in wire order
// those land at the *end* of the previous-block field: header word 8 is
// 0x00000000 in both KAT vectors and in every mainnet header that will ever be
// added to them. A kernel that dropped word 8 from its message schedule would
// reproduce both published digests and pass the differential test too, which
// hashes a real header. Only a header no chain ever accepted can tell "reads
// word 8" from "ignores word 8", and this test manufactures one a bit at a time.
//
// The nonce is checked the same way, and so is the target comparison in the
// direction the device is responsible for: a target one below the right answer
// must return nothing.
//
// SKIPs where there is no Vulkan device or no shader, like the other device
// tests: neither is a wrong answer.

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "backends/vulkan/vulkan_common.h"

extern "C" {
#include "core/miner.h"
}

#include <cstdarg>
#include <cstdio>
#include <cstring>
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

// Every nonce meets this, so a dispatch of one nonce returns that nonce and its
// digest. The point here is to read the device's answer for a chosen nonce, not
// to search for one, and a target is the only way to ask a mining kernel for it.
const uint32_t kOpenTarget[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
};

// More than the one a single-nonce dispatch can produce, so a kernel emitting
// several is seen doing it rather than truncated into looking correct.
constexpr int kMaxSolutions = 16;

void print_hash(const char *label, const uint32_t *hash)
{
    std::printf("  %-9s ", label);
    for (int i = 7; i >= 0; i--)
        std::printf("%08x", hash[i]);
    std::printf("\n");
}

// What the device makes of exactly one nonce. False means the device did not
// answer the question -- a failed dispatch, or a candidate count that says the
// kernel is not doing what this test assumes -- and it has already been logged.
bool device_digest(vkminer::Kernel &kernel, const uint32_t *header,
                   uint32_t nonce, uint32_t out[8])
{
    if (!kernel.dispatch(header, kOpenTarget, nonce, 1)) {
        fail("the kernel refused a dispatch of one nonce");
        return false;
    }

    vkminer::Solution found[kMaxSolutions];
    const int n = kernel.collect(found, kMaxSolutions);
    if (n < 0) {
        fail("the device failed while hashing one nonce");
        return false;
    }
    // One nonce, a target every hash meets: exactly one candidate, and any
    // other number is the kernel disagreeing about what it was asked.
    if (n != 1) {
        fail("one nonce against an open target produced %d candidates", n);
        return false;
    }
    if (found[0].nonce != nonce) {
        fail("asked for nonce %08x and the device answered about %08x", nonce,
             found[0].nonce);
        return false;
    }

    std::memcpy(out, found[0].hash, 8 * sizeof(uint32_t));
    return true;
}

// One published vector, perturbed a bit at a time.
bool run_vector(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                const vkminer::KnownAnswer &answer)
{
    const size_t words = algo.header_bytes() / 4;
    const size_t nonce_word = algo.nonce_word();

    std::vector<uint32_t> header(words, 0);
    for (size_t i = 0; i < words; i++)
        header[i] = be32dec(answer.header + i * 4);
    if (nonce_word < words)
        header[nonce_word] = 0;

    // The positive control, and it is not redundant with the startup self-test:
    // without it a device that returned a constant would "change its answer"
    // for no word at all and every check below would fail for the wrong reason.
    uint32_t base[8];
    if (!device_digest(kernel, header.data(), answer.nonce, base))
        return false;

    if (std::memcmp(base, answer.digest, sizeof base) != 0) {
        fail("%s: the device does not reproduce the published digest, so "
             "nothing below is worth reading", answer.label);
        uint32_t published[8];   // copied rather than cast: the vector's bytes
        std::memcpy(published, answer.digest, sizeof published);  // need not align
        print_hash("expected", published);
        print_hash("got", base);
        return false;
    }

    unsigned ignored = 0, wrong = 0;

    for (size_t w = 0; w < words; w++) {
        // The nonce word carries no information -- the dispatch supplies the
        // nonce and the miner zeroes this -- so a kernel is *right* to ignore
        // it. It gets its own check below instead.
        if (w == nonce_word)
            continue;

        std::vector<uint32_t> probe = header;
        probe[w] ^= 1u;   // one bit, so nothing is proven by brute force

        uint32_t got[8];
        if (!device_digest(kernel, probe.data(), answer.nonce, got))
            return false;

        uint32_t want[8];
        algo.hash(probe.data(), answer.nonce, want);

        if (std::memcmp(got, base, sizeof base) == 0) {
            fail("%s: flipping a bit of header word %u left the device's "
                 "digest unchanged -- the kernel does not read that word",
                 answer.label, static_cast<unsigned>(w));
            ignored++;
        } else if (std::memcmp(got, want, sizeof want) != 0) {
            fail("%s: header word %u perturbed -- the device and the reference "
                 "disagree about the result", answer.label,
                 static_cast<unsigned>(w));
            print_hash("reference", want);
            print_hash("device", got);
            wrong++;
        }
    }

    // The nonce itself, by the same rule. A kernel that hashed the header and
    // ignored its nonce would have passed every check above.
    {
        uint32_t got[8];
        if (!device_digest(kernel, header.data(), answer.nonce + 1, got))
            return false;

        uint32_t want[8];
        algo.hash(header.data(), answer.nonce + 1, want);

        if (std::memcmp(got, base, sizeof base) == 0)
            fail("%s: the next nonce hashed to the same digest -- the kernel "
                 "does not read the nonce", answer.label);
        else if (std::memcmp(got, want, sizeof want) != 0)
            fail("%s: the device and the reference disagree about the next "
                 "nonce", answer.label);
    }

    // The device's own half of the target comparison. The published digest is
    // met exactly; one less than its low word is not, and a kernel that emits
    // anyway is one whose candidates are only as good as the host re-verify
    // behind them. Sound because word 0 of a mainnet digest is nonzero, which
    // is checked rather than assumed -- a vector added later with a zero low
    // word would silently turn this into a different test.
    if (base[0] == 0) {
        fail("%s: the low digest word is zero, so the decrement below would "
             "borrow", answer.label);
    } else {
        uint32_t tight[8];
        std::memcpy(tight, base, sizeof tight);
        tight[0]--;

        if (!kernel.dispatch(header.data(), tight, answer.nonce, 1)) {
            fail("the kernel refused a dispatch of one nonce");
            return false;
        }
        vkminer::Solution found[kMaxSolutions];
        const int n = kernel.collect(found, kMaxSolutions);
        if (n < 0) {
            fail("the device failed while hashing one nonce");
            return false;
        }
        if (n != 0)
            fail("%s: the device emitted a candidate whose hash is above the "
                 "target it was given", answer.label);
    }

    if (!ignored && !wrong)
        std::printf("ok   %s: every one of the %u header words changes the "
                    "device's answer, and changes it to the reference's\n",
                    answer.label, static_cast<unsigned>(words - 1));
    return !ignored && !wrong;
}

bool run_device(vkminer::ComputeBackend &backend,
                const vkminer::DeviceInfo &info,
                const vkminer::Algorithm &algo)
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

    const vkminer::KnownAnswer *answers = nullptr;
    const size_t count = algo.known_answers(&answers);
    if (!count) {
        fail("%s carries no known-answer vectors to perturb", algo.name());
        return false;
    }

    bool ok = true;
    for (size_t i = 0; i < count; i++)
        ok = run_vector(*kernel, algo, answers[i]) && ok;
    return ok;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    // --no-int64 as the differential test takes it: an algorithm with a 2x32
    // fallback has two kernels, and the one this device would not otherwise
    // choose is the one nobody ever runs.
    const char *name = "sha256d";
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--no-int64") == 0)
            opt_no_int64 = true;
        else
            name = argv[i];
    }

    std::unique_ptr<vkminer::Algorithm> algo = vkminer::create_algorithm(name);
    if (!algo) {
        std::printf("FAIL no algorithm called '%s'\n", name);
        return 1;
    }

    // On, for the same reason the differential test has them on: a kernel that
    // produces the right answers through undefined behaviour produces wrong
    // ones on a driver nobody here has.
    opt_vk_validate = true;

    std::unique_ptr<vkminer::ComputeBackend> backend =
        vkminer::make_vulkan_backend();
    if (!backend || !backend->init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    for (const vkminer::DeviceInfo &info : backend->devices())
        run_device(*backend, info, *algo);

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
