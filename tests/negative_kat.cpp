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
// Perturbation is the only way to cover some of those words, which is what
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

#include "algorithms/kawpow/kawpow.h"
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
bool device_digest(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                   const uint32_t *header, uint64_t nonce, uint32_t out[8])
{
    // What the worker asks before every dispatch, and for the same reason: a
    // kernel that hashes against a table, or against a program compiled from
    // the header, has to be told which one this header wants. Both are no-ops
    // for an algorithm that needs neither -- and one of the words perturbed
    // below is what decides the second, so this cannot be hoisted out.
    if (!kernel.prepare_state(algo.state_key(header)) ||
        !kernel.prepare_program(algo.program_key(header))) {
        fail("the kernel could not prepare itself for this header");
        return false;
    }

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
        fail("asked for nonce %s and the device answered about %s",
             vkminer::nonce_hex(nonce).c_str(),
             vkminer::nonce_hex(found[0].nonce).c_str());
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
    if (!device_digest(kernel, algo, header.data(), answer.nonce, base))
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

    unsigned ignored = 0, wrong = 0, inert = 0;

    for (size_t w = 0; w < words; w++) {
        // The nonce word carries no information -- the dispatch supplies the
        // nonce and the miner zeroes this -- so a kernel is *right* to ignore
        // it. It gets its own check below instead.
        if (w == nonce_word)
            continue;

        // Which bit to flip is the reference's answer rather than this test's.
        // Bit 0 is the usual one and moves the digest for most algorithms, but
        // a header word need not reach it bit for bit: KawPoW's block height
        // selects the inner program by way of a period several blocks long, so
        // its lowest bit is genuinely inert and a kernel producing the same
        // digest under it is correct. Asking the reference for the first bit
        // that does move keeps the assertion at "the device reads this word"
        // instead of "the device reads this bit", and costs one host hash per
        // word wherever bit 0 already works.
        std::vector<uint32_t> probe = header;
        uint32_t want[8];
        unsigned bit = 0;
        for (; bit < 32; bit++) {
            probe[w] = header[w] ^ (1u << bit);   // one bit, never a search
            algo.hash(probe.data(), answer.nonce, want);
            if (std::memcmp(want, base, sizeof base) != 0)
                break;
        }

        // No bit of it reaches the digest at all. That is a statement about the
        // algorithm, not about the device: nothing here can tell a kernel that
        // reads such a word from one that ignores it, so it is reported rather
        // than passed over in silence.
        if (bit == 32) {
            std::printf("     %s: header word %u is inert -- no single bit of "
                        "it moves the reference's digest\n", answer.label,
                        static_cast<unsigned>(w));
            inert++;
            continue;
        }

        uint32_t got[8];
        if (!device_digest(kernel, algo, probe.data(), answer.nonce, got))
            return false;

        if (std::memcmp(got, base, sizeof base) == 0) {
            fail("%s: flipping bit %u of header word %u left the device's "
                 "digest unchanged -- the kernel does not read that word",
                 answer.label, bit, static_cast<unsigned>(w));
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
        if (!device_digest(kernel, algo, header.data(), answer.nonce + 1, got))
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

    // Words actually put to the device: everything but the nonce's, where the
    // header has one at all, less any the reference says nothing reaches.
    const unsigned tested =
        static_cast<unsigned>(words - (nonce_word < words ? 1 : 0)) - inert;

    if (!ignored && !wrong) {
        std::printf("ok   %s: every one of the %u header words changes the "
                    "device's answer, and changes it to the reference's",
                    answer.label, tested);
        if (inert)
            std::printf(" (%u more carry no bit that reaches it)", inert);
        std::printf("\n");
    }
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
    size_t count = algo.known_answers(&answers);

    // An algorithm may have nothing published that this test can use: KawPoW's
    // vectors are answers against the whole of an epoch's table and this hashes
    // against a truncated one, so it withholds them rather than let a wrong
    // table look like a wrong kernel. Manufacture a header there. A vector's
    // worth is that a third party can confirm it, and nothing below asks that
    // of one -- the words are perturbed into headers no chain ever saw on the
    // second dispatch anyway, which is the whole point of the file. What is
    // lost is only the positive control's external witness, and the startup KAT
    // and the host-side KAT both hold that already.
    std::vector<unsigned char> made_header;
    unsigned char made_digest[32];
    vkminer::KnownAnswer made = {};
    if (!count) {
        const size_t words = algo.header_bytes() / 4;
        std::vector<uint32_t> hdr(words);
        for (size_t i = 0; i < words; i++)
            hdr[i] = static_cast<uint32_t>(0x9e3779b9u * (i + 1));
        if (algo.nonce_word() < words)
            hdr[algo.nonce_word()] = 0;   // as run_vector will read it back

        made_header.resize(words * 4);
        for (size_t i = 0; i < words; i++)
            be32enc(made_header.data() + i * 4, hdr[i]);

        made.label = "manufactured";
        made.header = made_header.data();
        made.nonce = 0xdeadbeefu;   // inside a 32-bit nonce field as well
        uint32_t digest[8];
        algo.hash(hdr.data(), made.nonce, digest);
        std::memcpy(made_digest, digest, sizeof made_digest);
        made.digest = made_digest;

        answers = &made;
        count = 1;
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

    // KawPoW is built by hand rather than by name, for the reason the other two
    // KawPoW device tests do it: the registry's version generates a gigabyte of
    // DAG on the device under test, and a run that spent most of itself in a
    // setup pass could fail for two reasons at once. A short host-built table
    // uploaded instead decides neither question by accident -- the line index
    // is taken modulo its length on both sides -- and leaves the hash under
    // test, which is what is being perturbed. Same epoch and same length as
    // those tests use, so a disagreement can be chased in either of them.
    constexpr uint64_t kKawpowLines = 8192;
    std::unique_ptr<vkminer::Algorithm> algo =
        std::strcmp(name, "kawpow") == 0
            ? vkminer::make_progpow_host_dag(vkminer::kawpow::kKawpow, 0, kKawpowLines)
            : vkminer::create_algorithm(name);
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
