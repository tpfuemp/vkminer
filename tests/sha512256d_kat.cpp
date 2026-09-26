// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the sha512256d Algorithm, in two layers.
//
// First, the primitive against FIPS 180-4's SHA-512/256 vectors, which isolate
// a wrong initial value. The 112-byte vector also covers two-block padding.
//
// Second, as in sha3t_kat.cpp, the contract between struct work and the hash:
// each Radiant block id is the digest of its header, which must also clear the
// header's own nBits.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/sha512.h"
}

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>

// Globals the inherited C expects the miner to define; verify() reaches them.
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
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

void print_bytes(const char *label, const unsigned char *bytes)
{
    std::printf("  %-9s ", label);
    for (int i = 0; i < 32; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// NIST's SHA-512/256 examples: "abc" and the 112-byte two-block message.
const unsigned char kAbcDigest[32] = {
    0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9,
    0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab,
    0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46,
    0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23,
};

const char kLongMessage[] =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

const unsigned char kLongDigest[32] = {
    0x39, 0x28, 0xe1, 0x84, 0xfb, 0x86, 0x90, 0xf8,
    0x40, 0xda, 0x39, 0x88, 0x12, 0x1d, 0x31, 0xbe,
    0x65, 0xcb, 0x9d, 0x3e, 0xf8, 0x3e, 0xe6, 0x14,
    0x6f, 0xea, 0xc8, 0x61, 0xe1, 0x9b, 0x56, 0x3a,
};

void check_primitive()
{
    unsigned char got[32];

    sha512_256_full(got, "abc", 3);
    if (std::memcmp(got, kAbcDigest, 32) != 0) {
        fail("SHA-512/256(\"abc\") is not FIPS 180-4's -- check the IV");
        print_bytes("expected", kAbcDigest);
        print_bytes("got", got);
    }

    static_assert(sizeof kLongMessage - 1 == 112, "the FIPS message is 112 bytes");
    sha512_256_full(got, kLongMessage, sizeof kLongMessage - 1);
    if (std::memcmp(got, kLongDigest, 32) != 0) {
        fail("SHA-512/256 of the 112-byte FIPS message is wrong -- check the "
             "two-block padding");
        print_bytes("expected", kLongDigest);
        print_bytes("got", got);
    }

    // SHA-512 cut to 32 bytes must not pass for SHA-512/256.
    unsigned char wide[64];
    sha512_full(wide, "abc", 3);
    if (std::memcmp(wide, kAbcDigest, 32) == 0)
        fail("SHA-512 truncated agrees with SHA-512/256, so the IV is SHA-512's");
}

// The 256-bit target a header's nBits encodes, in fulltest()'s word order.
// Decoded here on purpose, independent of the code under test.
bool nbits_target(const unsigned char *header, uint32_t target[8])
{
    uint32_t bits = le32dec(header + 72);
    uint32_t mantissa = bits & 0x00ffffffu;
    unsigned exponent = bits >> 24;

    if (exponent < 4 || exponent > 32 || mantissa == 0)
        return false;

    unsigned char bytes[32] = { 0 };
    for (unsigned i = 0; i < 3; i++)
        bytes[exponent - 3 + i] = static_cast<unsigned char>(mantissa >> (i * 8));

    for (size_t i = 0; i < 8; i++)
        target[i] = le32dec(bytes + i * 4);
    return true;
}

// One vector: hash() reproduces the block id, the digest clears the header's
// nBits, and verify() agrees.
void check(vkminer::Algorithm &algo, const vkminer::KnownAnswer &answer)
{
    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(answer.header + i * 4);

    // Zero word 19 so a reference reading the nonce from the header fails.
    header[19] = 0;

    uint32_t hash[8];
    algo.hash(header, answer.nonce, hash);

    if (std::memcmp(hash, answer.digest, 32) != 0) {
        fail("%s hashed to the wrong digest", answer.label);
        print_bytes("expected", answer.digest);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash));
    }

    uint32_t network[8];
    uint32_t verified[8];
    if (!nbits_target(answer.header, network)) {
        fail("%s: nBits does not decode to a usable target", answer.label);
    } else if (!algo.verify(header, answer.nonce, network, verified)) {
        fail("%s: the digest does not clear the header's own nBits",
             answer.label);
        print_bytes("target", reinterpret_cast<const unsigned char *>(network));
        print_bytes("got", reinterpret_cast<const unsigned char *>(verified));
    }

    uint32_t target[8];
    std::memcpy(target, hash, sizeof target);
    if (!algo.verify(header, answer.nonce, target, verified))
        fail("%s: verify() rejected a hash exactly equal to the target",
             answer.label);
    if (std::memcmp(verified, hash, sizeof hash) != 0)
        fail("%s: verify() and hash() disagree about the digest", answer.label);

    if (target[0] == 0) {
        fail("%s: low digest word is zero, so the decrement below would borrow",
             answer.label);
    } else {
        target[0]--;
        if (algo.verify(header, answer.nonce, target, verified))
            fail("%s: verify() accepted a hash above the target", answer.label);
    }

    std::memcpy(target, hash, sizeof target);
    if (algo.verify(header, answer.nonce + 1, target, verified))
        fail("%s: verify() accepted the wrong nonce", answer.label);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    check_primitive();

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("sha512256d");
    if (!algo) {
        std::printf("FAIL: the registry has no 'sha512256d'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "sha512256d") != 0)
        fail("create_algorithm(\"sha512256d\") returned something else");

    // Radiant's genesis nBits is 0x1d00ffff: Bitcoin's difficulty scale.
    if (algo->target_factor() != 1.)
        fail("sha512256d quotes difficulty on the Bitcoin scale, and "
             "target_factor says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: sha512256d publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("sha512256d: SHA-512/256 matches FIPS 180-4, and %zu mined "
                "block headers hash to their published block hash, clear "
                "their own nBits, and verify correctly\n", count);
    return 0;
}
