// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the groestl Algorithm, in three layers.
//
// 1. Groestl-512 against the round 3 submission's vector (round 1 had other
//    round constants and ShiftBytes), and the S-box against FIPS 197.
// 2. Each Groestlcoin block id is reproduced and clears its own nBits.
// 3. The stratum settings: difficulty 256 times Bitcoin's scale, and a coinbase
//    txid that is one SHA-256.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/groestl512.h"
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

void print_bytes(const char *label, const unsigned char *bytes, size_t n)
{
    std::printf("  %-9s ", label);
    for (size_t i = 0; i < n; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// Groestl round 3, Groestl-512 of the empty message, from the submission.
const unsigned char kEmptyDigest[64] = {
    0x6d, 0x3a, 0xd2, 0x9d, 0x27, 0x91, 0x10, 0xee,
    0xf3, 0xad, 0xbd, 0x66, 0xde, 0x2a, 0x03, 0x45,
    0xa7, 0x7b, 0xae, 0xde, 0x15, 0x57, 0xf5, 0xd0,
    0x99, 0xfc, 0xe0, 0xc0, 0x3d, 0x6d, 0xc2, 0xba,
    0x8e, 0x6d, 0x4a, 0x66, 0x33, 0xdf, 0xbd, 0x66,
    0x05, 0x3c, 0x20, 0xfa, 0xa8, 0x7d, 0x1a, 0x11,
    0xf3, 0x9a, 0x7f, 0xbe, 0x4a, 0x6c, 0x2f, 0x00,
    0x98, 0x01, 0x37, 0x03, 0x08, 0xfc, 0x4a, 0xd8,
};

void check_primitive()
{
    unsigned char got[64];

    groestl512_full(got, "", 0);
    if (std::memcmp(got, kEmptyDigest, 64) != 0) {
        fail("Groestl-512 of the empty message is not the submission's -- check "
             "the round constants and ShiftBytes (round 1 against round 3)");
        print_bytes("expected", kEmptyDigest, 64);
        print_bytes("got", got, 64);
    }

    // FIPS 197's S-box, spot values.
    if (groestl512_sbox(0x00) != 0x63 || groestl512_sbox(0x01) != 0x7c
        || groestl512_sbox(0x53) != 0xed || groestl512_sbox(0xff) != 0x16)
        fail("the S-box does not match FIPS 197");
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

// One vector: hash() reproduces the digest, the digest clears the header's
// nBits, verify() agrees -- and one Groestl-512 alone does not.
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
        print_bytes("expected", answer.digest, 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash), 32);
    }

    unsigned char once[64];
    groestl512_full(once, answer.header, 80);
    if (std::memcmp(once, answer.digest, 32) == 0)
        fail("%s: one Groestl-512 gives the digest, so the second is missing",
             answer.label);

    uint32_t network[8];
    uint32_t verified[8];
    if (!nbits_target(answer.header, network)) {
        fail("%s: nBits does not decode to a usable target", answer.label);
    } else if (!algo.verify(header, answer.nonce, network, verified)) {
        fail("%s: the digest does not clear the header's own nBits",
             answer.label);
        print_bytes("target", reinterpret_cast<const unsigned char *>(network), 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(verified), 32);
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
        vkminer::create_algorithm("groestl");
    if (!algo) {
        std::printf("FAIL: the registry has no 'groestl'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "groestl") != 0)
        fail("create_algorithm(\"groestl\") returned something else");

    // yiimp's algorithm table: groestl's difficulty multiplier is 0x100.
    if (algo->target_factor() != 256.)
        fail("groestl quotes difficulty 256 times the Bitcoin scale, and "
             "target_factor says %g", algo->target_factor());

    // Groestlcoin's txid is one SHA-256 (its HashWriter drops the second).
    if (!algo->coinbase_sha256())
        fail("groestl's coinbase txid is a single SHA-256, and "
             "coinbase_sha256() says otherwise");

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: groestl publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("groestl: Groestl-512 matches the round 3 vector, and %zu "
                "Groestlcoin headers hash to their block id, clear their own "
                "nBits, and verify correctly\n", count);
    return 0;
}
