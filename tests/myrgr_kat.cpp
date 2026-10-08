// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the myr-gr Algorithm. Groestl-512 itself is
// groestl_kat's.
//
// 1. Each header's version marks a non-merge-mined Myriadcoin groestl block.
// 2. Each digest is reproduced and clears the header's own nBits; Groestl-512
//    alone and SHA-256 of only 32 Groestl bytes do not.
// 3. Bitcoin's difficulty scale and a SHA-256d coinbase.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/groestl512.h"
#include "core/sha256.h"
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

// Myriadcoin's version bits: the algorithm in 9..11, auxpow in 8.
const uint32_t kVersionAlgoMask = 7u << 9;
const uint32_t kVersionGroestl = 2u << 9;
const uint32_t kVersionAuxpow = 1u << 8;

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

// Digest in memory order at or below a target in fulltest()'s word order.
bool clears(const unsigned char *digest, const uint32_t target[8])
{
    for (int i = 7; i >= 0; i--) {
        uint32_t word = le32dec(digest + i * 4);
        if (word != target[i])
            return word < target[i];
    }
    return true;
}

// One vector: a groestl block, hash() reproduces the digest, it clears nBits,
// verify() agrees, and neither near miss clears it.
void check(vkminer::Algorithm &algo, const vkminer::KnownAnswer &answer)
{
    uint32_t version = le32dec(answer.header);
    if ((version & kVersionAlgoMask) != kVersionGroestl)
        fail("%s: version %08x is not a groestl block's", answer.label, version);
    if (version & kVersionAuxpow)
        fail("%s: version %08x is merge-mined, so its proof of work is the "
             "parent's", answer.label, version);

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

    uint32_t network[8];
    uint32_t verified[8];
    if (!nbits_target(answer.header, network)) {
        fail("%s: nBits does not decode to a usable target", answer.label);
        return;
    }
    if (!algo.verify(header, answer.nonce, network, verified)) {
        fail("%s: the digest does not clear the header's own nBits",
             answer.label);
        print_bytes("target", reinterpret_cast<const unsigned char *>(network), 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(verified), 32);
    }

    unsigned char groestl[64], truncated[32];
    groestl512_full(groestl, answer.header, 80);
    if (clears(groestl, network))
        fail("%s: Groestl-512 alone clears nBits, so the SHA-256 proves nothing",
             answer.label);
    sha256_full(truncated, groestl, 32);
    if (clears(truncated, network))
        fail("%s: SHA-256 of 32 Groestl bytes clears nBits too, so the vector "
             "cannot tell 32 from 64", answer.label);

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

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("myr-gr");
    if (!algo) {
        std::printf("FAIL: the registry has no 'myr-gr'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "myr-gr") != 0)
        fail("create_algorithm(\"myr-gr\") returned something else");

    // Myriadcoin's GetDifficulty() uses Bitcoin's scale for every algorithm.
    if (algo->target_factor() != 1.)
        fail("myr-gr quotes difficulty on the Bitcoin scale, and "
             "target_factor says %g", algo->target_factor());

    // Myriadcoin's txid is Bitcoin's SHA-256d; only groestl's chain differs.
    if (algo->coinbase_sha256())
        fail("myr-gr's coinbase txid is SHA-256d, and coinbase_sha256() "
             "says a single SHA-256");

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: myr-gr publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("myr-gr: %zu Myriadcoin groestl headers hash to digests that "
                "clear their own nBits, where Groestl alone and a 32-byte "
                "SHA-256 do not, and verify correctly\n", count);
    return 0;
}
