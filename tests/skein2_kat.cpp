// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the skein2 Algorithm. Skein-512-512 itself is
// skein_kat's; this checks the composition: each Woodcoin header's digest is
// reproduced, clears the header's own nBits, and is not what one Skein, or
// skein's Skein-then-SHA-256, gives.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/skein512.h"
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

void check(vkminer::Algorithm &algo, vkminer::Algorithm &skein,
           const vkminer::KnownAnswer &answer)
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

    unsigned char once[64];
    skein512_full(once, answer.header, 80);
    if (std::memcmp(once, answer.digest, 32) == 0)
        fail("%s: one Skein gives the digest, so the second is missing",
             answer.label);

    uint32_t with_sha[8];
    skein.hash(header, answer.nonce, with_sha);
    if (std::memcmp(with_sha, answer.digest, 32) == 0)
        fail("%s: skein's Skein-then-SHA-256 gives the digest", answer.label);

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
        vkminer::create_algorithm("skein2");
    std::unique_ptr<vkminer::Algorithm> skein =
        vkminer::create_algorithm("skein");
    if (!algo || !skein) {
        std::printf("FAIL: the registry has no 'skein2' or no 'skein'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "skein2") != 0)
        fail("create_algorithm(\"skein2\") returned something else");

    // Woodcoin's GetDifficulty() divides by Bitcoin's 0x1d00ffff.
    if (algo->target_factor() != 1.)
        fail("skein2 quotes difficulty on the Bitcoin scale, and "
             "target_factor says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: skein2 publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, *skein, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("skein2: %zu Woodcoin headers hash to their digest, clear "
                "their own nBits, and verify correctly\n", count);
    return 0;
}
