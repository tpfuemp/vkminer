// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the blake2s Algorithm, the counterpart to
// sha256d_kat.cpp. Same question: not whether BLAKE2s is right, but whether the
// contract between struct work and the hash holds.
//
// It differs in where the answers are anchored. A Bitcoin block's digest is its
// identity and every explorer prints it; Verge's is not, because
// CBlockHeader::GetHash() returns the scrypt hash whatever mined the block. So
// the anchor here is that each digest clears the nBits its own header declares,
// decoded below from the wire bytes rather than taken on trust from the miner.
// Those targets leave ~39 bits of margin, so two vectors clearing them is a
// 2^-78 coincidence unless the assembly and the algorithm are both right.
//
// The digests come from the algorithm's own table rather than being written out
// again: duplicating them would only check that two copies of an unverifiable
// constant match, where reading the table catches the reference drifting from
// what the self-test and the shader are both measured against.
//
// Everything is compared as bytes, not words -- a word comparison bakes this
// host's endianness in and stops testing the thing the test exists for.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
}

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>

// The inherited C expects the miner to own these. fulltest() reaches for
// opt_debug and applog, so a test that calls verify() needs them defined.
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

// The 256-bit target a header declares about itself, in the word order
// fulltest() compares. Bitcoin's compact encoding, which Verge inherited: the
// top byte is a base-256 exponent and the low three bytes the mantissa, so the
// mantissa's least significant byte lands at byte `exponent - 3`.
//
// Decoded here rather than borrowed from the inherited C on purpose -- this is
// the one value in the test not allowed to come from the code under test.
bool nbits_target(const unsigned char *header, uint32_t target[8])
{
    uint32_t bits = le32dec(header + 72);
    uint32_t mantissa = bits & 0x00ffffffu;
    unsigned exponent = bits >> 24;

    // Neither vector is near these edges. The guard is so that a vector added
    // later with an odd nBits fails loudly rather than silently producing a
    // target no digest can clear, or one every digest clears.
    if (exponent < 4 || exponent > 32 || mantissa == 0)
        return false;

    unsigned char bytes[32] = { 0 };
    for (unsigned i = 0; i < 3; i++)
        bytes[exponent - 3 + i] = static_cast<unsigned char>(mantissa >> (i * 8));

    for (size_t i = 0; i < 8; i++)
        target[i] = le32dec(bytes + i * 4);
    return true;
}

// One vector: hash() must reproduce the digest the algorithm publishes, that
// digest must clear the difficulty the header itself states, and verify() must
// agree with both.
void check(vkminer::Algorithm &algo, const vkminer::KnownAnswer &answer)
{
    // The conversion the rest of the miner does on the way in, done here too
    // rather than hand-writing words that only happen to be right on this host.
    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(answer.header + i * 4);

    // hash() takes the nonce separately, so zeroing word 19 fails a reference
    // that reads it out of the header instead of out of its argument.
    header[19] = 0;

    uint32_t hash[8];
    algo.hash(header, answer.nonce, hash);

    if (std::memcmp(hash, answer.digest, 32) != 0) {
        fail("%s hashed to the wrong digest", answer.label);
        print_bytes("expected", answer.digest);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash));
    }

    // The anchor: the network accepted this block at the difficulty its own
    // header states, so whatever the network computed cleared this target. If
    // what comes out here clears it too, the assembly and the round structure
    // are both right to within 2^-39.
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

    // A target equal to the hash, which the network's hash <= target rule meets
    // exactly. This is what a backend's re-check of a candidate amounts to.
    uint32_t target[8];
    std::memcpy(target, hash, sizeof target);

    if (!algo.verify(header, answer.nonce, target, verified))
        fail("%s: verify() rejected a hash exactly equal to the target",
             answer.label);
    if (std::memcmp(verified, hash, sizeof hash) != 0)
        fail("%s: verify() and hash() disagree about the digest", answer.label);

    // One less than the hash, so the hash no longer meets it. Word 0 is nonzero
    // in both vectors, so the decrement cannot borrow; the guard is so that a
    // vector added later with a zero low word fails loudly instead of quietly
    // turning this into a different test.
    if (target[0] == 0) {
        fail("%s: low digest word is zero, so the decrement below would borrow",
             answer.label);
    } else {
        target[0]--;
        if (algo.verify(header, answer.nonce, target, verified))
            fail("%s: verify() accepted a hash above the target", answer.label);
    }

    // A different nonce must not pass a target the right nonce only just met.
    // At 2^-256 a pass means hash() ignored its nonce, not that it got lucky.
    std::memcpy(target, hash, sizeof target);
    if (algo.verify(header, answer.nonce + 1, target, verified))
        fail("%s: verify() accepted the wrong nonce", answer.label);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("blake2s");
    if (!algo) {
        std::printf("FAIL: the registry has no 'blake2s'\n");
        return 1;
    }

    // The registry key and what the algorithm calls itself are two strings, and
    // the log lines, the usage text and --algo all trust that they match.
    if (std::strcmp(algo->name(), "blake2s") != 0)
        fail("create_algorithm(\"blake2s\") returned something else");
    if (!vkminer::create_algorithm("BLAKE2S"))
        fail("--algo is case sensitive, and should not be");

    // Adding an algorithm must not have made the registry answer to everything.
    if (vkminer::create_algorithm("blake2b"))
        fail("the registry answered to an algorithm it does not have");

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: blake2s publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("blake2s: %zu mined block headers hash, clear their own nBits, "
                "and verify correctly\n", count);
    return 0;
}
