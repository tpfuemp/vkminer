// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the bmw512 Algorithm: BMW-512 round 2 vectors, then
// DigitalNote headers, each hashing to its block id and clearing its own nBits.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/bmw512.h"
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

// BMW-512 of the empty message (round 2 submission; sphlib agrees).
const unsigned char kEmptyDigest[64] = {
    0x6a, 0x72, 0x56, 0x55, 0xc4, 0x2b, 0xc8, 0xa2,
    0xa2, 0x05, 0x49, 0xdd, 0x5a, 0x23, 0x3a, 0x6a,
    0x2b, 0xeb, 0x01, 0x61, 0x69, 0x75, 0x85, 0x1f,
    0xd1, 0x22, 0x50, 0x4e, 0x60, 0x4b, 0x46, 0xaf,
    0x7d, 0x96, 0x69, 0x7d, 0x0b, 0x63, 0x33, 0xdb,
    0x1d, 0x17, 0x09, 0xd6, 0xdf, 0x32, 0x8d, 0x2a,
    0x6c, 0x78, 0x65, 0x51, 0xb0, 0xcc, 0xe2, 0x25,
    0x5e, 0x8c, 0x73, 0x32, 0xb4, 0x81, 0x9c, 0x0e,
};

// BMW-512 of the bytes 00 01 .. 3f, as sphlib computes it.
const unsigned char kPattern64Digest[64] = {
    0x82, 0x41, 0x68, 0x67, 0x1c, 0x2e, 0x3f, 0x35,
    0xeb, 0xba, 0x82, 0xb6, 0x3b, 0x9e, 0x6c, 0x42,
    0xb8, 0x41, 0x1c, 0xdc, 0xda, 0x10, 0x41, 0x26,
    0x4b, 0xb5, 0xf5, 0x0a, 0xbd, 0x50, 0x7d, 0x18,
    0x27, 0xed, 0xcf, 0xff, 0x05, 0x0f, 0x6c, 0x86,
    0x75, 0xcb, 0x8c, 0xcb, 0xa8, 0x69, 0x9c, 0x84,
    0x3d, 0xcf, 0x5f, 0xb8, 0x1c, 0xca, 0xda, 0xb1,
    0xde, 0xef, 0x0d, 0x9c, 0xf4, 0x77, 0x02, 0x57,
};

void check_vector(const char *label, const unsigned char *msg, size_t len,
                  const unsigned char expected[64])
{
    unsigned char digest[64];
    bmw512_full(digest, msg, len);
    if (std::memcmp(digest, expected, 64) != 0) {
        fail("BMW-512 of %s", label);
        print_bytes("expected", expected, 64);
        print_bytes("got", digest, 64);
    }
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

// The kernel's job words must not read the nonce, and must read the rest of
// the header. Whether they are the right words only the kernels can show:
// --self-test and diff_test run them against bmw512_full().
void check_precompute(const vkminer::KnownAnswer &answer)
{
    unsigned char data[80];
    std::memcpy(data, answer.header, sizeof data);

    uint64_t base[35], other[35];
    bmw512_80_precompute(base, data);

    for (unsigned flip : { 0x00000001u, 0x80000000u, 0xffffffffu }) {
        le32enc(data + 76, le32dec(answer.header + 76) ^ flip);
        bmw512_80_precompute(other, data);
        if (std::memcmp(base, other, sizeof base) != 0)
            fail("%s: the job words change with nonce bits %08x",
                 answer.label, flip);
    }

    // Nor with nBits, the other half of M[9]: the kernel adds all of that word
    // back, from the push block, so the job leaves all of it out.
    std::memcpy(data, answer.header, sizeof data);
    data[72] ^= 1;
    bmw512_80_precompute(other, data);
    if (std::memcmp(base, other, sizeof base) != 0)
        fail("%s: the job words change with nBits", answer.label);

    // Byte 71 is the last of M[8].
    for (size_t at : { size_t(0), size_t(71) }) {
        std::memcpy(data, answer.header, sizeof data);
        data[at] ^= 1;
        bmw512_80_precompute(other, data);
        if (std::memcmp(base, other, sizeof base) == 0)
            fail("%s: the job words ignore header byte %zu",
                 answer.label, at);
    }
}

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

    unsigned char once[64], twice[64];
    bmw512_full(once, answer.header, 80);
    bmw512_full(twice, once, sizeof once);
    if (std::memcmp(twice, answer.digest, 32) == 0)
        fail("%s: BMW-512 twice gives the digest", answer.label);

    uint32_t network[8];
    uint32_t verified[8];
    if (!nbits_target(answer.header, network)) {
        fail("%s: nBits does not decode to a usable target", answer.label);
    } else if (!algo.verify(header, answer.nonce, network, verified)) {
        fail("%s: the digest does not clear the header's own nBits",
             answer.label);
        print_bytes("target",
                    reinterpret_cast<const unsigned char *>(network), 32);
        print_bytes("got",
                    reinterpret_cast<const unsigned char *>(verified), 32);
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

    check_precompute(answer);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    unsigned char pattern[64];
    for (size_t i = 0; i < sizeof pattern; i++)
        pattern[i] = static_cast<unsigned char>(i);
    check_vector("the empty message", nullptr, 0, kEmptyDigest);
    check_vector("00 01 .. 3f", pattern, sizeof pattern, kPattern64Digest);

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("bmw512");
    if (!algo) {
        std::printf("FAIL: the registry has no 'bmw512'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "bmw512") != 0)
        fail("create_algorithm(\"bmw512\") returned something else");

    if (algo->target_factor() != 256.)
        fail("bmw512 pools quote difficulty 256 times easier, and "
             "target_factor says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: bmw512 publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("bmw512: BMW-512 round 2 vectors pass; %zu DigitalNote headers "
                "hash to their ids, clear their own nBits, and verify "
                "correctly\n", count);
    return 0;
}
