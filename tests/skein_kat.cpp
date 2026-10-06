// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the skein Algorithm, in three layers.
//
// 1. Skein-512-512 against the specification's vectors, version 1.3 (1.2 used
//    different rotation constants).
// 2. The IV the kernels carry, against the configuration block computed here.
// 3. Each header's digest is reproduced and clears the header's own nBits.

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

void print_bytes(const char *label, const unsigned char *bytes, size_t n)
{
    std::printf("  %-9s ", label);
    for (size_t i = 0; i < n; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// Skein 1.3, Skein-512-512 of the empty message.
const unsigned char kEmptyDigest[64] = {
    0xbc, 0x5b, 0x4c, 0x50, 0x92, 0x55, 0x19, 0xc2,
    0x90, 0xcc, 0x63, 0x42, 0x77, 0xae, 0x3d, 0x62,
    0x57, 0x21, 0x23, 0x95, 0xcb, 0xa7, 0x33, 0xbb,
    0xad, 0x37, 0xa4, 0xaf, 0x0f, 0xa0, 0x6a, 0xf4,
    0x1f, 0xca, 0x79, 0x03, 0xd0, 0x65, 0x64, 0xfe,
    0xa7, 0xa2, 0xd3, 0x73, 0x0d, 0xbd, 0xb8, 0x0c,
    0x1f, 0x85, 0x56, 0x2d, 0xfc, 0xc0, 0x70, 0x33,
    0x4e, 0xa4, 0xd1, 0xd9, 0xe7, 0x2c, 0xba, 0x7a,
};

// Skein 1.3, Skein-512-512 of the one byte ff.
const unsigned char kOneByteDigest[64] = {
    0x71, 0xb7, 0xbc, 0xe6, 0xfe, 0x64, 0x52, 0x22,
    0x7b, 0x9c, 0xed, 0x60, 0x14, 0x24, 0x9e, 0x5b,
    0xf9, 0xa9, 0x75, 0x4c, 0x3a, 0xd6, 0x18, 0xcc,
    0xc4, 0xe0, 0xaa, 0xe1, 0x6b, 0x31, 0x6c, 0xc8,
    0xca, 0x69, 0x8d, 0x86, 0x43, 0x07, 0xed, 0x3e,
    0x80, 0xb6, 0xef, 0x15, 0x70, 0x81, 0x2a, 0xc5,
    0x27, 0x2d, 0xc4, 0x09, 0xb5, 0xa0, 0x12, 0xdf,
    0x2a, 0x57, 0x91, 0x02, 0xf3, 0x40, 0x61, 0x7a,
};

// Skein 1.3, Skein-512-512 of the 64 bytes ff fe .. c0.
const unsigned char kOneBlockDigest[64] = {
    0x45, 0x86, 0x3b, 0xa3, 0xbe, 0x0c, 0x4d, 0xfc,
    0x27, 0xe7, 0x5d, 0x35, 0x84, 0x96, 0xf4, 0xac,
    0x9a, 0x73, 0x6a, 0x50, 0x5d, 0x93, 0x13, 0xb4,
    0x2b, 0x2f, 0x5e, 0xad, 0xa7, 0x9f, 0xc1, 0x7f,
    0x63, 0x86, 0x1e, 0x94, 0x7a, 0xfb, 0x1d, 0x05,
    0x6a, 0xa1, 0x99, 0x57, 0x5a, 0xd3, 0xf8, 0xc9,
    0xa3, 0xcc, 0x17, 0x80, 0xb5, 0xe5, 0xfa, 0x4c,
    0xae, 0x05, 0x0e, 0x98, 0x98, 0x76, 0x62, 0x5b,
};

// Skein 1.3, Skein-512-512 of the 128 bytes ff fe .. 80.
const unsigned char kTwoBlockDigest[64] = {
    0x91, 0xcc, 0xa5, 0x10, 0xc2, 0x63, 0xc4, 0xdd,
    0xd0, 0x10, 0x53, 0x0a, 0x33, 0x07, 0x33, 0x09,
    0x62, 0x86, 0x31, 0xf3, 0x08, 0x74, 0x7e, 0x1b,
    0xcb, 0xaa, 0x90, 0xe4, 0x51, 0xca, 0xb9, 0x2e,
    0x51, 0x88, 0x08, 0x7a, 0xf4, 0x18, 0x87, 0x73,
    0xa3, 0x32, 0x30, 0x3e, 0x66, 0x67, 0xa7, 0xa2,
    0x10, 0x85, 0x6f, 0x74, 0x21, 0x39, 0x00, 0x00,
    0x71, 0xf4, 0x8e, 0x8b, 0xa2, 0xa5, 0xad, 0xb7,
};

// The chaining value after the configuration block for a 512-bit digest: the
// same eight words shaders/common/skein512.glsl carries as
// skein512_512_iv_words.
const uint64_t kIv[8] = {
    UINT64_C(0x4903adff749c51ce), UINT64_C(0x0d95de399746df03),
    UINT64_C(0x8fd1934127c79bce), UINT64_C(0x9a255629ff352cb1),
    UINT64_C(0x5db62599df6ca7b0), UINT64_C(0xeabe394ca9d5c3f4),
    UINT64_C(0x991112c71a75b523), UINT64_C(0xae18a40b660fcc33),
};

void check_primitive()
{
    unsigned char message[128];
    for (size_t i = 0; i < sizeof message; i++)
        message[i] = static_cast<unsigned char>(0xff - i);

    struct {
        const char *what;
        size_t len;
        const unsigned char *digest;
    } const vectors[] = {
        { "the empty message",              0,   kEmptyDigest    },
        { "one byte ff",                    1,   kOneByteDigest  },
        { "one block, ff..c0",              64,  kOneBlockDigest },
        { "two blocks, ff..80",             128, kTwoBlockDigest },
    };

    for (const auto &v : vectors) {
        unsigned char got[64];
        skein512_full(got, message, v.len);
        if (std::memcmp(got, v.digest, 64) != 0) {
            fail("Skein-512-512 of %s is not the specification's -- check the "
                 "rotation constants (1.2 against 1.3) and the tweak", v.what);
            print_bytes("expected", v.digest, 64);
            print_bytes("got", got, 64);
        }
    }

    uint64_t iv[8];
    skein512_iv(iv);
    for (int i = 0; i < 8; i++) {
        if (iv[i] != kIv[i]) {
            fail("the configuration block computes to an IV word %d of "
                 "%016llx, and the kernels carry %016llx", i,
                 static_cast<unsigned long long>(iv[i]),
                 static_cast<unsigned long long>(kIv[i]));
        }
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

// One vector: hash() reproduces the digest, the digest clears the header's
// nBits, verify() agrees -- and Skein without the SHA-256 does not.
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

    unsigned char skein_only[64];
    skein512_full(skein_only, answer.header, 80);
    if (std::memcmp(skein_only, answer.digest, 32) == 0)
        fail("%s: Skein alone gives the digest, so the SHA-256 is missing",
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
        vkminer::create_algorithm("skein");
    if (!algo) {
        std::printf("FAIL: the registry has no 'skein'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "skein") != 0)
        fail("create_algorithm(\"skein\") returned something else");

    // Auroracoin's GetDifficulty() divides by Bitcoin's 0x1d00ffff for every
    // algorithm, skein included: Bitcoin's difficulty scale.
    if (algo->target_factor() != 1.)
        fail("skein quotes difficulty on the Bitcoin scale, and "
             "target_factor says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: skein publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("skein: Skein-512-512 matches the 1.3 vectors, the configuration "
                "block computes to the kernels' IV, and %zu block headers hash "
                "to their digest, clear their own nBits, and verify correctly\n",
                count);
    return 0;
}
