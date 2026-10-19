// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the qubit Algorithm, in three layers.
//
// 1. Each of the five primitives alone, against sph's C as ccminer ships it
//    (an implementation independent of src/core/), at three lengths: empty,
//    64 bytes (what every stage after the first hashes) and 120 bytes (which
//    pushes SHAvite's and ECHO's length fields into a second block). The
//    message is the bytes 0, 1, 2, ... All five are the round 2 SHA-3
//    submissions: Luffa v2, CubeHash16/32, tweaked SHAvite-3, tweaked SIMD and
//    ECHO. A round 1 constant or rotation fails here, not in the chain.
// 2. The chain over the header 0x00..0x4f, stage by stage: the five 64-byte
//    states ccminer's qubithash() passes between stages. A wrong stage shows
//    up as the first state that differs, not as one wrong digest.
// 3. The Algorithm: hash() reproduces each vector's digest from header words,
//    verify() agrees, and no single stage gives the digest. Six of the
//    vectors are Auroracoin and DigiByte qubit blocks. Both chains are
//    multi-algorithm, so a block id is SHA-256d and says nothing about qubit;
//    each is anchored on its own nBits instead.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/cubehash512.h"
#include "core/echo512.h"
#include "core/luffa512.h"
#include "core/shavite512.h"
#include "core/simd512.h"
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

// 64 bytes from 128 hex digits.
void unhex64(const char *hex, unsigned char out[64])
{
    for (size_t i = 0; i < 64; i++) {
        unsigned v = 0;
        std::sscanf(hex + 2 * i, "%2x", &v);
        out[i] = static_cast<unsigned char>(v);
    }
}

typedef void (*HashFn)(void *, const void *, size_t);

struct PrimitiveVector {
    const char *name;
    HashFn fn;
    size_t len;
    const char *digest;
};

const PrimitiveVector kPrimitives[] = {
    { "Luffa-512", luffa512_full, 0,
      "6e7de4501189b3ca58f3ac114916654bbcd4922024b4cc1cd764acfe8ab4b780"
      "5df133eab345ffdb1c414564c924f48e0a301824e2ac4c34bd4efde2e43da90e" },
    { "Luffa-512", luffa512_full, 64,
      "a7fa7b1f6efdeebb4eb2d53b28412a4962fa7236c775a0472e97af3035d0cebb"
      "794c97465bc89e9d26983a7b0a9283cc716dee3a6083817030dda4a4625f5d00" },
    { "Luffa-512", luffa512_full, 120,
      "3da50d173bbd94ac0c9d9375ee386e463aefe484a3ef26d68d22f72d97fa5faf"
      "8f52baa89bd1b57e91bc0f7ad0446abd98e8430ac2ca1c6f07db2ca81d20a270" },
    { "CubeHash-512", cubehash512_full, 0,
      "4a1d00bbcfcb5a9562fb981e7f7db3350fe2658639d948b9d57452c22328bb32"
      "f468b072208450bad5ee178271408be0b16e5633ac8a1e3cf9864cfbfc8e043a" },
    { "CubeHash-512", cubehash512_full, 64,
      "501336304d235cf9825da6f26623f20cf338c2efa1eac0f668dc1d99a1f67bf6"
      "17453a1c861c9628f7b98dd5ca50baf6d75299f13fa43d28d39b40314161135f" },
    { "CubeHash-512", cubehash512_full, 120,
      "aa423bfd246ae6c924c2a2f9518e0aaea293d9b23543db6ec2c6f0af3fb96adb"
      "b3b986213141d3ce0e1dfabe8ff0a6306df294208a391c05583979e2d504081d" },
    { "SHAvite-512", shavite512_full, 0,
      "a485c1b2578459d1efc5dddd840bb0b4a650ac82fe68f58c4442ccda747da006"
      "b2d1dc6b4a4eb7d84ff91e1f466fef429d259acd995dddcad16fa545c7a6e5ba" },
    { "SHAvite-512", shavite512_full, 64,
      "4b53734538b113c1637104887e9f2150fa4ad9ec70552d8ed62f0134a47a2f4e"
      "8134b2366932983b4127cbcba59cda04bf6d0005b5ba04dea92879f15e80a28a" },
    { "SHAvite-512", shavite512_full, 120,
      "d1e7be8e066ccefbf620efa8f00458ba350fc4bb57bf16ec87daf8de56a45c57"
      "230186580d29522edde589d1dff4e36f9f4da38cac7684ad58b2038b37d92677" },
    { "SIMD-512", simd512_full, 0,
      "51a5af7e243cd9a5989f7792c880c4c3168c3d60c4518725fe5757d1f7a69c63"
      "66977eaba7905ce2da5d7cfd07773725f0935b55f3efb954996689a49b6d29e0" },
    { "SIMD-512", simd512_full, 64,
      "c09546e438b49f5cd6bd2b51581ad381c14b6d543efc00c193ee94dca4d58b90"
      "0c5315985a5eac4571c2141cc995c3bc0233aed662094f3fd2176a9c05bfb4e4" },
    { "SIMD-512", simd512_full, 120,
      "012ea2e06e6a8131652934aa96718d95c93d38f5f84183a864911e5a14e810c6"
      "05f27193ada5fb27386bd21b5f4a5b79da1ef64608a73779a128be08d9ec0653" },
    { "ECHO-512", echo512_full, 0,
      "158f58cc79d300a9aa292515049275d051a28ab931726d0ec44bdd9faef4a702"
      "c36db9e7922fff077402236465833c5cc76af4efc352b4b44c7fa15aa0ef234e" },
    { "ECHO-512", echo512_full, 64,
      "2f7a64cec7e07c9d791f902b838e9a776c03da43ef8858e89c16bbfa7eff641d"
      "5e309d9a51e13177cbb86fb1021070c64763fa93b39824dafd773154cf2ec058" },
    { "ECHO-512", echo512_full, 120,
      "8482f2574bba5092b24b5d8797b7a240d9688a8dbe8d423254ce522b8683d276"
      "53f5924eac5ed95b40e8fa30389dc15f7ba5b0fd65edb6dcf3e73cd41b4cb62f" },
};

void check_primitives()
{
    unsigned char msg[120];
    for (size_t i = 0; i < sizeof msg; i++)
        msg[i] = static_cast<unsigned char>(i);

    for (const PrimitiveVector &v : kPrimitives) {
        unsigned char want[64], got[64];
        unhex64(v.digest, want);
        v.fn(got, msg, v.len);
        if (std::memcmp(got, want, 64) != 0) {
            fail("%s of %zu bytes is not sph's", v.name, v.len);
            print_bytes("expected", want, 64);
            print_bytes("got", got, 64);
        }
    }
}

// The state after each stage, ccminer's qubithash() on the header 0x00..0x4f.
const char *const kChain[5] = {
    "5224f8bc8335d5ea30e9aaa415eafb14b49f13921b5aaa085b5c9eb2ba4e6805"
    "dfb17b7816b24b027c8c8b4a1b4efbde2da2359cc7907e348fb1c8e547d52f24",
    "0c2ae3fddede6f6d217a14bbb8b15e8f48c5c93a40d920ecec4aaa2461bb4a5e"
    "2cadbc32f55d331716d28cbfb5afacd95807b66c2c9cb2b4486bbf5f10c73d07",
    "99c1424254036c187399fe20e0bf845e52e3970faa08c3118cd1baae6a2f8a32"
    "fde998385885ca0a702a4a8c536f49458a10d2fffc5b37ca1141f1798d71cfe8",
    "a23cd0804a3a61a17cf5d294d869902dfc94461bf2c442679042f9fff840b8d5"
    "72758e0e5f42995e0038ac2f16a351d99ff1dd6b031826e0cd47a95bdbf7a6f6",
    "5f445fc9277a5af9e10c6d580bcec9e801a241e75e9734ce2acd3143db177c15"
    "8a4be4f44d1b167f7ee650b2ead3f0236952d754a2e72f6235701d4901244084",
};

void check_chain()
{
    static const char *const kStage[5] = {
        "Luffa", "CubeHash", "SHAvite", "SIMD", "ECHO" };

    unsigned char header[80];
    for (size_t i = 0; i < sizeof header; i++)
        header[i] = static_cast<unsigned char>(i);

    unsigned char s[64], t[64];
    for (size_t k = 0; k < 5; k++) {
        switch (k) {
        case 0: luffa512_full(t, header, sizeof header); break;
        case 1: cubehash512_full(t, s, sizeof s); break;
        case 2: shavite512_full(t, s, sizeof s); break;
        case 3: simd512_full(t, s, sizeof s); break;
        default: echo512_full(t, s, sizeof s); break;
        }

        unsigned char want[64];
        unhex64(kChain[k], want);
        if (std::memcmp(t, want, 64) != 0) {
            fail("the chain first differs after stage %zu, %s", k + 1,
                 kStage[k]);
            print_bytes("expected", want, 64);
            print_bytes("got", t, 64);
            return;
        }
        std::memcpy(s, t, sizeof s);
    }
}

// The 256-bit target a header's nBits encodes, in fulltest()'s word order, or
// false where the field is not a real one (the counting header's). Decoded here
// on purpose, independent of the code under test.
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

// Chain blocks whose digest cleared their own nBits.
int anchored = 0;

// hash() reproduces the digest, verify() agrees, a chain block's digest clears
// its own nBits, and no stage alone gives it.
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

    HashFn fns[5] = { luffa512_full, cubehash512_full, shavite512_full,
                      simd512_full, echo512_full };
    for (HashFn fn : fns) {
        unsigned char once[64];
        fn(once, answer.header, 80);
        if (std::memcmp(once, answer.digest, 32) == 0)
            fail("%s: one stage alone gives the digest", answer.label);
    }

    uint32_t target[8];
    uint32_t verified[8];

    // A qubit block's version carries 0x800 in the algorithm bits.
    uint32_t network[8];
    if (nbits_target(answer.header, network)) {
        if ((le32dec(answer.header) & 0xf00u) != 0x800u)
            fail("%s: nVersion does not mark a qubit block", answer.label);
        if (!algo.verify(header, answer.nonce, network, verified)) {
            fail("%s: the digest does not clear the header's own nBits",
                 answer.label);
            print_bytes("target", reinterpret_cast<const unsigned char *>(network), 32);
            print_bytes("got", reinterpret_cast<const unsigned char *>(verified), 32);
        } else {
            anchored++;
        }
    }

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

    check_primitives();
    check_chain();

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("qubit");
    if (!algo) {
        std::printf("FAIL: the registry has no 'qubit'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "qubit") != 0)
        fail("create_algorithm(\"qubit\") returned something else");

    // yiimp's algorithm table: qubit's difficulty multiplier is 1.
    if (algo->target_factor() != 1.)
        fail("qubit quotes difficulty on the Bitcoin scale, and target_factor "
             "says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: qubit publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (anchored < 6)
        fail("only %d chain block(s) clear their own nBits; six are wanted",
             anchored);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("qubit: %zu primitive vectors and the five chain states match "
                "sph, %zu header(s) hash and verify correctly, and %d "
                "chain block(s) clear their own nBits\n",
                sizeof kPrimitives / sizeof kPrimitives[0], count, anchored);
    return 0;
}
