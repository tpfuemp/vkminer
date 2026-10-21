// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the x13 Algorithm, in three layers.
//
// 1. Hamsi-512 and Fugue-512 (round 2) against sph's independent C, over the
//    bytes 0, 1, 2, ... at lengths covering every partial block of both.
// 2. The thirteen 64-byte states of sph's x13 over the header 0x00..0x4f, so
//    a wrong stage shows up as the first state that differs.
// 3. The Algorithm: hash() and verify() reproduce each vector, no single stage
//    gives the digest, and the six chain blocks clear their own nBits.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/blake512.h"
#include "core/bmw512.h"
#include "core/cubehash512.h"
#include "core/echo512.h"
#include "core/fugue512.h"
#include "core/groestl512.h"
#include "core/hamsi512.h"
#include "core/jh512.h"
#include "core/keccak512.h"
#include "core/luffa512.h"
#include "core/shavite512.h"
#include "core/simd512.h"
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
    { "Hamsi-512", hamsi512_full, 0,
      "5cd7436a91e27fc809d7015c3407540633dab391127113ce6ba360f0c1e35f40"
      "4510834a551610d6e871e75651ea381a8ba628af1dcf2b2be13af2eb6247290f" },
    { "Hamsi-512", hamsi512_full, 1,
      "cf85a498ab91e4c811f40bec54dbe33777ab146ac800cfd449ac01f06c524293"
      "46ad199cc6aa52fb7bb0ade5ee8ef445c623bd31ee6f4512d176e8aa8d238327" },
    { "Hamsi-512", hamsi512_full, 3,
      "9c69c1f6fcc5a3a39d6ed8940f96cd6a63b8e96da4e746437fa36f912e6867a0"
      "2d82cce800665d475211b63d4183ec39a61e77890006f9232423501b20e28494" },
    { "Hamsi-512", hamsi512_full, 4,
      "e0dc5077e427e3d8aed0df9f4fe271d4703f46acdd716d0be020493a7bcb12d2"
      "3d6a7792a0ba0572161a0b5fa8d162534a789312d2c5575c8d34ccc88a13f075" },
    { "Hamsi-512", hamsi512_full, 7,
      "684d44aa1383c91dc7db0b944f5dc897fa6e59dda503a88c8975f5a6b7a1f8bf"
      "4fee028167fc8b98cd75d714e84f8857d088c359bf61f97fe0c13c0b63a517cf" },
    { "Hamsi-512", hamsi512_full, 8,
      "b76a1a968d04644bd1e1a34fd168f60020c3a8cd88d6b33da16e964314a52efb"
      "4548c99b2d40d6c02e922477ccecead25228d2cf94e9dc2eb8b984d34ef9c90c" },
    { "Hamsi-512", hamsi512_full, 64,
      "f8c6d6ab542ce32043e06a04a37ee4116652adc877b360dc1232e3f095b29495"
      "60536b795b189b393b3c4459dec7cfb0eab0030d6190770de849381232e816b4" },
    { "Hamsi-512", hamsi512_full, 80,
      "ddc76097ae674238c6552aa64f2fdf7610794a3aa4ea1bb91121e1beb90bcce9"
      "e6276c6e838b9c5726685fe5cee3c5ad3b5b960b7b0a6c87c49c4bd6d55a0f27" },
    { "Hamsi-512", hamsi512_full, 120,
      "57bea8aa729850e4300fc51b60d52745d73ba7731b8d513777d25ecc82af02bc"
      "af1e81db76646d64e9c08f52da392f46d5e595cc64ea942231ae2f7d266e115e" },
    { "Hamsi-512", hamsi512_full, 144,
      "a014195586e7ac41b202eb8ad6aa27d6f46ea0a5719ecac2c5d1d23eb8f517b5"
      "737ef62e438d3d496a8204d63d4ded92ebf64cefd600104b828e7c17504b8802" },
    { "Hamsi-512", hamsi512_full, 200,
      "48d8cf806000b77d956b1e0a0b69c5848b32fbbfc2604eb5deb80895aec7cce2"
      "1bdb58283441939009b059b3ec3b81fe7f6a4124e757a8c7205b98e2434cda66" },
    { "Fugue-512", fugue512_full, 0,
      "3124f0cbb5a1c2fb3ce747ada63ed2ab3bcd74795cef2b0e805d5319fcc360b4"
      "617b6a7eb631d66f6d106ed0724b56fa8c1110f9b8df1c6898e7ca3c2dfccf79" },
    { "Fugue-512", fugue512_full, 1,
      "a824b9966cce3ea0935cb3a39e1a1a29d49df02f50a0dbd5e07afb1408cd605b"
      "208b833cd2fd46d8f1ea489e33df305ba09c7e448e5bc59c260049d58514e442" },
    { "Fugue-512", fugue512_full, 3,
      "dcbedc717e7682f4bc699e1d441ec99aa4d40957a8f8330ed352124ab099a30e"
      "4ed43f2252c1fb69e85ce7769e60a20811fdef29809a0e4f29e7455f990885e1" },
    { "Fugue-512", fugue512_full, 4,
      "fa60d44cb02f1912a26527c3682c73696e67b25efdb29aedc5a66f130d88ed73"
      "eca52db39ea62600d32ea8b0236b9883931c877fd5d13a3157385d3f7d7fa2c6" },
    { "Fugue-512", fugue512_full, 7,
      "dae25819c5127b866a490bd105b6ba664073c7fcc156e96d5cb20ec1c92dd8b6"
      "c840263470c65ad334e9d3320e0ee49dc9e40a915510e13f382079e44c6a969f" },
    { "Fugue-512", fugue512_full, 8,
      "98ec37194d18a2998e397709827e0956d712dc3bd89f8b01598f16a18fbb65af"
      "bd28485e477eb84ce977e824c6aeda686c9cbf843c4a48abdcafead8c2090dac" },
    { "Fugue-512", fugue512_full, 64,
      "8daf6fdf358c3c83179afc8d072d5f8b648237175e6c82aa7ca4c376ce7ef6f0"
      "fb85e4d7b8eec86b5b1dd06b2bf2c9bc0ec61cee1e3202a004e5ed28ae90c98b" },
    { "Fugue-512", fugue512_full, 80,
      "3009e6260bde541fef9ea1856a61fd66ed8a4532ae6a99e1f70abdc690830305"
      "8e53327c4f5ae4d6191261a5693b8663cc2146087f7326a0aa7d938058bd2153" },
    { "Fugue-512", fugue512_full, 120,
      "f5e65fcd6c8c328dff1a8b1c256c507b997fa71c19e2ffcdc54c4022ca66a5e0"
      "5cc12588f7c5582b96bb3b6fcc7ace7b31a9558632e48219bf343e24b371868a" },
    { "Fugue-512", fugue512_full, 144,
      "ee7188f60feb3d7ae16ee39727b54a32f2c2bed39f2a6303cb3b11531a4cad56"
      "3c0d50ef59ef012da9779797f0a3f40a3f322efabf0d0262e1cc135a480d859d" },
    { "Fugue-512", fugue512_full, 200,
      "88f8da517de270d368f78346d8b64fb8c774a9528b2bfac5fe6e20a8a35e9fc4"
      "ff35320e6e4729fb2488c1fbb7b2c5c36ed55a8d1e8524a7dc608ce50f5b07e8" },
};

void check_primitives()
{
    unsigned char msg[200];
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

const HashFn kStages[13] = {
    blake512_full, bmw512_full, groestl512_full, skein512_full, jh512_full,
    keccak512_full, luffa512_full, cubehash512_full, shavite512_full,
    simd512_full, echo512_full, hamsi512_full, fugue512_full,
};

const char *const kStageNames[13] = {
    "BLAKE", "BMW", "Groestl", "Skein", "JH", "Keccak", "Luffa", "CubeHash",
    "SHAvite", "SIMD", "ECHO", "Hamsi", "Fugue",
};

// The state after each stage, sph's x13 on the header 0x00..0x4f.
const char *const kChain[13] = {
    "dbc2a88576bdc79a75daad04c14262237cba3eed3421381c5ae269e8f2ac537d"
    "dc87a7bef5267469daea8a63e35437a0f30ce92cea8e25dc67b9848be1276536",
    "a91ec8c4b84ecacb8c5f053a5edfdc62b4fc03b699b65c964beda9d4b59a85eb"
    "fe9ebd3f848c9992442a7b1039510bf0a452659f995b489d2fbd60827ab49d2b",
    "647d221c1212549be764f4c3e7606dccd05a7f7241e35e030398117779604758"
    "7bc601a3a9fec543f711d6e05898ac810c85f5513e2e5b63ae1e6c2d7d7fb7ef",
    "7c9341c833519036e14e56c096b6bdae1aa7dda46e2986be501925dce62e1224"
    "35d17d09c1728194ff6142aec99680226466f941063be6e6d839154d07d0b98f",
    "26434e46d0efead22e7ee8cc12f48722332af18e414ed07d84199c3670b4365b"
    "33def4b49d9d7dbcffbe4efc6e2aa5e9f866fcefb3df13fb676e90b78bd19c67",
    "a6693ec4d5761707c5df42ccf8299134726bd3a238e0f30db0d3a7bbe63a03b7"
    "a2255bd8f1ffea285b705de9db1dd487f63b4e9b29a92bbed86dc75b266c161e",
    "3344f1519807d92fff7f76bdebcd466c0f875d3a07a1a65e25b8acc29463d7b6"
    "02cf10298887ee46950d46abe498c61008a66495968da636cf27678a4bde18eb",
    "eb22f5ce20d9f257bb204b7cf7aa8c944bcdf66bab949d6ba66cd7aa8a1aee65"
    "d82aa7fb5ed2a3f11ff66e84fa7e9f12df3fa93bf60dcc3b23a33f13001f9db0",
    "6dbfb9422153ec532edbfef7e2f5a63f9d11f53f9affddbcddfc8f548c6210f5"
    "2ac6b185be4d945a3d19b4e52fc773516eb3c37bcda51b4da5360e5b22404810",
    "63d2f805d948a0c15d3e5a3fa57074b4f146973a6ed388c7b2cb7c28945db67c"
    "8d14ef3ba52fece1b759d41e2afbb28f4dca09bd798a5691da7c5adf6ea57780",
    "412e767aa9a39ee210ea9ce424de4ff5ee35e61a8c27506bc2365ff7d4e3ecce"
    "3d3e39a5fc7b4a1860f3198ddc3e29ca2c74f6fbd3603e38951e4acc90e93296",
    "c80e0cd29a74265a367607ce3f44afc367b6386c5048bdfa9f2611e5dd538cea"
    "2dfe0aac062548d529a968c476ad1453240f78fa01c40787d78539bac0dfec5d",
    "44e39c878aa74badd072b531b2fdf181051431053f486fc36435b347e3986dac"
    "437a7186bbce38c247693048ad760782be4b2b81cd2692d9f3489cb13c4360cc",
};

void check_chain()
{
    unsigned char header[80];
    for (size_t i = 0; i < sizeof header; i++)
        header[i] = static_cast<unsigned char>(i);

    unsigned char s[64], t[64];
    for (size_t k = 0; k < 13; k++) {
        if (k == 0)
            kStages[k](t, header, sizeof header);
        else
            kStages[k](t, s, sizeof s);

        unsigned char want[64];
        unhex64(kChain[k], want);
        if (std::memcmp(t, want, 64) != 0) {
            fail("the chain first differs after stage %zu, %s", k + 1,
                 kStageNames[k]);
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

    for (HashFn fn : kStages) {
        unsigned char once[64];
        fn(once, answer.header, 80);
        if (std::memcmp(once, answer.digest, 32) == 0)
            fail("%s: one stage alone gives the digest", answer.label);
    }

    uint32_t target[8];
    uint32_t verified[8];

    uint32_t network[8];
    if (nbits_target(answer.header, network)) {
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

    // The next nonce's digest, wherever it lands against this one: the
    // counting header's digest is high, so it can legitimately be below.
    uint32_t next[8];
    algo.hash(header, answer.nonce + 1, next);
    std::memcpy(target, hash, sizeof target);
    bool accepted = algo.verify(header, answer.nonce + 1, target, verified);
    if (std::memcmp(verified, next, sizeof next) != 0)
        fail("%s: verify() did not hash the nonce it was given", answer.label);
    if (accepted != fulltest(next, target))
        fail("%s: verify() and fulltest() disagree about the next nonce",
             answer.label);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    check_primitives();
    check_chain();

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("x13");
    if (!algo) {
        std::printf("FAIL: the registry has no 'x13'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "x13") != 0)
        fail("create_algorithm(\"x13\") returned something else");

    // yiimp's algorithm table: x13's difficulty multiplier is 1.
    if (algo->target_factor() != 1.)
        fail("x13 quotes difficulty on the Bitcoin scale, and target_factor "
             "says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: x13 publishes no known answers\n");
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

    std::printf("x13: %zu primitive vectors and the thirteen chain states match "
                "sph, %zu header(s) hash and verify correctly, and %d "
                "chain block(s) clear their own nBits\n",
                sizeof kPrimitives / sizeof kPrimitives[0], count, anchored);
    return 0;
}
