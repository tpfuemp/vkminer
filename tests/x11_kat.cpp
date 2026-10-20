// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the x11 Algorithm, in three layers.
//
// 1. The three primitives x11 adds (BLAKE-512, JH-512, Keccak-512 with 0x01
//    padding) against sph's independent C, over the bytes 0, 1, 2, ... at
//    lengths 0, 64, 80, 120, 144 and 200, which cover each padding case.
// 2. The eleven 64-byte states of sph's x11 over the header 0x00..0x4f, so a
//    wrong stage shows up as the first state that differs.
// 3. The Algorithm: hash() and verify() reproduce each vector, no single stage
//    gives the digest, and the five Dash blocks clear their own nBits.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
#include "core/blake512.h"
#include "core/bmw512.h"
#include "core/cubehash512.h"
#include "core/echo512.h"
#include "core/groestl512.h"
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
    { "BLAKE-512", blake512_full, 0,
      "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b"
      "628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8" },
    { "BLAKE-512", blake512_full, 64,
      "4d47291b807750d2ce6ced17ae71dc24f5a3205f4fe309537488242c4420cd32"
      "d997beda4d560200cbcf3e9d68143e69f08c54b82ce77db7c22d0e17b5a1363e" },
    { "BLAKE-512", blake512_full, 80,
      "dbc2a88576bdc79a75daad04c14262237cba3eed3421381c5ae269e8f2ac537d"
      "dc87a7bef5267469daea8a63e35437a0f30ce92cea8e25dc67b9848be1276536" },
    { "BLAKE-512", blake512_full, 120,
      "3bff10f204cee60a442c25f981876e7db8d27b2c63ddfc35cf078369ac575c59"
      "20e4f491026447b1a22cdf8d9635d0d9b0f3d3397bb5196c004364a05575d4b7" },
    { "BLAKE-512", blake512_full, 144,
      "222b2ea94aa00b81582757382164bcf61570744e38421a3086ea0a40e6411c44"
      "f09dad7bb4c6773ba2b05e5f90cb85648478db57a5fdba03c01cff22e3d84e7a" },
    { "BLAKE-512", blake512_full, 200,
      "e327afcd4b6113e8f9571f030f60b4b85ea29df58c35ac1d0daceefe9edb17c6"
      "ce5a8bf5934214da6a3746f72c8b96cfce9625f4edf157408d67a6d3071d5980" },
    { "JH-512", jh512_full, 0,
      "90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fa"
      "be69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f" },
    { "JH-512", jh512_full, 64,
      "483560d10cadec86db6f390f6267e12f99594587d44c202902e8e4bb6c70c6c7"
      "fdff6b19965650e15e240bcfcefe4e5051567ef96c758b800efdcaf50a5d5bbd" },
    { "JH-512", jh512_full, 80,
      "db6ddd149ab87f5e90d87496755c10bfd29d195394a4253f6d6a39990ff9a523"
      "1e0b0118aa2ea80f995f7e10e2579613898c66c127b511fade3ef6c1cfebcff2" },
    { "JH-512", jh512_full, 120,
      "eba5b3fc377dd5fc458a1d5cfdde381991c91bdba9b321b66174e3d93afe0b0b"
      "72fe9261ad86f64e8f319002c1f96cce748360cd7a4c7398ac16b6c8aff2f0a6" },
    { "JH-512", jh512_full, 144,
      "167af9abb54b39aea6153b170e2ad8491c1dcfba3f8f4d46d514cf6446d7e04e"
      "3855bf13c25f10bcf77ee97735b00bd8d8dd6a3130951613348aa98b530af8fd" },
    { "JH-512", jh512_full, 200,
      "f887f615cf46099a0582a23e7dd8cb5110de8d0056840d20bf38bde116defd27"
      "faba3bf6d4df1cf34acef5df1b660a393e836f960e8dc88c604704b031428465" },
    { "Keccak-512", keccak512_full, 0,
      "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
      "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e" },
    { "Keccak-512", keccak512_full, 64,
      "59bff1edb37c403bea6387e283c5d4d8878246592807d22328fbc11ec1e029cd"
      "b6659300529849189ad647fde9ad4a8918202ba310b936ac6a1d477e4284ac4b" },
    { "Keccak-512", keccak512_full, 80,
      "9b61b6456ae23b6533a6d22f8d52d8f775e34db06352f3c43550717dec83eacc"
      "93360b403ce6802edf8967aa11d886d10b4b0f8dc0bb6af07473bbb9f1202c9d" },
    { "Keccak-512", keccak512_full, 120,
      "498ef663b284b390c2efff4917d3a473f4acbfd60478b613c5b148a524c7c77a"
      "ac111b9f628b3126495a771d563434ed3568030899a28d660a122a7c7e79cddd" },
    { "Keccak-512", keccak512_full, 144,
      "eeab6ad7c545ba3be7fb5e25d15fcf3cf573eee7062ed7edbe0322c65bbcac59"
      "d213d222beb3c8d3110f1431eb27fc268d9b91849cc8e6210f45ece4cc8d312a" },
    { "Keccak-512", keccak512_full, 200,
      "f452d81b62b961f8023f8228cbe780379b36c49ddcef29e0dffb01a930c2cc53"
      "a694ed6ae3f0d224a2f1be55814a81841b90d56bcdf4a48a633f258a32dc14fc" },
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

const HashFn kStages[11] = {
    blake512_full, bmw512_full, groestl512_full, skein512_full, jh512_full,
    keccak512_full, luffa512_full, cubehash512_full, shavite512_full,
    simd512_full, echo512_full,
};

const char *const kStageNames[11] = {
    "BLAKE", "BMW", "Groestl", "Skein", "JH", "Keccak", "Luffa", "CubeHash",
    "SHAvite", "SIMD", "ECHO",
};

// The state after each stage, sph's x11 on the header 0x00..0x4f.
const char *const kChain[11] = {
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
};

void check_chain()
{
    unsigned char header[80];
    for (size_t i = 0; i < sizeof header; i++)
        header[i] = static_cast<unsigned char>(i);

    unsigned char s[64], t[64];
    for (size_t k = 0; k < 11; k++) {
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
        vkminer::create_algorithm("x11");
    if (!algo) {
        std::printf("FAIL: the registry has no 'x11'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "x11") != 0)
        fail("create_algorithm(\"x11\") returned something else");

    // yiimp's algorithm table: x11's difficulty multiplier is 1.
    if (algo->target_factor() != 1.)
        fail("x11 quotes difficulty on the Bitcoin scale, and target_factor "
             "says %g", algo->target_factor());

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: x11 publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check(*algo, answers[i]);

    if (anchored < 5)
        fail("only %d chain block(s) clear their own nBits; five are wanted",
             anchored);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("x11: %zu primitive vectors and the eleven chain states match "
                "sph, %zu header(s) hash and verify correctly, and %d "
                "chain block(s) clear their own nBits\n",
                sizeof kPrimitives / sizeof kPrimitives[0], count, anchored);
    return 0;
}
