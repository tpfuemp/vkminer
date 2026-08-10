// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for scrypt. It has an anchor the other two algorithms did
// not: RFC 7914 §12 publishes vectors for the function itself, so the reference
// can be checked against a standards document rather than against a chain.
//
// That matters because the mining parameters are anchored no better than
// blake2s's were -- Litecoin's block hash is SHA-256d, and its scrypt digest
// appears on no explorer. So this test is in two halves. The RFC vectors say
// Salsa20/8, BlockMix, ROMix and PBKDF2 are right, at parameters nobody mines
// at. The mined headers say the 80-byte assembly and the N=1024 parameters are
// right: their digests came out of OpenSSL rather than out of this code, and
// each clears the difficulty its own header declares -- a target near 2^199,
// which a wrong implementation's uniform digest clears about once in 2^57.
//
// Neither half would be enough alone: the RFC vectors never see an 80-byte
// header, and a header clearing its own nBits would still do so if Salsa20 were
// subtly wrong in a way that preserved uniformity.

#include "algorithms/registry.h"
#include "algorithms/scrypt/scrypt.h"

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

void print_bytes(const char *label, const unsigned char *bytes, size_t len)
{
    std::printf("  %-9s ", label);
    for (size_t i = 0; i < len; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// ------------------------------------------------------------- RFC 7914 §12

struct RfcVector {
    const char *label;
    const char *password;
    const char *salt;
    uint32_t n, r, p;
    unsigned char expected[64];
};

// The first three of the RFC's four. The fourth is the same function at
// N = 1048576, which wants a gigabyte of scratchpad to tell us what the third
// already did, and is left out on purpose.
const RfcVector kRfcVectors[] = {
    {
        "RFC 7914 N=16 r=1 p=1", "", "", 16, 1, 1,
        {
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
            0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
            0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
            0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
            0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
            0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
            0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
        },
    },
    {
        "RFC 7914 N=1024 r=8 p=16", "password", "NaCl", 1024, 8, 16,
        {
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
            0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
            0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
            0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
            0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
            0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
            0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
        },
    },
    {
        "RFC 7914 N=16384 r=8 p=1", "pleaseletmein", "SodiumChloride",
        16384, 8, 1,
        {
            0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48,
            0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
            0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
            0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
            0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
            0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
            0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
            0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
        },
    },
};

void check_rfc(const RfcVector &v)
{
    unsigned char got[64];
    vkminer::scrypt(reinterpret_cast<const unsigned char *>(v.password),
                    std::strlen(v.password),
                    reinterpret_cast<const unsigned char *>(v.salt),
                    std::strlen(v.salt), v.n, v.r, v.p, got, sizeof got);

    if (std::memcmp(got, v.expected, sizeof got) != 0) {
        fail("%s", v.label);
        print_bytes("expected", v.expected, sizeof v.expected);
        print_bytes("got", got, sizeof got);
        return;
    }
    std::printf("ok   %s\n", v.label);
}

// A parameter set nobody mines at and nothing publishes, checked for a property
// rather than a value: scrypt must depend on every byte of its password and
// salt. A reference that dropped one would still match the vectors above if it
// dropped a byte they do not have.
void check_avalanche()
{
    unsigned char password[80];
    unsigned char salt[80];
    for (size_t i = 0; i < sizeof password; i++) {
        password[i] = static_cast<unsigned char>(i * 7 + 1);
        salt[i] = static_cast<unsigned char>(i * 13 + 5);
    }

    unsigned char base[32];
    vkminer::scrypt(password, sizeof password, salt, sizeof salt, 64, 1, 1,
                    base, sizeof base);

    for (size_t i = 0; i < sizeof password; i++) {
        unsigned char probe[32];

        password[i] ^= 0x01;
        vkminer::scrypt(password, sizeof password, salt, sizeof salt, 64, 1, 1,
                        probe, sizeof probe);
        password[i] ^= 0x01;
        if (std::memcmp(base, probe, sizeof base) == 0)
            fail("password byte %zu does not reach the digest", i);

        salt[i] ^= 0x01;
        vkminer::scrypt(password, sizeof password, salt, sizeof salt, 64, 1, 1,
                        probe, sizeof probe);
        salt[i] ^= 0x01;
        if (std::memcmp(base, probe, sizeof base) == 0)
            fail("salt byte %zu does not reach the digest", i);
    }

    std::printf("ok   every password and salt byte reaches the digest\n");
}

// ------------------------------------------------------------ mined headers

// The 256-bit target a header declares about itself, in the word order
// fulltest() compares. Bitcoin's compact encoding, which Litecoin inherited:
// the top byte is a base-256 exponent and the low three bytes the mantissa, so
// the mantissa's least significant byte lands at byte `exponent - 3`.
//
// Decoded here rather than borrowed from the inherited C on purpose -- this is
// the one value in the test not allowed to come from the code under test.
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

void check_header(vkminer::Algorithm &algo, const vkminer::KnownAnswer &answer)
{
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
        print_bytes("expected", answer.digest, 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash), 32);
    }

    // The anchor: the network accepted this block at the difficulty its own
    // header states, so whatever the network computed cleared this target.
    uint32_t network[8];
    uint32_t verified[8];
    if (!nbits_target(answer.header, network)) {
        fail("%s: nBits does not decode to a usable target", answer.label);
    } else if (!algo.verify(header, answer.nonce, network, verified)) {
        fail("%s: the digest does not clear the header's own nBits",
             answer.label);
        print_bytes("target", reinterpret_cast<const unsigned char *>(network),
                    32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(verified),
                    32);
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

    if (target[0] == 0) {
        fail("%s: low digest word is zero, so the decrement below would borrow",
             answer.label);
    } else {
        target[0]--;
        if (algo.verify(header, answer.nonce, target, verified))
            fail("%s: verify() accepted a hash above the target", answer.label);
    }

    // A different nonce must not pass a target the right nonce only just met.
    std::memcpy(target, hash, sizeof target);
    if (algo.verify(header, answer.nonce + 1, target, verified))
        fail("%s: verify() accepted the wrong nonce", answer.label);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    for (const RfcVector &v : kRfcVectors)
        check_rfc(v);
    check_avalanche();

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("scrypt");
    if (!algo) {
        std::printf("FAIL: the registry has no 'scrypt'\n");
        return 1;
    }

    if (std::strcmp(algo->name(), "scrypt") != 0)
        fail("create_algorithm(\"scrypt\") returned something else");
    if (!vkminer::create_algorithm("SCRYPT"))
        fail("--algo is case sensitive, and should not be");

    const vkminer::KnownAnswer *answers = nullptr;
    size_t count = algo->known_answers(&answers);
    if (count == 0 || !answers) {
        std::printf("FAIL: scrypt publishes no known answers\n");
        return 1;
    }

    for (size_t i = 0; i < count; i++)
        check_header(*algo, answers[i]);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("scrypt: %zu RFC 7914 vector(s) and %zu mined block header(s) "
                "reproduce\n", sizeof kRfcVectors / sizeof kRfcVectors[0],
                count);
    return 0;
}
