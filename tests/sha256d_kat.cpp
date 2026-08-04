// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the sha256d Algorithm, one level above the scalar
// SHA-256 the other KAT covers. What is under test here is not the compression
// function -- that is already proven -- but the contract between struct work
// and the hash: nineteen header words plus a nonce go in, and the digest of the
// canonical 80-byte header comes out.
//
// Two mainnet blocks are used, and they are not redundant:
//
//   125552 (2011) is the vector everybody quotes. Version 1, a nonce of
//   2504433986 that is well away from zero and not palindromic in either byte
//   order, and a header that has been published for over a decade.
//
//   957533 (2026) is a modern header, and it is here for the fields 125552
//   cannot exercise: version 0x3fffe000 has its high bits set, so a reference
//   that treats the version as a small or signed integer fails on it and passes
//   on 125552; nbits is 0x17021a42 rather than a 2011-era value; and the digest
//   has 80 leading zero bits rather than 64.
//
// Both are checkable against any block explorer, which is the point -- the
// expected digests are anchored outside this codebase.
//
// Everything is compared as bytes rather than as words. A word comparison would
// bake this host's endianness into the expected values and quietly stop testing
// the thing the test exists for.

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

// A header as it goes over the wire, the nonce as struct work carries it, and
// the digest as it sits in memory.
struct Vector {
    const char *label;
    const unsigned char header[80];

    // The byte swap of the nonce an explorer prints. Every word of work.data is
    // a big-endian read of the wire, the nonce included, and the submit path
    // swaps it back with le32enc on the way out. Both spellings are "the nonce
    // of this block", and confusing them costs every share; the value below is
    // the one this miner counts in.
    uint32_t nonce;

    // The digest in memory order, which is the display hash read backwards. The
    // run of zero bytes at the end is the leading zeros of the block hash, and
    // it is the reason these vectors are worth having: a reference with its byte
    // order reversed produces a digest that ends in the first byte of the
    // display hash, not in a run of zeros, and the mistake is visible in the
    // first line of the diff.
    const unsigned char digest[32];
};

// Each header is laid out as it goes over the wire: version, previous hash,
// merkle root, timestamp, difficulty bits, nonce -- each little endian, which is
// why the two hashes read backwards from the way an explorer prints them.
const Vector kVectors[] = {
    {
        // Nonce 2504433986, display hash
        // 00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d.
        "block 125552",
        {
            0x01, 0x00, 0x00, 0x00,
            0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b,
            0xcd, 0x93, 0x17, 0xe2, 0xfe, 0x99, 0xf2, 0xde,
            0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4,
            0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75,
            0x04, 0x23, 0xdb, 0x8b, 0x1e, 0xb9, 0x42, 0xae,
            0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf,
            0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b,
            0xc7, 0xf5, 0xd7, 0x4d,
            0xf2, 0xb9, 0x44, 0x1a,
            0x42, 0xa1, 0x46, 0x95,
        },
        0x42a14695,
        {
            0x1d, 0xbd, 0x98, 0x1f, 0xe6, 0x98, 0x57, 0x76,
            0xb6, 0x44, 0xb1, 0x73, 0xa4, 0xd0, 0x38, 0x5d,
            0xdc, 0x1a, 0xa2, 0xa8, 0x29, 0x68, 0x8d, 0x1e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
    },
    {
        // Nonce 703811245, display hash
        // 00000000000000000000e9b8431c31dbc0bcf4ae76222fd00b10dec47b274cb4.
        // An empty block, so its merkle root is the coinbase txid alone --
        // irrelevant to the hash, but it is why the header is short of the
        // usual entropy and worth noting before someone "corrects" it.
        "block 957533",
        {
            0x00, 0xe0, 0xff, 0x3f,
            0x43, 0xd4, 0x81, 0xb0, 0x07, 0x92, 0x8a, 0x01,
            0xbd, 0x44, 0xd1, 0x65, 0x57, 0xc3, 0xb7, 0xe1,
            0xd5, 0xdb, 0x3a, 0x5f, 0x6f, 0x80, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x9b, 0xa8, 0x64, 0xa7, 0x69, 0x50, 0x10,
            0xb1, 0x92, 0x6e, 0x6d, 0xc4, 0xaf, 0xf1, 0x17,
            0xa0, 0xe7, 0x7c, 0xc8, 0xbe, 0x78, 0x09, 0x92,
            0x3e, 0x5e, 0xff, 0x80, 0x4c, 0x36, 0x8e, 0xd2,
            0x64, 0xe9, 0x51, 0x6a,
            0x42, 0x1a, 0x02, 0x17,
            0xad, 0x4e, 0xf3, 0x29,
        },
        0xad4ef329,
        {
            0xb4, 0x4c, 0x27, 0x7b, 0xc4, 0xde, 0x10, 0x0b,
            0xd0, 0x2f, 0x22, 0x76, 0xae, 0xf4, 0xbc, 0xc0,
            0xdb, 0x31, 0x1c, 0x43, 0xb8, 0xe9, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
    },
};

void print_bytes(const char *label, const unsigned char *bytes)
{
    std::printf("  %-9s ", label);
    for (int i = 0; i < 32; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// One vector: hash() must reproduce the published digest, and verify() must
// agree with it and with the target comparison built around it.
void check(vkminer::Algorithm &algo, const Vector &v)
{
    // struct work carries the header as host-order words, each holding what a
    // big-endian read of the wire bytes gives. This is the one conversion the
    // rest of the miner does on the way in, so the test does it too rather
    // than hand-writing words that only happen to be right on this machine.
    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(v.header + i * 4);

    // Word 19 is the nonce, and hash() takes it separately. Zeroing it here
    // means a reference that reads the nonce out of the header instead of out
    // of its argument fails, which is the bug a GPU kernel is most likely to
    // reproduce.
    header[19] = 0;

    uint32_t hash[8];
    algo.hash(header, v.nonce, hash);

    if (std::memcmp(hash, v.digest, sizeof v.digest) != 0) {
        fail("%s hashed to the wrong digest", v.label);
        print_bytes("expected", v.digest);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash));
    }

    // The same nonce through verify(), which is what a backend actually calls:
    // hash, then compare. A target equal to the hash is met, because the
    // network's rule is hash <= target.
    uint32_t target[8];
    std::memcpy(target, hash, sizeof target);

    uint32_t verified[8];
    if (!algo.verify(header, v.nonce, target, verified))
        fail("%s: verify() rejected a hash exactly equal to the target", v.label);
    if (std::memcmp(verified, hash, sizeof hash) != 0)
        fail("%s: verify() and hash() disagree about the digest", v.label);

    // One less than the hash, so the hash no longer meets it. Word 0 is the low
    // word of the 256-bit comparison fulltest() makes, and it is nonzero in both
    // vectors, so the decrement cannot borrow into word 1. The guard is here so
    // that a vector added later with a zero low word fails loudly instead of
    // quietly turning this into a different test.
    if (target[0] == 0) {
        fail("%s: low digest word is zero, so the decrement below would borrow", v.label);
    } else {
        target[0]--;
        if (algo.verify(header, v.nonce, target, verified))
            fail("%s: verify() accepted a hash above the target", v.label);
    }

    // A different nonce must not pass a target the right nonce only just met.
    // Sound only because these targets have at least 64 leading zero bits: any
    // other nonce clearing one is a 2^-64 event, so a pass here means hash()
    // ignored its nonce argument rather than that the test got unlucky.
    std::memcpy(target, hash, sizeof target);
    if (algo.verify(header, v.nonce + 1, target, verified))
        fail("%s: verify() accepted the wrong nonce", v.label);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("sha256d");
    if (!algo) {
        std::printf("FAIL: the registry has no 'sha256d'\n");
        return 1;
    }

    // The name is round-tripped rather than assumed: the registry key and what
    // the algorithm calls itself are two strings, and the log lines, the usage
    // text and --algo all trust that they match.
    if (std::strcmp(algo->name(), "sha256d") != 0)
        fail("create_algorithm(\"sha256d\") returned something else");

    // An alternative spelling has to reach the same algorithm.
    if (!vkminer::create_algorithm("SHA256D"))
        fail("--algo is case sensitive, and should not be");
    if (vkminer::create_algorithm("no-such-algo"))
        fail("the registry answered to a name it does not have");

    for (const Vector &v : kVectors)
        check(*algo, v);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("sha256d: %zu published block headers hash and verify correctly\n",
                sizeof kVectors / sizeof kVectors[0]);
    return 0;
}
