// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the step before the hash: turning a mining.notify into
// the eighty bytes that get hashed. The sha256d KAT starts from an already
// assembled header, so everything this file covers had no test at all --
// coinbase assembly from the two halves and the two extranonces, the merkle
// root, and the word order std_build_block_header leaves the header in.
//
// The vector is a share this miner submitted to a live pool and had accepted,
// captured off the wire: the mining.subscribe reply that fixed extranonce1, the
// mining.notify it was solved against, and the mining.submit that came back
// result:true. The share is worth difficulty 2.3382 against a stratum
// difficulty of 1 -- a number the pool arrived at independently, from nothing
// but the five values in the submit.
//
// A synthetic job could not test this. The fields that break header assembly
// are exactly the ones a hand-written vector gets self-consistently wrong: a
// 78-byte coinbase scriptSig split across coinb1, both extranonces and coinb2;
// an empty merkle branch; and a version of zero.

#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
}

#include <cstdio>
#include <cstring>
#include <memory>

// The inherited C expects the miner to own these.
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

void fail(const char *what)
{
    std::printf("FAIL: %s\n", what);
    failures++;
}

// mining.subscribe: result[1] is extranonce1, result[2] the size the miner must
// use for extranonce2. Four bytes each, which is what the 08 push at the end of
// coinb1 below reserves room for.
const unsigned char kExtranonce1[4] = { 0x80, 0x07, 0xe1, 0xbb };
const unsigned char kExtranonce2[4] = { 0x00, 0x00, 0x00, 0x00 };

// mining.notify, job 3a409. The prevhash is stored exactly as it arrives; the
// swap into header order happens in std_build_block_header, which is the thing
// under test, so doing it here would test nothing.
const unsigned char kPrevhash[32] = {
    0x25, 0xe6, 0x44, 0x61, 0xaa, 0xf2, 0xfa, 0xde,
    0x90, 0xd7, 0x86, 0xb7, 0x81, 0x03, 0x48, 0x08,
    0x4d, 0x8b, 0xb8, 0x35, 0x01, 0x1a, 0x56, 0xd0,
    0x68, 0x9c, 0x29, 0xf5, 0x5e, 0x92, 0x40, 0xa7,
};

// The generation input, an ffffffff outpoint, and a scriptSig whose declared
// length is 0x4e = 78 bytes -- of which only ten are here. The rest arrives as
// the extranonces and the head of coinb2, and a builder that trusts the length
// byte over the concatenation gets a coinbase that hashes to nothing.
const char kCoinb1[] =
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4e03622842044358726a08";

// "/zpool.ca/", the fabe6d6d merged-mining tag with its 32-byte commitment, then
// the single output and the locktime.
const char kCoinb2[] =
    "2f7a706f6f6c2e63612f1cd1999b2f00fabe6d6de7a6e06406823582fab852d1c437df1746"
    "38dc7345e1fdf8916e12e7cb7074f380000000000000000000000001806e87740100000019"
    "76a9146c05352933d58f6ba2ff6223d0f276aa35a0f26688ac00000000";

// Zero. Not a placeholder -- it is what the pool sent, and a header builder that
// treats the version as anything but four opaque bytes has nothing to fail on
// until it meets a job like this one.
const unsigned char kVersion[4] = { 0x00, 0x00, 0x00, 0x00 };
const unsigned char kNbits[4]   = { 0x1a, 0x00, 0x8a, 0x57 };
const unsigned char kNtime[4]   = { 0x6a, 0x72, 0x58, 0x43 };

// mining.submit's fifth parameter, byte-reversed into the spelling struct work
// carries. The submit path reverses it again on the way out, which is how this
// value and the "4cea0550" on the wire are the same nonce.
constexpr uint32_t kNonce = 0x5005ea4c;

// The eighty bytes the two above have to add up to. Bytes 36..67 are the
// coinbase txid, so a merkle root computed over a mis-assembled coinbase shows
// up here rather than as a bad hash forty lines later.
const unsigned char kHeader[80] = {
    0x00, 0x00, 0x00, 0x00,
    0x61, 0x44, 0xe6, 0x25, 0xde, 0xfa, 0xf2, 0xaa,
    0xb7, 0x86, 0xd7, 0x90, 0x08, 0x48, 0x03, 0x81,
    0x35, 0xb8, 0x8b, 0x4d, 0xd0, 0x56, 0x1a, 0x01,
    0xf5, 0x29, 0x9c, 0x68, 0xa7, 0x40, 0x92, 0x5e,
    0x69, 0x06, 0x75, 0xda, 0xa9, 0x73, 0xab, 0x54,
    0x95, 0x9d, 0x96, 0xe7, 0x3e, 0xd6, 0xa2, 0x85,
    0x1b, 0x76, 0x2e, 0xd2, 0x0e, 0xec, 0x54, 0x6b,
    0x2d, 0x70, 0x11, 0x74, 0x82, 0x1e, 0x6b, 0xa9,
    0x43, 0x58, 0x72, 0x6a,
    0x57, 0x8a, 0x00, 0x1a,
    0x50, 0x05, 0xea, 0x4c,
};

// Display hash 000000006d7c4d03a70b307dd06198554535d046bf0f92fc8c60605cbb3c1171,
// read backwards. Only four zero bytes at the end: this is a share, not a block,
// and the network target it did not meet is 31.05 M.
const unsigned char kDigest[32] = {
    0x71, 0x11, 0x3c, 0xbb, 0x5c, 0x60, 0x60, 0x8c,
    0xfc, 0x92, 0x0f, 0xbf, 0x46, 0xd0, 0x35, 0x45,
    0x55, 0x98, 0x61, 0xd0, 0x7d, 0x30, 0x0b, 0xa7,
    0x03, 0x4d, 0x7c, 0x6d, 0x00, 0x00, 0x00, 0x00,
};

void print_bytes(const char *label, const unsigned char *bytes, size_t n)
{
    std::printf("  %-9s ", label);
    for (size_t i = 0; i < n; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// struct work holds the header as words; the wire holds it as bytes. Writing
// the words back out big-endian is the inverse of the be32dec the miner does on
// the way in, so this is the header as the pool would see it.
void header_bytes(const struct work *w, unsigned char out[80])
{
    for (int i = 0; i < 20; i++)
        be32enc(out + i * 4, w->data[i]);
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    // std_build_block_header lays the prevhash out one way for Stratum and the
    // other way for getwork, off this flag. The vector is a Stratum job.
    have_stratum = true;

    unsigned char coinb1[128], coinb2[256];
    const size_t coinb1_len = std::strlen(kCoinb1) / 2;
    const size_t coinb2_len = std::strlen(kCoinb2) / 2;
    if (!hex2bin(coinb1, kCoinb1, coinb1_len) ||
        !hex2bin(coinb2, kCoinb2, coinb2_len)) {
        std::printf("FAIL: the vector's own hex does not decode\n");
        return 1;
    }

    // The coinbase the pool told the miner to build: its two halves with both
    // extranonces between them, in that order and no other.
    unsigned char coinbase[512];
    size_t n = 0;
    std::memcpy(coinbase + n, coinb1, coinb1_len);          n += coinb1_len;
    std::memcpy(coinbase + n, kExtranonce1, sizeof kExtranonce1); n += sizeof kExtranonce1;
    std::memcpy(coinbase + n, kExtranonce2, sizeof kExtranonce2); n += sizeof kExtranonce2;
    std::memcpy(coinbase + n, coinb2, coinb2_len);          n += coinb2_len;

    struct stratum_ctx sctx;
    std::memset(&sctx, 0, sizeof sctx);
    sctx.xnonce2_size = sizeof kExtranonce2;
    sctx.job.coinbase = coinbase;
    sctx.job.coinbase_size = n;
    sctx.job.merkle_count = 0;   // Tx 0: the root is the coinbase txid alone
    std::memcpy(sctx.job.prevhash, kPrevhash, sizeof kPrevhash);
    std::memcpy(sctx.job.version, kVersion, sizeof kVersion);
    std::memcpy(sctx.job.nbits, kNbits, sizeof kNbits);
    std::memcpy(sctx.job.ntime, kNtime, sizeof kNtime);

    struct work work;
    std::memset(&work, 0, sizeof work);
    std_build_extraheader(&work, &sctx);

    // Everything but the nonce, which the header build does not own.
    unsigned char built[80];
    header_bytes(&work, built);
    if (std::memcmp(built, kHeader, 76) != 0) {
        fail("the job did not assemble into the header the pool was given");
        print_bytes("expected", kHeader, 76);
        print_bytes("got", built, 76);
    }

    // The padding the second SHA-256 block needs: 0x80 immediately after the
    // eighty bytes, and the bit length at the end. Nothing else reaches in to
    // set these, so a header build that forgets them hashes garbage.
    if (work.data[20] != 0x80000000 || work.data[31] != 0x00000280)
        fail("the header build left the SHA-256 padding words unset");

    // With the nonce in place the whole eighty bytes must match, and hashing
    // them must give the digest the pool credited.
    work.data[STD_NONCE_INDEX] = kNonce;
    header_bytes(&work, built);
    if (std::memcmp(built, kHeader, sizeof kHeader) != 0)
        fail("the nonce did not land in the header where the pool expects it");

    std::unique_ptr<vkminer::Algorithm> algo = vkminer::create_algorithm("sha256d");
    if (!algo) {
        std::printf("FAIL: the registry has no 'sha256d'\n");
        return 1;
    }

    uint32_t hash[8];
    algo->hash(work.data, kNonce, hash);
    if (std::memcmp(hash, kDigest, sizeof kDigest) != 0) {
        fail("the reconstructed job hashed to a digest the pool did not accept");
        print_bytes("expected", kDigest, 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(hash), 32);
    }

    // The share is worth 2.3382, so it clears a difficulty-1 and a difficulty-2
    // target and misses a difficulty-3 one. Bracketing it this way pins the
    // value without comparing floats, and it exercises the same diff_to_hash
    // the miner uses to turn mining.set_difficulty into work->target.
    uint32_t target[8];
    uint32_t verified[8];
    for (double diff : { 1.0, 2.0 }) {
        diff_to_hash(target, diff);
        if (!algo->verify(work.data, kNonce, target, verified))
            fail("verify() rejected the share at a difficulty the pool accepted it at");
    }
    diff_to_hash(target, 3.0);
    if (algo->verify(work.data, kNonce, target, verified))
        fail("verify() accepted the share above its own difficulty");

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("stratum: an accepted share rebuilds from its job, "
                "hashes and verifies correctly\n");
    return 0;
}
