// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the step before the hash: turning a mining.notify into
// the eighty bytes that get hashed. The sha256d KAT starts from an already
// assembled header, so everything this file covers had no test at all --
// coinbase assembly from the two halves and the two extranonces, the merkle
// root, and the word order std_build_block_header leaves the header in. The
// same vector then covers rolling extranonce2, which is how a device gets a
// fresh nonce range without waiting for the next job.
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
//
// The second half of the file does the same for lbry, whose header is this one
// with a 32-byte claimtrie root between the merkle root and ntime -- so every
// mutable field after it moves by eight words, and a builder that got the
// layout right and the shift wrong would mine and be rejected on every share.

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

// The tail of the scriptSig -- the pool's tag, then the fabe6d6d merged-mining
// marker with its 32-byte commitment -- and after it the single output and the
// locktime.
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

// LBRY block 1300000, mined January 2023 -- the third of the vectors the lbry
// KAT hashes, reused here for the other end of the same layout. A mined block
// is a stronger anchor than a captured job for everything except the coinbase:
// the network accepted these 112 bytes in this order, and the digest below
// clears the target its own nBits encodes.
const unsigned char kLbryHeader[112] = {
    0x00, 0x00, 0x00, 0x20,
    0x9d, 0x72, 0xc5, 0xdb, 0x07, 0xf6, 0xf5, 0xff,
    0xae, 0xd5, 0x77, 0x6b, 0xac, 0x27, 0xb8, 0xcf,
    0xdb, 0xe5, 0x7c, 0x45, 0xc5, 0xf7, 0xcc, 0x4e,
    0x46, 0x5d, 0x24, 0xf3, 0x41, 0x11, 0xb3, 0x96,
    0x83, 0xf2, 0x21, 0xb3, 0x48, 0xb7, 0x0f, 0x79,
    0xa9, 0x10, 0x5d, 0x62, 0xba, 0x50, 0xdf, 0x94,
    0xc6, 0xb0, 0x18, 0x20, 0x95, 0x9c, 0x88, 0x16,
    0xa0, 0x94, 0xc6, 0x46, 0x35, 0x7e, 0x87, 0xcc,
    0x1a, 0xed, 0x82, 0xca, 0x97, 0xbe, 0xd8, 0x7f,
    0x5e, 0x85, 0x57, 0xff, 0x43, 0xa3, 0x8e, 0x33,
    0x0b, 0xda, 0xcd, 0xca, 0xba, 0xd2, 0x7f, 0x49,
    0xd4, 0xfa, 0x49, 0x3a, 0xe9, 0x04, 0xf5, 0x2e,
    0x51, 0x23, 0xd2, 0x63,
    0xef, 0xc8, 0x00, 0x1a,
    0x59, 0xa3, 0xd0, 0x0e,
};

const unsigned char kLbryDigest[32] = {
    0xae, 0x30, 0xcf, 0x78, 0x2b, 0x5a, 0xd9, 0x57,
    0x37, 0x54, 0x5d, 0x00, 0x2f, 0x7e, 0xd2, 0x15,
    0x31, 0x10, 0xfc, 0xb6, 0x53, 0xa0, 0x6e, 0x93,
    0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The same prevhash as bytes 4..35 above, with each word reversed: that is the
// spelling Stratum sends and the builder undoes, and it is why the sha256d
// vector's kPrevhash does not read like its header either. Written out rather
// than computed, so that a builder which stopped swapping fails here instead of
// agreeing with a test that made the same change.
const unsigned char kLbryPrevhash[32] = {
    0xdb, 0xc5, 0x72, 0x9d, 0xff, 0xf5, 0xf6, 0x07,
    0x6b, 0x77, 0xd5, 0xae, 0xcf, 0xb8, 0x27, 0xac,
    0x45, 0x7c, 0xe5, 0xdb, 0x4e, 0xcc, 0xf7, 0xc5,
    0xf3, 0x24, 0x5d, 0x46, 0x96, 0xb3, 0x11, 0x41,
};

// The claimtrie root the same way: bytes 68..99 above with each word reversed.
// It is a chain hash the pool read out of its node, so Stratum word-swaps it
// exactly as it word-swaps the prevhash, and the builder undoes both. Handing
// the builder bytes 68..99 straight would put one spelling on both sides of
// the conversion, which is a test that cannot fail however the builder swaps.
// Written out for the same reason kLbryPrevhash is.
const unsigned char kLbryClaim[32] = {
    0xca, 0x82, 0xed, 0x1a, 0x7f, 0xd8, 0xbe, 0x97,
    0xff, 0x57, 0x85, 0x5e, 0x33, 0x8e, 0xa3, 0x43,
    0xca, 0xcd, 0xda, 0x0b, 0x49, 0x7f, 0xd2, 0xba,
    0x3a, 0x49, 0xfa, 0xd4, 0x2e, 0xf5, 0x04, 0xe9,
};

// Version 0x20000000, time 0x63d22351, nBits 0x1a00c8ef -- each as the four
// bytes a notify carries, which is the header's own spelling of them.
const unsigned char kLbryVersion[4] = { 0x20, 0x00, 0x00, 0x00 };
const unsigned char kLbryNtime[4]   = { 0x63, 0xd2, 0x23, 0x51 };
const unsigned char kLbryNbits[4]   = { 0x1a, 0x00, 0xc8, 0xef };

constexpr uint32_t kLbryNonce = 0x59a3d00e;

// Groestlcoin's genesis coinbase, from its CreateGenesisBlock. One SHA-256 of
// it is the block's merkle root, 3ce968df...6628bb; SHA-256d is not.
const unsigned char kGrsCoinbase[185] = {
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x3a, 0x04, 0xff, 0xff, 0x00, 0x1d, 0x01,
    0x04, 0x32, 0x50, 0x72, 0x65, 0x73, 0x73, 0x75,
    0x72, 0x65, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20,
    0x62, 0x65, 0x20, 0x70, 0x75, 0x74, 0x20, 0x6f,
    0x6e, 0x20, 0x56, 0x6c, 0x61, 0x64, 0x69, 0x6d,
    0x69, 0x72, 0x20, 0x50, 0x75, 0x74, 0x69, 0x6e,
    0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x43, 0x72,
    0x69, 0x6d, 0x65, 0x61, 0xff, 0xff, 0xff, 0xff,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x43, 0x41, 0x04, 0x67, 0x8a, 0xfd, 0xb0,
    0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6,
    0x71, 0x30, 0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28,
    0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea,
    0x1f, 0x61, 0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f,
    0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5,
    0x1e, 0xc1, 0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7,
    0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b,
    0x6b, 0xf1, 0x1d, 0x5f, 0xac, 0x00, 0x00, 0x00,
    0x00,
};

// The genesis header that root goes into, nonce included.
const unsigned char kGrsHeader[80] = {
    0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xbb, 0x28, 0x66, 0xaa,
    0xca, 0x46, 0xc4, 0x42, 0x8a, 0xd0, 0x8b, 0x57,
    0xbc, 0x9d, 0x14, 0x93, 0xab, 0xaf, 0x64, 0x72,
    0x4b, 0x6c, 0x30, 0x52, 0xa7, 0xc8, 0xf9, 0x58,
    0xdf, 0x68, 0xe9, 0x3c, 0xed, 0x3d, 0x2b, 0x53,
    0xff, 0xff, 0x0f, 0x1e, 0x83, 0x5b, 0x03, 0x00,
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

void lbry_header_bytes(const struct work *w, unsigned char out[112])
{
    for (int i = 0; i < 28; i++)
        be32enc(out + i * 4, w->data[i]);
}

// The 256-bit threshold nBits stands for: a three-byte mantissa shifted up by
// (exponent - 3) bytes. Written out here rather than gone through
// nbits_to_diff and diff_to_hash, because that round trip passes through a
// double and this comparison is exact.
void nbits_to_target(uint32_t nbits, unsigned char out[32])
{
    std::memset(out, 0, 32);
    const unsigned exp = nbits >> 24;
    const uint32_t mantissa = nbits & 0x00ffffff;
    if (exp < 3)
        return;
    for (unsigned i = 0; i < 3; i++)
        if (exp - 3 + i < 32)
            out[exp - 3 + i] = static_cast<unsigned char>(mantissa >> (8 * i));
}

// Both are 256-bit little-endian, which is the order a digest lands in memory
// in and the order an explorer prints backwards.
bool below(const unsigned char *hash, const unsigned char *target)
{
    for (int i = 31; i >= 0; i--)
        if (hash[i] != target[i])
            return hash[i] < target[i];
    return false;
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

    // The same job again, through the path the scheduler takes when a device
    // exhausts a nonce range mid-job. Rolling the counter back to the value
    // this share was actually found with has to reproduce the header the pool
    // accepted: that is what distinguishes a rebuild from a change.
    pthread_mutex_init(&sctx.work_lock, nullptr);
    sctx.job.xnonce2 = coinbase + coinb1_len + sizeof kExtranonce1;
    char job_id[] = "3a409";
    sctx.job.job_id = job_id;

    struct work rolled;
    std::memset(&rolled, 0, sizeof rolled);
    rolled.job_id = strdup(job_id);

    if (!stratum_set_extranonce2(&rolled, &sctx, 0)) {
        fail("the extranonce2 roll refused the job the work holds");
    } else {
        header_bytes(&rolled, built);
        if (std::memcmp(built, kHeader, 76) != 0) {
            fail("rolling extranonce2 back to this share's own value did not "
                 "rebuild its header");
            print_bytes("expected", kHeader, 76);
            print_bytes("got", built, 76);
        }
    }

    // A different coinbase is a different merkle root and nothing else. The
    // fields that belong to the job have to survive untouched, or the miner
    // would be hashing a header the pool never authorised.
    unsigned char next[80];
    if (!stratum_set_extranonce2(&rolled, &sctx, 1)) {
        fail("the extranonce2 roll refused to advance");
    } else {
        header_bytes(&rolled, next);
        if (std::memcmp(next + 36, kHeader + 36, 32) == 0)
            fail("a different extranonce2 produced the same merkle root");
        if (std::memcmp(next, kHeader, 36) != 0 ||
            std::memcmp(next + 68, kHeader + 68, 8) != 0)
            fail("rolling extranonce2 changed a field that belongs to the job");

        // Little-endian, and the whole width the pool asked for. A counter
        // written the other way round still mines, and still submits an
        // extranonce2 the pool cannot reconstruct the coinbase from.
        const unsigned char expect[4] = { 0x01, 0x00, 0x00, 0x00 };
        if (rolled.xnonce2_len != sizeof expect ||
            std::memcmp(rolled.xnonce2, expect, sizeof expect) != 0)
            fail("the counter did not land in extranonce2 little-endian");
    }

    // The work holds a job the pool has moved on from. Rebuilding it against
    // the current coinbase would mine a header belonging to neither job, so
    // the roll has to refuse and leave the work alone for the caller to
    // replace.
    free(rolled.job_id);
    rolled.job_id = strdup("not-this-job");
    if (stratum_set_extranonce2(&rolled, &sctx, 2)) {
        fail("the roll rebuilt work whose job the pool no longer has");
    } else {
        unsigned char after[80];
        header_bytes(&rolled, after);
        if (std::memcmp(after, next, sizeof after) != 0)
            fail("the refused roll modified the work anyway");
    }

    // ---- lbry ------------------------------------------------------------
    //
    // The layout is the algorithm's answer and reaches the header build through
    // these globals, so the binding is part of what is under test: a dialect
    // that arrived without its indices would build a 112-byte header and then
    // submit the ntime and nonce out of Bitcoin's positions in it.
    vkminer::bind_protocol_settings("lbry");
    if (opt_stratum_dialect != STRATUM_LBRY)
        fail("'lbry' did not select its own stratum dialect");
    if (opt_ntime_index != LBRY_NTIME_INDEX ||
        opt_nbits_index != LBRY_NBITS_INDEX ||
        opt_nonce_index != LBRY_NONCE_INDEX)
        fail("'lbry' selected its dialect without the header indices that go "
             "with it");

    // The merkle root and the claimtrie root both come out of the block: the
    // first because reproducing it would need the block's own coinbase, which
    // the vector above already covers for the shared code that builds it, and
    // the second because there is nowhere else it could come from -- it is a
    // consensus value the miner cannot compute.
    // Copied into words because that is the shape the builder takes them in --
    // the same shape stratum_job holds them in, where they are four-byte
    // aligned and these constants need not be.
    uint32_t lbry_prevhash[8], lbry_merkle[8];
    std::memcpy(lbry_prevhash, kLbryPrevhash, sizeof lbry_prevhash);
    std::memcpy(lbry_merkle, kLbryHeader + 36, sizeof lbry_merkle);

    struct work lbry;
    std::memset(&lbry, 0, sizeof lbry);
    lbry_build_block_header(&lbry, le32dec(kLbryVersion),
                            lbry_prevhash, lbry_merkle, kLbryClaim,
                            le32dec(kLbryNtime), le32dec(kLbryNbits));

    unsigned char lbry_built[112];
    lbry_header_bytes(&lbry, lbry_built);
    if (std::memcmp(lbry_built, kLbryHeader, 108) != 0) {
        fail("the block's own fields did not reassemble into its header");
        print_bytes("expected", kLbryHeader, 108);
        print_bytes("got", lbry_built, 108);
    }

    // 112 bytes, not 80: the terminator moves to word 28 and the length is 896
    // bits. Nothing here hashes out of this buffer -- the shader pads for
    // itself -- but a header that describes itself as the wrong length is read
    // by the next person and believed.
    if (lbry.data[28] != 0x80000000 || lbry.data[31] != 0x00000380)
        fail("the lbry header build padded for an 80-byte message");

    lbry.data[opt_nonce_index] = kLbryNonce;
    lbry_header_bytes(&lbry, lbry_built);
    if (std::memcmp(lbry_built, kLbryHeader, sizeof kLbryHeader) != 0)
        fail("the nonce did not land at the word eight along from Bitcoin's");

    std::unique_ptr<vkminer::Algorithm> lbry_algo =
        vkminer::create_algorithm("lbry");
    if (!lbry_algo) {
        std::printf("FAIL: the registry has no 'lbry'\n");
        return 1;
    }

    uint32_t lbry_hash[8];
    lbry_algo->hash(lbry.data, kLbryNonce, lbry_hash);
    const unsigned char *lbry_hash_bytes =
        reinterpret_cast<const unsigned char *>(lbry_hash);
    if (std::memcmp(lbry_hash, kLbryDigest, sizeof kLbryDigest) != 0) {
        fail("the reassembled block did not hash to its own digest");
        print_bytes("expected", kLbryDigest, 32);
        print_bytes("got", lbry_hash_bytes, 32);
    }

    // The claim that makes the rest of it mean something: these bytes in this
    // order are a solution the network accepted. A layout that happened to
    // hash cleanly but put a field in the wrong place would not clear this.
    //
    // be32dec, not the le32dec the builder takes: those four bytes are the
    // number 0x1a00c8ef written down, and the header stores it backwards. The
    // miner only ever needs the reversed spelling -- nbits_to_diff swaps it
    // back itself -- so this is the one place the value is read as itself.
    unsigned char lbry_target[32];
    nbits_to_target(be32dec(kLbryNbits), lbry_target);
    if (!below(lbry_hash_bytes, lbry_target)) {
        fail("the block's digest does not clear the target its own nBits set");
        print_bytes("target", lbry_target, 32);
        print_bytes("hash", lbry_hash_bytes, 32);
    }

    // What a builder that kept Bitcoin's header would have produced. The
    // claimtrie root is the one field with no local source, so leaving it zero
    // is the failure that looks most like working: the miner hashes, finds
    // shares, and the pool rejects every one of them.
    struct work no_claim;
    std::memset(&no_claim, 0, sizeof no_claim);
    const unsigned char zero_claim[32] = { 0 };
    lbry_build_block_header(&no_claim, le32dec(kLbryVersion),
                            lbry_prevhash, lbry_merkle, zero_claim,
                            le32dec(kLbryNtime), le32dec(kLbryNbits));
    no_claim.data[opt_nonce_index] = kLbryNonce;

    unsigned char without[112];
    lbry_header_bytes(&no_claim, without);
    if (std::memcmp(without, kLbryHeader, 68) != 0 ||
        std::memcmp(without + 100, kLbryHeader + 100, 12) != 0)
        fail("dropping the claimtrie root moved a field that is not it");

    uint32_t no_claim_hash[8];
    lbry_algo->hash(no_claim.data, kLbryNonce, no_claim_hash);
    if (std::memcmp(no_claim_hash, kLbryDigest, sizeof kLbryDigest) == 0)
        fail("the claimtrie root does not reach the hash");

    // And the path a real job takes into it: the same coinbase as above,
    // through std_build_extraheader, which is where the dialect chooses a
    // builder. The two shapes are compared against each other rather than
    // against a stored header, because the coinbase here has been rolled and
    // the merkle root is whatever that roll made it -- what has to hold is
    // that the lbry header is the Bitcoin one with 32 bytes inserted.
    struct work bitcoin_shape, lbry_shape;
    std::memset(&bitcoin_shape, 0, sizeof bitcoin_shape);
    std::memset(&lbry_shape, 0, sizeof lbry_shape);

    opt_stratum_dialect = STRATUM_BITCOIN;
    std_build_extraheader(&bitcoin_shape, &sctx);

    // job.extra holds what hex2bin made of the notify's claim parameter, so it
    // is the word-swapped spelling; the header it has to produce is the other
    // one. Comparing those two is the point of this leg -- with the same bytes
    // on both sides it passes without the swap ever happening.
    std::memcpy(sctx.job.extra, kLbryClaim, sizeof sctx.job.extra);
    opt_stratum_dialect = STRATUM_LBRY;
    std_build_extraheader(&lbry_shape, &sctx);

    unsigned char shape80[80], shape112[112];
    header_bytes(&bitcoin_shape, shape80);
    lbry_header_bytes(&lbry_shape, shape112);

    // Version, prevhash and merkle root: the same job, in the same place.
    if (std::memcmp(shape112, shape80, 68) != 0)
        fail("the lbry dialect changed the part of the header it shares with "
             "Bitcoin's");
    if (std::memcmp(shape112 + 68, kLbryHeader + 68, 32) != 0)
        fail("the claimtrie root the job carried did not reach the header");
    if (std::memcmp(shape112 + 100, shape80 + 68, 8) != 0)
        fail("ntime and nbits did not move along by the claimtrie root");

    // Back to sha256d, which is the switch a running miner makes over the
    // control API. The layout has to go with it: a miner left on lbry's
    // indices would submit an 80-byte job's nonce from a word past its end.
    vkminer::bind_protocol_settings("sha256d");
    if (opt_stratum_dialect != STRATUM_BITCOIN ||
        opt_ntime_index != STD_NTIME_INDEX ||
        opt_nbits_index != STD_NBITS_INDEX ||
        opt_nonce_index != STD_NONCE_INDEX)
        fail("switching away from 'lbry' left its header layout behind");

    // ---- groestl ---------------------------------------------------------
    // One SHA-256 of the coinbase, not two.
    vkminer::bind_protocol_settings("groestl");
    if (!opt_coinbase_sha256)
        fail("'groestl' did not select a single-SHA-256 coinbase txid");

    struct stratum_ctx grs;
    std::memset(&grs, 0, sizeof grs);
    grs.job.coinbase = const_cast<unsigned char *>(kGrsCoinbase);
    grs.job.coinbase_size = sizeof kGrsCoinbase;
    grs.job.merkle_count = 0;
    // A notify carries these three big-endian; the header holds them little.
    for (int i = 0; i < 4; i++) {
        grs.job.version[i] = kGrsHeader[3 - i];
        grs.job.ntime[i] = kGrsHeader[68 + 3 - i];
        grs.job.nbits[i] = kGrsHeader[72 + 3 - i];
    }

    struct work grs_work;
    std::memset(&grs_work, 0, sizeof grs_work);
    std_build_extraheader(&grs_work, &grs);
    grs_work.data[STD_NONCE_INDEX] = be32dec(kGrsHeader + 76);
    unsigned char grs_built[80];
    header_bytes(&grs_work, grs_built);
    if (std::memcmp(grs_built, kGrsHeader, 80) != 0) {
        fail("Groestlcoin's genesis coinbase did not rebuild its header");
        print_bytes("expected", kGrsHeader, 80);
        print_bytes("got", grs_built, 80);
    }

    // Back on sha256d the same coinbase must give another root.
    vkminer::bind_protocol_settings("sha256d");
    if (opt_coinbase_sha256)
        fail("switching away from 'groestl' left its coinbase hash behind");
    std::memset(&grs_work, 0, sizeof grs_work);
    std_build_extraheader(&grs_work, &grs);
    header_bytes(&grs_work, grs_built);
    if (std::memcmp(grs_built + 36, kGrsHeader + 36, 32) == 0)
        fail("a SHA-256d coinbase gave Groestlcoin's merkle root");

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("stratum: an accepted share rebuilds from its job, "
                "hashes and verifies correctly, and rolling extranonce2 "
                "rebuilds it again\n");
    std::printf("stratum: a mined lbry block rebuilds from its fields, clears "
                "its own nBits, and a job's claimtrie root reaches the header "
                "with everything after it eight words along\n");
    std::printf("stratum: Groestlcoin's genesis coinbase rebuilds its header "
                "with a single-SHA-256 txid, and sha256d's double hash does "
                "not\n");
    return 0;
}
