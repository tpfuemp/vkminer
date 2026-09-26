// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// lbry: a chain of five hashes over a 112-byte block header.
//
//     h1  = SHA256( SHA256( header ) )
//     h2  = SHA512( h1 )
//     out = SHA256( SHA256( RIPEMD160( h2[0..31] ) || RIPEMD160( h2[32..63] ) ) )
//
// LBRY Credits mines this. Three things about it are not Bitcoin, and each one
// is a way to ship a miner that hashes correctly and has every share rejected.
//
// The header is 112 bytes, not 80: Bitcoin's with a 32-byte claimtrie root
// spliced in after the merkle root, so version(4) + prevhash(32) +
// merkleroot(32) + claimtrie(32) + time(4) + bits(4) + nonce(4). The nonce is
// word 27 rather than word 19, still in the second SHA-256 block but three
// words later than Bitcoin's.
//
// A difficulty of 1 means 2^40 hashes here, not 2^32, so target_factor() is
// 256. Nothing about the hash says so -- it is the chain's choice about what a
// pool's quoted difficulty means, and getting it wrong submits 256x too many
// shares or 256x too few.
//
// RIPEMD-160 is little-endian, which SHA-2 is not. The two boundaries around
// the RIPEMD pair are the only places in the chain where a word changes
// convention; everywhere else each stage eats the previous stage's digest bytes
// untouched. See lbry_kernel.glsl, which makes the same two swaps.
//
// Byte order at the edges is SHA-256d's: struct work holds each header word as
// a big-endian read of the wire, and the digest comes back as little-endian
// words, the order fulltest() compares in.

#include "algorithms/lbry/lbry.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/ripemd160.h"
#include "core/sha256.h"
#include "core/sha512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block lbry_kernel.glsl declares: exactly the 128 bytes
// Vulkan guarantees. The GLSL and this struct are one definition written in two
// languages, and only the asserts would notice them drifting apart.
//
// Everything that does not depend on the nonce is done on the host: the first
// block's compression, and twelve rounds and ten schedule words of the second.
// Only the top 64 bits of the target fit; the host re-checks all 256.
struct LbryPush {
    uint32_t midstate[8];   // SHA-256 state after header words 0..15
    uint32_t midbuffer[8];  // and after twelve rounds of the block that follows
    uint32_t sched[10];     // that block's w[16..25], five of them short a term
    uint32_t tail10;        // header word 26, which is w[10] and is read again
    uint32_t target[2];     // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(LbryPush) == 128,
              "lbry_kernel.glsl's push block is 128 bytes");
static_assert(sizeof(LbryPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(LbryPush, midbuffer) == 32, "push block layout");
static_assert(offsetof(LbryPush, sched) == 64, "push block layout");
static_assert(offsetof(LbryPush, tail10) == 104, "push block layout");
static_assert(offsetof(LbryPush, target) == 108, "push block layout");
static_assert(offsetof(LbryPush, nonce_start) == 116, "push block layout");

// ---------------------------------------------------------------- the hash

// The scalar reference, and the oracle every candidate is re-checked against.
// Five calls, no state, nothing shared between the stages: that is what the
// algorithm is, and writing it any other way would make a shared bug with the
// shader possible.
void lbry_hash_112(void *out, const unsigned char header[112])
{
    unsigned char h1[32], h2[64], r[40];

    sha256d(h1, header, 112);
    sha512_full(h2, h1, 32);
    // The low half first. The two are independent, so only the order they are
    // concatenated in distinguishes this from a hash of the same bytes.
    ripemd160_full(r, h2, 32);
    ripemd160_full(r + 20, h2 + 32, 32);
    sha256d(out, r, 40);
}

// ------------------------------------------------------------- the vectors

// Three mainnet headers, rebuilt field by field from what a block explorer
// reports and checked two independent ways.
//
// First the block id: lbrycrd overrides GetPoWHash() and leaves Bitcoin's
// GetHash() alone, so the id an explorer prints is plain SHA-256d of these 112
// bytes. That anchors the layout and every byte-order decision in building it,
// while saying nothing about SHA-512 or RIPEMD-160. Second the proof of work:
// each digest below is under the target that block's own nBits encodes, which
// only the hash the network agreed on can achieve. The pair pins the layout to
// a published number and the arithmetic to consensus.
//
// The three are six years and three difficulty regimes apart, so a nonce, a
// timestamp or a claimtrie root that is benign in one is not benign in all.
//
// Digests are in memory order, the display hash read backwards. The trailing
// zero bytes are the proof of work's leading zeros: a byte-order mistake puts
// them at the other end, visible without counting.

// Block 100000, mined December 2016. Id
// 095b46877b987c07ce608c706d4fdd6d760e7da43f8c8063af5c445b7d9efae2, nBits
// 0x1b0411c8.
const unsigned char kHeader100000[112] = {
    0x00, 0x00, 0x00, 0x20,
    0x24, 0xcb, 0xdc, 0x86, 0x44, 0xee, 0x39, 0x83,
    0xe6, 0x6b, 0x00, 0x3a, 0x07, 0x33, 0x89, 0x1c,
    0x06, 0x9c, 0xa7, 0x4c, 0x11, 0x4c, 0x03, 0x4c,
    0x7b, 0x3e, 0x2e, 0x7a, 0xd7, 0xa1, 0x2c, 0xd6,
    0x7e, 0x95, 0xe0, 0x55, 0x5c, 0x0e, 0x05, 0x6f,
    0x6f, 0x2a, 0xf5, 0x38, 0x26, 0x8f, 0xf9, 0xd2,
    0x1b, 0x42, 0x0e, 0x52, 0x97, 0x50, 0xd0, 0x8e,
    0xac, 0xb2, 0x5c, 0x40, 0xf1, 0x32, 0x29, 0x36,
    0x63, 0x71, 0x09, 0xb8, 0xa0, 0x51, 0x15, 0x76,
    0x04, 0xc1, 0xc1, 0x63, 0xcd, 0x39, 0x23, 0x76,
    0x87, 0xf6, 0x24, 0x4b, 0x4e, 0x6d, 0x2b, 0x3a,
    0x94, 0xe9, 0xd8, 0x16, 0xba, 0xba, 0xec, 0xbb,
    0x10, 0xc5, 0x60, 0x58,
    0xc8, 0x11, 0x04, 0x1b,
    0x2b, 0x9c, 0x43, 0x00,
};

const unsigned char kDigest100000[32] = {
    0xc2, 0xcb, 0x70, 0x3a, 0x38, 0xa7, 0x46, 0xc8,
    0xcf, 0xba, 0x95, 0x7f, 0x2d, 0xa4, 0xaa, 0xf4,
    0x78, 0xfa, 0x7a, 0xe1, 0xeb, 0x9c, 0xce, 0x5e,
    0x06, 0x68, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Block 700000, mined January 2020. Id
// beaf6432c9a7be3ea8c333bd7a90d4b3e07b0f20c86aa2e5dfebc9eba340201c, nBits
// 0x1a02509e.
const unsigned char kHeader700000[112] = {
    0x00, 0x00, 0x00, 0x20,
    0xdf, 0xc7, 0x52, 0x61, 0xcf, 0xd4, 0x14, 0xab,
    0xa4, 0x00, 0xd1, 0x8a, 0x78, 0x61, 0x7a, 0x64,
    0xb5, 0x13, 0xe4, 0x8b, 0x10, 0xb7, 0xf6, 0x7d,
    0x8f, 0xaa, 0xe5, 0x95, 0x9f, 0xfc, 0x76, 0x17,
    0x1e, 0xd7, 0x1e, 0x8e, 0x93, 0x61, 0x47, 0xb2,
    0x6d, 0xda, 0x91, 0x52, 0xee, 0x93, 0x5f, 0xc9,
    0x91, 0xec, 0xfd, 0xfa, 0xeb, 0xd5, 0x59, 0xd3,
    0x77, 0xca, 0xdf, 0x09, 0x8d, 0x4e, 0xea, 0xe0,
    0x4d, 0xe1, 0x64, 0x59, 0xb1, 0xf8, 0xc2, 0x0f,
    0xc4, 0x07, 0x06, 0xd9, 0xdb, 0x4d, 0x0b, 0x51,
    0x22, 0xf8, 0x45, 0x0a, 0x49, 0x20, 0x8f, 0xb6,
    0xcb, 0x84, 0xfc, 0x27, 0x6d, 0x7f, 0x0a, 0x9c,
    0x16, 0x8c, 0x1f, 0x5e,
    0x9e, 0x50, 0x02, 0x1a,
    0x90, 0x96, 0xdb, 0x19,
};

const unsigned char kDigest700000[32] = {
    0xda, 0x04, 0xb9, 0xf4, 0x02, 0xc2, 0xed, 0x60,
    0xd8, 0xb9, 0xe5, 0x54, 0xe4, 0xc9, 0xb6, 0xa3,
    0x08, 0xcd, 0x31, 0x64, 0x0d, 0x38, 0xce, 0x13,
    0x0d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Block 1300000, mined January 2023. Id
// 3d8b48a930a029ad31a22d5e5beee413b9b6f7902e29537448d8e2d6a00b407c, nBits
// 0x1a00c8ef.
const unsigned char kHeader1300000[112] = {
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

const unsigned char kDigest1300000[32] = {
    0xae, 0x30, 0xcf, 0x78, 0x2b, 0x5a, 0xd9, 0x57,
    0x37, 0x54, 0x5d, 0x00, 0x2f, 0x7e, 0xd2, 0x15,
    0x31, 0x10, 0xfc, 0xb6, 0x53, 0xa0, 0x6e, 0x93,
    0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The nonces are the byte swap of the one an explorer prints, as for SHA-256d:
// every word of work.data is a big-endian read of the wire, the nonce included.
const KnownAnswer kAnswers[] = {
    { "LBC block 100000",  kHeader100000,  0x2b9c4300, kDigest100000  },
    { "LBC block 700000",  kHeader700000,  0x9096db19, kDigest700000  },
    { "LBC block 1300000", kHeader1300000, 0x59a3d00e, kDigest1300000 },
};

class Lbry final : public Algorithm {
public:
    const char *name() const override { return "lbry"; }

    // Bitcoin's header with a 32-byte claimtrie root in the middle of it.
    size_t header_bytes() const override { return 112; }
    size_t nonce_word() const override { return 27; }

    // A difficulty of 1 is 2^40 hashes on this chain. The factor is not derived
    // from anything here; it is the chain's own convention, and both reference
    // miners set it to the same 256.
    double target_factor() const override { return 256.; }

    // The kernel screens on the top 64 bits; see LbryPush.
    int screen_bits() const override { return 64; }

    // Bitcoin's stratum, plus the claimtrie root the header needs and the
    // miner cannot compute. It has to come down the wire with the job, which
    // is the one place this protocol differs -- and it is why the header
    // build, and so every index into it, is lbry's own.
    StratumDialect stratum_dialect() const override
    {
        return StratumDialect::kLbry;
    }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // SHA-512's lane is 64 bits and shaderInt64 is optional, so the two shaders
    // are the same text compiled over two lane types -- the same split sha3t
    // makes, for the same reason and with the same constraint: Int64 is an
    // OpCapability declared for the module as a whole, so a device without the
    // feature rejects the module however unreachable its 64-bit half is. That
    // rules out a specialization constant and leaves two modules.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
#ifdef VKMINER_HAVE_SHADERS
        const bool wide = device.int64;

        // Only where the device leaves no choice. Where both build, this is a
        // guess the tuner is about to overrule, and the kernel logs which one
        // it really created.
        if (!wide && !announced_) {
            announced_ = true;
            applog(LOG_INFO, "lbry on %s: 32-bit lane pairs, because "
                             "shaderInt64 is not available here",
                   device.name.c_str());
        }

        return spec_for(wide);
#else
        (void)device;
        return spec_for(false);
#endif
    }

    // Both, where the device can build both. Which is faster is not a question
    // the feature bit answers -- on Ampere, which has no 64-bit integer ALU,
    // sha3t's 2x32 module beats its 64-bit one by 28% -- so the 64-bit one goes
    // first as the guess and the tuner settles it.
    size_t kernels(const DeviceInfo &device, KernelSpec *out,
                   size_t max) const override
    {
        size_t count = 0;
#ifdef VKMINER_HAVE_SHADERS
        if (device.int64 && count < max) {
            const KernelSpec spec = spec_for(true);
            if (spec.spirv)
                out[count++] = spec;
        }
#else
        (void)device;
#endif
        if (count < max) {
            const KernelSpec spec = spec_for(false);
            if (spec.spirv)
                out[count++] = spec;
        }
        return count;
    }

    // Everything that is the same for every nonce in the dispatch: the first
    // 64 bytes of the header, then the second block as far as it goes before
    // the nonce is needed.
    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target || capacity < sizeof(LbryPush))
            return 0;

        LbryPush push;

        // No swapping anywhere: each word already holds four header bytes in
        // the big-endian order SHA-256's message schedule reads them in.
        sha256_midstate(push.midstate, dispatch.header);

        // Words 16..26 are the rest of the header; 27 is the nonce, which the
        // kernel substitutes per invocation. Word 26 goes along separately
        // because the schedule reads it again at w[26].
        sha256_advance_nonce_block_112(push.midbuffer, push.sched,
                                       push.midstate, dispatch.header + 16);
        push.tail10 = dispatch.header[26];

        // The top 64 bits only; the host compares all 256 before submitting.
        push.target[0] = dispatch.target[6];
        push.target[1] = dispatch.target[7];

        // The low half, because this kernel's nonce is one header word -- the
        // same halving hash() makes, and the reason the two agree about which
        // nonces those are.
        push.nonce_start = static_cast<uint32_t>(dispatch.nonce_start);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        // 112 bytes: 27 header words as the pool sent them, then the nonce --
        // which is one of those words, so this algorithm's share of the 64-bit
        // nonce the two axes carry is its low half.
        unsigned char data[112];
        for (size_t i = 0; i < 27; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 27 * 4, static_cast<uint32_t>(nonce));

        lbry_hash_112(out, data);
    }

private:
    // One of the two modules, named so a log and a tuning file can say which
    // ran. A spec with no SPIR-V is not an error: the CPU backend still has the
    // reference.
    KernelSpec spec_for(bool wide) const
    {
        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        spec.variant = wide ? "int64" : "2x32";

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, because the spec hands out a pointer
        // into it. One Algorithm belongs to one worker, so this needs no lock.
        ShaderModule &module = wide ? module64_ : module32_;
        if (module.words.empty()
            && !load_shader(wide ? "lbry" : "lbry32", &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // A replacement shader loaded through --algo-dir may declare its own
        // layout, and then it is the one that has to be believed.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(LbryPush);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses
#else
        (void)wide;
#endif
        return spec;
    }

#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module64_;
    mutable ShaderModule module32_;

    // A device that cannot run the 64-bit module is worth one line: a run that
    // quietly took the other path is a run whose numbers describe something
    // else.
    mutable bool announced_ = false;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_lbry()
{
    return std::unique_ptr<Algorithm>(new Lbry());
}

}  // namespace vkminer
