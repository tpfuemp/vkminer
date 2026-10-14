// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// heavyhash: Optical Bitcoin's proof of work, and Ursula's since its fork.
//
//     digest = SHA3-256( first ^ pack( M * nibbles( first ) >> 10 ) ),
//     first  = SHA3-256( header )
//
// with M a 64x64 matrix of 4-bit entries drawn from the previous block hash
// (src/core/heavyhash.c). Everything else is Bitcoin's: 80-byte header, nonce
// in word 19, SHA-256d merkle root, difficulty scale and stratum. The host
// builds the matrix once per previous block hash; the kernel reads it from its
// uniform block.

#include "algorithms/heavyhash/heavyhash.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/heavyhash.h"
#include "core/miner.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block heavyhash_kernel.glsl declares, sha3t's exactly: the
// whole header, since an 80-byte message is one absorbed block.
struct HeavyhashPush {
    uint32_t block[19];  // header words 0..18, byte-reversed
    uint32_t target[8];  // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(HeavyhashPush) == 120,
              "heavyhash_kernel.glsl's push block is 120 bytes");
static_assert(offsetof(HeavyhashPush, target) == 76, "push block layout");
static_assert(offsetof(HeavyhashPush, nonce_start) == 108, "push block layout");

// The uniform block: column j at words 32j .. 32j + 31, word k holding row 2k
// in its low half and row 2k + 1 in its high half.
struct HeavyhashUniform {
    uint32_t words[64 * 32];
};

static_assert(sizeof(HeavyhashUniform) == 8192,
              "heavyhash_kernel.glsl's uniform block is 8192 bytes");
static_assert(sizeof(HeavyhashUniform) <= kMaxUniformBytes,
              "the backend stages a uniform block of at most kMaxUniformBytes");

// The header as it went over the wire, from struct work's words. The nonce
// bytes are left zero; the matrix never reads them.
void wire_header(const uint32_t *header, unsigned char out[80])
{
    for (size_t i = 0; i < 19; i++)
        be32enc(out + i * 4, header[i]);
    std::memset(out + 76, 0, 4);
}

// The matrix for this header's previous block hash, cached per thread (hash()
// runs on whichever thread re-checks a candidate) until the hash changes.
const uint8_t (*matrix_for(const unsigned char wire[80]))[64]
{
    struct Cache {
        bool valid = false;
        unsigned char prev[32];
        uint8_t matrix[64][64];
    };
    static thread_local Cache cache;

    if (!cache.valid || std::memcmp(cache.prev, wire + 4, 32) != 0) {
        heavyhash_matrix(cache.matrix, wire);
        std::memcpy(cache.prev, wire + 4, 32);
        cache.valid = true;
    }
    return cache.matrix;
}

// ------------------------------------------------------------- the vectors
//
// OBTC's two genesis headers. The PoW hash is the block id there, so the
// digests are the ids obtc-core's chainparams.cpp asserts, byte-reversed.
// Their previous hash is zero, so the third header, a child of the mainnet
// genesis, covers the matrix seed; its digest is from an independent Python
// transcription, not from the chain.
const unsigned char kHeaderMain[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf5, 0xfe, 0xbb, 0xad, 0x19, 0x86, 0x4a, 0x69,
    0x00, 0xb6, 0xce, 0x84, 0x28, 0x75, 0x11, 0xe6,
    0xe7, 0x46, 0x22, 0x9c, 0xe6, 0x23, 0x9f, 0xf3,
    0xdf, 0x74, 0x81, 0x65, 0x47, 0x78, 0xa4, 0xc4,
    0xd3, 0xe1, 0x5d, 0x60,
    0xff, 0xff, 0x00, 0x1c,
    0x07, 0x47, 0xd0, 0x42,
};

// 0000000000115c7a7e3ff65d77ee96de527953ca6e43e77246929741408f95c0
const unsigned char kDigestMain[32] = {
    0xc0, 0x95, 0x8f, 0x40, 0x41, 0x97, 0x92, 0x46,
    0x72, 0xe7, 0x43, 0x6e, 0xca, 0x53, 0x79, 0x52,
    0xde, 0x96, 0xee, 0x77, 0x5d, 0xf6, 0x3f, 0x7e,
    0x7a, 0x5c, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeaderTest[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf5, 0xfe, 0xbb, 0xad, 0x19, 0x86, 0x4a, 0x69,
    0x00, 0xb6, 0xce, 0x84, 0x28, 0x75, 0x11, 0xe6,
    0xe7, 0x46, 0x22, 0x9c, 0xe6, 0x23, 0x9f, 0xf3,
    0xdf, 0x74, 0x81, 0x65, 0x47, 0x78, 0xa4, 0xc4,
    0xe5, 0xf0, 0xbf, 0x60,
    0xff, 0x3f, 0x00, 0x1d,
    0x1b, 0xcb, 0x80, 0x7b,
};

// 00000000248ecbf08dbd9470a22a4bd3497e25abd132676b55c4ed33f1613256
const unsigned char kDigestTest[32] = {
    0x56, 0x32, 0x61, 0xf1, 0x33, 0xed, 0xc4, 0x55,
    0x6b, 0x67, 0x32, 0xd1, 0xab, 0x25, 0x7e, 0x49,
    0xd3, 0x4b, 0x2a, 0xa2, 0x70, 0x94, 0xbd, 0x8d,
    0xf0, 0xcb, 0x8e, 0x24, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeaderChild[80] = {
    0x00, 0x00, 0x00, 0x20,
    0xc0, 0x95, 0x8f, 0x40, 0x41, 0x97, 0x92, 0x46,
    0x72, 0xe7, 0x43, 0x6e, 0xca, 0x53, 0x79, 0x52,
    0xde, 0x96, 0xee, 0x77, 0x5d, 0xf6, 0x3f, 0x7e,
    0x7a, 0x5c, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf5, 0xfe, 0xbb, 0xad, 0x19, 0x86, 0x4a, 0x69,
    0x00, 0xb6, 0xce, 0x84, 0x28, 0x75, 0x11, 0xe6,
    0xe7, 0x46, 0x22, 0x9c, 0xe6, 0x23, 0x9f, 0xf3,
    0xdf, 0x74, 0x81, 0x65, 0x47, 0x78, 0xa4, 0xc4,
    0x30, 0xe4, 0x5d, 0x60,
    0xff, 0xff, 0x00, 0x1c,
    0x78, 0x56, 0x34, 0x12,
};

const unsigned char kDigestChild[32] = {
    0x85, 0x7c, 0x06, 0x63, 0x78, 0x76, 0xad, 0xff,
    0xa6, 0x7b, 0x8d, 0xa4, 0xd0, 0x7b, 0x6b, 0xdc,
    0x62, 0x13, 0xf8, 0x6d, 0xa3, 0xfd, 0x3f, 0xf5,
    0x4d, 0xd4, 0x38, 0x41, 0x95, 0xba, 0xb7, 0x4c,
};

// The nonces are the byte swap of the ones chainparams.cpp passes, as for
// SHA-256d.
const KnownAnswer kAnswers[] = {
    { "OBTC mainnet genesis", kHeaderMain, 0x0747d042, kDigestMain },
    { "OBTC testnet genesis", kHeaderTest, 0x1bcb807b, kDigestTest },
    { "child of the OBTC mainnet genesis", kHeaderChild, 0x78563412,
      kDigestChild },
};

class Heavyhash final : public Algorithm {
public:
    const char *name() const override { return "heavyhash"; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // Two modules over one text, as for sha3t. The opening guess is the 2x32
    // one even where both build: it was the faster one wherever measured.
    // The tuner races both.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
        (void)device;
        return spec_for(false);
    }

    // Both where both build, 64-bit first; the tuner picks.
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

    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(HeavyhashPush))
            return 0;

        HeavyhashPush push;

        unsigned char wire[80];
        wire_header(dispatch.header, wire);
        for (size_t i = 0; i < 19; i++)
            push.block[i] = le32dec(wire + i * 4);

        std::memcpy(push.target, dispatch.target, sizeof push.target);
        // The low half: this kernel's nonce is one header word, as hash()'s is.
        push.nonce_start = static_cast<uint32_t>(dispatch.nonce_start);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    // The matrix, rearranged for the kernel. Every dispatch, but the matrix
    // itself is made only when the previous block hash moves.
    size_t prepare_uniform(const Dispatch &dispatch, void *out,
                           size_t capacity) const override
    {
        if (!dispatch.header || capacity < sizeof(HeavyhashUniform))
            return 0;

        unsigned char wire[80];
        wire_header(dispatch.header, wire);
        const uint8_t (*m)[64] = matrix_for(wire);

        HeavyhashUniform block;
        for (size_t j = 0; j < 64; j++)
            for (size_t k = 0; k < 32; k++)
                block.words[32 * j + k] =
                    static_cast<uint32_t>(m[2 * k][j])
                    | static_cast<uint32_t>(m[2 * k + 1][j]) << 16;

        std::memcpy(out, &block, sizeof block);
        return sizeof block;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        unsigned char wire[80];
        wire_header(header, wire);
        be32enc(wire + 76, static_cast<uint32_t>(nonce));

        unsigned char digest[32];
        heavyhash_core(digest, matrix_for(wire), wire, sizeof wire);

        // SHA3 squeezes little-endian, already the order fulltest() compares.
        for (size_t i = 0; i < 8; i++)
            out[i] = le32dec(digest + i * 4);
    }

private:
    KernelSpec spec_for(bool wide) const
    {
        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        spec.variant = wide ? "int64" : "2x32";

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, since the spec points into it. One
        // Algorithm per worker, so no lock.
        ShaderModule &module = wide ? module64_ : module32_;
        if (module.words.empty()
            && !load_shader(wide ? "heavyhash" : "heavyhash32", &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // A shader --algo-dir supplies may declare its own layout; believe it.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(HeavyhashPush);
        spec.uniform_bytes = sizeof(HeavyhashUniform);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module64_;
    mutable ShaderModule module32_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_heavyhash()
{
    return std::unique_ptr<Algorithm>(new Heavyhash());
}

}  // namespace vkminer
