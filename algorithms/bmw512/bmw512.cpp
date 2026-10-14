// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// bmw512: BMW-512 of the 80-byte block header, cut to the first 32 bytes.
//
// DigitalNote's proof of work and block id. Bitcoin's header, nonce at word
// 19. Header words go to the device in wire order; header and padding are one
// block, so there is no midstate. Most of the first compression does not read
// the nonce, though: the host computes that part and the kernel reads it from
// a uniform block (bmw512_80_precompute() in src/core/bmw512.c).

#include "algorithms/bmw512/bmw512.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/bmw512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block bmw512_kernel.glsl declares; keep the two in step.
// Only the top 64 bits of the target go; the host re-checks all 256.
struct Bmw512Push {
    uint32_t header[19];  // header words 0..18, little-endian reads of the wire
    uint32_t target[2];   // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Bmw512Push) == 96,
              "bmw512_kernel.glsl's push block is 96 bytes");
static_assert(offsetof(Bmw512Push, target) == 76, "push block layout");
static_assert(offsetof(Bmw512Push, nonce_start) == 84, "push block layout");

// The uniform block bmw512_kernel.glsl declares: bmw512_80_precompute()'s 35
// words as (low, high) pairs, padded to std140's sixteen-byte array stride.
struct Bmw512Uniform {
    uint32_t words[72];
};

static_assert(sizeof(Bmw512Uniform) == 288,
              "bmw512_kernel.glsl's uniform block is 288 bytes");

// ------------------------------------------------------------- the vectors

// DigitalNote's block id is this hash, so each digest is the published id in
// memory order. All are proof-of-work blocks.

// DigitalNote block 0, mined January 2019. Id
// 00000d8e7d39218c4c02132e95a3896d46939b9b95624cf9dd2b0b794e6c216a, nBits
// 0x1f03ffff.
const unsigned char kXdn0Header[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4a, 0x00, 0x23, 0x34, 0xd5, 0x53, 0x3a, 0x74,
    0xb8, 0x95, 0x14, 0x01, 0x03, 0x94, 0xca, 0x41,
    0x3a, 0xa8, 0x34, 0xe3, 0xd5, 0x30, 0xea, 0xd1,
    0x54, 0x0d, 0x37, 0xb1, 0x2c, 0x15, 0x9d, 0x3b,
    0x60, 0x4c, 0x42, 0x5c,
    0xff, 0xff, 0x03, 0x1f,
    0x64, 0x37, 0x00, 0x00,
};

const unsigned char kXdn0Digest[32] = {
    0x6a, 0x21, 0x6c, 0x4e, 0x79, 0x0b, 0x2b, 0xdd,
    0xf9, 0x4c, 0x62, 0x95, 0x9b, 0x9b, 0x93, 0x46,
    0x6d, 0x89, 0xa3, 0x95, 0x2e, 0x13, 0x02, 0x4c,
    0x8c, 0x21, 0x39, 0x7d, 0x8e, 0x0d, 0x00, 0x00,
};

// DigitalNote block 1, mined January 2019. Id
// 0000246c37061884d4f9a390cf0db25cca1525a63f01f906367d5af1c409a8aa, nBits
// 0x1f03ffff.
const unsigned char kXdn1Header[80] = {
    0x07, 0x00, 0x00, 0x00,
    0x6a, 0x21, 0x6c, 0x4e, 0x79, 0x0b, 0x2b, 0xdd,
    0xf9, 0x4c, 0x62, 0x95, 0x9b, 0x9b, 0x93, 0x46,
    0x6d, 0x89, 0xa3, 0x95, 0x2e, 0x13, 0x02, 0x4c,
    0x8c, 0x21, 0x39, 0x7d, 0x8e, 0x0d, 0x00, 0x00,
    0x91, 0xb4, 0x49, 0x80, 0x1c, 0x1e, 0xcf, 0x12,
    0x66, 0x43, 0xca, 0x49, 0x29, 0x2c, 0xa3, 0x0e,
    0x9e, 0x8c, 0xb3, 0x61, 0xe4, 0xbd, 0x04, 0x23,
    0x12, 0x7b, 0x90, 0x50, 0x75, 0xc6, 0x10, 0xa4,
    0x3e, 0x89, 0x4d, 0x5c,
    0xff, 0xff, 0x03, 0x1f,
    0x00, 0x00, 0x34, 0x0f,
};

const unsigned char kXdn1Digest[32] = {
    0xaa, 0xa8, 0x09, 0xc4, 0xf1, 0x5a, 0x7d, 0x36,
    0x06, 0xf9, 0x01, 0x3f, 0xa6, 0x25, 0x15, 0xca,
    0x5c, 0xb2, 0x0d, 0xcf, 0x90, 0xa3, 0xf9, 0xd4,
    0x84, 0x18, 0x06, 0x37, 0x6c, 0x24, 0x00, 0x00,
};

// DigitalNote block 399997, mined July 2021. Id
// 0000000000032dc8000a1c58beec963e559fa1c73a58923a527ed2b29f526a8f, nBits
// 0x1b040f18.
const unsigned char kXdn399997Header[80] = {
    0x07, 0x00, 0x00, 0x00,
    0xae, 0x6a, 0x99, 0xbf, 0xf5, 0xec, 0xe3, 0x71,
    0x97, 0xb5, 0x21, 0xa0, 0x3b, 0xff, 0x6b, 0x32,
    0x45, 0x3c, 0xbc, 0x18, 0x67, 0xf7, 0x2f, 0x53,
    0x04, 0x00, 0xf9, 0xae, 0xe5, 0x03, 0x08, 0x2d,
    0x67, 0xb6, 0x6a, 0xd3, 0xf1, 0x9c, 0x44, 0x51,
    0x29, 0xc7, 0x34, 0xbb, 0xf9, 0x0d, 0x25, 0xa2,
    0xb6, 0x01, 0x97, 0xbd, 0x22, 0x6e, 0x59, 0x2d,
    0x7b, 0x4e, 0x5e, 0x7e, 0x7e, 0xb4, 0xdc, 0x4e,
    0x9c, 0x97, 0xf4, 0x60,
    0x18, 0x0f, 0x04, 0x1b,
    0x1f, 0xec, 0x8b, 0xa4,
};

const unsigned char kXdn399997Digest[32] = {
    0x8f, 0x6a, 0x52, 0x9f, 0xb2, 0xd2, 0x7e, 0x52,
    0x3a, 0x92, 0x58, 0x3a, 0xc7, 0xa1, 0x9f, 0x55,
    0x3e, 0x96, 0xec, 0xbe, 0x58, 0x1c, 0x0a, 0x00,
    0xc8, 0x2d, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// DigitalNote block 1239603, mined October 2026. Id
// 0000000000cb1b857caff4627b7c8b988a539f020543ed409ee54d7a03359b4e, nBits
// 0x1c019b04.
const unsigned char kXdn1239603Header[80] = {
    0x07, 0x00, 0x00, 0x00,
    0x4f, 0xfa, 0x3f, 0x5b, 0x2f, 0x07, 0x4c, 0x42,
    0xbf, 0xa4, 0x9e, 0x79, 0x78, 0x87, 0xed, 0x44,
    0x88, 0xfa, 0x18, 0x6b, 0x76, 0x69, 0x35, 0x96,
    0xab, 0x7e, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00,
    0xd0, 0xb3, 0x96, 0xb0, 0x00, 0x11, 0x3b, 0x71,
    0x44, 0x30, 0x72, 0xe4, 0x2c, 0xe6, 0x77, 0x75,
    0x90, 0x37, 0xfb, 0xa5, 0xf6, 0xad, 0x88, 0x14,
    0x82, 0xe9, 0xa2, 0x59, 0x1a, 0xff, 0x87, 0xd2,
    0x76, 0x06, 0xce, 0x6a,
    0x04, 0x9b, 0x01, 0x1c,
    0x5c, 0x2f, 0x84, 0x05,
};

const unsigned char kXdn1239603Digest[32] = {
    0x4e, 0x9b, 0x35, 0x03, 0x7a, 0x4d, 0xe5, 0x9e,
    0x40, 0xed, 0x43, 0x05, 0x02, 0x9f, 0x53, 0x8a,
    0x98, 0x8b, 0x7c, 0x7b, 0x62, 0xf4, 0xaf, 0x7c,
    0x85, 0x1b, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// DigitalNote block 1239605, mined October 2026. Id
// 00000000017f4a624128e9738ae3c7d1bb55df7dc373f46427b4bfba392f2404, nBits
// 0x1c019b03.
const unsigned char kXdn1239605Header[80] = {
    0x07, 0x00, 0x00, 0x00,
    0x3a, 0xeb, 0xdd, 0x3b, 0x88, 0x35, 0x6b, 0x5f,
    0x3c, 0xae, 0xb1, 0x25, 0x78, 0x4d, 0xc9, 0x05,
    0x3d, 0xae, 0x65, 0x74, 0xc5, 0xc1, 0x4d, 0x74,
    0xe8, 0xf6, 0x9a, 0x66, 0xa7, 0x51, 0x62, 0x36,
    0xcf, 0xcf, 0x30, 0x2f, 0x47, 0x49, 0x71, 0xe8,
    0x84, 0xe7, 0xcf, 0xbc, 0x6e, 0x7e, 0xcc, 0x1d,
    0x1a, 0xe3, 0xa4, 0xd4, 0x1c, 0xe6, 0x92, 0x54,
    0xe7, 0x01, 0x22, 0x80, 0xd0, 0x56, 0x98, 0x47,
    0x18, 0x08, 0xce, 0x6a,
    0x03, 0x9b, 0x01, 0x1c,
    0x09, 0xf4, 0xb9, 0x01,
};

const unsigned char kXdn1239605Digest[32] = {
    0x04, 0x24, 0x2f, 0x39, 0xba, 0xbf, 0xb4, 0x27,
    0x64, 0xf4, 0x73, 0xc3, 0x7d, 0xdf, 0x55, 0xbb,
    0xd1, 0xc7, 0xe3, 0x8a, 0x73, 0xe9, 0x28, 0x41,
    0x62, 0x4a, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
};

// DigitalNote block 1239619, mined October 2026. Id
// 0000000001038ae86aec7916f1b950eddc37c832b5219cd972d445df6b669c66, nBits
// 0x1c01b0a4.
const unsigned char kXdn1239619Header[80] = {
    0x07, 0x00, 0x00, 0x00,
    0xf9, 0xc3, 0x97, 0x64, 0x78, 0x92, 0xb6, 0x61,
    0xf4, 0x64, 0x63, 0x81, 0x97, 0xfa, 0xe2, 0xbe,
    0x7d, 0x54, 0x5c, 0xbd, 0xc7, 0xef, 0xad, 0x0a,
    0x75, 0x69, 0x5f, 0x26, 0xfe, 0xda, 0x85, 0x34,
    0x5d, 0x30, 0xfa, 0xe2, 0xfa, 0x20, 0xb2, 0x84,
    0x1e, 0x17, 0x4d, 0x35, 0x65, 0x90, 0x29, 0xf5,
    0x86, 0x0c, 0x6a, 0x94, 0x0b, 0x39, 0xf0, 0x39,
    0x11, 0x03, 0x5a, 0x68, 0xc8, 0xb8, 0x53, 0x7b,
    0xdd, 0x14, 0xce, 0x6a,
    0xa4, 0xb0, 0x01, 0x1c,
    0x06, 0xbe, 0xd6, 0x06,
};

const unsigned char kXdn1239619Digest[32] = {
    0x66, 0x9c, 0x66, 0x6b, 0xdf, 0x45, 0xd4, 0x72,
    0xd9, 0x9c, 0x21, 0xb5, 0x32, 0xc8, 0x37, 0xdc,
    0xed, 0x50, 0xb9, 0xf1, 0x16, 0x79, 0xec, 0x6a,
    0xe8, 0x8a, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "XDN block 0",       kXdn0Header,       0x64370000, kXdn0Digest       },
    { "XDN block 1",       kXdn1Header,       0x0000340f, kXdn1Digest       },
    { "XDN block 399997",  kXdn399997Header,  0x1fec8ba4, kXdn399997Digest  },
    { "XDN block 1239603", kXdn1239603Header, 0x5c2f8405, kXdn1239603Digest },
    { "XDN block 1239605", kXdn1239605Header, 0x09f4b901, kXdn1239605Digest },
    { "XDN block 1239619", kXdn1239619Header, 0x06bed606, kXdn1239619Digest },
};

class Bmw512 final : public Algorithm {
public:
    const char *name() const override { return "bmw512"; }

    // Pools quote bmw512 difficulty 256 times easier than the chain's.
    double target_factor() const override { return 256.; }

    // The kernel screens on the top 64 bits; see Bmw512Push.
    int screen_bits() const override { return 64; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // Three modules over one text, because Int64 is a module-wide capability:
    // int64, uvec2 lanes with 64-bit adds ("int64-wide"), and 2x32. The wide
    // one opens where it builds; the tuner races all three.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
#ifdef VKMINER_HAVE_SHADERS
        const bool wide = device.int64;

        if (!wide && !announced_) {
            announced_ = true;
            applog(LOG_INFO, "bmw512 on %s: 32-bit lane pairs, because "
                             "shaderInt64 is not available here",
                   device.name.c_str());
        }

        return spec_for(wide ? kWideAdd : kPairs);
#else
        (void)device;
        return spec_for(kPairs);
#endif
    }

    // Every module the device can build, 64-bit first; the tuner picks.
    size_t kernels(const DeviceInfo &device, KernelSpec *out,
                   size_t max) const override
    {
        size_t count = 0;
#ifdef VKMINER_HAVE_SHADERS
        if (device.int64) {
            for (Module m : { kWideAdd, kWide }) {
                const KernelSpec spec = spec_for(m);
                if (spec.spirv && count < max)
                    out[count++] = spec;
            }
        }
#else
        (void)device;
#endif
        if (count < max) {
            const KernelSpec spec = spec_for(kPairs);
            if (spec.spirv)
                out[count++] = spec;
        }
        return count;
    }

    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(Bmw512Push))
            return 0;

        Bmw512Push push;

        // Back to wire order, read little-endian.
        for (size_t i = 0; i < 19; i++) {
            unsigned char bytes[4];
            be32enc(bytes, dispatch.header[i]);
            push.header[i] = le32dec(bytes);
        }

        push.target[0] = dispatch.target[6];
        push.target[1] = dispatch.target[7];

        // The nonce is one header word; hash() truncates it the same way.
        push.nonce_start = static_cast<uint32_t>(dispatch.nonce_start);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    size_t prepare_uniform(const Dispatch &dispatch, void *out,
                           size_t capacity) const override
    {
        if (!dispatch.header || capacity < sizeof(Bmw512Uniform))
            return 0;

        // The nonce bytes stay zero; nothing written here reads them.
        unsigned char data[80] = {};
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, dispatch.header[i]);

        uint64_t words[35];
        bmw512_80_precompute(words, data);

        Bmw512Uniform block = {};
        for (size_t i = 0; i < 35; i++) {
            block.words[2 * i] = static_cast<uint32_t>(words[i]);
            block.words[2 * i + 1] = static_cast<uint32_t>(words[i] >> 32);
        }

        std::memcpy(out, &block, sizeof block);
        return sizeof block;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, static_cast<uint32_t>(nonce));

        unsigned char digest[64];
        bmw512_full(digest, data, sizeof data);
        std::memcpy(out, digest, 32);
    }

private:
    enum Module { kWide, kWideAdd, kPairs, kModules };

    // One of the modules. A spec with no SPIR-V is not an error: the CPU
    // backend still has the reference.
    KernelSpec spec_for(Module m) const
    {
        static const char *const kVariant[kModules] = {
            "int64", "int64-wide", "2x32" };
        static const char *const kShader[kModules] = {
            "bmw512", "bmw512_wide", "bmw512_32" };

        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        spec.variant = kVariant[m];

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, since the spec points into it. One
        // Algorithm per worker, so no lock.
        ShaderModule &module = modules_[m];
        if (module.words.empty() && !load_shader(kShader[m], &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // A shader from --algo-dir may declare its own layout; believe it.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(Bmw512Push);
        spec.uniform_bytes = sizeof(Bmw512Uniform);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule modules_[kModules];

    // A device that cannot run the 64-bit module is worth one line.
    mutable bool announced_ = false;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_bmw512()
{
    return std::unique_ptr<Algorithm>(new Bmw512());
}

}  // namespace vkminer
