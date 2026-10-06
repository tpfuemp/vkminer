// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// skein: Skein-512-512 of the 80-byte block header, then SHA-256 of that.
//
//     out = SHA256( Skein-512-512( header ) )
//
// Skeincoin's proof of work and block hash; also the skein algorithm of
// Auroracoin and DigiByte, whose block id is SHA-256d. Bitcoin's header, nonce
// at word 19, difficulty on Bitcoin's scale. The trailing SHA-256 is part of
// the algorithm.
//
// The first 64 header bytes hold no nonce, so prepare() runs their Skein block
// and pushes the chaining value. Skein reads little-endian words, so header
// words are swapped back to wire order on the host.

#include "algorithms/skein/skein.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/sha256.h"
#include "core/skein512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block skein_kernel.glsl declares; keep the two in step.
// Only the top 64 bits of the target go; the host re-checks all 256.
struct SkeinPush {
    uint32_t midstate[16];  // the chaining value after bytes 0..63, low half first
    uint32_t tail[3];       // header words 16..18, little-endian reads of the wire
    uint32_t target[2];     // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(SkeinPush) == 96, "skein_kernel.glsl's push block is 96 bytes");
static_assert(sizeof(SkeinPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(SkeinPush, target) == 76, "push block layout");
static_assert(offsetof(SkeinPush, nonce_start) == 84, "push block layout");

// ------------------------------------------------------------- the vectors

// Skeincoin's block id is this hash: its genesis ids, as its chainparams.cpp
// asserts them, in memory order. Auroracoin's block id is SHA-256d, so its
// mined headers are anchored on clearing their own nBits instead.

// Skeincoin genesis, November 2013. Id
// 0000046cebed69de151ada93a60cb8a5f9490a196399abe714bb83ad5b20f985, nBits
// 0x1e0fffff.
const unsigned char kSkcGenesisHeader[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x49, 0xb1, 0x56, 0x31, 0xcf, 0x03, 0x75,
    0x63, 0x2e, 0xdc, 0xf4, 0x93, 0x48, 0x68, 0x39,
    0x84, 0xb2, 0x9c, 0xd6, 0x30, 0xbe, 0x15, 0x3d,
    0x59, 0x07, 0x49, 0xbc, 0xe3, 0x85, 0xb3, 0xa4,
    0xcb, 0xb0, 0x73, 0x52,
    0xff, 0xff, 0x0f, 0x1e,
    0x4a, 0x11, 0xd0, 0x7c,
};

const unsigned char kSkcGenesisDigest[32] = {
    0x85, 0xf9, 0x20, 0x5b, 0xad, 0x83, 0xbb, 0x14,
    0xe7, 0xab, 0x99, 0x63, 0x19, 0x0a, 0x49, 0xf9,
    0xa5, 0xb8, 0x0c, 0xa6, 0x93, 0xda, 0x1a, 0x15,
    0xde, 0x69, 0xed, 0xeb, 0x6c, 0x04, 0x00, 0x00,
};

// Skeincoin testnet genesis. Id
// 00000015f9fb4c1c9cc55ad08b6ec47fcce2b00bc482a2c48914ab6506daf439, nBits
// 0x1e0fffff.
const unsigned char kSkcTestGenesisHeader[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa3, 0x49, 0xb1, 0x56, 0x31, 0xcf, 0x03, 0x75,
    0x63, 0x2e, 0xdc, 0xf4, 0x93, 0x48, 0x68, 0x39,
    0x84, 0xb2, 0x9c, 0xd6, 0x30, 0xbe, 0x15, 0x3d,
    0x59, 0x07, 0x49, 0xbc, 0xe3, 0x85, 0xb3, 0xa4,
    0x73, 0x86, 0x65, 0x52,
    0xff, 0xff, 0x0f, 0x1e,
    0x13, 0xb7, 0xcb, 0x18,
};

const unsigned char kSkcTestGenesisDigest[32] = {
    0x39, 0xf4, 0xda, 0x06, 0x65, 0xab, 0x14, 0x89,
    0xc4, 0xa2, 0x82, 0xc4, 0x0b, 0xb0, 0xe2, 0xcc,
    0x7f, 0xc4, 0x6e, 0x8b, 0xd0, 0x5a, 0xc5, 0x9c,
    0x1c, 0x4c, 0xfb, 0xf9, 0x15, 0x00, 0x00, 0x00,
};

// Auroracoin block 1000000, mined September 2017. Id
// e5289e4263ebef11e2970cd56698aa17f5bc5a895aa3b674fb5dda9e29351a3b, proof of
// work 000000000000de1c705a8dbd37c5812c6efe6d1ab3eae129d7ec28d4c1b402b2, nBits
// 0x1b04c431.
const unsigned char kAur1000000Header[80] = {
    0x02, 0x06, 0x00, 0x00,
    0xc1, 0xf9, 0xd2, 0x62, 0xfc, 0x68, 0x89, 0xfe,
    0x9f, 0xc3, 0x9e, 0xc8, 0xf1, 0xad, 0x61, 0xa9,
    0x6d, 0xc0, 0x4b, 0x56, 0x44, 0x87, 0xfe, 0x4f,
    0x23, 0x07, 0xf9, 0x4e, 0x49, 0x6d, 0xbf, 0x21,
    0x6a, 0x79, 0x72, 0x70, 0xc6, 0x1b, 0x87, 0x2f,
    0x6e, 0x57, 0x07, 0x13, 0xff, 0xe5, 0x58, 0x23,
    0x43, 0xa6, 0x37, 0xed, 0xeb, 0xab, 0x20, 0xcb,
    0x36, 0xf1, 0xf3, 0xb9, 0x91, 0xec, 0xcf, 0x08,
    0x15, 0x32, 0xbb, 0x59,
    0x31, 0xc4, 0x04, 0x1b,
    0xf3, 0x82, 0x56, 0xe3,
};

const unsigned char kAur1000000Digest[32] = {
    0xb2, 0x02, 0xb4, 0xc1, 0xd4, 0x28, 0xec, 0xd7,
    0x29, 0xe1, 0xea, 0xb3, 0x1a, 0x6d, 0xfe, 0x6e,
    0x2c, 0x81, 0xc5, 0x37, 0xbd, 0x8d, 0x5a, 0x70,
    0x1c, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Auroracoin block 3000003, mined April 2021. Id
// 62fcd5a15506fb829c688b81a9116f5a842c5dc178ebbed242b8f8a03666395e, proof of
// work 000000000000ac127e1aceac1d679306d1b8f755bc3cf235c49d51452a247d90, nBits
// 0x1b025dfb.
const unsigned char kAur3000003Header[80] = {
    0x02, 0x06, 0x00, 0x00,
    0xd1, 0x88, 0x72, 0x29, 0x02, 0x8d, 0x7a, 0x8f,
    0xc3, 0x1b, 0x3b, 0x56, 0x3f, 0x80, 0x31, 0xac,
    0xac, 0x33, 0xf7, 0x33, 0xa2, 0x30, 0xe0, 0x99,
    0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe6, 0xac, 0x51, 0x86, 0xdc, 0x7c, 0x3f, 0xb3,
    0x06, 0xf1, 0x84, 0x28, 0x54, 0x5c, 0x55, 0xad,
    0x7e, 0xed, 0xa3, 0xe6, 0x63, 0xdf, 0x57, 0xdb,
    0x7e, 0x18, 0x97, 0x18, 0x9f, 0xaa, 0x43, 0x06,
    0xa1, 0x09, 0x6e, 0x60,
    0xfb, 0x5d, 0x02, 0x1b,
    0x2c, 0x3f, 0x13, 0x66,
};

const unsigned char kAur3000003Digest[32] = {
    0x90, 0x7d, 0x24, 0x2a, 0x45, 0x51, 0x9d, 0xc4,
    0x35, 0xf2, 0x3c, 0xbc, 0x55, 0xf7, 0xb8, 0xd1,
    0x06, 0x93, 0x67, 0x1d, 0xac, 0xce, 0x1a, 0x7e,
    0x12, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Auroracoin block 5886783, mined October 2026, with BIP9 bits in the version.
// Id 6dea87b27af0272f6412fd427fddb8b2da49b27ea7a5bd6459e124fab4ee5cb9, proof of
// work 00000000000172d9749c10dd7547017bc70b4cf74aa8db7ece812b3b8aab31f5, nBits
// 0x1b02c79b.
const unsigned char kAur5886783Header[80] = {
    0x02, 0x06, 0x00, 0x20,
    0x94, 0xda, 0xec, 0xd1, 0xe3, 0x30, 0xf8, 0xf0,
    0x2b, 0xf3, 0x15, 0xc4, 0x92, 0xbe, 0xd6, 0xf6,
    0x92, 0x2c, 0x20, 0x31, 0xa1, 0x04, 0xcc, 0xd1,
    0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa1, 0x4a, 0x6a, 0x21, 0xf2, 0x37, 0x1c, 0xc3,
    0x42, 0xcb, 0x70, 0x80, 0x55, 0xa2, 0x16, 0xb6,
    0x54, 0x8b, 0xeb, 0x54, 0xad, 0x3c, 0xf1, 0xa4,
    0x06, 0xf9, 0x27, 0x3f, 0x4b, 0x4f, 0xa6, 0xa6,
    0x1a, 0x18, 0xc5, 0x6a,
    0x9b, 0xc7, 0x02, 0x1b,
    0x45, 0x9b, 0x35, 0x5d,
};

const unsigned char kAur5886783Digest[32] = {
    0xf5, 0x31, 0xab, 0x8a, 0x3b, 0x2b, 0x81, 0xce,
    0x7e, 0xdb, 0xa8, 0x4a, 0xf7, 0x4c, 0x0b, 0xc7,
    0x7b, 0x01, 0x47, 0x75, 0xdd, 0x10, 0x9c, 0x74,
    0xd9, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "SKC genesis",         kSkcGenesisHeader,     0x4a11d07c, kSkcGenesisDigest     },
    { "SKC testnet genesis", kSkcTestGenesisHeader, 0x13b7cb18, kSkcTestGenesisDigest },
    { "AUR block 1000000",   kAur1000000Header,     0xf38256e3, kAur1000000Digest     },
    { "AUR block 3000003",   kAur3000003Header,     0x2c3f1366, kAur3000003Digest     },
    { "AUR block 5886783",   kAur5886783Header,     0x459b355d, kAur5886783Digest     },
};

class Skein final : public Algorithm {
public:
    const char *name() const override { return "skein"; }

    // The kernel screens on the top 64 bits; see SkeinPush.
    int screen_bits() const override { return 64; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // Two modules over one text, because Int64 is a module-wide capability.
    // This is the opening guess; the tuner races both.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
#ifdef VKMINER_HAVE_SHADERS
        const bool wide = device.int64;

        if (!wide && !announced_) {
            announced_ = true;
            applog(LOG_INFO, "skein on %s: 32-bit lane pairs, because "
                             "shaderInt64 is not available here",
                   device.name.c_str());
        }

        return spec_for(wide ? kWide : kPairs);
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
        if (device.int64 && count < max) {
            const KernelSpec spec = spec_for(kWide);
            if (spec.spirv)
                out[count++] = spec;
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
            || capacity < sizeof(SkeinPush))
            return 0;

        SkeinPush push;

        // Back to wire order, which Skein reads little-endian.
        unsigned char wire[76];
        for (size_t i = 0; i < 19; i++)
            be32enc(wire + i * 4, dispatch.header[i]);

        uint64_t h[8];
        skein512_midstate(h, wire);
        for (size_t i = 0; i < 8; i++) {
            push.midstate[2 * i] = static_cast<uint32_t>(h[i]);
            push.midstate[2 * i + 1] = static_cast<uint32_t>(h[i] >> 32);
        }
        for (size_t i = 0; i < 3; i++)
            push.tail[i] = le32dec(wire + 64 + i * 4);

        push.target[0] = dispatch.target[6];
        push.target[1] = dispatch.target[7];

        // The nonce is one header word; hash() truncates it the same way.
        push.nonce_start = static_cast<uint32_t>(dispatch.nonce_start);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    // The scalar reference, kept simple: two independent calls.
    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, static_cast<uint32_t>(nonce));

        unsigned char skein[64];
        skein512_full(skein, data, sizeof data);
        sha256_full(out, skein, sizeof skein);
    }

private:
    enum Module { kWide, kPairs, kModules };

    // One of the modules. A spec with no SPIR-V is not an error: the CPU
    // backend still has the reference.
    KernelSpec spec_for(Module m) const
    {
        static const char *const kVariant[kModules] = { "int64", "2x32" };
        static const char *const kShader[kModules] = { "skein", "skein32" };

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
                                 : sizeof(SkeinPush);
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

std::unique_ptr<Algorithm> make_skein()
{
    return std::unique_ptr<Algorithm>(new Skein());
}

}  // namespace vkminer
