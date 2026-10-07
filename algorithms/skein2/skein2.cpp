// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// skein2: Skein-512-512 of the 80-byte block header, then Skein-512-512 of
// that, cut to the first 32 bytes.
//
// Woodcoin's proof of work; its block id is SHA-256d. Bitcoin's header, nonce
// at word 19, difficulty on Bitcoin's scale.
//
// The first 64 header bytes hold no nonce, so prepare() runs their Skein block
// and pushes the chaining value. Skein reads little-endian words, so header
// words are swapped back to wire order on the host.

#include "algorithms/skein2/skein2.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/skein512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block skein2_kernel.glsl declares; keep the two in step.
// Only the top 64 bits of the target go; the host re-checks all 256.
struct Skein2Push {
    uint32_t midstate[16];  // the chaining value after bytes 0..63, low half first
    uint32_t tail[3];       // header words 16..18, little-endian reads of the wire
    uint32_t target[2];     // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Skein2Push) == 96,
              "skein2_kernel.glsl's push block is 96 bytes");
static_assert(sizeof(Skein2Push) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(Skein2Push, target) == 76, "push block layout");
static_assert(offsetof(Skein2Push, nonce_start) == 84, "push block layout");

// ------------------------------------------------------------- the vectors

// Woodcoin's block id is SHA-256d, so each header is anchored on its id and
// each digest on clearing the header's own nBits.

// Woodcoin genesis, mined October 2014. Id
// 30758383eae55ae5c7752b73388c1c85bdfbe930ad25ad877252841ed1e734a4, proof of
// work 00000f36ceeabb4fa0e3915d9f9d5d0c56bf24c574a24ba25646309854b50201, nBits
// 0x1e0ffff0.
const unsigned char kLogGenesisHeader[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd6, 0x31, 0x83, 0xd5, 0x2e, 0x0a, 0xa8, 0xbc,
    0x18, 0x81, 0xf9, 0xad, 0x68, 0x5e, 0x2a, 0x39,
    0x37, 0x3b, 0xdc, 0x67, 0xc7, 0xe1, 0xf8, 0xc1,
    0x95, 0x05, 0xc0, 0x6e, 0x91, 0xb7, 0x08, 0xd5,
    0xec, 0x23, 0x45, 0x54,
    0xf0, 0xff, 0x0f, 0x1e,
    0x95, 0x47, 0x18, 0x00,
};

const unsigned char kLogGenesisDigest[32] = {
    0x01, 0x02, 0xb5, 0x54, 0x98, 0x30, 0x46, 0x56,
    0xa2, 0x4b, 0xa2, 0x74, 0xc5, 0x24, 0xbf, 0x56,
    0x0c, 0x5d, 0x9d, 0x9f, 0x5d, 0x91, 0xe3, 0xa0,
    0x4f, 0xbb, 0xea, 0xce, 0x36, 0x0f, 0x00, 0x00,
};

// Woodcoin block 612, mined October 2014. Id
// 04f4046893d471beaaad633cead45dda536d1090917b1db061af24e708c7427e, proof of
// work 000000000005f75252ebb2d45b3d9804a5bcfd0d24df4583d955656a89ff08e8, nBits
// 0x1c355175.
const unsigned char kLog612Header[80] = {
    0x01, 0x00, 0x00, 0x00,
    0xff, 0x82, 0xf6, 0xd0, 0x7b, 0x31, 0x20, 0x4e,
    0xcf, 0x23, 0x00, 0x81, 0x08, 0xa8, 0x44, 0x18,
    0xa3, 0x20, 0x2a, 0xc2, 0x83, 0x22, 0xf2, 0x47,
    0x27, 0x09, 0xe6, 0x5e, 0xff, 0xa3, 0x1b, 0xe5,
    0x30, 0x89, 0x36, 0xb5, 0x80, 0xfa, 0x93, 0xb6,
    0x52, 0x81, 0xe7, 0x76, 0x36, 0x6b, 0x94, 0xb1,
    0xf3, 0x10, 0xef, 0x86, 0x21, 0xe8, 0xfe, 0xfa,
    0x8f, 0xc2, 0x1e, 0x86, 0x8a, 0x78, 0xb3, 0x2b,
    0x23, 0x66, 0x49, 0x54,
    0x75, 0x51, 0x35, 0x1c,
    0xdf, 0xdf, 0x04, 0x03,
};

const unsigned char kLog612Digest[32] = {
    0xe8, 0x08, 0xff, 0x89, 0x6a, 0x65, 0x55, 0xd9,
    0x83, 0x45, 0xdf, 0x24, 0x0d, 0xfd, 0xbc, 0xa5,
    0x04, 0x98, 0x3d, 0x5b, 0xd4, 0xb2, 0xeb, 0x52,
    0x52, 0xf7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Woodcoin block 2756085, mined October 2026. Id
// 6f91f771cbb0445c6444feb316f4652d26d7689d56faede66cb0eeee842f790f, proof of
// work 000000000f2ca3480228a8c977d8b32642da8c6c16a44077aa2e68daa83c080b, nBits
// 0x1d05a678.
const unsigned char kLog2756085Header[80] = {
    0x00, 0x00, 0x00, 0x20,
    0xcd, 0xd3, 0xec, 0x56, 0x5d, 0xff, 0x94, 0xed,
    0xec, 0xca, 0x11, 0x7f, 0x52, 0x70, 0x57, 0xe8,
    0x5f, 0x58, 0x7b, 0xb7, 0xc0, 0xaa, 0xb8, 0xfb,
    0xc5, 0xbd, 0xc2, 0xb2, 0x22, 0xe3, 0x5e, 0x94,
    0x3b, 0x24, 0xf2, 0x7c, 0xdf, 0xfb, 0x8a, 0x2a,
    0xeb, 0xbe, 0x2a, 0x24, 0xed, 0xe5, 0x60, 0x21,
    0x1b, 0xef, 0x95, 0x5c, 0xa9, 0xce, 0x0e, 0xaa,
    0x89, 0x7f, 0xa2, 0x9f, 0x0a, 0x13, 0xc7, 0x04,
    0x3a, 0x57, 0xc5, 0x6a,
    0x78, 0xa6, 0x05, 0x1d,
    0x02, 0x39, 0xa4, 0x11,
};

const unsigned char kLog2756085Digest[32] = {
    0x0b, 0x08, 0x3c, 0xa8, 0xda, 0x68, 0x2e, 0xaa,
    0x77, 0x40, 0xa4, 0x16, 0x6c, 0x8c, 0xda, 0x42,
    0x26, 0xb3, 0xd8, 0x77, 0xc9, 0xa8, 0x28, 0x02,
    0x48, 0xa3, 0x2c, 0x0f, 0x00, 0x00, 0x00, 0x00,
};

// Woodcoin block 2755585, mined October 2026. Id
// a752899811959ea4861a754d3875b37f32d81de8783d7ede71e8773a2f3d6290, proof of
// work 0000000344f578ae4f52bef7c3045750c71d43debc1ea63f6eab4a6edb7ece2e, nBits
// 0x1d05ca9f.
const unsigned char kLog2755585Header[80] = {
    0x00, 0x00, 0x00, 0x20,
    0x35, 0x61, 0x7c, 0xd3, 0xc8, 0xcb, 0x4f, 0xb4,
    0x82, 0x03, 0xb3, 0xf7, 0x31, 0x7d, 0xb2, 0x24,
    0x4e, 0xc0, 0x0e, 0x21, 0xb8, 0xf9, 0x8b, 0x96,
    0xf9, 0x4e, 0xcb, 0x38, 0x5a, 0x05, 0xd8, 0xce,
    0xdc, 0x22, 0xb0, 0x84, 0xb6, 0x14, 0x88, 0x14,
    0x13, 0xce, 0xb1, 0xbb, 0xaa, 0xe1, 0x51, 0x2f,
    0x2e, 0x4f, 0x07, 0xc7, 0x98, 0xb5, 0x08, 0xb1,
    0x67, 0x6f, 0x98, 0xf1, 0xed, 0xcd, 0x13, 0xe1,
    0xe6, 0x5e, 0xc4, 0x6a,
    0x9f, 0xca, 0x05, 0x1d,
    0x82, 0x97, 0xb1, 0x70,
};

const unsigned char kLog2755585Digest[32] = {
    0x2e, 0xce, 0x7e, 0xdb, 0x6e, 0x4a, 0xab, 0x6e,
    0x3f, 0xa6, 0x1e, 0xbc, 0xde, 0x43, 0x1d, 0xc7,
    0x50, 0x57, 0x04, 0xc3, 0xf7, 0xbe, 0x52, 0x4f,
    0xae, 0x78, 0xf5, 0x44, 0x03, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "LOG genesis",        kLogGenesisHeader,  0x95471800, kLogGenesisDigest },
    { "LOG block 612",      kLog612Header,      0xdfdf0403, kLog612Digest     },
    { "LOG block 2755585",  kLog2755585Header,  0x8297b170, kLog2755585Digest },
    { "LOG block 2756085",  kLog2756085Header,  0x0239a411, kLog2756085Digest },
};

class Skein2 final : public Algorithm {
public:
    const char *name() const override { return "skein2"; }

    // The kernel screens on the top 64 bits; see Skein2Push.
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
            applog(LOG_INFO, "skein2 on %s: 32-bit lane pairs, because "
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
            || capacity < sizeof(Skein2Push))
            return 0;

        Skein2Push push;

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

        unsigned char first[64], second[64];
        skein512_full(first, data, sizeof data);
        skein512_full(second, first, sizeof first);
        std::memcpy(out, second, 32);
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
            "skein2", "skein2_wide", "skein2_32" };

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
                                 : sizeof(Skein2Push);
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

std::unique_ptr<Algorithm> make_skein2()
{
    return std::unique_ptr<Algorithm>(new Skein2());
}

}  // namespace vkminer
