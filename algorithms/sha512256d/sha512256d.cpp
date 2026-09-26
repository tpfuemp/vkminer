// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// sha512256d: SHA-512/256 applied twice over an 80-byte block header.
//
//     out = SHA512/256( SHA512/256( header ) )
//
// Radiant (RXD) uses it as both proof of work and block hash, so a block id is
// this digest. Bitcoin's header, nonce at word 19, difficulty on Bitcoin's
// scale (genesis nBits 0x1d00ffff).
//
// SHA-512/256 is SHA-512 from its own initial value (FIPS 180-4 5.3.6.2), cut
// to 32 bytes -- not SHA-512's output truncated.
//
// Byte order at the edges is SHA-256d's: header words are big-endian reads of
// the wire, the digest is little-endian words as fulltest() compares them.

#include "algorithms/sha512256d/sha512256d.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/sha512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block sha512256d_kernel.glsl declares; keep the two in
// step. No midstate: the state after the job-constant rounds 0..8 plus the
// message words the schedule still reads exceeds 128 bytes. Only the top 64
// bits of the target go; the host re-checks all 256.
struct Sha512256dPush {
    uint32_t header[19];  // header words 0..18; word 19 is the nonce
    uint32_t target[2];   // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Sha512256dPush) == 96,
              "sha512256d_kernel.glsl's push block is 96 bytes");
static_assert(sizeof(Sha512256dPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(Sha512256dPush, target) == 76, "push block layout");
static_assert(offsetof(Sha512256dPush, nonce_start) == 84, "push block layout");

// ------------------------------------------------------------- the vectors

// Three mainnet Radiant headers from three difficulty regimes. Radiant's
// block id is this algorithm, so each digest is the published id in memory
// order (the display hash reversed), and each clears its own nBits.

// Block 1000, mined June 2022. Id
// 0000000044e996ecaa61413b88f7a4b3c4d0d2afcbc5511e9780869769dd2e1b, nBits
// 0x1d00ffff.
const unsigned char kHeader1000[80] = {
    0x00, 0x00, 0x00, 0x20,
    0xba, 0x63, 0xa6, 0x12, 0xb3, 0x04, 0xfb, 0x75,
    0xe6, 0xfc, 0x32, 0xba, 0xc5, 0xfb, 0x6f, 0x87,
    0xe1, 0x1b, 0x5b, 0x22, 0xb2, 0xc4, 0x6a, 0xe4,
    0xf8, 0xae, 0xe4, 0xaf, 0x00, 0x00, 0x00, 0x00,
    0x38, 0xc5, 0x06, 0x89, 0x64, 0xf0, 0x20, 0x37,
    0x2b, 0x95, 0x50, 0x28, 0x92, 0xa6, 0xb0, 0xd0,
    0x5d, 0xff, 0x89, 0x66, 0x76, 0x2a, 0xcc, 0xdb,
    0x80, 0xa6, 0x4b, 0x2c, 0xc6, 0x44, 0xb7, 0xcb,
    0xed, 0x37, 0xb1, 0x62,
    0xff, 0xff, 0x00, 0x1d,
    0x2e, 0xc8, 0xe1, 0x6c,
};

const unsigned char kDigest1000[32] = {
    0x1b, 0x2e, 0xdd, 0x69, 0x97, 0x86, 0x80, 0x97,
    0x1e, 0x51, 0xc5, 0xcb, 0xaf, 0xd2, 0xd0, 0xc4,
    0xb3, 0xa4, 0xf7, 0x88, 0x3b, 0x41, 0x61, 0xaa,
    0xec, 0x96, 0xe9, 0x44, 0x00, 0x00, 0x00, 0x00,
};

// Block 100000, mined April 2023. Id
// 000000000000027dc3f6a5a811cf78b4b45a1e17a925d88fc8ae196c7ccf9c08, nBits
// 0x1a04f548.
const unsigned char kHeader100000[80] = {
    0x00, 0x00, 0x00, 0x20,
    0x9d, 0x6a, 0xa4, 0x36, 0x0e, 0xd0, 0xfc, 0x4e,
    0x09, 0x56, 0x11, 0xc7, 0x04, 0xca, 0xce, 0xf0,
    0x7f, 0x20, 0x0c, 0x69, 0x57, 0xb7, 0x3a, 0x42,
    0x91, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xd4, 0xd6, 0x00, 0xdc, 0x69, 0xaa, 0xbc, 0x68,
    0x51, 0x39, 0xe5, 0x35, 0x01, 0x77, 0xff, 0x6b,
    0xb8, 0x67, 0x37, 0x01, 0xc0, 0xc6, 0x22, 0xaa,
    0xd5, 0x25, 0x35, 0x03, 0x0b, 0x09, 0xbd, 0x0c,
    0x4e, 0x7b, 0x2c, 0x64,
    0x48, 0xf5, 0x04, 0x1a,
    0xe6, 0xbd, 0x02, 0x3a,
};

const unsigned char kDigest100000[32] = {
    0x08, 0x9c, 0xcf, 0x7c, 0x6c, 0x19, 0xae, 0xc8,
    0x8f, 0xd8, 0x25, 0xa9, 0x17, 0x1e, 0x5a, 0xb4,
    0xb4, 0x78, 0xcf, 0x11, 0xa8, 0xa5, 0xf6, 0xc3,
    0x7d, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Block 300000, mined February 2025. Id
// 000000000000000208b8226b4b725c79706b138f49c55f440d7f50297a9c56ee, nBits
// 0x1916d776.
const unsigned char kHeader300000[80] = {
    0x00, 0x00, 0x00, 0x20,
    0x3a, 0xe2, 0xd3, 0xa4, 0x24, 0xb0, 0x4a, 0x0b,
    0x10, 0x13, 0x3b, 0x62, 0xd8, 0x56, 0xad, 0xd0,
    0x50, 0x4e, 0x5c, 0xb3, 0x60, 0x9a, 0xa1, 0xd0,
    0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x72, 0xa5, 0x7d, 0xbb, 0xd3, 0xff, 0x5a,
    0x6a, 0x3c, 0xc9, 0xdb, 0x5f, 0xd8, 0x4a, 0x13,
    0xb3, 0xc7, 0xa8, 0x8b, 0xee, 0x14, 0x04, 0x1f,
    0x9d, 0x45, 0x23, 0xe1, 0x3a, 0x3d, 0x37, 0x20,
    0xd9, 0xba, 0xb0, 0x67,
    0x76, 0xd7, 0x16, 0x19,
    0x7c, 0x61, 0x27, 0x95,
};

const unsigned char kDigest300000[32] = {
    0xee, 0x56, 0x9c, 0x7a, 0x29, 0x50, 0x7f, 0x0d,
    0x44, 0x5f, 0xc5, 0x49, 0x8f, 0x13, 0x6b, 0x70,
    0x79, 0x5c, 0x72, 0x4b, 0x6b, 0x22, 0xb8, 0x08,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "RXD block 1000",   kHeader1000,   0x2ec8e16c, kDigest1000   },
    { "RXD block 100000", kHeader100000, 0xe6bd023a, kDigest100000 },
    { "RXD block 300000", kHeader300000, 0x7c612795, kDigest300000 },
};

class Sha512256d final : public Algorithm {
public:
    const char *name() const override { return "sha512256d"; }

    // The kernel screens on the top 64 bits; see Sha512256dPush.
    int screen_bits() const override { return 64; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // Two modules over one text: Int64 is a module-wide capability.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
#ifdef VKMINER_HAVE_SHADERS
        const bool wide = device.int64;

        // Where both build, this is only the tuner's starting guess.
        if (!wide && !announced_) {
            announced_ = true;
            applog(LOG_INFO, "sha512256d on %s: 32-bit lane pairs, because "
                             "shaderInt64 is not available here",
                   device.name.c_str());
        }

        return spec_for(wide);
#else
        (void)device;
        return spec_for(false);
#endif
    }

    // Every module the device can build, 64-bit first; the tuner picks.
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
            || capacity < sizeof(Sha512256dPush))
            return 0;

        Sha512256dPush push;

        // No swap: the words are already big-endian, as SHA-512 reads them.
        std::memcpy(push.header, dispatch.header, sizeof push.header);

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

        unsigned char first[32];
        sha512_256_full(first, data, sizeof data);
        sha512_256_full(out, first, sizeof first);
    }

private:
    // One of the two modules. A spec with no SPIR-V is not an error: the CPU
    // backend still has the reference.
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
            && !load_shader(wide ? "sha512256d" : "sha512256d32", &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // A shader from --algo-dir may declare its own layout; believe it.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(Sha512256dPush);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses
#else
        (void)wide;
#endif
        return spec;
    }

#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module64_;
    mutable ShaderModule module32_;

    // A device that cannot run the 64-bit module is worth one line.
    mutable bool announced_ = false;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_sha512256d()
{
    return std::unique_ptr<Algorithm>(new Sha512256d());
}

}  // namespace vkminer
