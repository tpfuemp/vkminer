// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// groestl: Groestl-512 of the 80-byte block header, then Groestl-512 of that,
// cut to the first 32 bytes.
//
// Groestlcoin's proof of work and block hash. Bitcoin's header, nonce at word
// 19. A stratum difficulty is 256 times easier than Bitcoin's, and the
// coinbase txid is a single SHA-256.
//
// Groestl reads its message bytes in order, so header words are swapped back
// to wire order on the host and uploaded as little-endian reads.

#include "algorithms/groestl/groestl.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/groestl512.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block groestl_kernel.glsl declares; keep the two in step.
// Only the top 64 bits of the target go; the host re-checks all 256.
struct GroestlPush {
    uint32_t header[19];  // header words 0..18, little-endian reads of the wire
    uint32_t target[2];   // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(GroestlPush) == 96,
              "groestl_kernel.glsl's push block is 96 bytes");
static_assert(offsetof(GroestlPush, target) == 76, "push block layout");
static_assert(offsetof(GroestlPush, nonce_start) == 84, "push block layout");

// ------------------------------------------------------------- the vectors

// Groestlcoin's block id is this hash, so each digest is the published id in
// memory order.

// Groestlcoin genesis, mined March 2014. Id
// 00000ac5927c594d49cc0bdb81759d0da8297eb614683d3acb62f0703b639023, nBits
// 0x1e0fffff.
const unsigned char kGrsGenesisHeader[80] = {
    0x70, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbb, 0x28, 0x66, 0xaa, 0xca, 0x46, 0xc4, 0x42,
    0x8a, 0xd0, 0x8b, 0x57, 0xbc, 0x9d, 0x14, 0x93,
    0xab, 0xaf, 0x64, 0x72, 0x4b, 0x6c, 0x30, 0x52,
    0xa7, 0xc8, 0xf9, 0x58, 0xdf, 0x68, 0xe9, 0x3c,
    0xed, 0x3d, 0x2b, 0x53,
    0xff, 0xff, 0x0f, 0x1e,
    0x83, 0x5b, 0x03, 0x00,
};

const unsigned char kGrsGenesisDigest[32] = {
    0x23, 0x90, 0x63, 0x3b, 0x70, 0xf0, 0x62, 0xcb,
    0x3a, 0x3d, 0x68, 0x14, 0xb6, 0x7e, 0x29, 0xa8,
    0x0d, 0x9d, 0x75, 0x81, 0xdb, 0x0b, 0xcc, 0x49,
    0x4d, 0x59, 0x7c, 0x92, 0xc5, 0x0a, 0x00, 0x00,
};

// Groestlcoin block 1000000, mined March 2016. Id
// 000000000df8560f2612d5f28b52ed1cf81b0f87ac0c9c7242cbcf721ca6854a, nBits
// 0x1c1a008a.
const unsigned char kGrs1000000Header[80] = {
    0x03, 0x00, 0x00, 0x00,
    0xb3, 0x3a, 0x09, 0xb2, 0xc7, 0x55, 0x26, 0xaa,
    0xed, 0x7d, 0xff, 0xe9, 0xb7, 0xd4, 0x9c, 0x3f,
    0x40, 0xed, 0x92, 0x09, 0x61, 0x0a, 0x69, 0xc1,
    0xa9, 0x56, 0xe5, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x89, 0x46, 0x05, 0xc4, 0xe2, 0x28, 0x26,
    0xc9, 0x0e, 0x6c, 0xf9, 0x94, 0x66, 0xd9, 0x73,
    0x68, 0x47, 0x1a, 0x54, 0x79, 0x08, 0xe7, 0x07,
    0x3d, 0x31, 0x24, 0xac, 0x0d, 0xa9, 0x7d, 0x49,
    0x09, 0x8a, 0xde, 0x56,
    0x8a, 0x00, 0x1a, 0x1c,
    0xb3, 0xfa, 0x17, 0x08,
};

const unsigned char kGrs1000000Digest[32] = {
    0x4a, 0x85, 0xa6, 0x1c, 0x72, 0xcf, 0xcb, 0x42,
    0x72, 0x9c, 0x0c, 0xac, 0x87, 0x0f, 0x1b, 0xf8,
    0x1c, 0xed, 0x52, 0x8b, 0xf2, 0xd5, 0x12, 0x26,
    0x0f, 0x56, 0xf8, 0x0d, 0x00, 0x00, 0x00, 0x00,
};

// Groestlcoin block 4000000, mined March 2022. Id
// 0000000000000e48fb994ec0e5a5c64a83582f8504fa713af6045ae95cd4a207, nBits
// 0x1a1248bc.
const unsigned char kGrs4000000Header[80] = {
    0x00, 0x00, 0x00, 0x20,
    0x34, 0xe4, 0x3b, 0x19, 0x67, 0x38, 0x65, 0xb9,
    0x17, 0x6b, 0xf0, 0x9d, 0x3e, 0x95, 0x26, 0x94,
    0x04, 0x09, 0xfe, 0x94, 0xf8, 0x7c, 0x1e, 0x41,
    0xee, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0e, 0xf7, 0xb9, 0x70, 0x84, 0xba, 0x9a, 0xc5,
    0xbc, 0xfc, 0xbf, 0xeb, 0x5d, 0xd5, 0x7f, 0x8a,
    0x61, 0x5d, 0x60, 0xd6, 0x87, 0xb8, 0xcc, 0x95,
    0xe5, 0x6e, 0x45, 0x12, 0x02, 0x0b, 0x68, 0x63,
    0x55, 0x75, 0x2b, 0x62,
    0xbc, 0x48, 0x12, 0x1a,
    0x01, 0x89, 0xf7, 0x76,
};

const unsigned char kGrs4000000Digest[32] = {
    0x07, 0xa2, 0xd4, 0x5c, 0xe9, 0x5a, 0x04, 0xf6,
    0x3a, 0x71, 0xfa, 0x04, 0x85, 0x2f, 0x58, 0x83,
    0x4a, 0xc6, 0xa5, 0xe5, 0xc0, 0x4e, 0x99, 0xfb,
    0x48, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Groestlcoin block 6289200, mined October 2026. Id
// 00000000000031e1f019964a15d5489d205574c4863f5b572ef106cf479bed56, nBits
// 0x1b00e887.
const unsigned char kGrs6289200Header[80] = {
    0x00, 0x00, 0x00, 0x20,
    0xed, 0xf1, 0x44, 0x44, 0xd9, 0x5c, 0x84, 0xd1,
    0xd3, 0xb3, 0x2a, 0x72, 0x70, 0x2a, 0x85, 0x97,
    0x25, 0x39, 0x4e, 0xd1, 0x50, 0xfb, 0xed, 0x65,
    0x58, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5e, 0x9d, 0xb4, 0xf2, 0x22, 0x6a, 0x96, 0xb7,
    0x57, 0x5b, 0x7a, 0x7f, 0xa8, 0x22, 0x07, 0xe0,
    0xd9, 0x8c, 0x38, 0x82, 0x0a, 0x08, 0xd4, 0x3f,
    0x17, 0xb0, 0x37, 0x3c, 0x8b, 0xc7, 0x67, 0x41,
    0x21, 0x1e, 0xc6, 0x6a,
    0x87, 0xe8, 0x00, 0x1b,
    0x20, 0x9e, 0x2c, 0xb6,
};

const unsigned char kGrs6289200Digest[32] = {
    0x56, 0xed, 0x9b, 0x47, 0xcf, 0x06, 0xf1, 0x2e,
    0x57, 0x5b, 0x3f, 0x86, 0xc4, 0x74, 0x55, 0x20,
    0x9d, 0x48, 0xd5, 0x15, 0x4a, 0x96, 0x19, 0xf0,
    0xe1, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "GRS genesis",        kGrsGenesisHeader,   0x835b0300, kGrsGenesisDigest  },
    { "GRS block 1000000",  kGrs1000000Header,   0xb3fa1708, kGrs1000000Digest  },
    { "GRS block 4000000",  kGrs4000000Header,   0x0189f776, kGrs4000000Digest  },
    { "GRS block 6289200",  kGrs6289200Header,   0x209e2cb6, kGrs6289200Digest  },
};

class Groestl final : public Algorithm {
public:
    const char *name() const override { return "groestl"; }

    double target_factor() const override { return 256.; }

    bool coinbase_sha256() const override { return true; }

    // The kernel screens on the top 64 bits; see GroestlPush.
    int screen_bits() const override { return 64; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // One module: 32-bit words only. Bitsliced, two nonces to an invocation.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
        (void)device;

        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, since the spec points into it. One
        // Algorithm per worker, so no lock.
        if (module_.words.empty() && !load_shader(name(), &module_))
            return spec;

        spec.spirv = module_.words.data();
        spec.spirv_words = module_.words.size();

        // A shader from --algo-dir may declare its own layout; believe it.
        spec.storage_buffers = module_.storage_buffers
                             ? module_.storage_buffers : 1;
        spec.push_constant_bytes = module_.push_constant_bytes
                                 ? module_.push_constant_bytes
                                 : sizeof(GroestlPush);
        spec.local_size_x = module_.local_size_x;  // 0: the backend chooses
        spec.nonces_per_invocation = 2;
#endif
        return spec;
    }

    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(GroestlPush))
            return 0;

        GroestlPush push;

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

    // The scalar reference, kept simple: two independent calls.
    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, static_cast<uint32_t>(nonce));

        unsigned char first[64], second[64];
        groestl512_full(first, data, sizeof data);
        groestl512_full(second, first, sizeof first);
        std::memcpy(out, second, 32);
    }

private:
#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_groestl()
{
    return std::unique_ptr<Algorithm>(new Groestl());
}

}  // namespace vkminer
