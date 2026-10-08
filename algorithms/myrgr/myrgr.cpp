// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// myr-gr: SHA256( Groestl-512( header ) ), all 64 Groestl bytes hashed.
//
// Myriadcoin's groestl algorithm. Bitcoin's header, nonce word, difficulty
// scale and SHA-256d coinbase. The Groestl half is groestl's.

#include "algorithms/myrgr/myrgr.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/groestl512.h"
#include "core/sha256.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// groestl_kernel.glsl's push block; keep the two in step. Only the top 64 bits
// of the target go; the host re-checks all 256.
struct MyrgrPush {
    uint32_t header[19];  // header words 0..18, little-endian reads of the wire
    uint32_t target[2];   // the top 64 bits, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(MyrgrPush) == 96,
              "groestl_kernel.glsl's push block is 96 bytes");
static_assert(offsetof(MyrgrPush, target) == 76, "push block layout");
static_assert(offsetof(MyrgrPush, nonce_start) == 84, "push block layout");

// ------------------------------------------------------------- the vectors

// A Myriadcoin block id is SHA-256d, so each digest is anchored on clearing
// the header's own nBits. Groestl blocks only: version bits 9..11 == 2 and the
// auxpow bit 8 clear.

// Myriadcoin block 141851, mined April 2014. Id
// 67c593289c8bdbd0ebe98105996a781c21255d140aaee69c2e72cbde709360b2, proof of
// work 00000000001a8dd18765b749584efaade112f7bdc1b9b2ac57dd125b7098f947, nBits
// 0x1c009f82.
const unsigned char kMyr141851Header[80] = {
    0x02, 0x04, 0x00, 0x00,
    0x3e, 0xb9, 0xf8, 0xc6, 0xa5, 0xcf, 0x21, 0x0a,
    0xb1, 0x15, 0x2b, 0x10, 0x4b, 0xaa, 0xb1, 0xf1,
    0x5f, 0x03, 0xd6, 0x6b, 0xc5, 0x99, 0x7b, 0xf4,
    0x8d, 0x89, 0xd2, 0xef, 0xed, 0x90, 0x18, 0xc6,
    0x7c, 0x00, 0x56, 0xeb, 0x4b, 0x7b, 0x9b, 0x09,
    0x92, 0xe0, 0x3a, 0x54, 0x1b, 0x18, 0x23, 0xce,
    0x2a, 0xf5, 0x6d, 0x08, 0x5a, 0x73, 0xc2, 0xd9,
    0x9d, 0xd8, 0xcb, 0x9e, 0xb0, 0x28, 0x69, 0x8a,
    0x5e, 0x6b, 0x4a, 0x53,
    0x82, 0x9f, 0x00, 0x1c,
    0xd8, 0xa2, 0x0b, 0x01,
};

const unsigned char kMyr141851Digest[32] = {
    0x47, 0xf9, 0x98, 0x70, 0x5b, 0x12, 0xdd, 0x57,
    0xac, 0xb2, 0xb9, 0xc1, 0xbd, 0xf7, 0x12, 0xe1,
    0xad, 0xfa, 0x4e, 0x58, 0x49, 0xb7, 0x65, 0x87,
    0xd1, 0x8d, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Myriadcoin block 2210004, mined October 2017, with BIP9 bits in the version.
// Id b984f53a83d8d9fff5208d43dd69e7ac3c1df55565e72c3af532bc2a5237ec10, proof
// of work 00000000005d3c6d27c51216aff4ef1b87007d514f33fed68719cbbd773b9470,
// nBits 0x1b5ddd1d.
const unsigned char kMyr2210004Header[80] = {
    0x04, 0x04, 0x5a, 0x00,
    0x61, 0xc8, 0xf7, 0x4a, 0x76, 0x73, 0xe8, 0xfa,
    0x75, 0xab, 0x5f, 0x51, 0x57, 0x57, 0xbf, 0x6b,
    0xa2, 0x2f, 0xaf, 0x3d, 0xa4, 0x2c, 0x29, 0x04,
    0x93, 0x3e, 0x69, 0x35, 0xc8, 0xeb, 0x2a, 0x7a,
    0xc3, 0x2d, 0x0d, 0x00, 0x5a, 0x77, 0xa5, 0xdc,
    0x94, 0xae, 0x92, 0x32, 0xd4, 0x31, 0x09, 0xb7,
    0x95, 0xc7, 0xf0, 0xf5, 0x74, 0x2d, 0xde, 0xe3,
    0x9b, 0x0b, 0xd8, 0x7b, 0xe8, 0x03, 0x73, 0x41,
    0x7e, 0x23, 0xe0, 0x59,
    0x1d, 0xdd, 0x5d, 0x1b,
    0xc2, 0x94, 0xeb, 0x06,
};

const unsigned char kMyr2210004Digest[32] = {
    0x70, 0x94, 0x3b, 0x77, 0xbd, 0xcb, 0x19, 0x87,
    0xd6, 0xfe, 0x33, 0x4f, 0x51, 0x7d, 0x00, 0x87,
    0x1b, 0xef, 0xf4, 0xaf, 0x16, 0x12, 0xc5, 0x27,
    0x6d, 0x3c, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Myriadcoin block 2772293, mined April 2019. Id
// 4c6c7e4d166c2d198a4a2331ec95864789fbf063c074b0198d19ebd2c020dfe8, proof of
// work 00000000000030093e111d64e4138b71d510f2f55fea4b2b313cd47d59ba527a, nBits
// 0x1b008147.
const unsigned char kMyr2772293Header[80] = {
    0x00, 0x04, 0x5a, 0x20,
    0xcb, 0xb7, 0x82, 0x22, 0xfb, 0xf3, 0xc5, 0x20,
    0x78, 0x8e, 0x0b, 0x8d, 0x6f, 0x06, 0x3d, 0xea,
    0x19, 0x34, 0x52, 0xa5, 0xf3, 0xcb, 0x46, 0xf3,
    0x98, 0xd5, 0x70, 0xf5, 0x4c, 0x06, 0xf9, 0x2f,
    0x1f, 0x31, 0x9f, 0x7b, 0x15, 0x20, 0x14, 0x8d,
    0x34, 0x5b, 0x49, 0x65, 0x18, 0x00, 0xd0, 0xfd,
    0x28, 0x1b, 0x95, 0x60, 0xe5, 0x0d, 0xe1, 0x2f,
    0xcf, 0x91, 0x23, 0xaf, 0x41, 0x08, 0x26, 0x19,
    0x3f, 0x23, 0xbc, 0x5c,
    0x47, 0x81, 0x00, 0x1b,
    0x74, 0xbc, 0x57, 0x50,
};

const unsigned char kMyr2772293Digest[32] = {
    0x7a, 0x52, 0xba, 0x59, 0x7d, 0xd4, 0x3c, 0x31,
    0x2b, 0x4b, 0xea, 0x5f, 0xf5, 0xf2, 0x10, 0xd5,
    0x71, 0x8b, 0x13, 0xe4, 0x64, 0x1d, 0x11, 0x3e,
    0x09, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Myriadcoin block 3731705, mined October 2026. Id
// 16e165eab8d8b3ca865f2473aed1729b120a4b0687d2afed7acd10593e576301, proof of
// work 0000000000018940c13a018edb0756c3c9f87f281fa08017fdedd8bfa51c4e74, nBits
// 0x1b02954f.
const unsigned char kMyr3731705Header[80] = {
    0x00, 0x04, 0x5a, 0x20,
    0xcc, 0x7e, 0xb6, 0xfa, 0x25, 0x54, 0xdd, 0x11,
    0xee, 0xf8, 0x47, 0x87, 0xd9, 0x96, 0xf9, 0xfe,
    0x13, 0xf3, 0x21, 0xc3, 0x9c, 0xd2, 0xe1, 0x72,
    0xb3, 0xa9, 0xd8, 0x45, 0xca, 0x6e, 0x8b, 0x9f,
    0xfc, 0x12, 0x8f, 0x10, 0x38, 0xdb, 0x4d, 0x34,
    0xed, 0xfd, 0x2b, 0xb3, 0x7e, 0x1c, 0x93, 0xd2,
    0x43, 0x0b, 0x5f, 0x43, 0x4a, 0x0a, 0x5b, 0xf4,
    0x54, 0x1b, 0x57, 0x9f, 0xe3, 0x7b, 0xa8, 0xb3,
    0xdd, 0x56, 0xc7, 0x6a,
    0x4f, 0x95, 0x02, 0x1b,
    0xa1, 0x70, 0x27, 0xe0,
};

const unsigned char kMyr3731705Digest[32] = {
    0x74, 0x4e, 0x1c, 0xa5, 0xbf, 0xd8, 0xed, 0xfd,
    0x17, 0x80, 0xa0, 0x1f, 0x28, 0x7f, 0xf8, 0xc9,
    0xc3, 0x56, 0x07, 0xdb, 0x8e, 0x01, 0x3a, 0xc1,
    0x40, 0x89, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Nonces are byte-swapped from what an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "MYR block 141851",   kMyr141851Header,   0xd8a20b01, kMyr141851Digest  },
    { "MYR block 2210004",  kMyr2210004Header,  0xc294eb06, kMyr2210004Digest },
    { "MYR block 2772293",  kMyr2772293Header,  0x74bc5750, kMyr2772293Digest },
    { "MYR block 3731705",  kMyr3731705Header,  0xa17027e0, kMyr3731705Digest },
};

class Myrgr final : public Algorithm {
public:
    const char *name() const override { return "myr-gr"; }

    // The kernel screens on the top 64 bits; see MyrgrPush.
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
        if (module_.words.empty() && !load_shader("myrgr", &module_))
            return spec;

        spec.spirv = module_.words.data();
        spec.spirv_words = module_.words.size();

        // A shader from --algo-dir may declare its own layout; believe it.
        spec.storage_buffers = module_.storage_buffers
                             ? module_.storage_buffers : 1;
        spec.push_constant_bytes = module_.push_constant_bytes
                                 ? module_.push_constant_bytes
                                 : sizeof(MyrgrPush);
        spec.local_size_x = module_.local_size_x;  // 0: the backend chooses
        spec.nonces_per_invocation = 2;
#endif
        return spec;
    }

    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(MyrgrPush))
            return 0;

        MyrgrPush push;

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

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, static_cast<uint32_t>(nonce));

        unsigned char groestl[64];
        groestl512_full(groestl, data, sizeof data);
        sha256_full(out, groestl, sizeof groestl);
    }

private:
#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_myrgr()
{
    return std::unique_ptr<Algorithm>(new Myrgr());
}

}  // namespace vkminer
