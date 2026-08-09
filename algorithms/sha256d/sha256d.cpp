// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SHA-256d: SHA-256 applied twice over an 80-byte block header. Bitcoin's
// algorithm, and the bring-up target here because it is simple enough to check
// by reading and has published test vectors going back to 2009.
//
// The whole of the difficulty is byte order, and it is worth stating exactly
// once. struct work carries the header as twenty 32-bit words in host order,
// each word holding a field the way the pool sent it. SHA-256 consumes bytes,
// big-endian. So each word is written out big-endian before hashing, and the
// digest that comes back is read as little-endian words, which is the order
// fulltest() compares in and the order Bitcoin prints a block hash reversed
// from. Getting this wrong produces a miner that benchmarks perfectly and has
// every share rejected -- see the known-answer test, which exists to make that
// failure impossible to ship.

#include "algorithms/sha256d/sha256d.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/sha256.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block sha256d.comp declares, and the reason the kernel has
// two SHA-256 compressions to do per nonce rather than four -- and now starts
// the first of them at round 4 rather than round 0.
//
// 124 bytes against a guaranteed minimum of 128, so this still fits on every
// device Vulkan allows to exist, but it no longer fits with room to spare.
// ⚠️ Anything added here from now on has to displace something, or move out of
// push constants entirely. The asserts below are not ceremony: the GLSL and
// this struct are one definition written in two languages, and nothing else
// would notice a word inserted in one of them.
struct Sha256dPush {
    uint32_t midstate[8];  // after header words 0..15; the feed-forward needs it
    uint32_t advanced[8];  // working variables entering round 4, at nonce 0
    uint32_t sched[4];     // message words 16..19, at nonce 0
    uint32_t target[8];    // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Sha256dPush) == 124,
              "sha256d.comp's push block is 124 bytes");
static_assert(sizeof(Sha256dPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(Sha256dPush, advanced) == 32, "push block layout");
static_assert(offsetof(Sha256dPush, sched) == 64, "push block layout");
static_assert(offsetof(Sha256dPush, target) == 80, "push block layout");
static_assert(offsetof(Sha256dPush, nonce_start) == 112, "push block layout");

// Two mainnet block headers, exactly as they went over the wire, and the
// digests they are known to produce. Both are checkable against any block
// explorer, which is the whole point: they anchor this miner's arithmetic to
// something outside this codebase.
//
// They are not redundant. 125552 is the vector everybody quotes -- version 1,
// a nonce well away from zero and not palindromic in either byte order.
// 957533 is a modern header, and it exercises what 125552 cannot: version
// 0x3fffe000 has its high bits set, so a shader that treats the version as a
// signed or small integer passes on 125552 and fails here.
//
// The digests are in memory order, which is the display hash read backwards.
// The run of zero bytes at the end is the block hash's leading zeros, and it is
// why these are worth having: a byte order mistake produces a digest that ends
// in the first byte of the display hash instead, and the difference is visible
// at a glance.
const unsigned char kHeader125552[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b,
    0xcd, 0x93, 0x17, 0xe2, 0xfe, 0x99, 0xf2, 0xde,
    0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4,
    0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75,
    0x04, 0x23, 0xdb, 0x8b, 0x1e, 0xb9, 0x42, 0xae,
    0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf,
    0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b,
    0xc7, 0xf5, 0xd7, 0x4d,
    0xf2, 0xb9, 0x44, 0x1a,
    0x42, 0xa1, 0x46, 0x95,
};

const unsigned char kDigest125552[32] = {
    0x1d, 0xbd, 0x98, 0x1f, 0xe6, 0x98, 0x57, 0x76,
    0xb6, 0x44, 0xb1, 0x73, 0xa4, 0xd0, 0x38, 0x5d,
    0xdc, 0x1a, 0xa2, 0xa8, 0x29, 0x68, 0x8d, 0x1e,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeader957533[80] = {
    0x00, 0xe0, 0xff, 0x3f,
    0x43, 0xd4, 0x81, 0xb0, 0x07, 0x92, 0x8a, 0x01,
    0xbd, 0x44, 0xd1, 0x65, 0x57, 0xc3, 0xb7, 0xe1,
    0xd5, 0xdb, 0x3a, 0x5f, 0x6f, 0x80, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x9b, 0xa8, 0x64, 0xa7, 0x69, 0x50, 0x10,
    0xb1, 0x92, 0x6e, 0x6d, 0xc4, 0xaf, 0xf1, 0x17,
    0xa0, 0xe7, 0x7c, 0xc8, 0xbe, 0x78, 0x09, 0x92,
    0x3e, 0x5e, 0xff, 0x80, 0x4c, 0x36, 0x8e, 0xd2,
    0x64, 0xe9, 0x51, 0x6a,
    0x42, 0x1a, 0x02, 0x17,
    0xad, 0x4e, 0xf3, 0x29,
};

const unsigned char kDigest957533[32] = {
    0xb4, 0x4c, 0x27, 0x7b, 0xc4, 0xde, 0x10, 0x0b,
    0xd0, 0x2f, 0x22, 0x76, 0xae, 0xf4, 0xbc, 0xc0,
    0xdb, 0x31, 0x1c, 0x43, 0xb8, 0xe9, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The nonces are the byte swap of the one an explorer prints. Every word of
// work.data is a big-endian read of the wire, the nonce included, and the
// submit path swaps it back on the way out. Both spellings are "the nonce of
// this block", and confusing them costs every share.
const KnownAnswer kAnswers[] = {
    { "block 125552", kHeader125552, 0x42a14695, kDigest125552 },
    { "block 957533", kHeader957533, 0xad4ef329, kDigest957533 },
};

class Sha256d final : public Algorithm {
public:
    const char *name() const override { return "sha256d"; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    KernelSpec kernel(const DeviceInfo &device) const override
    {
        (void)device;

        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, because the spec hands out a pointer
        // into it. One Algorithm belongs to one worker, so this needs no lock;
        // if that ever stops being true, this is what breaks.
        if (module_.words.empty() && !load_shader(name(), &module_))
            return spec;  // no shader: the CPU backend still has a reference

        spec.spirv = module_.words.data();
        spec.spirv_words = module_.words.size();

        // A replacement shader loaded through --algo-dir may declare its own
        // layout, and then it is the one that has to be believed: the numbers
        // below describe the kernel that shipped, not the one being run.
        spec.storage_buffers = module_.storage_buffers
                             ? module_.storage_buffers : 1;
        spec.push_constant_bytes = module_.push_constant_bytes
                                 ? module_.push_constant_bytes
                                 : sizeof(Sha256dPush);
        spec.local_size_x = module_.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

    // Everything that is the same for every nonce in the dispatch. The first
    // 64 bytes of the header hold no nonce, so their compression is done here
    // once instead of on the device a few billion times -- and so are the
    // first four rounds of the block that does hold it, which depend on the
    // nonce only through additions the device can put back.
    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(Sha256dPush))
            return 0;

        Sha256dPush push;

        // Header words 0..15 are the first block, 16..18 the start of the
        // second, and 19 is the nonce the kernel substitutes per invocation.
        // No swapping anywhere: each word already holds four header bytes in
        // the big-endian order SHA-256's message schedule reads them in.
        uint32_t tail[3];
        for (size_t i = 0; i < 3; i++)
            tail[i] = dispatch.header[16 + i];

        sha256_midstate(push.midstate, dispatch.header);

        // The midstate stays even though the device no longer starts from it:
        // rounds 0..3 do, and the feed-forward at the end of the compression
        // adds it back word for word. Advancing the state does not retire it.
        sha256_advance_nonce_block(push.advanced, push.sched,
                                   push.midstate, tail);

        std::memcpy(push.target, dispatch.target, sizeof push.target);
        push.nonce_start = dispatch.nonce_start;
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    void hash(const uint32_t *header, uint32_t nonce,
              uint32_t out[8]) const override
    {
        // 80 bytes: 19 header words as the pool sent them, then the nonce.
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, nonce);

        sha256d(out, data, sizeof data);
    }

#ifdef VKMINER_HAVE_SHADERS
private:
    mutable ShaderModule module_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_sha256d()
{
    return std::unique_ptr<Algorithm>(new Sha256d());
}

}  // namespace vkminer
