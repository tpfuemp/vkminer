// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// BLAKE2s-256 over an 80-byte block header, unkeyed. Verge mines one of its
// five algorithms this way.
//
// The byte order is the mirror image of SHA-256d's. struct work carries each
// header word as a big-endian read of the wire, and SHA-256 reads its message
// big-endian, so sha256d hands those words to the compression unchanged.
// BLAKE2s reads its message little-endian (RFC 7693 sec. 2.6), so every message word
// is the byte reversal of the header word it comes from. This file writes the
// header out big-endian -- the same 80 wire bytes sha256d hashes -- and reads it
// back little-endian, rather than swapping words in place: the wire bytes are
// the only form checkable against a block explorer.
//
// The digest needs no swap in either direction. BLAKE2s emits its state
// little-endian, which is already the order fulltest() compares in.

#include "algorithms/blake2s/blake2s.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// The push constant block blake2s.comp declares: 88 bytes against a guaranteed
// minimum of 128. The asserts are not ceremony -- the GLSL and this struct are
// one definition written twice, and nothing else would notice a word inserted
// in one of them.
struct Blake2sPush {
    uint32_t midstate[8];  // chaining value after the first 64 header bytes
    uint32_t block[3];     // final block message words 0..2, byte-reversed
    uint32_t target[8];    // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Blake2sPush) == 88,
              "blake2s.comp's push block is 88 bytes");
static_assert(sizeof(Blake2sPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(Blake2sPush, block) == 32, "push block layout");
static_assert(offsetof(Blake2sPush, target) == 44, "push block layout");
static_assert(offsetof(Blake2sPush, nonce_start) == 76, "push block layout");

// ---------------------------------------------------------------- the hash
//
// A transliteration of RFC 7693, kept deliberately slow and obvious. It is the
// oracle every device candidate is re-checked against, so it must stay readable
// against the specification; if it is ever the bottleneck, the answer is fewer
// candidates, not a faster reference.

const uint32_t kIV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

// RFC 7693 sec. 2.7. A table here, so that it can be diffed against the document;
// the kernel applies the same permutation at compile time instead.
const unsigned char kSigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

void mix(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

// One compression. `counter` is the message bytes hashed including this block
// and `last` sets the finalization flag -- the two things that stop a hash of
// the first 64 bytes from also being a hash of the whole header.
void compress(uint32_t h[8], const uint32_t m[16], uint32_t counter, bool last)
{
    uint32_t v[16];

    for (int i = 0; i < 8; i++) {
        v[i] = h[i];
        v[i + 8] = kIV[i];
    }

    // v[13] takes the counter's high half, zero for an 80-byte header.
    v[12] ^= counter;
    if (last)
        v[14] = ~v[14];

    for (int r = 0; r < 10; r++) {
        const unsigned char *s = kSigma[r];
        mix(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        mix(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        mix(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        mix(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        mix(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        mix(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i + 8];
}

// The chaining value after the first 64 bytes of a header. 0x01010020 is the
// parameter block of an unkeyed BLAKE2s-256 -- digest length 32, key length 0,
// fanout 1, depth 1 -- xored into the first state word.
void midstate(uint32_t h[8], const unsigned char header[64])
{
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = le32dec(header + i * 4);

    std::memcpy(h, kIV, sizeof kIV);
    h[0] ^= 0x01010020u;

    compress(h, m, 64, false);
}

// The whole 80 bytes: the block above, then the 16 remaining bytes padded with
// zeros to a full block and marked final at a byte count of 80.
void blake2s_80(uint32_t out[8], const unsigned char header[80])
{
    uint32_t h[8];
    midstate(h, header);

    uint32_t m[16] = { 0 };
    for (int i = 0; i < 4; i++)
        m[i] = le32dec(header + 64 + i * 4);

    compress(h, m, 80, true);

    std::memcpy(out, h, 32);
}

// ------------------------------------------------------------- the vectors
//
// Two Verge mainnet headers as they went over the wire, and the digests they
// produce. Verge encodes which of its five algorithms mined a block in the
// version field -- `nVersion & (15 << 11)` is `4 << 11` for BLAKE2s, and 0x2004
// is that value.
//
// These are anchored on the difficulty bits, not on a published digest.
// Verge's explorers show the *scrypt* hash of a header whatever mined it, so a
// BLAKE2s block's BLAKE2s digest is on display nowhere. What is on display is
// the header, and each digest below clears the nbits its own header carries --
// 0x1b01d063 and 0x1b019822, about 39 bits of margin each. A header assembled
// wrongly, or a BLAKE2s implemented wrongly, gives a digest spread over 256
// bits and clears either target with probability ~2^-39. So the leading zeros
// are the proof, exactly as they are for the SHA-256d vectors.
//
// The two are not redundant: 9393489's nonce has the high bit set, so anything
// treating the nonce as signed passes 9393486 and fails it.
const unsigned char kHeader9393486[80] = {
    0x04, 0x20, 0x00, 0x00,
    0x97, 0x64, 0x37, 0xb6, 0xc3, 0xd9, 0x3e, 0xd2,
    0xb9, 0x0c, 0x05, 0x78, 0x9b, 0xcf, 0xfc, 0xcd,
    0x68, 0x59, 0x86, 0xc8, 0x33, 0x50, 0x53, 0xfd,
    0x03, 0xb6, 0xe6, 0x33, 0x10, 0x3b, 0x4d, 0x75,
    0x33, 0x73, 0x77, 0xce, 0xcd, 0x54, 0x9e, 0x0b,
    0x44, 0xb8, 0xa3, 0x18, 0xf3, 0x3e, 0x75, 0x2e,
    0xc1, 0x80, 0xc6, 0x76, 0xd3, 0xaf, 0xdd, 0xb0,
    0xfd, 0xc6, 0x24, 0xa5, 0x08, 0x8c, 0x69, 0xc7,
    0x72, 0x0c, 0x79, 0x6a,
    0x63, 0xd0, 0x01, 0x1b,
    0x67, 0x24, 0x86, 0x05,
};

const unsigned char kDigest9393486[32] = {
    0xdb, 0xbd, 0xb9, 0x56, 0x2d, 0x65, 0x97, 0x0e,
    0x00, 0x8a, 0x3e, 0xbb, 0x05, 0x94, 0x79, 0x50,
    0xde, 0x84, 0xa1, 0x72, 0x00, 0x9f, 0x7a, 0x0c,
    0xc3, 0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeader9393489[80] = {
    0x04, 0x20, 0x00, 0x00,
    0x85, 0xfd, 0x60, 0x23, 0x0b, 0x1a, 0x43, 0xd5,
    0x2a, 0x1b, 0xa2, 0x2c, 0x89, 0xaa, 0xe9, 0x72,
    0x94, 0xfa, 0x53, 0xde, 0xbe, 0x84, 0x53, 0xbd,
    0x11, 0xf9, 0xfa, 0x89, 0xdd, 0xb3, 0xea, 0x47,
    0x13, 0xf4, 0xc9, 0x83, 0x8b, 0xd7, 0x34, 0xf0,
    0x06, 0x20, 0x1e, 0x85, 0xae, 0x88, 0xe3, 0x98,
    0x24, 0x8a, 0x94, 0xeb, 0xc6, 0xa6, 0x0c, 0x62,
    0xb0, 0x64, 0xf1, 0xc6, 0xfb, 0x81, 0xad, 0x00,
    0xa7, 0x0c, 0x79, 0x6a,
    0x22, 0x98, 0x01, 0x1b,
    0xe7, 0x60, 0x57, 0x64,
};

const unsigned char kDigest9393489[32] = {
    0xf7, 0x89, 0x89, 0x70, 0x99, 0x53, 0x06, 0xb4,
    0xb5, 0x9a, 0x24, 0x96, 0x80, 0xd1, 0x61, 0xa1,
    0x80, 0xdf, 0xc1, 0x5d, 0x0d, 0x90, 0xb0, 0x93,
    0x48, 0x1e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The nonces are the byte swap of the one an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "Verge block 9393486", kHeader9393486, 0x67248605, kDigest9393486 },
    { "Verge block 9393489", kHeader9393489, 0xe7605764, kDigest9393489 },
};

class Blake2s final : public Algorithm {
public:
    const char *name() const override { return "blake2s"; }

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
        // layout, and then it is the one that has to be believed.
        spec.storage_buffers = module_.storage_buffers
                             ? module_.storage_buffers : 1;
        spec.push_constant_bytes = module_.push_constant_bytes
                                 ? module_.push_constant_bytes
                                 : sizeof(Blake2sPush);
        spec.local_size_x = module_.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

    // Everything that is the same for every nonce in the dispatch. The first 64
    // header bytes hold no nonce, so their compression happens here once rather
    // than on the device a few billion times.
    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(Blake2sPush))
            return 0;

        Blake2sPush push;

        // The wire bytes, which both the midstate and the final block are read
        // out of. Word 19, the nonce, is left out -- the device substitutes it.
        unsigned char header[76];
        for (size_t i = 0; i < 19; i++)
            be32enc(header + i * 4, dispatch.header[i]);

        midstate(push.midstate, header);

        // The final block's three non-nonce message words, read little-endian
        // off the wire: the reversal described above, once per dispatch.
        for (size_t i = 0; i < 3; i++)
            push.block[i] = le32dec(header + 64 + i * 4);

        std::memcpy(push.target, dispatch.target, sizeof push.target);
        // The low half: this kernel's nonce is one header word, as hash()'s is.
        push.nonce_start = static_cast<uint32_t>(dispatch.nonce_start);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        // Byte for byte the buffer sha256d builds: the two algorithms differ in
        // how they read it, not in what it is.
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, static_cast<uint32_t>(nonce));

        blake2s_80(out, data);
    }

#ifdef VKMINER_HAVE_SHADERS
private:
    mutable ShaderModule module_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_blake2s()
{
    return std::unique_ptr<Algorithm>(new Blake2s());
}

}  // namespace vkminer
