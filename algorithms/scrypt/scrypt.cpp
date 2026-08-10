// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// scrypt(N=1024, r=1, p=1) over an 80-byte block header -- Litecoin's algorithm,
// and the first here that is bound by memory rather than by arithmetic. Every
// hash needs its own 128 KiB scratchpad, written once and then read in an order
// it computes as it goes, which is the whole point of the function and the whole
// difficulty of running it on a device.
//
// Structure, RFC 7914 §6: PBKDF2 the header into 128 bytes, run those through
// ROMix, then PBKDF2 the result back down to 32. ROMix is where the memory goes
// -- N passes filling the scratchpad, then N more reading it at an index derived
// from the data, so nothing can be prefetched and nothing can be skipped.
//
// Byte order, as for every algorithm here: struct work's words are written out
// big-endian to rebuild the wire header, scrypt itself is little-endian
// throughout, and the 32-byte result is read back as little-endian words --
// which is the order fulltest() compares in.

#include "algorithms/scrypt/scrypt.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
#include "core/sha256.h"
}

#include <cstddef>
#include <cstring>
#include <vector>

namespace vkminer {
namespace {

// The push constant block scrypt.comp declares: 120 bytes against a guaranteed
// minimum of 128. The asserts are not ceremony -- the GLSL and this struct are
// one definition written twice, and nothing else would notice a word inserted
// in one of them.
struct ScryptPush {
    uint32_t header[19];   // wire words 0..18, big-endian as SHA-256 reads them
    uint32_t target[8];    // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(ScryptPush) == 120,
              "scrypt.comp's push block is 120 bytes");
static_assert(sizeof(ScryptPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(ScryptPush, target) == 76, "push block layout");
static_assert(offsetof(ScryptPush, nonce_start) == 108, "push block layout");

constexpr size_t kBlockBytes  = 64;   // SHA-256's block, and Salsa20's
constexpr size_t kDigestBytes = 32;

// HMAC-SHA256, RFC 2104. Written out with the padded blocks visible rather than
// through an incremental SHA-256 API, because the reference has no such API and
// because this way it can be checked against the RFC by reading it.
void hmac_sha256(const unsigned char *key, size_t key_len,
                 const unsigned char *msg, size_t msg_len,
                 unsigned char out[kDigestBytes])
{
    // A key longer than the block is hashed first; a shorter one is zero
    // padded. Both cases arise here -- the password is the 80-byte header, the
    // salt-side key in the second PBKDF2 is the same 80 bytes.
    unsigned char k0[kBlockBytes] = { 0 };
    if (key_len > kBlockBytes)
        sha256_full(k0, key, key_len);
    else
        std::memcpy(k0, key, key_len);

    std::vector<unsigned char> inner(kBlockBytes + msg_len);
    for (size_t i = 0; i < kBlockBytes; i++)
        inner[i] = static_cast<unsigned char>(k0[i] ^ 0x36);
    if (msg_len)
        std::memcpy(inner.data() + kBlockBytes, msg, msg_len);

    unsigned char inner_hash[kDigestBytes];
    sha256_full(inner_hash, inner.data(), inner.size());

    unsigned char outer[kBlockBytes + kDigestBytes];
    for (size_t i = 0; i < kBlockBytes; i++)
        outer[i] = static_cast<unsigned char>(k0[i] ^ 0x5c);
    std::memcpy(outer + kBlockBytes, inner_hash, kDigestBytes);

    sha256_full(out, outer, sizeof outer);
}

uint32_t rotl32(uint32_t x, unsigned bits)
{
    return (x << bits) | (x >> (32 - bits));
}

// The Salsa20/8 core: eight rounds over sixteen words, then the input added
// back. In place, so `block` is both the input that gets added and the
// destination.
//
// The quarter-rounds are written as the four column rounds and four row rounds
// they are, in the order the Salsa20 specification gives them. Eight rounds
// means four passes of the pair.
void salsa20_8(uint32_t block[16])
{
    uint32_t x[16];
    std::memcpy(x, block, sizeof x);

    for (int i = 0; i < 8; i += 2) {
        // Columns.
        x[ 4] ^= rotl32(x[ 0] + x[12],  7);
        x[ 8] ^= rotl32(x[ 4] + x[ 0],  9);
        x[12] ^= rotl32(x[ 8] + x[ 4], 13);
        x[ 0] ^= rotl32(x[12] + x[ 8], 18);
        x[ 9] ^= rotl32(x[ 5] + x[ 1],  7);
        x[13] ^= rotl32(x[ 9] + x[ 5],  9);
        x[ 1] ^= rotl32(x[13] + x[ 9], 13);
        x[ 5] ^= rotl32(x[ 1] + x[13], 18);
        x[14] ^= rotl32(x[10] + x[ 6],  7);
        x[ 2] ^= rotl32(x[14] + x[10],  9);
        x[ 6] ^= rotl32(x[ 2] + x[14], 13);
        x[10] ^= rotl32(x[ 6] + x[ 2], 18);
        x[ 3] ^= rotl32(x[15] + x[11],  7);
        x[ 7] ^= rotl32(x[ 3] + x[15],  9);
        x[11] ^= rotl32(x[ 7] + x[ 3], 13);
        x[15] ^= rotl32(x[11] + x[ 7], 18);

        // Rows.
        x[ 1] ^= rotl32(x[ 0] + x[ 3],  7);
        x[ 2] ^= rotl32(x[ 1] + x[ 0],  9);
        x[ 3] ^= rotl32(x[ 2] + x[ 1], 13);
        x[ 0] ^= rotl32(x[ 3] + x[ 2], 18);
        x[ 6] ^= rotl32(x[ 5] + x[ 4],  7);
        x[ 7] ^= rotl32(x[ 6] + x[ 5],  9);
        x[ 4] ^= rotl32(x[ 7] + x[ 6], 13);
        x[ 5] ^= rotl32(x[ 4] + x[ 7], 18);
        x[11] ^= rotl32(x[10] + x[ 9],  7);
        x[ 8] ^= rotl32(x[11] + x[10],  9);
        x[ 9] ^= rotl32(x[ 8] + x[11], 13);
        x[10] ^= rotl32(x[ 9] + x[ 8], 18);
        x[12] ^= rotl32(x[15] + x[14],  7);
        x[13] ^= rotl32(x[12] + x[15],  9);
        x[14] ^= rotl32(x[13] + x[12], 13);
        x[15] ^= rotl32(x[14] + x[13], 18);
    }

    for (int i = 0; i < 16; i++)
        block[i] += x[i];
}

// scryptBlockMix, RFC 7914 §4. 2r blocks in, 2r blocks out, and the output is
// the even-indexed results followed by the odd-indexed ones -- a shuffle that is
// the identity at r = 1 and is written out anyway, because r = 1 is this coin's
// choice and not the function's.
void block_mix(const uint32_t *in, uint32_t *out, uint32_t r)
{
    uint32_t x[16];
    std::memcpy(x, in + (2 * r - 1) * 16, sizeof x);

    for (uint32_t i = 0; i < 2 * r; i++) {
        for (int k = 0; k < 16; k++)
            x[k] ^= in[i * 16 + k];
        salsa20_8(x);

        const uint32_t slot = (i / 2) + ((i & 1) ? r : 0);
        std::memcpy(out + slot * 16, x, sizeof x);
    }
}

// scryptROMix, RFC 7914 §5. The first loop fills the scratchpad; the second
// reads it back at an index the data itself decides, which is what makes the
// function sequentially memory-hard.
void romix(uint32_t *b, uint32_t r, uint32_t n, uint32_t *v, uint32_t *tmp)
{
    const size_t words = 32 * r;

    for (uint32_t i = 0; i < n; i++) {
        std::memcpy(v + i * words, b, words * sizeof(uint32_t));
        block_mix(b, tmp, r);
        std::memcpy(b, tmp, words * sizeof(uint32_t));
    }

    for (uint32_t i = 0; i < n; i++) {
        // Integerify: block 2r-1 read as a little-endian integer, of which only
        // the low word can matter because n is a power of two no larger than
        // 2^32. The words are already little-endian decoded, so this is a read.
        const uint32_t j = b[words - 16] & (n - 1);

        for (size_t k = 0; k < words; k++)
            b[k] ^= v[j * words + k];
        block_mix(b, tmp, r);
        std::memcpy(b, tmp, words * sizeof(uint32_t));
    }
}

}  // namespace

void pbkdf2_sha256(const unsigned char *password, size_t password_len,
                   const unsigned char *salt, size_t salt_len,
                   uint32_t iterations, unsigned char *out, size_t out_len)
{
    // The salt with a four-byte big-endian block counter appended, which is the
    // message every HMAC in the first round takes.
    std::vector<unsigned char> message(salt_len + 4);
    if (salt_len)
        std::memcpy(message.data(), salt, salt_len);

    size_t done = 0;
    for (uint32_t block = 1; done < out_len; block++) {
        be32enc(message.data() + salt_len, block);

        unsigned char u[kDigestBytes];
        unsigned char t[kDigestBytes];
        hmac_sha256(password, password_len, message.data(), message.size(), u);
        std::memcpy(t, u, sizeof t);

        // scrypt asks for one iteration, so this loop does not run at all
        // there. It is written because PBKDF2 is defined with it and a
        // reference that only does the case in front of it is not a reference.
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(password, password_len, u, sizeof u, u);
            for (size_t k = 0; k < sizeof t; k++)
                t[k] ^= u[k];
        }

        const size_t take = out_len - done < sizeof t ? out_len - done
                                                      : sizeof t;
        std::memcpy(out + done, t, take);
        done += take;
    }
}

void scrypt(const unsigned char *password, size_t password_len,
            const unsigned char *salt, size_t salt_len,
            uint32_t n, uint32_t r, uint32_t p,
            unsigned char *out, size_t out_len)
{
    // n has to be a power of two for Integerify's mask to be a modulo, and the
    // rest of the function assumes r and p are nonzero. Callers here are fixed
    // and correct; this is so that a later one that is not fails visibly.
    if (n < 2 || (n & (n - 1)) || !r || !p) {
        std::memset(out, 0, out_len);
        return;
    }

    const size_t block_bytes = 128 * static_cast<size_t>(r);
    const size_t words = 32 * static_cast<size_t>(r);

    std::vector<unsigned char> b(block_bytes * p);
    pbkdf2_sha256(password, password_len, salt, salt_len, 1, b.data(),
                  b.size());

    std::vector<uint32_t> block(words);
    std::vector<uint32_t> scratch(words * static_cast<size_t>(n));
    std::vector<uint32_t> tmp(words);

    for (uint32_t i = 0; i < p; i++) {
        unsigned char *lane = b.data() + static_cast<size_t>(i) * block_bytes;

        for (size_t k = 0; k < words; k++)
            block[k] = le32dec(lane + k * 4);

        romix(block.data(), r, n, scratch.data(), tmp.data());

        for (size_t k = 0; k < words; k++)
            le32enc(lane + k * 4, block[k]);
    }

    pbkdf2_sha256(password, password_len, b.data(), b.size(), 1, out, out_len);
}

namespace {

// Two mined Litecoin headers. Litecoin publishes no scrypt digest -- the hash an
// explorer prints is SHA-256d, as it is for Bitcoin -- so these digests were
// produced by OpenSSL's scrypt, an implementation with nothing in common with
// this one, and each clears the difficulty its own header declares. A wrong
// implementation lands under a target of that size with probability about
// 2^-57, so the pair is not a coincidence anything gets to have twice.
const unsigned char kHeader2500000[80] = {
    0x00, 0x00, 0x00, 0x20, 0x36, 0xf8, 0x9e, 0x04,
    0x79, 0xd1, 0x44, 0x97, 0x5f, 0xc7, 0xad, 0x2f,
    0x3b, 0xf8, 0x4b, 0x40, 0x45, 0xb4, 0x27, 0x6d,
    0x03, 0xe0, 0x4a, 0x5f, 0x70, 0xfc, 0xc6, 0x96,
    0xaf, 0xdf, 0x56, 0xa0, 0x4c, 0xa3, 0x64, 0xf9,
    0x69, 0xfb, 0x04, 0xc5, 0x20, 0x33, 0xa9, 0xfe,
    0x62, 0xa0, 0x92, 0x67, 0xde, 0x23, 0x2a, 0x8c,
    0x80, 0x67, 0x4c, 0xf3, 0xcf, 0xa0, 0xf9, 0x3e,
    0x44, 0x9d, 0xc6, 0x93, 0xd5, 0xc9, 0x9c, 0x64,
    0xd0, 0xa2, 0x00, 0x1a, 0x1b, 0xda, 0x14, 0x67,
};

const unsigned char kDigest2500000[32] = {
    0xac, 0x38, 0xee, 0x03, 0xcd, 0x32, 0xf8, 0x01,
    0x14, 0x3b, 0xac, 0xdb, 0x7c, 0xd7, 0x44, 0xe3,
    0x2a, 0x7e, 0x6f, 0x04, 0x55, 0xda, 0xc5, 0x45,
    0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeader2500003[80] = {
    0x00, 0x00, 0x00, 0x20, 0xbd, 0x4c, 0x5c, 0x80,
    0x24, 0xe7, 0x01, 0x12, 0x4e, 0xc2, 0x80, 0xa7,
    0x66, 0xb2, 0xbb, 0x96, 0xa5, 0xf2, 0x2a, 0x5d,
    0xa2, 0xf8, 0x95, 0x09, 0xa0, 0x8a, 0xd5, 0x88,
    0x33, 0x41, 0xc9, 0x99, 0x52, 0xd6, 0xc2, 0x4c,
    0xcb, 0xd8, 0xa9, 0xa5, 0xc6, 0x6c, 0x41, 0x7a,
    0x4c, 0x76, 0xba, 0x13, 0x84, 0xee, 0x0b, 0xce,
    0xe3, 0xda, 0xa2, 0xff, 0x76, 0xcb, 0x67, 0xe4,
    0x39, 0x97, 0x4d, 0x89, 0xbc, 0xcc, 0x9c, 0x64,
    0xd0, 0xa2, 0x00, 0x1a, 0xa3, 0x45, 0xd3, 0x24,
};

const unsigned char kDigest2500003[32] = {
    0x1c, 0xbb, 0x4e, 0xc4, 0x17, 0xee, 0x1b, 0x7e,
    0x4a, 0x49, 0x23, 0x0d, 0xd7, 0xb5, 0x3d, 0x25,
    0x45, 0xbf, 0xaa, 0x43, 0xb3, 0xd9, 0x92, 0x6a,
    0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The nonces are the byte swap of the one an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "Litecoin block 2500000", kHeader2500000, 0x1bda1467, kDigest2500000 },
    { "Litecoin block 2500003", kHeader2500003, 0xa345d324, kDigest2500003 },
};

class Scrypt final : public Algorithm {
public:
    const char *name() const override { return "scrypt"; }

    // The 2^16 offset every scrypt pool quotes difficulty in. Stratum
    // difficulty 8 here is a target 8/65536 of Bitcoin's difficulty-1, which
    // is half a million hashes a share rather than thirty-four billion.
    double target_factor() const override { return 65536.; }

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

        // What one invocation needs to itself, and the only thing this
        // algorithm gets to say about how large a dispatch may be. How much of
        // the device's memory is free, and how much of it is already promised
        // to dispatches in flight, is the backend's to know.
        spec.scratch_bytes = kScryptScratchBytes;

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, because the spec hands out a pointer
        // into it. One Algorithm belongs to one worker, so this needs no lock;
        // if that ever stops being true, this is what breaks.
        if (module_.words.empty() && !load_shader(name(), &module_))
            return spec;  // no shader: the CPU backend still has a reference

        spec.spirv = module_.words.data();
        spec.spirv_words = module_.words.size();

        // A replacement shader loaded through --algo-dir may declare its own
        // layout, and then it is the one that has to be believed. Two buffers
        // here where the other kernels want one: the candidates, then the
        // scratchpad.
        spec.storage_buffers = module_.storage_buffers
                             ? module_.storage_buffers : 2;
        spec.push_constant_bytes = module_.push_constant_bytes
                                 ? module_.push_constant_bytes
                                 : sizeof(ScryptPush);
        spec.local_size_x = module_.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

    // There is no midstate to hoist and no target to rearrange: the whole
    // header goes across as the shader's message words, which is what struct
    // work's words already are. All this does is copy, and it exists so that
    // the shader is not reading a block laid out by a different algorithm.
    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target
            || capacity < sizeof(ScryptPush))
            return 0;

        ScryptPush push;

        for (size_t i = 0; i < 19; i++)
            push.header[i] = dispatch.header[i];

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
        // The same 80 bytes every algorithm here rebuilds, and then the header
        // is both the password and the salt -- scrypt's parameters as Litecoin
        // fixed them, not a choice this code makes.
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, nonce);

        unsigned char digest[32];
        scrypt(data, sizeof data, data, sizeof data, 1024, 1, 1, digest,
               sizeof digest);

        for (size_t i = 0; i < 8; i++)
            out[i] = le32dec(digest + i * 4);
    }

#ifdef VKMINER_HAVE_SHADERS
private:
    mutable ShaderModule module_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_scrypt()
{
    return std::unique_ptr<Algorithm>(new Scrypt());
}

}  // namespace vkminer
