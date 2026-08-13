// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// sha3t: three SHA3-256 in a row over an 80-byte block header.
//
//     hash = SHA3-256( SHA3-256( SHA3-256( header ) ) )
//
// BitcoinIII (BC3) and Fjarcode (FJAR) mine this. It is Bitcoin with the block
// hash swapped out and nothing else changed: the merkle root is still SHA-256d
// and a difficulty of 1 still means 2^32 hashes, so there is no target_factor()
// below and the Stratum side needs nothing.
//
// ⚠️ Two things the name hides, either of which hashes plausibly and has every
// share rejected: the padding is SHA3's (0x06), not Keccak's (0x01), and it is
// three hashes, not two -- sha3d is the two-hash algorithm.
//
// ⚠️ The byte order is BLAKE2s's, not SHA-256d's: SHA3 absorbs little-endian,
// so every message word is the byte reversal of the header word it comes from.
// The digest needs no swap, SHA3 squeezing little-endian already.

#include "algorithms/sha3t/sha3t.h"

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

// The push constant block sha3t_kernel.glsl declares: 120 bytes against a
// guaranteed minimum of 128. The GLSL and this struct are one definition
// written twice, and nothing but the asserts would notice them diverging.
//
// It carries the whole header because there is no midstate to carry: eighty
// bytes is a single absorbed block, so the first permutation already depends on
// the nonce.
struct Sha3tPush {
    uint32_t block[19];  // header words 0..18, byte-reversed
    uint32_t target[8];  // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_start;
    uint32_t count;
    uint32_t capacity;
};

static_assert(sizeof(Sha3tPush) == 120,
              "sha3t_kernel.glsl's push block is 120 bytes");
static_assert(sizeof(Sha3tPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(Sha3tPush, target) == 76, "push block layout");
static_assert(offsetof(Sha3tPush, nonce_start) == 108, "push block layout");

// ---------------------------------------------------------------- the hash
//
// A transliteration of FIPS 202, deliberately slow and obvious: it is the
// oracle every device candidate is re-checked against, so it has to stay
// readable against the specification.

// FIPS 202 §3.2.5, the round constants of iota.
const uint64_t kRc[24] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
    0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
    0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
    0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
    0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull,
};

// FIPS 202 §3.2.2, the rotation offsets of rho, indexed x + 5y as the state is.
const unsigned kRho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

uint64_t rotl64(uint64_t x, unsigned n)
{
    // Lane 0 has an offset of zero, and a shift by the full width of the type
    // is undefined rather than a no-op.
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

void keccakf(uint64_t a[25])
{
    for (int r = 0; r < 24; r++) {
        uint64_t c[5], d[5], b[25];

        for (int x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++)
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 25; y += 5)
                a[x + y] ^= d[x];

        // rho and pi, which are one move: the lane at (x, y) is rotated by its
        // own offset and lands at (y, 2x + 3y).
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rotl64(a[x + 5 * y], kRho[x + 5 * y]);

        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                a[y + x] = b[y + x]
                         ^ ((~b[y + (x + 1) % 5]) & b[y + (x + 2) % 5]);

        a[0] ^= kRc[r];
    }
}

// SHA3-256 of a message shorter than the 136-byte rate, which is the only case
// here: 80 bytes once and 32 bytes twice. One block, one permutation, and the
// first four lanes squeezed out little-endian.
//
// 0x06 is the domain separation and the first pad bit together (FIPS 202 §B.2);
// 0x80 is the last pad bit. ⚠️ Keccak-256, as Ethereum and Maxcoin use it,
// differs from this in that byte and nowhere else.
void sha3_256(unsigned char out[32], const unsigned char *in, size_t len)
{
    uint64_t a[25] = { 0 };

    for (size_t i = 0; i < len; i++)
        a[i / 8] ^= static_cast<uint64_t>(in[i]) << (8 * (i % 8));

    a[len / 8] ^= static_cast<uint64_t>(0x06) << (8 * (len % 8));
    a[16] ^= 0x8000000000000000ull;

    keccakf(a);

    for (size_t i = 0; i < 4; i++)
        for (size_t j = 0; j < 8; j++)
            out[i * 8 + j] = static_cast<unsigned char>(a[i] >> (8 * j));
}

void sha3t_80(uint32_t out[8], const unsigned char header[80])
{
    unsigned char digest[32];

    sha3_256(digest, header, 80);
    sha3_256(digest, digest, 32);
    sha3_256(digest, digest, 32);

    for (size_t i = 0; i < 8; i++)
        out[i] = le32dec(digest + i * 4);
}

// ------------------------------------------------------------- the vectors
//
// Two BitcoinIII mainnet headers as they went over the wire, and the digests
// they produce. BC3 makes sha3t its *block hash* as well as its proof of work,
// so each digest below is the identity an explorer prints for that block,
// byte-reversed -- nothing here is anchored on an implementation, this one
// included.
//
// Both are post-fork: BC3 selects the block-hash algorithm on version bit 12,
// set from height 30240 on, and a header from below that hashes with SHA-256d.
//
// The two are not redundant: 39663's nonce has the high bit clear and 44172's
// set, so anything treating the nonce as signed passes one and fails the other.
const unsigned char kHeader44172[80] = {
    0x00, 0x10, 0x00, 0x20,
    0x67, 0xc9, 0x1a, 0x71, 0x1e, 0x42, 0x85, 0x7b,
    0xad, 0x16, 0x4a, 0xc3, 0x8b, 0xb7, 0x53, 0xb8,
    0x89, 0x4b, 0x4a, 0x91, 0x6d, 0xf2, 0x44, 0x2f,
    0xf3, 0x0c, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5a, 0x5d, 0xb8, 0xab, 0x4e, 0xf4, 0x26, 0x62,
    0x80, 0x93, 0x7e, 0x14, 0x5b, 0x22, 0xa6, 0x3a,
    0xc1, 0x83, 0x71, 0x85, 0xee, 0x68, 0x9e, 0x20,
    0xde, 0xf7, 0x39, 0xb9, 0xec, 0xe8, 0xf0, 0x0c,
    0x99, 0x90, 0x28, 0x6a,
    0x1e, 0xa4, 0x12, 0x1b,
    0x69, 0x1a, 0x58, 0xb6,
};

// Block hash 000000000011a263e8de3583baa9e74434b23c07729fea70aa981c3752f3351f.
const unsigned char kDigest44172[32] = {
    0x1f, 0x35, 0xf3, 0x52, 0x37, 0x1c, 0x98, 0xaa,
    0x70, 0xea, 0x9f, 0x72, 0x07, 0x3c, 0xb2, 0x34,
    0x44, 0xe7, 0xa9, 0xba, 0x83, 0x35, 0xde, 0xe8,
    0x63, 0xa2, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const unsigned char kHeader39663[80] = {
    0x00, 0x10, 0x00, 0x20,
    0x36, 0x49, 0xfb, 0x7a, 0x2d, 0x04, 0xcc, 0x06,
    0xba, 0xec, 0x6c, 0x80, 0xc6, 0x6d, 0x3b, 0xb2,
    0x9a, 0xdf, 0x48, 0x1d, 0xd6, 0xe7, 0xc2, 0xc6,
    0xe6, 0x2b, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0xf5, 0x0c, 0xab, 0x68, 0xac, 0x35, 0xb4,
    0xf4, 0x72, 0x41, 0x77, 0x4f, 0x1f, 0x58, 0xc2,
    0x3f, 0xfb, 0xfe, 0x27, 0xe0, 0xd7, 0x8a, 0xb8,
    0x35, 0x5e, 0x4d, 0x83, 0xf1, 0xf8, 0x41, 0xa1,
    0x12, 0x42, 0x16, 0x6a,
    0xff, 0xff, 0x00, 0x1c,
    0xc6, 0xe4, 0x55, 0x39,
};

// Block hash 0000000000721a3f1660543ce9bccdbd367188122643c99ef81f4fcdd57efd27.
const unsigned char kDigest39663[32] = {
    0x27, 0xfd, 0x7e, 0xd5, 0xcd, 0x4f, 0x1f, 0xf8,
    0x9e, 0xc9, 0x43, 0x26, 0x12, 0x88, 0x71, 0x36,
    0xbd, 0xcd, 0xbc, 0xe9, 0x3c, 0x54, 0x60, 0x16,
    0x3f, 0x1a, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// The nonces are the byte swap of the one an explorer prints, as for SHA-256d.
const KnownAnswer kAnswers[] = {
    { "BC3 block 44172", kHeader44172, 0x691a58b6, kDigest44172 },
    { "BC3 block 39663", kHeader39663, 0xc6e45539, kDigest39663 },
};

class Sha3t final : public Algorithm {
public:
    const char *name() const override { return "sha3t"; }

    size_t known_answers(const KnownAnswer **out) const override
    {
        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // The first kernel here that depends on what the device can do: a Keccak
    // lane is 64 bits and shaderInt64 is optional, so the two shaders are the
    // same text compiled over two lane types.
    //
    // ⚠️ It cannot be a specialization constant. Int64 is an OpCapability,
    // declared for the module as a whole, and a device without the feature
    // rejects the module however unreachable the 64-bit half becomes.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
#ifdef VKMINER_HAVE_SHADERS
        const bool wide = device.int64;

        // Only where the device leaves no choice. Where both modules build,
        // this would be a guess the tuner is about to overrule, and the kernel
        // logs which one it really created.
        if (!wide && !announced_) {
            announced_ = true;
            applog(LOG_INFO, "sha3t on %s: 32-bit lane pairs, because "
                             "shaderInt64 is not available here",
                   device.name.c_str());
        }

        return spec_for(wide);
#else
        (void)device;
        return spec_for(false);
#endif
    }

    // Both, where the device can build both: which is faster is not a question
    // the feature bit answers, so the 64-bit one goes first as the guess and
    // the tuner settles it. Without the feature there is one candidate, a
    // module declaring the Int64 capability being rejected before anything can
    // be measured about it.
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

    // Nothing per-job to precompute, so this is the byte order and nothing
    // else: the header written out as it went over the wire and read back the
    // way SHA3 absorbs it, rather than swapped in place -- the wire bytes are
    // the only form checkable against an explorer. Word 19 is the device's.
    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target || capacity < sizeof(Sha3tPush))
            return 0;

        Sha3tPush push;

        unsigned char header[76];
        for (size_t i = 0; i < 19; i++)
            be32enc(header + i * 4, dispatch.header[i]);
        for (size_t i = 0; i < 19; i++)
            push.block[i] = le32dec(header + i * 4);

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
        // Byte for byte the buffer sha256d builds: the algorithms differ in how
        // they read it, not in what it is.
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, nonce);

        sha3t_80(out, data);
    }

private:
    // One of the two modules, named so a log and a tuning file can say which
    // ran. A spec with no SPIR-V is not an error here either: the CPU backend
    // still has the reference.
    KernelSpec spec_for(bool wide) const
    {
        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        spec.variant = wide ? "int64" : "2x32";

#ifdef VKMINER_HAVE_SHADERS
        // Loaded on first use and kept, because the spec hands out a pointer
        // into it. One Algorithm belongs to one worker, so this needs no lock;
        // if that ever stops being true, this is what breaks.
        ShaderModule &module = wide ? module64_ : module32_;
        if (module.words.empty()
            && !load_shader(wide ? "sha3t" : "sha3t32", &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // A replacement shader loaded through --algo-dir may declare its own
        // layout, and then it is the one that has to be believed.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(Sha3tPush);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses
#endif
        return spec;
    }

#ifdef VKMINER_HAVE_SHADERS
    mutable ShaderModule module64_;
    mutable ShaderModule module32_;

    // A device that cannot run the 64-bit module is worth one line: a run that
    // quietly took the other path is a run whose numbers describe something
    // else.
    mutable bool announced_ = false;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_sha3t()
{
    return std::unique_ptr<Algorithm>(new Sha3t());
}

}  // namespace vkminer
