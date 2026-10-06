// skein: one nonce per invocation. Skein-512-512 of the header, then SHA-256.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by skein.comp and skein32.comp; 64-bit words are TLANE, so never
// `+` one, use tadd().
//
// The host runs the first Skein block (header bytes 0..63, no nonce) and pushes
// the chaining value. Each nonce costs the second block, the output block and
// two SHA-256 compressions.
//
// Byte order: the tail words are little-endian reads of the wire, two to a
// Skein word, earlier one low. SHA-256 reads Skein's output big-endian; its
// state is byte-reversed into the little-endian words the host compares.

#ifndef VKMINER_ALGORITHMS_SKEIN_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_SKEIN_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha256.glsl"
#include "shaders/common/skein512.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by SkeinPush in skein.cpp, which asserts the layout.
layout(push_constant) uniform Push {
    uint midstate[16];  // the chaining value after bytes 0..63, low half first
    uint tail[3];       // header words 16..18, little-endian reads of the wire
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// One SHA-256 round; the working variables rotate through the argument list.
#define SKEIN_SHA256_ROUND(a, b, c, d, e, f, g, h, k, w)                   \
    {                                                                      \
        uint t1 = (h) + sha256_big_s1(e) + sha256_ch(e, f, g) + (k) + (w); \
        uint t2 = sha256_big_s0(a) + sha256_maj(a, b, c);                  \
        (d) += t1;                                                         \
        (h)  = t1 + t2;                                                    \
    }

#define SKEIN_SHA256_ROUND8(i)                                                 \
    SKEIN_SHA256_ROUND(a, b, c, d, e, f, g, h, sha256_k[(i) + 0], w[(i) + 0]); \
    SKEIN_SHA256_ROUND(h, a, b, c, d, e, f, g, sha256_k[(i) + 1], w[(i) + 1]); \
    SKEIN_SHA256_ROUND(g, h, a, b, c, d, e, f, sha256_k[(i) + 2], w[(i) + 2]); \
    SKEIN_SHA256_ROUND(f, g, h, a, b, c, d, e, sha256_k[(i) + 3], w[(i) + 3]); \
    SKEIN_SHA256_ROUND(e, f, g, h, a, b, c, d, sha256_k[(i) + 4], w[(i) + 4]); \
    SKEIN_SHA256_ROUND(d, e, f, g, h, a, b, c, sha256_k[(i) + 5], w[(i) + 5]); \
    SKEIN_SHA256_ROUND(c, d, e, f, g, h, a, b, sha256_k[(i) + 6], w[(i) + 6]); \
    SKEIN_SHA256_ROUND(b, c, d, e, f, g, h, a, sha256_k[(i) + 7], w[(i) + 7])

// w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]).
#define SKEIN_SHA256_SCHED(i)                                              \
    w[i] = w[(i) - 16] + sha256_small_s0(w[(i) - 15])                      \
         + w[(i) -  7] + sha256_small_s1(w[(i) -  2])

#define SKEIN_SHA256_SCHED8(i)                                             \
    SKEIN_SHA256_SCHED((i) + 0); SKEIN_SHA256_SCHED((i) + 1);              \
    SKEIN_SHA256_SCHED((i) + 2); SKEIN_SHA256_SCHED((i) + 3);              \
    SKEIN_SHA256_SCHED((i) + 4); SKEIN_SHA256_SCHED((i) + 5);              \
    SKEIN_SHA256_SCHED((i) + 6); SKEIN_SHA256_SCHED((i) + 7)

// One compression, written out so that `w` is only indexed by constants: the
// padding block folds to constants, and no array is indexed by the round.
// sha256_compress() is rolled and much slower here on some GPUs.
void skein_sha256_block(inout uint state[8], inout uint w[64])
{
    SKEIN_SHA256_SCHED8(16); SKEIN_SHA256_SCHED8(24);
    SKEIN_SHA256_SCHED8(32); SKEIN_SHA256_SCHED8(40);
    SKEIN_SHA256_SCHED8(48); SKEIN_SHA256_SCHED8(56);

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    SKEIN_SHA256_ROUND8( 0); SKEIN_SHA256_ROUND8( 8);
    SKEIN_SHA256_ROUND8(16); SKEIN_SHA256_ROUND8(24);
    SKEIN_SHA256_ROUND8(32); SKEIN_SHA256_ROUND8(40);
    SKEIN_SHA256_ROUND8(48); SKEIN_SHA256_ROUND8(56);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void skein_search(uint nonce)
{
    TLANE h[8];
    TLANE m[8];
    for (uint i = 0u; i < 8u; i++)
        h[i] = tlane(push.midstate[2u * i], push.midstate[2u * i + 1u]);

    // Message block 2: bytes 64..79 and zeros, position 80, final. The nonce is
    // the high half of word 1.
    m[0] = tlane(push.tail[0], push.tail[1]);
    m[1] = tlane(push.tail[2], bswap32(nonce));
    for (uint i = 2u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(80u, 0u),
                 tlane(0u, kSkeinT1Msg | kSkeinT1Final));

    // Output block: an eight-byte zero counter, position 8, first and final.
    for (uint i = 0u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(8u, 0u),
                 tlane(0u, kSkeinT1Out | kSkeinT1First | kSkeinT1Final));

    // SHA-256 of Skein's 64 bytes read big-endian; a Skein word's low half
    // holds the earlier four bytes.
    uint w[64];
    w[ 0] = bswap32(tlo(h[0]));   w[ 1] = bswap32(thi(h[0]));
    w[ 2] = bswap32(tlo(h[1]));   w[ 3] = bswap32(thi(h[1]));
    w[ 4] = bswap32(tlo(h[2]));   w[ 5] = bswap32(thi(h[2]));
    w[ 6] = bswap32(tlo(h[3]));   w[ 7] = bswap32(thi(h[3]));
    w[ 8] = bswap32(tlo(h[4]));   w[ 9] = bswap32(thi(h[4]));
    w[10] = bswap32(tlo(h[5]));   w[11] = bswap32(thi(h[5]));
    w[12] = bswap32(tlo(h[6]));   w[13] = bswap32(thi(h[6]));
    w[14] = bswap32(tlo(h[7]));   w[15] = bswap32(thi(h[7]));
    uint state[8] = sha256_iv;
    skein_sha256_block(state, w);

    // Padding for a 512-bit message.
    w[ 0] = 0x80000000u;   w[ 1] = 0u;   w[ 2] = 0u;   w[ 3] = 0u;
    w[ 4] = 0u;            w[ 5] = 0u;   w[ 6] = 0u;   w[ 7] = 0u;
    w[ 8] = 0u;            w[ 9] = 0u;   w[10] = 0u;   w[11] = 0u;
    w[12] = 0u;            w[13] = 0u;   w[14] = 0u;   w[15] = 512u;
    skein_sha256_block(state, w);

    uint top = bswap32(state[7]);
    uint next = bswap32(state[6]);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(top);

    // A prefix of the share test; the host compares all 256 bits.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && next > push.target[0])
        return;

    uint hash[8];
    for (uint i = 0u; i < 8u; i++)
        hash[i] = bswap32(state[i]);

    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        skein_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_SKEIN_KERNEL_GLSL_INCLUDED
