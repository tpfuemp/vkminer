// sha512256d: one nonce per invocation. SHA-512/256 of the header, then again.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by sha512256d.comp and sha512256d32.comp. 64-bit words are SLANE,
// so one text serves both lane types; never `+` an SLANE, use sadd().
//
// Each nonce is two compressions: the 80-byte header (one padded block), then
// the 32-byte digest of it.
//
// Byte order: header words are big-endian reads of the wire, so two of them
// form one SHA-512 word, earlier one high. The digest's 64-bit words are split
// high half first and byte-reversed into the little-endian words the host
// compares.

#ifndef VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha512.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by Sha512256dPush in sha512256d.cpp, which asserts the
// layout.
layout(push_constant) uniform Push {
    uint header[19];    // header words 0..18; word 19 is the nonce
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// One SHA-512 round. The caller rotates the names instead of shuffling values.
#define S5D_STEP(a, b, c, d, e, f, g, h, k, w)                           \
    {                                                                     \
        SLANE t1 = sadd(sadd(sadd(h, sha512_big_s1(e)),                   \
                             sadd(sha512_ch(e, f, g), k)),                \
                        w);                                               \
        SLANE t2 = sadd(sha512_big_s0(a), sha512_maj(a, b, c));           \
        (d) = sadd(d, t1);                                                \
        (h) = sadd(t1, t2);                                               \
    }

// One message-schedule slot, expanded in place over a named sixteen-word
// window: w[i-16] += s0(w[i-15]) + w[i-7] + s1(w[i-2]).
#define S5D_SCHED(wa, wb, wi, wn)                                         \
    {                                                                     \
        (wa) = sadd(sadd(wa, sha512_small_s0(wb)),                        \
                    sadd(wi, sha512_small_s1(wn)));                       \
    }

// Rounds i..i+15 straight off the message.
#define S5D_ROUNDS16(i)                                                           \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  0u), w0);          \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  1u), w1);          \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) +  2u), w2);          \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) +  3u), w3);          \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) +  4u), w4);          \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) +  5u), w5);          \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) +  6u), w6);          \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) +  7u), w7);          \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  8u), w8);          \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  9u), w9);          \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) + 10u), w10);         \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) + 11u), w11);         \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) + 12u), w12);         \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) + 13u), w13);         \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) + 14u), w14);         \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) + 15u), w15)

// Rounds i..i+15 for i >= 16, each preceded by the schedule word it reads.
#define S5D_ROUNDS16_SCHED(i)                                                     \
    S5D_SCHED(w0, w1, w9, w14);                                                   \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  0u), w0);          \
    S5D_SCHED(w1, w2, w10, w15);                                                  \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  1u), w1);          \
    S5D_SCHED(w2, w3, w11, w0);                                                   \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) +  2u), w2);          \
    S5D_SCHED(w3, w4, w12, w1);                                                   \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) +  3u), w3);          \
    S5D_SCHED(w4, w5, w13, w2);                                                   \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) +  4u), w4);          \
    S5D_SCHED(w5, w6, w14, w3);                                                   \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) +  5u), w5);          \
    S5D_SCHED(w6, w7, w15, w4);                                                   \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) +  6u), w6);          \
    S5D_SCHED(w7, w8, w0, w5);                                                    \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) +  7u), w7);          \
    S5D_SCHED(w8, w9, w1, w6);                                                    \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  8u), w8);          \
    S5D_SCHED(w9, w10, w2, w7);                                                   \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  9u), w9);          \
    S5D_SCHED(w10, w11, w3, w8);                                                  \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) + 10u), w10);         \
    S5D_SCHED(w11, w12, w4, w9);                                                  \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) + 11u), w11);         \
    S5D_SCHED(w12, w13, w5, w10);                                                 \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) + 12u), w12);         \
    S5D_SCHED(w13, w14, w6, w11);                                                 \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) + 13u), w13);         \
    S5D_SCHED(w14, w15, w7, w12);                                                 \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) + 14u), w14);         \
    S5D_SCHED(w15, w0, w8, w13);                                                  \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) + 15u), w15)

// One SHA-512/256 compression from the IV with full feed-forward. `m` is read
// only at constant indices, so the callers' padding words fold.
void sha512256d_block(out SLANE state[8], SLANE m[16])
{
    SLANE w0  = m[ 0], w1  = m[ 1], w2  = m[ 2], w3  = m[ 3];
    SLANE w4  = m[ 4], w5  = m[ 5], w6  = m[ 6], w7  = m[ 7];
    SLANE w8  = m[ 8], w9  = m[ 9], w10 = m[10], w11 = m[11];
    SLANE w12 = m[12], w13 = m[13], w14 = m[14], w15 = m[15];

    SLANE v0 = sha512_256_iv(0u), v1 = sha512_256_iv(1u);
    SLANE v2 = sha512_256_iv(2u), v3 = sha512_256_iv(3u);
    SLANE v4 = sha512_256_iv(4u), v5 = sha512_256_iv(5u);
    SLANE v6 = sha512_256_iv(6u), v7 = sha512_256_iv(7u);

    S5D_ROUNDS16(0u);
    S5D_ROUNDS16_SCHED(16u);
    S5D_ROUNDS16_SCHED(32u);
    S5D_ROUNDS16_SCHED(48u);
    S5D_ROUNDS16_SCHED(64u);

    // Ten whole turns, so v0..v7 hold a..h in that order again.
    state[0] = sadd(sha512_256_iv(0u), v0);
    state[1] = sadd(sha512_256_iv(1u), v1);
    state[2] = sadd(sha512_256_iv(2u), v2);
    state[3] = sadd(sha512_256_iv(3u), v3);
    state[4] = sadd(sha512_256_iv(4u), v4);
    state[5] = sadd(sha512_256_iv(5u), v5);
    state[6] = sadd(sha512_256_iv(6u), v6);
    state[7] = sadd(sha512_256_iv(7u), v7);
}

void sha512256d_search(uint nonce)
{
    // First pass: ten header words (nBits high and nonce low in the last),
    // then padding and a 640-bit length.
    SLANE m[16];
    for (int i = 0; i < 9; i++)
        m[i] = slane(push.header[2 * i + 1], push.header[2 * i]);
    m[ 9] = slane(nonce, push.header[18]);
    m[10] = slane(0u, 0x80000000u);
    m[11] = slane(0u, 0u);
    m[12] = slane(0u, 0u);
    m[13] = slane(0u, 0u);
    m[14] = slane(0u, 0u);
    m[15] = slane(0x280u, 0u);               // 640 bits = 80 bytes

    SLANE state[8];
    sha512256d_block(state, m);

    // Second pass: the first four state words, padded for a 256-bit length.
    for (int i = 0; i < 4; i++)
        m[i] = state[i];
    m[ 4] = slane(0u, 0x80000000u);
    for (int i = 5; i < 15; i++)
        m[i] = slane(0u, 0u);
    m[15] = slane(0x100u, 0u);               // 256 bits

    sha512256d_block(state, m);

    // The most significant 64 bits of the digest: state word 3, as two
    // little-endian words.
    uint top = bswap32(slo(state[3]));
    uint next = bswap32(shi(state[3]));

    // Compiled away unless the pipeline was built with the probe on; see
    // candidates.glsl.
    probe_best(top);

    // A prefix of the share test; the host compares all 256 bits.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && next > push.target[0])
        return;

    uint hash[8];
    for (int i = 0; i < 4; i++) {
        hash[2 * i]     = bswap32(shi(state[i]));
        hash[2 * i + 1] = bswap32(slo(state[i]));
    }

    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        sha512256d_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED
