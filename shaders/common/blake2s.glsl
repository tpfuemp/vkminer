// BLAKE2s, RFC 7693, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The mixing function and the state, and nothing else: the round permutation is
// a compile-time constant per round, so it belongs at the call site where a
// kernel can name the message words it actually has.

#ifndef VKMINER_SHADERS_COMMON_BLAKE2S_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_BLAKE2S_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

// Equal to SHA-256's by coincidence of construction, not by definition. Kept as
// its own array so that no kernel comes to depend on the coincidence.
const uint blake2s_iv[8] = uint[8](
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u);

// Unkeyed BLAKE2s-256: digest length 32, key length 0, fanout 1, depth 1.
const uint blake2s_param = 0x01010020u;

// RFC 7693 sec. 3.1.
#define BLAKE2S_G(a, b, c, d, x, y)  \
    {                                \
        (a) += (b) + (x);            \
        (d) = rotr32((d) ^ (a), 16u); \
        (c) += (d);                  \
        (b) = rotr32((b) ^ (c), 12u); \
        (a) += (b) + (y);            \
        (d) = rotr32((d) ^ (a), 8u);  \
        (c) += (d);                  \
        (b) = rotr32((b) ^ (c), 7u);  \
    }

// Four columns, then four diagonals. x0..xf are this round's message words with
// sigma already applied -- the caller permutes by choosing what to pass, so
// nothing here is indexed at run time.
#define BLAKE2S_ROUND(v, x0, x1, x2, x3, x4, x5, x6, x7,   \
                         x8, x9, xa, xb, xc, xd, xe, xf)   \
    BLAKE2S_G(v[0], v[4], v[ 8], v[12], x0, x1);           \
    BLAKE2S_G(v[1], v[5], v[ 9], v[13], x2, x3);           \
    BLAKE2S_G(v[2], v[6], v[10], v[14], x4, x5);           \
    BLAKE2S_G(v[3], v[7], v[11], v[15], x6, x7);           \
    BLAKE2S_G(v[0], v[5], v[10], v[15], x8, x9);           \
    BLAKE2S_G(v[1], v[6], v[11], v[12], xa, xb);           \
    BLAKE2S_G(v[2], v[7], v[ 8], v[13], xc, xd);           \
    BLAKE2S_G(v[3], v[4], v[ 9], v[14], xe, xf)

// The working state a compression starts from. `last` is a compile-time bool at
// every call site, so the complement folds away.
//
// The counter is 64 bits in the specification; its high half, v[13], is omitted
// because no caller here hashes 2^32 bytes.
#define BLAKE2S_INIT(v, h, counter, last)                        \
    {                                                            \
        v[ 0] = h[0]; v[ 1] = h[1]; v[ 2] = h[2]; v[ 3] = h[3];  \
        v[ 4] = h[4]; v[ 5] = h[5]; v[ 6] = h[6]; v[ 7] = h[7];  \
        v[ 8] = blake2s_iv[0];                                   \
        v[ 9] = blake2s_iv[1];                                   \
        v[10] = blake2s_iv[2];                                   \
        v[11] = blake2s_iv[3];                                   \
        v[12] = blake2s_iv[4] ^ uint(counter);                   \
        v[13] = blake2s_iv[5];                                   \
        v[14] = (last) ? ~blake2s_iv[6] : blake2s_iv[6];         \
        v[15] = blake2s_iv[7];                                   \
    }

#endif  // VKMINER_SHADERS_COMMON_BLAKE2S_GLSL_INCLUDED
