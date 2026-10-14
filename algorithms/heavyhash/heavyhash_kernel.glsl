// heavyhash: one nonce per invocation. SHA3-256, a 64x64 matrix product, SHA3-256.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by heavyhash.comp and heavyhash32.comp, which differ only in the
// Keccak lane type. The per-job matrix arrives in the uniform block and every
// read of it is at a compile-time offset. Byte order is sha3t's: header words
// arrive byte-reversed, the nonce is reversed here, the digest needs no swap.

#ifndef VKMINER_ALGORITHMS_HEAVYHASH_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_HEAVYHASH_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha3.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// 120 bytes. Mirrored by HeavyhashPush in heavyhash.cpp, which asserts it.
layout(push_constant) uniform Push {
    uint block[19];    // header words 0..18, already byte-reversed
    uint target[8];    // as fulltest() compares: little-endian, most significant last
    uint nonce_start;
    uint count;        // nonces to test, which is not the invocation count
    uint capacity;     // candidates the result buffer can hold
} push;

// 8192 bytes, mirrored by HeavyhashUniform. Column j is m[8j .. 8j + 7]:
// 32 words, word k holding row 2k in its low half and row 2k + 1 in its high
// half, so one multiply-add does two rows. A row sum peaks at 14400, so a half
// never carries into the other.
layout(std140, binding = 1) uniform Job {
    uvec4 m[512];
} job;

// Column j times nibble v, into the four accumulators. j is a literal at every
// expansion, so every load is at a constant offset.
#define HH_COL(j, v)                                                          \
    {                                                                         \
        uint nib = (v);                                                       \
        acc0 += job.m[(j) * 8 + 0] * nib;                                     \
        acc1 += job.m[(j) * 8 + 1] * nib;                                     \
        acc2 += job.m[(j) * 8 + 2] * nib;                                     \
        acc3 += job.m[(j) * 8 + 3] * nib;                                     \
        acc4 += job.m[(j) * 8 + 4] * nib;                                     \
        acc5 += job.m[(j) * 8 + 5] * nib;                                     \
        acc6 += job.m[(j) * 8 + 6] * nib;                                     \
        acc7 += job.m[(j) * 8 + 7] * nib;                                     \
    }

// Byte b of the first digest is columns 2b (its high nibble) and 2b + 1.
#define HH_BYTE(b)                                                            \
    {                                                                         \
        uint byt = (d[(b) >> 2] >> (8 * ((b) & 3))) & 0xffu;                  \
        HH_COL(2 * (b), byt >> 4)                                             \
        HH_COL(2 * (b) + 1, byt & 0xfu)                                       \
    }

#define HH_WORD(w)                                                            \
    HH_BYTE(4 * (w)) HH_BYTE(4 * (w) + 1) HH_BYTE(4 * (w) + 2) HH_BYTE(4 * (w) + 3)

// Four accumulator words are four bytes of the product: each half is a row's
// sum, >> 10 is its nibble, and the even row is the byte's high nibble.
uint hh_pack(uvec4 acc)
{
    uvec4 b = (((acc >> 10u) & 0xfu) << 4u) | (acc >> 26u);
    return b.x | (b.y << 8u) | (b.z << 16u) | (b.w << 24u);
}

void main()
{
    uint index = gl_GlobalInvocationID.x;
    if (index >= push.count)
        return;

    uint nonce = push.nonce_start + index;

    KLANE a[25];
    for (int i = 0; i < 25; i++)
        a[i] = klane(0u, 0u);

    // Eighty bytes is ten lanes, so the nonce is the high half of the tenth and
    // the padding starts on a lane boundary in the eleventh.
    for (int i = 0; i < 9; i++)
        a[i] = klane(push.block[2 * i], push.block[2 * i + 1]);
    a[9] = klane(push.block[18], bswap32(nonce));
    a[10] = klane(0x06u, 0u);
    a[SHA3_256_RATE_LANES - 1] = klane(0u, 0x80000000u);

    sha3_keccakf(a);

    uint d[8];
    for (int i = 0; i < 4; i++) {
        d[2 * i] = klo(a[i]);
        d[2 * i + 1] = khi(a[i]);
    }

    uvec4 acc0 = uvec4(0u), acc1 = uvec4(0u), acc2 = uvec4(0u), acc3 = uvec4(0u);
    uvec4 acc4 = uvec4(0u), acc5 = uvec4(0u), acc6 = uvec4(0u), acc7 = uvec4(0u);

    HH_WORD(0) HH_WORD(1) HH_WORD(2) HH_WORD(3)
    HH_WORD(4) HH_WORD(5) HH_WORD(6) HH_WORD(7)

    // SHA3-256 of the 32 bytes: four lanes of message and two of padding in an
    // otherwise empty state.
    for (int i = 0; i < 25; i++)
        a[i] = klane(0u, 0u);

    a[0] = klane(d[0] ^ hh_pack(acc0), d[1] ^ hh_pack(acc1));
    a[1] = klane(d[2] ^ hh_pack(acc2), d[3] ^ hh_pack(acc3));
    a[2] = klane(d[4] ^ hh_pack(acc4), d[5] ^ hh_pack(acc5));
    a[3] = klane(d[6] ^ hh_pack(acc6), d[7] ^ hh_pack(acc7));
    a[4] = klane(0x06u, 0u);
    a[SHA3_256_RATE_LANES - 1] = klane(0u, 0x80000000u);

    sha3_keccakf(a);

    // The most significant digest word: the high half of lane 3.
    uint top = khi(a[3]);

    probe_best(top);

    if (top > push.target[7])
        return;

    uint state[8];
    for (int i = 0; i < 4; i++) {
        state[2 * i] = klo(a[i]);
        state[2 * i + 1] = khi(a[i]);
    }

    // The full comparison, most significant word first.
    for (int i = 7; i >= 0; i--) {
        if (state[i] > push.target[i])
            return;
        if (state[i] < push.target[i])
            break;
    }

    emit_candidate(push.capacity, nonce, state);
}

#endif  // VKMINER_ALGORITHMS_HEAVYHASH_KERNEL_GLSL_INCLUDED
