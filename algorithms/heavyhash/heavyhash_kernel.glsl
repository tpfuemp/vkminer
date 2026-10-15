// heavyhash: one nonce per invocation. SHA3-256, a 64x64 matrix product, SHA3-256.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by heavyhash.comp and heavyhash32.comp, which differ only in the
// Keccak lane type, and by heavyhash_dot.comp, which is heavyhash32.comp with
// the matrix step as byte dot products (HH_DOT). The per-job matrix arrives in
// the uniform block and every read of it is at a compile-time offset. Byte
// order is sha3t's: header words arrive byte-reversed, the nonce is reversed
// here, the digest needs no swap.

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

// 12288 bytes, mirrored by HeavyhashUniform. Column j is m[8j .. 8j + 7]:
// 32 words, word k holding row 2k in its low half and row 2k + 1 in its high
// half, so one multiply-add does two rows. A row sum peaks at 14400, so a half
// never carries into the other. dm is the same matrix by rows for HH_DOT: row
// i is dm[4i .. 4i + 3], 16 words, byte b of word w holding column 4w + b.
// The other modules declare only m, and the host fills both.
layout(std140, binding = 1) uniform Job {
    uvec4 m[512];
#ifdef HH_DOT
    uvec4 dm[256];
#endif
} job;

#ifdef HH_DOT

// Columns 4w .. 4w + 3 of row i against the nibbles packed the same way.
#define HH_DOT4(i, k)                                                         \
    (dotPacked4x8EXT(job.dm[4 * (i) + (k)].x, nw[4 * (k)])                    \
     + dotPacked4x8EXT(job.dm[4 * (i) + (k)].y, nw[4 * (k) + 1])              \
     + dotPacked4x8EXT(job.dm[4 * (i) + (k)].z, nw[4 * (k) + 2])              \
     + dotPacked4x8EXT(job.dm[4 * (i) + (k)].w, nw[4 * (k) + 3]))

// Row i's nibble of the product: its sum peaks at 14400, so >> 10 is < 15.
#define HH_ROW(i)                                                             \
    ((HH_DOT4(i, 0) + HH_DOT4(i, 1) + HH_DOT4(i, 2) + HH_DOT4(i, 3)) >> 10)

// Byte b of the product: row 2b is its high nibble.
#define HH_PBYTE(b) ((HH_ROW(2 * (b)) << 4) | HH_ROW(2 * (b) + 1))

#define HH_PWORD(q)                                                           \
    (HH_PBYTE(4 * (q)) | (HH_PBYTE(4 * (q) + 1) << 8)                         \
     | (HH_PBYTE(4 * (q) + 2) << 16) | (HH_PBYTE(4 * (q) + 3) << 24))

// Two digest bytes' nibbles as four bytes, high nibble first: h and l hold the
// high and low nibbles of those bytes in their two low bytes.
uint hh_nibbles(uint h, uint l)
{
    return (h & 0xffu) | ((l & 0xffu) << 8) | ((h & 0xff00u) << 8)
         | ((l & 0xff00u) << 16);
}

#endif

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

// One Keccak-f round, as sha3_keccakf writes it. Split here rather than in the
// shared sha3.glsl so the last round can sit outside the loop, where the
// compiler drops the lanes nobody reads.
void hh_round(inout KLANE a[25], uvec2 rc)
{
    KLANE c[5];
    KLANE d[5];
    KLANE b[25];

    for (int x = 0; x < 5; x++)
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (int x = 0; x < 5; x++)
        d[x] = c[(x + 4) % 5] ^ krotl(c[(x + 1) % 5], 1u);
    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 25; y += 5)
            a[x + y] ^= d[x];

    for (int x = 0; x < 5; x++)
        for (int y = 0; y < 5; y++)
            b[y + 5 * ((2 * x + 3 * y) % 5)] =
                krotl(a[x + 5 * y], sha3_rho[x + 5 * y]);

    for (int y = 0; y < 25; y += 5)
        for (int x = 0; x < 5; x++)
            a[y + x] = b[y + x]
                     ^ ((~b[y + (x + 1) % 5]) & b[y + (x + 2) % 5]);

    a[0] ^= klane(rc.x, rc.y);
}

// Rounds 0..22; the caller finishes with hh_round(a, sha3_rc[23]) or hh_top().
// Round 0 is peeled so the compiler can fold its mostly constant input.
void hh_keccakf_head(inout KLANE a[25])
{
    hh_round(a, sha3_rc[0]);
    for (int r = 1; r < 23; r++)
        hh_round(a, sha3_rc[r]);
}

// The high word of lane 3 after the last round, from the state before it. Lane
// 3 is row 0's chi over b[3], b[4], b[0], which rho and pi take from lanes 18,
// 24 and 0; iota touches only lane 0. Every column parity is still needed.
uint hh_top(KLANE a[25])
{
    KLANE c[5];
    for (int x = 0; x < 5; x++)
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];

    KLANE b0 = a[0] ^ c[4] ^ krotl(c[1], 1u);
    KLANE b3 = krotl(a[18] ^ c[2] ^ krotl(c[4], 1u), sha3_rho[18]);
    KLANE b4 = krotl(a[24] ^ c[3] ^ krotl(c[0], 1u), sha3_rho[24]);

    return khi(b3 ^ (~b4 & b0));
}

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

    // Only lanes 0..3 of the last round are read, so the other 21 drop out.
    hh_keccakf_head(a);
    hh_round(a, sha3_rc[23]);

    uint d[8];
    for (int i = 0; i < 4; i++) {
        d[2 * i] = klo(a[i]);
        d[2 * i + 1] = khi(a[i]);
    }

#ifdef HH_DOT
    // The 64 nibbles, four to a word in column order.
    uint nw[16];
    for (int q = 0; q < 8; q++) {
        uint h = (d[q] >> 4) & 0x0f0f0f0fu;
        uint l = d[q] & 0x0f0f0f0fu;
        nw[2 * q] = hh_nibbles(h, l);
        nw[2 * q + 1] = hh_nibbles(h >> 16, l >> 16);
    }

    uint p[8];
    p[0] = HH_PWORD(0); p[1] = HH_PWORD(1); p[2] = HH_PWORD(2); p[3] = HH_PWORD(3);
    p[4] = HH_PWORD(4); p[5] = HH_PWORD(5); p[6] = HH_PWORD(6); p[7] = HH_PWORD(7);

    // SHA3-256 of the 32 bytes, as below.
    for (int i = 0; i < 25; i++)
        a[i] = klane(0u, 0u);

    a[0] = klane(d[0] ^ p[0], d[1] ^ p[1]);
    a[1] = klane(d[2] ^ p[2], d[3] ^ p[3]);
    a[2] = klane(d[4] ^ p[4], d[5] ^ p[5]);
    a[3] = klane(d[6] ^ p[6], d[7] ^ p[7]);
#else
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
#endif
    a[4] = klane(0x06u, 0u);
    a[SHA3_256_RATE_LANES - 1] = klane(0u, 0x80000000u);

    hh_keccakf_head(a);

    // The most significant digest word, the high half of lane 3, without the
    // rest of the last round. Only a nonce that passes it computes the digest.
    uint top = hh_top(a);

    probe_best(top);

    if (top > push.target[7])
        return;

    hh_round(a, sha3_rc[23]);

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
