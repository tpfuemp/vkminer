// Luffa-512, version 2 of the specification: one 32-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Five lanes of eight words, v[8 * lane + word], words as the specification's
// big-endian reads of the message. No padding and no output here; the caller
// owns both. src/core/luffa512.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_LUFFA512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_LUFFA512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint kLuffa512Iv[40] = uint[40](
    0x6d251e69u, 0x44b051e0u, 0x4eaa6fb4u, 0xdbf78465u,
    0x6e292011u, 0x90152df4u, 0xee058139u, 0xdef610bbu,
    0xc3b44b95u, 0xd9d2f256u, 0x70eee9a0u, 0xde099fa3u,
    0x5d9b0557u, 0x8fc944b3u, 0xcf1ccf0eu, 0x746cd581u,
    0xf7efc89du, 0x5dba5781u, 0x04016ce5u, 0xad659c05u,
    0x0306194fu, 0x666d1836u, 0x24aa230au, 0x8b264ae7u,
    0x858075d5u, 0x36d79cceu, 0xe571f7d7u, 0x204b1f67u,
    0x35870c6au, 0x57e9e923u, 0x14bcb808u, 0x7cde72ceu,
    0x6c68e9beu, 0x5ec41e22u, 0xc825b7c7u, 0xaffb4363u,
    0xf5df3999u, 0x0fc688f1u, 0xb07224ccu, 0x03e86ceau);

// Multiplication by x of the eight words starting at b, in place.
#define LUFFA_MUL2(a, b)                                                    \
    {                                                                       \
        uint t_ = a[(b) + 7];                                               \
        a[(b) + 7] = a[(b) + 6]; a[(b) + 6] = a[(b) + 5];                   \
        a[(b) + 5] = a[(b) + 4]; a[(b) + 4] = a[(b) + 3] ^ t_;              \
        a[(b) + 3] = a[(b) + 2] ^ t_; a[(b) + 2] = a[(b) + 1];              \
        a[(b) + 1] = a[(b) + 0] ^ t_; a[(b) + 0] = t_;                      \
    }

// The bitsliced 4-bit S-box.
void luffa_sub_crumb(inout uint a0, inout uint a1, inout uint a2, inout uint a3)
{
    uint t = a0;
    a0 |= a1;
    a2 ^= a3;
    a1 = ~a1;
    a0 ^= a3;
    a3 &= t;
    a1 ^= a3;
    a3 ^= a2;
    a2 &= a0;
    a0 = ~a0;
    a2 ^= a1;
    a1 |= a3;
    t ^= a1;
    a3 ^= a2;
    a2 &= a1;
    a1 ^= a0;
    a0 = t;
}

void luffa_mix_word(inout uint u, inout uint v)
{
    v ^= u;
    u = rotl32(u, 2u) ^ v;
    v = rotl32(v, 14u) ^ u;
    u = rotl32(u, 10u) ^ v;
    v = rotl32(v, 1u);
}

// One step of the permutation of the lane at b; c0 and c4 are its constants.
#define LUFFA_STEP(b, c0, c4)                                               \
    luffa_sub_crumb(v[(b) + 0], v[(b) + 1], v[(b) + 2], v[(b) + 3]);        \
    luffa_sub_crumb(v[(b) + 5], v[(b) + 6], v[(b) + 7], v[(b) + 4]);        \
    luffa_mix_word(v[(b) + 0], v[(b) + 4]);                                 \
    luffa_mix_word(v[(b) + 1], v[(b) + 5]);                                 \
    luffa_mix_word(v[(b) + 2], v[(b) + 6]);                                 \
    luffa_mix_word(v[(b) + 3], v[(b) + 7]);                                 \
    v[(b) + 0] ^= (c0);                                                     \
    v[(b) + 4] ^= (c4)

// The tweak: words 4..7 of lane j rotated left by j.
#define LUFFA_TWEAK(b, j)                                                   \
    v[(b) + 4] = rotl32(v[(b) + 4], j); v[(b) + 5] = rotl32(v[(b) + 5], j); \
    v[(b) + 6] = rotl32(v[(b) + 6], j); v[(b) + 7] = rotl32(v[(b) + 7], j)

// The message injection MI for w = 5 and the tweak: everything in a block
// before the steps. Linear in m, so a caller can run it once with part of the
// message zeroed and xor that part in afterwards.
void luffa512_inject(inout uint v[40], uint m[8])
{
    uint a[8];
    for (uint k = 0u; k < 8u; k++)
        a[k] = v[k] ^ v[8u + k] ^ v[16u + k] ^ v[24u + k] ^ v[32u + k];
    LUFFA_MUL2(a, 0);
    for (uint k = 0u; k < 40u; k++)
        v[k] ^= a[k & 7u];

    uint b[8];
    for (uint k = 0u; k < 8u; k++)
        b[k] = v[k];
    LUFFA_MUL2(b, 0);
    for (uint k = 0u; k < 8u; k++)
        b[k] ^= v[8u + k];
    LUFFA_MUL2(v, 8);  for (uint k = 0u; k < 8u; k++) v[8u + k] ^= v[16u + k];
    LUFFA_MUL2(v, 16); for (uint k = 0u; k < 8u; k++) v[16u + k] ^= v[24u + k];
    LUFFA_MUL2(v, 24); for (uint k = 0u; k < 8u; k++) v[24u + k] ^= v[32u + k];
    LUFFA_MUL2(v, 32); for (uint k = 0u; k < 8u; k++) v[32u + k] ^= v[k];
    for (uint k = 0u; k < 8u; k++) v[k] = b[k];
    LUFFA_MUL2(v, 0);  for (uint k = 0u; k < 8u; k++) v[k] ^= v[32u + k];
    LUFFA_MUL2(v, 32); for (uint k = 0u; k < 8u; k++) v[32u + k] ^= v[24u + k];
    LUFFA_MUL2(v, 24); for (uint k = 0u; k < 8u; k++) v[24u + k] ^= v[16u + k];
    LUFFA_MUL2(v, 16); for (uint k = 0u; k < 8u; k++) v[16u + k] ^= v[8u + k];
    LUFFA_MUL2(v, 8);  for (uint k = 0u; k < 8u; k++) v[8u + k] ^= b[k];

    uint mm[8] = m;
    for (uint j = 0u; j < 5u; j++) {
        for (uint k = 0u; k < 8u; k++)
            v[8u * j + k] ^= mm[k];
        if (j < 4u)
            LUFFA_MUL2(mm, 0);
    }

    LUFFA_TWEAK(8, 1u);
    LUFFA_TWEAK(16, 2u);
    LUFFA_TWEAK(24, 3u);
    LUFFA_TWEAK(32, 4u);
}

// Each lane's eight steps, after luffa512_inject().
void luffa512_steps(inout uint v[40])
{
    LUFFA_STEP(0, 0x303994a6u, 0xe0337818u);
    LUFFA_STEP(0, 0xc0e65299u, 0x441ba90du);
    LUFFA_STEP(0, 0x6cc33a12u, 0x7f34d442u);
    LUFFA_STEP(0, 0xdc56983eu, 0x9389217fu);
    LUFFA_STEP(0, 0x1e00108fu, 0xe5a8bce6u);
    LUFFA_STEP(0, 0x7800423du, 0x5274baf4u);
    LUFFA_STEP(0, 0x8f5b7882u, 0x26889ba7u);
    LUFFA_STEP(0, 0x96e1db12u, 0x9a226e9du);

    LUFFA_STEP(8, 0xb6de10edu, 0x01685f3du);
    LUFFA_STEP(8, 0x70f47aaeu, 0x05a17cf4u);
    LUFFA_STEP(8, 0x0707a3d4u, 0xbd09cacau);
    LUFFA_STEP(8, 0x1c1e8f51u, 0xf4272b28u);
    LUFFA_STEP(8, 0x707a3d45u, 0x144ae5ccu);
    LUFFA_STEP(8, 0xaeb28562u, 0xfaa7ae2bu);
    LUFFA_STEP(8, 0xbaca1589u, 0x2e48f1c1u);
    LUFFA_STEP(8, 0x40a46f3eu, 0xb923c704u);

    LUFFA_STEP(16, 0xfc20d9d2u, 0xe25e72c1u);
    LUFFA_STEP(16, 0x34552e25u, 0xe623bb72u);
    LUFFA_STEP(16, 0x7ad8818fu, 0x5c58a4a4u);
    LUFFA_STEP(16, 0x8438764au, 0x1e38e2e7u);
    LUFFA_STEP(16, 0xbb6de032u, 0x78e38b9du);
    LUFFA_STEP(16, 0xedb780c8u, 0x27586719u);
    LUFFA_STEP(16, 0xd9847356u, 0x36eda57fu);
    LUFFA_STEP(16, 0xa2c78434u, 0x703aace7u);

    LUFFA_STEP(24, 0xb213afa5u, 0xe028c9bfu);
    LUFFA_STEP(24, 0xc84ebe95u, 0x44756f91u);
    LUFFA_STEP(24, 0x4e608a22u, 0x7e8fce32u);
    LUFFA_STEP(24, 0x56d858feu, 0x956548beu);
    LUFFA_STEP(24, 0x343b138fu, 0xfe191be2u);
    LUFFA_STEP(24, 0xd0ec4e3du, 0x3cb226e5u);
    LUFFA_STEP(24, 0x2ceb4882u, 0x5944a28eu);
    LUFFA_STEP(24, 0xb3ad2208u, 0xa1c4c355u);

    LUFFA_STEP(32, 0xf0d2e9e3u, 0x5090d577u);
    LUFFA_STEP(32, 0xac11d7fau, 0x2d1925abu);
    LUFFA_STEP(32, 0x1bcb66f2u, 0xb46496acu);
    LUFFA_STEP(32, 0x6f2d9bc9u, 0xd1925ab0u);
    LUFFA_STEP(32, 0x78602649u, 0x29131ab6u);
    LUFFA_STEP(32, 0x8edae952u, 0x0fc053c3u);
    LUFFA_STEP(32, 0x3b6ba548u, 0x3f014f0cu);
    LUFFA_STEP(32, 0xedae9520u, 0xfc053c31u);
}

// One 32-byte block: injection, then the steps.
void luffa512_block(inout uint v[40], uint m[8])
{
    luffa512_inject(v, m);
    luffa512_steps(v);
}

// Digest word k of the current output block: the xor of the five lanes.
uint luffa512_out(uint v[40], uint k)
{
    return v[k] ^ v[8u + k] ^ v[16u + k] ^ v[24u + k] ^ v[32u + k];
}

#undef LUFFA_STEP
#undef LUFFA_TWEAK

#endif  // VKMINER_SHADERS_COMMON_LUFFA512_GLSL_INCLUDED
