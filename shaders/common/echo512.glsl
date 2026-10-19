// ECHO-512, the round 2 specification: one 128-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state is sixteen 128-bit words, four uints each, w[4 * word + i], laid
// out column by column in a 4x4 matrix: the chaining value v in words 0..7 and
// the block in 8..15. The caller owns the padding and the bit counter.
// src/core/echo512.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_ECHO512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_ECHO512_GLSL_INCLUDED

#include "shaders/common/aes.glsl"

// The 128-bit counter plus a small offset, as a round key.
void echo512_key(uint cnt[4], uint add, out uint key[4])
{
    key[0] = cnt[0] + add;
    uint c = key[0] < add ? 1u : 0u;
    key[1] = cnt[1] + c;
    c = (c == 1u && key[1] == 0u) ? 1u : 0u;
    key[2] = cnt[2] + c;
    c = (c == 1u && key[2] == 0u) ? 1u : 0u;
    key[3] = cnt[3] + c;
}

// One compression of the block m into the chaining value v, under the 128-bit
// bit counter cnt, least significant word first.
void echo512_compress(inout uint v[32], uint m[32], uint cnt[4])
{
    uint w[64];
    for (uint i = 0u; i < 32u; i++) {
        w[i] = v[i];
        w[32u + i] = m[i];
    }

    for (uint r = 0u; r < 10u; r++) {
        // BigSubWords: two AES rounds per word, the first keyed with the
        // counter plus the word's place in the whole run, two words at a time.
        for (uint n = 0u; n < 16u; n += 2u) {
            uint x[8];
            for (uint i = 0u; i < 8u; i++)
                x[i] = w[4u * n + i];
            aes_round2(x);
            uint k0[4], k1[4];
            echo512_key(cnt, 16u * r + n, k0);
            echo512_key(cnt, 16u * r + n + 1u, k1);
            for (uint i = 0u; i < 4u; i++) {
                x[i] ^= k0[i];
                x[4u + i] ^= k1[i];
            }
            aes_round2(x);
            for (uint i = 0u; i < 8u; i++)
                w[4u * n + i] = x[i];
        }

        // BigShiftRows: word (column c, row) from column c + row.
        uint t[64] = w;
        for (uint c = 0u; c < 4u; c++)
            for (uint row = 1u; row < 4u; row++)
                for (uint i = 0u; i < 4u; i++)
                    w[4u * (4u * c + row) + i] =
                        t[4u * (4u * ((c + row) & 3u) + row) + i];

        // BigMixColumns: AES MixColumns down each column, four bytes at once.
        for (uint c = 0u; c < 4u; c++) {
            for (uint i = 0u; i < 4u; i++) {
                uint a = w[16u * c + i];
                uint b = w[16u * c + 4u + i];
                uint d2 = w[16u * c + 8u + i];
                uint d3 = w[16u * c + 12u + i];
                uint ab = a ^ b, bc = b ^ d2, cd = d2 ^ d3, da = d3 ^ a;
                w[16u * c + i]       = aes_xtime4(ab) ^ b ^ cd;
                w[16u * c + 4u + i]  = aes_xtime4(bc) ^ d2 ^ da;
                w[16u * c + 8u + i]  = aes_xtime4(cd) ^ d3 ^ ab;
                w[16u * c + 12u + i] = aes_xtime4(da) ^ a ^ bc;
            }
        }
    }

    for (uint i = 0u; i < 32u; i++)
        v[i] ^= m[i] ^ w[i] ^ w[32u + i];
}

#endif  // VKMINER_SHADERS_COMMON_ECHO512_GLSL_INCLUDED
