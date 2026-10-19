// SHAvite-3-512, the round 2 specification: one 128-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sixteen little-endian words of chaining value, four quarters of four. The
// block's 448 words of round keys are produced 32 at a time, one block of them
// per round, each from the one before, so only two blocks are ever live. The
// caller owns the padding and the bit counter. src/core/shavite512.c is the
// scalar reference.

#ifndef VKMINER_SHADERS_COMMON_SHAVITE512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHAVITE512_GLSL_INCLUDED

#include "shaders/common/aes.glsl"

const uint kShavite512Iv[16] = uint[16](
    0x72FCCDD8u, 0x79CA4727u, 0x128A077Bu, 0x40D55AECu,
    0xD1901A06u, 0x430AE307u, 0xB29F5CD1u, 0xDF07FBFCu,
    0x8E45D73Du, 0x681AB538u, 0xBDE86578u, 0xDD577E47u,
    0xE275EADEu, 0x502D9FCDu, 0xB9357178u, 0x022A4B9Au);

// Round-key block b (1..13) from block b - 1, in place. Odd blocks are the
// nonlinear ones: an AES round of each quarter of the old block, rotated by a
// word, chained through the quarter before. The four AES rounds read only the
// old block, so they run as two pairs before the chain. Even blocks are linear.
// The counter goes in at words 32, 164, 316 and 440, each time in another
// order and with one word inverted.
void shavite512_next_keys(inout uint k[32], uint b, uint cnt[4])
{
    uint n[32];
    if ((b & 1u) == 1u) {
        for (uint q = 0u; q < 8u; q += 2u) {
            uint x[8];
            x[0] = k[4u * q + 1u]; x[1] = k[4u * q + 2u];
            x[2] = k[4u * q + 3u]; x[3] = k[4u * q];
            x[4] = k[4u * q + 5u]; x[5] = k[4u * q + 6u];
            x[6] = k[4u * q + 7u]; x[7] = k[4u * q + 4u];
            aes_round2(x);
            for (uint i = 0u; i < 8u; i++)
                n[4u * q + i] = x[i];
        }
        for (uint i = 0u; i < 4u; i++)
            n[i] ^= k[28u + i];
        for (uint q = 0u; q < 8u; q++) {
            if (q > 0u)
                for (uint i = 0u; i < 4u; i++)
                    n[4u * q + i] ^= n[4u * q - 4u + i];

            // Word 32 * b + 4 * q of the schedule.
            uint u = 32u * b + 4u * q;
            if (u == 32u) {
                n[0] ^= cnt[0]; n[1] ^= cnt[1]; n[2] ^= cnt[2]; n[3] ^= ~cnt[3];
            } else if (u == 164u) {
                n[4] ^= cnt[3]; n[5] ^= cnt[2]; n[6] ^= cnt[1]; n[7] ^= ~cnt[0];
            } else if (u == 316u) {
                n[28] ^= cnt[2]; n[29] ^= cnt[3]; n[30] ^= cnt[0]; n[31] ^= ~cnt[1];
            } else if (u == 440u) {
                n[24] ^= cnt[1]; n[25] ^= cnt[0]; n[26] ^= cnt[3]; n[27] ^= ~cnt[2];
            }
        }
    } else {
        // rk[u] = rk[u - 32] ^ rk[u - 7]: seven back is in the old block for
        // the first seven words and in this one after.
        for (uint i = 0u; i < 32u; i++)
            n[i] = k[i] ^ (i < 7u ? k[25u + i] : n[i - 7u]);
    }
    k = n;
}

// One compression of the block m under the 128-bit bit counter cnt, least
// significant word first.
void shavite512_compress(inout uint h[16], uint m[32], uint cnt[4])
{
    uint k[32] = m;
    uint p[16] = h;

    for (uint r = 0u; r < 14u; r++) {
        if (r > 0u)
            shavite512_next_keys(k, r, cnt);

        // Quarter 0 takes F of quarter 1 with keys 0..15, and quarter 2 F of
        // quarter 3 with keys 16..31: four AES rounds each, side by side.
        uint x[8];
        for (uint i = 0u; i < 4u; i++) {
            x[i] = p[4u + i] ^ k[i];
            x[4u + i] = p[12u + i] ^ k[16u + i];
        }
        for (uint j = 1u; j < 4u; j++) {
            aes_round2(x);
            for (uint i = 0u; i < 4u; i++) {
                x[i] ^= k[4u * j + i];
                x[4u + i] ^= k[16u + 4u * j + i];
            }
        }
        aes_round2(x);
        for (uint i = 0u; i < 4u; i++) {
            p[i] ^= x[i];
            p[8u + i] ^= x[4u + i];
        }

        // Quarters (0, 1, 2, 3) become (3, 0, 1, 2).
        uint t[4];
        for (uint i = 0u; i < 4u; i++) {
            t[i] = p[12u + i];
            p[12u + i] = p[8u + i];
            p[8u + i] = p[4u + i];
            p[4u + i] = p[i];
            p[i] = t[i];
        }
    }

    for (uint i = 0u; i < 16u; i++)
        h[i] ^= p[i];
}

#endif  // VKMINER_SHADERS_COMMON_SHAVITE512_GLSL_INCLUDED
