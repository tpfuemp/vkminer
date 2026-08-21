// Keccak's permutation over 32-bit lanes.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Not a narrower call into the f[1600] this project already has for sha3t.
// It is a different permutation: 22 rounds instead of 24, the round constants
// truncated to their low half, and the rotation offsets taken mod 32. Nothing
// here is a lane pair and nothing here needs shaderInt64, which is the one
// thing it buys and the reason KawPoW builds on every device that can mine.
//
// The state is the whole of a KawPoW absorb -- 25 words, every one of them
// written by the caller -- so there is no rate here and no padding rule. What
// gets absorbed is the algorithm's business; this is the permutation and no
// more.

#ifndef VKMINER_SHADERS_COMMON_KECCAK_F800_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_KECCAK_F800_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint kKeccakF800Rounds = 22u;

const uint kKeccakF800Rc[22] = uint[22](
    0x00000001u, 0x00008082u, 0x0000808au, 0x80008000u, 0x0000808bu,
    0x80000001u, 0x80008081u, 0x00008009u, 0x0000008au, 0x00000088u,
    0x80008009u, 0x8000000au, 0x8000808bu, 0x0000008bu, 0x00008089u,
    0x00008003u, 0x00008002u, 0x00000080u, 0x0000800au, 0x8000000au,
    0x80008081u, 0x00008080u);

// Rho, in state order: f[1600]'s offsets reduced mod 32. Lane 0's offset is
// zero and bits.glsl's rotl32 is undefined there, so the zero is handled here
// rather than by making the shared rotate slower for every other caller.
const uint kKeccakF800Rho[25] = uint[25](
     0u,  1u, 30u, 28u, 27u,
     4u, 12u,  6u, 23u, 20u,
     3u, 10u, 11u, 25u,  7u,
     9u, 13u, 15u, 21u,  8u,
    18u,  2u, 29u, 24u, 14u);

void keccak_f800(inout uint st[25])
{
    for (uint round = 0u; round < kKeccakF800Rounds; round++) {
        uint c[5];
        for (uint x = 0u; x < 5u; x++)
            c[x] = st[x] ^ st[x + 5u] ^ st[x + 10u] ^ st[x + 15u] ^ st[x + 20u];

        for (uint x = 0u; x < 5u; x++) {
            uint d = c[(x + 4u) % 5u] ^ rotl32(c[(x + 1u) % 5u], 1u);
            for (uint y = 0u; y < 5u; y++)
                st[x + 5u * y] ^= d;
        }

        // Rho and pi together: lane (x, y) rotates by its own offset and moves
        // to (y, 2x + 3y).
        uint b[25];
        for (uint y = 0u; y < 5u; y++) {
            for (uint x = 0u; x < 5u; x++) {
                uint from = x + 5u * y;
                uint to = y + 5u * ((2u * x + 3u * y) % 5u);
                uint n = kKeccakF800Rho[from];
                b[to] = n == 0u ? st[from] : rotl32(st[from], n);
            }
        }

        for (uint y = 0u; y < 5u; y++) {
            for (uint x = 0u; x < 5u; x++)
                st[x + 5u * y] = b[x + 5u * y]
                               ^ (~b[(x + 1u) % 5u + 5u * y]
                                  & b[(x + 2u) % 5u + 5u * y]);
        }

        st[0] ^= kKeccakF800Rc[round];
    }
}

#endif  // VKMINER_SHADERS_COMMON_KECCAK_F800_GLSL_INCLUDED
