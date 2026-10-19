// CubeHash16/32-512, the round 2 parameters: sixteen rounds per 32-byte block.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state is 32 little-endian words. The caller xors a block into words
// 0..7, runs sixteen rounds, and owns the padding: a 0x80 byte and zeros to
// the block, then x[31] ^= 1 and 160 rounds. src/core/cubehash512.c is the
// scalar reference.

#ifndef VKMINER_SHADERS_COMMON_CUBEHASH512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_CUBEHASH512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint kCubehash512Iv[32] = uint[32](
    0x2AEA2A61u, 0x50F494D4u, 0x2D538B8Bu, 0x4167D83Eu,
    0x3FEE2313u, 0xC701CF8Cu, 0xCC39968Eu, 0x50AC5695u,
    0x4D42C787u, 0xA647A8B3u, 0x97CF0BEFu, 0x825B4537u,
    0xEEF864D2u, 0xF22090C4u, 0xD0E5CD33u, 0xA23911AEu,
    0xFCD398D9u, 0x148FE485u, 0x1B017BEFu, 0xB6444532u,
    0x6A536159u, 0x2FF5781Cu, 0x91FA7934u, 0x0DBADEA9u,
    0xD65C8A2Bu, 0xA5A70E75u, 0xB1C62456u, 0xBC796576u,
    0x1921C8F7u, 0xE7989AF1u, 0x7795D246u, 0xD43E3B44u);

// Two rounds, the specification's ten steps each. Every index is a constant
// once the loops unroll, so the swaps are renames, not moves.
void cubehash_round2(inout uint x[32])
{
    // Round one.
    for (uint i = 0u; i < 16u; i++) x[16u + i] += x[i];
    for (uint i = 0u; i < 16u; i++) x[i] = rotl32(x[i], 7u);
    for (uint i = 0u; i < 8u; i++) {
        uint t = x[i]; x[i] = x[i + 8u]; x[i + 8u] = t;
    }
    for (uint i = 0u; i < 16u; i++) x[i] ^= x[16u + i];
    for (uint i = 0u; i < 16u; i += 4u) {
        uint t = x[16u + i]; x[16u + i] = x[18u + i]; x[18u + i] = t;
        t = x[17u + i]; x[17u + i] = x[19u + i]; x[19u + i] = t;
    }
    for (uint i = 0u; i < 16u; i++) x[16u + i] += x[i];
    for (uint i = 0u; i < 16u; i++) x[i] = rotl32(x[i], 11u);
    for (uint i = 0u; i < 16u; i += 8u) {
        for (uint k = 0u; k < 4u; k++) {
            uint t = x[i + k]; x[i + k] = x[i + k + 4u]; x[i + k + 4u] = t;
        }
    }
    for (uint i = 0u; i < 16u; i++) x[i] ^= x[16u + i];
    for (uint i = 0u; i < 16u; i += 2u) {
        uint t = x[16u + i]; x[16u + i] = x[17u + i]; x[17u + i] = t;
    }

    // Round two, the same steps.
    for (uint i = 0u; i < 16u; i++) x[16u + i] += x[i];
    for (uint i = 0u; i < 16u; i++) x[i] = rotl32(x[i], 7u);
    for (uint i = 0u; i < 8u; i++) {
        uint t = x[i]; x[i] = x[i + 8u]; x[i + 8u] = t;
    }
    for (uint i = 0u; i < 16u; i++) x[i] ^= x[16u + i];
    for (uint i = 0u; i < 16u; i += 4u) {
        uint t = x[16u + i]; x[16u + i] = x[18u + i]; x[18u + i] = t;
        t = x[17u + i]; x[17u + i] = x[19u + i]; x[19u + i] = t;
    }
    for (uint i = 0u; i < 16u; i++) x[16u + i] += x[i];
    for (uint i = 0u; i < 16u; i++) x[i] = rotl32(x[i], 11u);
    for (uint i = 0u; i < 16u; i += 8u) {
        for (uint k = 0u; k < 4u; k++) {
            uint t = x[i + k]; x[i + k] = x[i + k + 4u]; x[i + k + 4u] = t;
        }
    }
    for (uint i = 0u; i < 16u; i++) x[i] ^= x[16u + i];
    for (uint i = 0u; i < 16u; i += 2u) {
        uint t = x[16u + i]; x[16u + i] = x[17u + i]; x[17u + i] = t;
    }
}

// n rounds, n even.
void cubehash512_rounds(inout uint x[32], uint n)
{
    for (uint r = 0u; r < n; r += 2u)
        cubehash_round2(x);
}

#endif  // VKMINER_SHADERS_COMMON_CUBEHASH512_GLSL_INCLUDED
