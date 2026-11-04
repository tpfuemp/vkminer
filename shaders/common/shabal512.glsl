// Shabal-512, the round 2 SHA-3 submission, over a 64- or 80-byte message.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Words are little-endian reads of the message and of the digest, the same
// convention as the 64-byte states the x11 family passes between stages.
// src/core/shabal512.c is the scalar reference, and derives the initial state
// below from the specification's prefix blocks.

#ifndef VKMINER_SHADERS_COMMON_SHABAL512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHABAL512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

// A[12], B[16], C[16] after the prefix, with the counter at 1.
const uint kShabal512Iv[44] = uint[44](
    0x20728dfdu, 0x46c0bd53u, 0xe782b699u, 0x55304632u,
    0x71b4ef90u, 0x0ea9e82cu, 0xdbb930f1u, 0xfad06b8bu,
    0xbe0cae40u, 0x8bd14410u, 0x76d2adacu, 0x28acab7fu,
    0xc1099cb7u, 0x07b385f3u, 0xe7442c26u, 0xcc8ad640u,
    0xeb6f56c7u, 0x1ea81aa9u, 0x73b9d314u, 0x1de85d08u,
    0x48910a5au, 0x893b22dbu, 0xc5a0df44u, 0xbbc4324eu,
    0x72d2f240u, 0x75941d99u, 0x6d8bde82u, 0xa1a7502bu,
    0xd9bf68d1u, 0x58bad750u, 0x56028cb2u, 0x8134f359u,
    0xb5d469d8u, 0x941a8cc2u, 0x418b2a6eu, 0x04052780u,
    0x7f07d787u, 0x5194358fu, 0x3c60d665u, 0xbe97d79au,
    0x950c3434u, 0xaed9a06du, 0x2537dc8du, 0x7cdb5969u);

// The keyed permutation: B rotated by 17, three passes of sixteen word
// updates, then 36 additions of C into A.
void shabal512_permute(inout uint a[12], inout uint b[16], uint c[16],
                       uint m[16])
{
    for (uint i = 0u; i < 16u; i++)
        b[i] = rotl32(b[i], 17u);

    for (uint j = 0u; j < 3u; j++)
        for (uint i = 0u; i < 16u; i++) {
            uint k = (16u * j + i) % 12u;
            uint v = rotl32(a[(k + 11u) % 12u], 15u) * 5u;
            uint u = (a[k] ^ v ^ c[(24u - i) % 16u]) * 3u;
            a[k] = u ^ b[(i + 13u) % 16u]
                 ^ (b[(i + 9u) % 16u] & ~b[(i + 6u) % 16u]) ^ m[i];
            b[i] = ~(rotl32(b[i], 1u) ^ a[k]);
        }

    for (uint j = 0u; j < 36u; j++)
        a[j % 12u] += c[(j + 3u) % 16u];
}

// Shabal-512 of the first `words` words of `msg`, 16 or 20; a constant at
// every call site. One full block under counter 1, then the padded final
// block under counter 2, permuted four times and never subtracted.
void shabal512_hash(uint msg[20], uint words, out uint h[16])
{
    uint a[12], b[16], c[16], m[16];
    for (uint k = 0u; k < 12u; k++)
        a[k] = kShabal512Iv[k];
    for (uint k = 0u; k < 16u; k++) {
        b[k] = kShabal512Iv[12u + k];
        c[k] = kShabal512Iv[28u + k];
        m[k] = msg[k];
    }

    for (uint k = 0u; k < 16u; k++)
        b[k] += m[k];
    a[0] ^= 1u;
    shabal512_permute(a, b, c, m);
    for (uint k = 0u; k < 16u; k++) {
        c[k] -= m[k];
        uint t = b[k];
        b[k] = c[k];
        c[k] = t;
    }

    for (uint k = 0u; k < 16u; k++)
        m[k] = k + 16u < words ? msg[k + 16u] : 0u;
    m[words - 16u] = 0x80u;

    for (uint k = 0u; k < 16u; k++)
        b[k] += m[k];
    for (uint r = 0u; r < 4u; r++) {
        if (r > 0u)
            for (uint k = 0u; k < 16u; k++) {
                uint t = b[k];
                b[k] = c[k];
                c[k] = t;
            }
        a[0] ^= 2u;
        shabal512_permute(a, b, c, m);
    }

    h = b;
}

#endif  // VKMINER_SHADERS_COMMON_SHABAL512_GLSL_INCLUDED
