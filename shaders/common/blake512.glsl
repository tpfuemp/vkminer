// BLAKE-512, the final SHA-3 submission: one 128-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Not BLAKE2b, and not blake2s.glsl's function either: BLAKE-512 has sixteen
// rounds, rotations 32/25/16/11, a constant xored into every message word and
// its own padding.
//
// Words are BKLANE, big-endian reads of the message as the specification has
// them. No padding here; the caller owns it. src/core/blake512.c is the scalar
// reference.

#ifndef VKMINER_SHADERS_COMMON_BLAKE512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_BLAKE512_GLSL_INCLUDED

#ifdef VKMINER_BLAKE512_INT64

// The includer declares the extension.
#define BKLANE uint64_t

BKLANE bklane(uint lo, uint hi) { return uint64_t(lo) | (uint64_t(hi) << 32); }
uint   bklo(BKLANE x)           { return uint(x); }
uint   bkhi(BKLANE x)           { return uint(x >> 32); }

BKLANE bkadd(BKLANE a, BKLANE b) { return a + b; }

// n is a constant in 1..63 at every call site.
BKLANE bkrotr(BKLANE x, uint n) { return (x >> n) | (x << (64u - n)); }

#else

#define BKLANE uvec2   // .x is the low half, .y the high half

BKLANE bklane(uint lo, uint hi) { return uvec2(lo, hi); }
uint   bklo(BKLANE x)           { return x.x; }
uint   bkhi(BKLANE x)           { return x.y; }

#ifdef VKMINER_BLAKE512_WIDE_ADD

// The packs are bitcasts. Needs shaderInt64; the includer declares it.
BKLANE bkadd(BKLANE a, BKLANE b)
{
    return unpackUint2x32(packUint2x32(a) + packUint2x32(b));
}

#else

BKLANE bkadd(BKLANE a, BKLANE b)
{
    uint carry;
    uint lo = uaddCarry(a.x, b.x, carry);
    return uvec2(lo, a.y + b.y + carry);
}

#endif  // VKMINER_BLAKE512_WIDE_ADD

// 32 or more swaps the halves first; n is constant, so the branches fold.
BKLANE bkrotr(BKLANE x, uint n)
{
    BKLANE v = (n >= 32u) ? x.yx : x;
    uint s = n & 31u;
    return s == 0u ? v
                   : uvec2((v.x >> s) | (v.y << (32u - s)),
                           (v.y >> s) | (v.x << (32u - s)));
}

#endif  // VKMINER_BLAKE512_INT64

// SHA-512's IV, which BLAKE-512 reuses, as (low, high).
const uvec2 kBlake512Iv[8] = uvec2[8](
    uvec2(0xf3bcc908u, 0x6a09e667u), uvec2(0x84caa73bu, 0xbb67ae85u),
    uvec2(0xfe94f82bu, 0x3c6ef372u), uvec2(0x5f1d36f1u, 0xa54ff53au),
    uvec2(0xade682d1u, 0x510e527fu), uvec2(0x2b3e6c1fu, 0x9b05688cu),
    uvec2(0xfb41bd6bu, 0x1f83d9abu), uvec2(0x137e2179u, 0x5be0cd19u));

// The first digits of pi, as (low, high).
const uvec2 kBlake512C[16] = uvec2[16](
    uvec2(0x85a308d3u, 0x243f6a88u), uvec2(0x03707344u, 0x13198a2eu),
    uvec2(0x299f31d0u, 0xa4093822u), uvec2(0xec4e6c89u, 0x082efa98u),
    uvec2(0x38d01377u, 0x452821e6u), uvec2(0x34e90c6cu, 0xbe5466cfu),
    uvec2(0xc97c50ddu, 0xc0ac29b7u), uvec2(0xb5470917u, 0x3f84d5b5u),
    uvec2(0x8979fb1bu, 0x9216d5d9u), uvec2(0x98dfb5acu, 0xd1310ba6u),
    uvec2(0xd01adfb7u, 0x2ffd72dbu), uvec2(0x6a267e96u, 0xb8e1afedu),
    uvec2(0xf12c7f99u, 0xba7c9045u), uvec2(0xb3916cf7u, 0x24a19947u),
    uvec2(0x858efc16u, 0x0801f2e2u), uvec2(0x71574e69u, 0x636920d8u));

// Word i of either table. Callers pass literals, so the lookup folds.
BKLANE blake512_iv(uint i) { return bklane(kBlake512Iv[i].x, kBlake512Iv[i].y); }
BKLANE blake512_c(uint i)  { return bklane(kBlake512C[i].x, kBlake512C[i].y); }

// G, with x and y this G's two sigma entries. Needs v[] and m[] in scope.
#define BLAKE512_G(a, b, c, d, x, y)                                      \
    {                                                                     \
        v[a] = bkadd(bkadd(v[a], v[b]), m[x] ^ blake512_c(y));            \
        v[d] = bkrotr(v[d] ^ v[a], 32u);                                  \
        v[c] = bkadd(v[c], v[d]);                                         \
        v[b] = bkrotr(v[b] ^ v[c], 25u);                                  \
        v[a] = bkadd(bkadd(v[a], v[b]), m[y] ^ blake512_c(x));            \
        v[d] = bkrotr(v[d] ^ v[a], 16u);                                  \
        v[c] = bkadd(v[c], v[d]);                                         \
        v[b] = bkrotr(v[b] ^ v[c], 11u);                                  \
    }

// Four columns, then four diagonals, under the round's permutation written
// out, so that no m[] or constant is indexed at run time.
#define BLAKE512_ROUND(s0, s1, s2, s3, s4, s5, s6, s7,                    \
                       s8, s9, sa, sb, sc, sd, se, sf)                    \
    BLAKE512_G(0, 4,  8, 12, s0, s1);                                     \
    BLAKE512_G(1, 5,  9, 13, s2, s3);                                     \
    BLAKE512_G(2, 6, 10, 14, s4, s5);                                     \
    BLAKE512_G(3, 7, 11, 15, s6, s7);                                     \
    BLAKE512_G(0, 5, 10, 15, s8, s9);                                     \
    BLAKE512_G(1, 6, 11, 12, sa, sb);                                     \
    BLAKE512_G(2, 7,  8, 13, sc, sd);                                     \
    BLAKE512_G(3, 4,  9, 14, se, sf)

// One block m into h under the bit counter t: the message bits hashed up to
// and including this block, or zero for a block of padding only. The
// counter's high 64 bits and the salt are zero.
void blake512_compress(inout BKLANE h[8], BKLANE m[16], BKLANE t)
{
    BKLANE v[16];
    for (uint i = 0u; i < 8u; i++)
        v[i] = h[i];
    for (uint i = 0u; i < 4u; i++)
        v[8u + i] = blake512_c(i);
    v[12] = t ^ blake512_c(4u);
    v[13] = t ^ blake512_c(5u);
    v[14] = blake512_c(6u);
    v[15] = blake512_c(7u);

    // Round r takes permutation r mod 10.
    BLAKE512_ROUND( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
    BLAKE512_ROUND(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
    BLAKE512_ROUND(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
    BLAKE512_ROUND( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
    BLAKE512_ROUND( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
    BLAKE512_ROUND( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);
    BLAKE512_ROUND(12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11);
    BLAKE512_ROUND(13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10);
    BLAKE512_ROUND( 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5);
    BLAKE512_ROUND(10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0);
    BLAKE512_ROUND( 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15);
    BLAKE512_ROUND(14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3);
    BLAKE512_ROUND(11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4);
    BLAKE512_ROUND( 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8);
    BLAKE512_ROUND( 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13);
    BLAKE512_ROUND( 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9);

    for (uint i = 0u; i < 8u; i++)
        h[i] ^= v[i] ^ v[8u + i];
}

#endif  // VKMINER_SHADERS_COMMON_BLAKE512_GLSL_INCLUDED
