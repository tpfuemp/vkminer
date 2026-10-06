// Skein-512's UBI block, version 1.3 of the specification, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One UBI block: Threefish-512 keyed by the chaining value, XORed with the
// plaintext. The tweak is the caller's, as are padding and lengths, so the
// same block serves any message layout. src/core/skein512.c is the scalar
// reference and spells out the tweak. Version 1.2's rotation constants differ.
//
// A word is TLANE: a uint64_t, or a uvec2 pair where shaderInt64 is missing.
// Never `+` a TLANE, use tadd(); in the pair build `+` drops the carry.

#ifndef VKMINER_SHADERS_COMMON_SKEIN512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SKEIN512_GLSL_INCLUDED

#ifdef VKMINER_SKEIN_INT64

// The includer declares the int64 extension.
#define TLANE uint64_t

TLANE tlane(uint lo, uint hi) { return uint64_t(lo) | (uint64_t(hi) << 32); }
uint  tlo(TLANE x)            { return uint(x); }
uint  thi(TLANE x)            { return uint(x >> 32); }

TLANE tadd(TLANE a, TLANE b)  { return a + b; }

// n is a rotation constant, 1..63, at every call site.
TLANE trotl(TLANE x, uint n)  { return (x << n) | (x >> (64u - n)); }

#else

#define TLANE uvec2   // .x is the low half, .y the high half

TLANE tlane(uint lo, uint hi) { return uvec2(lo, hi); }
uint  tlo(TLANE x)            { return x.x; }
uint  thi(TLANE x)            { return x.y; }

TLANE tadd(TLANE a, TLANE b)
{
    uint carry;
    uint lo = uaddCarry(a.x, b.x, carry);
    return uvec2(lo, a.y + b.y + carry);
}

// 32 or more swaps the halves first; n is constant, so the branches fold.
TLANE trotl(TLANE x, uint n)
{
    TLANE v = (n >= 32u) ? x.yx : x;
    uint s = n & 31u;
    return s == 0u ? v
                   : uvec2((v.x << s) | (v.y >> (32u - s)),
                           (v.y << s) | (v.x >> (32u - s)));
}

#endif  // VKMINER_SKEIN_INT64

// The tweak's second word for each block type, flags included. Bits 56..61
// hold the type, 62 is first and 63 is final; the position is the first word.
const uint kSkeinT1Msg       = 0x30000000u;   // high half: type 48
const uint kSkeinT1Out       = 0x3f000000u;   // high half: type 63
const uint kSkeinT1First     = 0x40000000u;
const uint kSkeinT1Final     = 0x80000000u;

// Skein-512-512's chaining value after the configuration block, as (low, high).
// tests/skein_kat.cpp recomputes it from the configuration block.
const uvec2 skein512_512_iv_words[8] = uvec2[8](
    uvec2(0x749c51ceu, 0x4903adffu), uvec2(0x9746df03u, 0x0d95de39u),
    uvec2(0x27c79bceu, 0x8fd19341u), uvec2(0xff352cb1u, 0x9a255629u),
    uvec2(0xdf6ca7b0u, 0x5db62599u), uvec2(0xa9d5c3f4u, 0xeabe394cu),
    uvec2(0x1a75b523u, 0x991112c7u), uvec2(0x660fcc33u, 0xae18a40bu));

TLANE skein512_512_iv(uint i)
{
    return tlane(skein512_512_iv_words[i].x, skein512_512_iv_words[i].y);
}

// One MIX: x0 += x1, x1 = rotl(x1, r) ^ x0.
#define SKEIN_MIX(x0, x1, r)                                              \
    {                                                                     \
        (x0) = tadd(x0, x1);                                              \
        (x1) = trotl(x1, r) ^ (x0);                                       \
    }

// Subkey s: k[(s + i) mod 9] to word i, tweak words to 5 and 6, s to word 7.
// s is a literal at every use, so the indices fold.
#define SKEIN_INJECT(s)                                                   \
    {                                                                     \
        p0 = tadd(p0, k[((s) + 0u) % 9u]);                                \
        p1 = tadd(p1, k[((s) + 1u) % 9u]);                                \
        p2 = tadd(p2, k[((s) + 2u) % 9u]);                                \
        p3 = tadd(p3, k[((s) + 3u) % 9u]);                                \
        p4 = tadd(p4, k[((s) + 4u) % 9u]);                                \
        p5 = tadd(p5, tadd(k[((s) + 5u) % 9u], t[(s) % 3u]));             \
        p6 = tadd(p6, tadd(k[((s) + 6u) % 9u], t[((s) + 1u) % 3u]));      \
        p7 = tadd(p7, tadd(k[((s) + 7u) % 9u], tlane(s, 0u)));            \
    }

// Four rounds after subkey s. The word permutation (spec table 3) is done by
// renaming; four rounds of it are the identity. Rotations are spec table 4.
#define SKEIN_ROUNDS4(s, r00, r01, r02, r03, r10, r11, r12, r13,          \
                      r20, r21, r22, r23, r30, r31, r32, r33)             \
    SKEIN_INJECT(s);                                                      \
    SKEIN_MIX(p0, p1, r00); SKEIN_MIX(p2, p3, r01);                       \
    SKEIN_MIX(p4, p5, r02); SKEIN_MIX(p6, p7, r03);                       \
    SKEIN_MIX(p2, p1, r10); SKEIN_MIX(p4, p7, r11);                       \
    SKEIN_MIX(p6, p5, r12); SKEIN_MIX(p0, p3, r13);                       \
    SKEIN_MIX(p4, p1, r20); SKEIN_MIX(p6, p3, r21);                       \
    SKEIN_MIX(p0, p5, r22); SKEIN_MIX(p2, p7, r23);                       \
    SKEIN_MIX(p6, p1, r30); SKEIN_MIX(p0, p7, r31);                       \
    SKEIN_MIX(p2, p5, r32); SKEIN_MIX(p4, p3, r33)

#define SKEIN_EVEN(s)                                                     \
    SKEIN_ROUNDS4(s, 46u, 36u, 19u, 37u, 33u, 27u, 14u, 42u,              \
                     17u, 49u, 36u, 39u, 44u,  9u, 54u, 56u)

#define SKEIN_ODD(s)                                                      \
    SKEIN_ROUNDS4(s, 39u, 30u, 34u, 24u, 13u, 50u, 10u, 17u,              \
                     25u, 29u, 39u, 43u,  8u, 35u, 56u, 22u)

// h = Threefish-512(key h, tweak (t0, t1), m) ^ m: 72 rounds, 19 subkeys.
void skein512_ubi(inout TLANE h[8], TLANE m[8], TLANE t0, TLANE t1)
{
    TLANE k[9];
    k[8] = tlane(0xa9fc1a22u, 0x1bd11bdau);   // C240, spec 3.3.2
    for (uint i = 0u; i < 8u; i++) {
        k[i] = h[i];
        k[8] ^= h[i];
    }

    TLANE t[3];
    t[0] = t0;
    t[1] = t1;
    t[2] = t0 ^ t1;

    TLANE p0 = m[0], p1 = m[1], p2 = m[2], p3 = m[3];
    TLANE p4 = m[4], p5 = m[5], p6 = m[6], p7 = m[7];

    SKEIN_EVEN(0u);  SKEIN_ODD(1u);
    SKEIN_EVEN(2u);  SKEIN_ODD(3u);
    SKEIN_EVEN(4u);  SKEIN_ODD(5u);
    SKEIN_EVEN(6u);  SKEIN_ODD(7u);
    SKEIN_EVEN(8u);  SKEIN_ODD(9u);
    SKEIN_EVEN(10u); SKEIN_ODD(11u);
    SKEIN_EVEN(12u); SKEIN_ODD(13u);
    SKEIN_EVEN(14u); SKEIN_ODD(15u);
    SKEIN_EVEN(16u); SKEIN_ODD(17u);
    SKEIN_INJECT(18u);

    h[0] = p0 ^ m[0]; h[1] = p1 ^ m[1]; h[2] = p2 ^ m[2]; h[3] = p3 ^ m[3];
    h[4] = p4 ^ m[4]; h[5] = p5 ^ m[5]; h[6] = p6 ^ m[6]; h[7] = p7 ^ m[7];
}

#endif  // VKMINER_SHADERS_COMMON_SKEIN512_GLSL_INCLUDED
