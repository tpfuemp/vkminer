// SIMD-512, the round 2 specification: one 128-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Thirty-two little-endian words, registers A, B, C, D of eight, h[8 * reg +
// lane]. The block is expanded by a 256-point number-theoretic transform over
// Z/257, reduced by folding (256 = -1). The caller owns the padding (zero
// fill, then a block holding only the bit count, compressed with final set).
// src/core/simd512.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_SIMD512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SIMD512_GLSL_INCLUDED

#extension GL_EXT_control_flow_attributes : require

#include "shaders/common/bits.glsl"

const uint kSimd512Iv[32] = uint[32](
    0x0BA16B95u, 0x72F999ADu, 0x9FECC2AEu, 0xBA3264FCu,
    0x5E894929u, 0x8E9F30E5u, 0x2F1DAA37u, 0xF0F2C558u,
    0xAC506643u, 0xA90635A5u, 0xE25B878Bu, 0xAAB7878Fu,
    0x88817F7Au, 0x0A02892Bu, 0x559A7550u, 0x598F657Eu,
    0x7EEF60A1u, 0x6B70E3E8u, 0x9C1714D1u, 0xB958E2A8u,
    0xAB02675Eu, 0xED1C014Fu, 0xCD8D65BBu, 0xFDB7A257u,
    0x09254899u, 0xD699C7BCu, 0x9019B6DCu, 0x2B9022E4u,
    0x8FA14956u, 0x21BF9BD3u, 0xB94D0943u, 0x6FFDDC22u);

// The group of sixteen transform values each step reads, by round.
const uint kSimd512Wsel[32] = uint[32](
     4u,  6u,  0u,  2u,  7u,  5u,  3u,  1u,
    15u, 11u, 12u,  8u,  9u, 13u, 10u, 14u,
    17u, 18u, 23u, 20u, 22u, 21u, 16u, 19u,
    30u, 24u, 25u, 31u, 27u, 29u, 28u, 26u);

// The seven lane permutations; step j of round i uses (i + j) mod 7.
const uint kSimd512Perm[56] = uint[56](
    1u, 0u, 3u, 2u, 5u, 4u, 7u, 6u,
    6u, 7u, 4u, 5u, 2u, 3u, 0u, 1u,
    2u, 3u, 0u, 1u, 6u, 7u, 4u, 5u,
    3u, 2u, 1u, 0u, 7u, 6u, 5u, 4u,
    5u, 4u, 7u, 6u, 1u, 0u, 3u, 2u,
    7u, 6u, 5u, 4u, 3u, 2u, 1u, 0u,
    4u, 5u, 6u, 7u, 0u, 1u, 2u, 3u);

// Rotations p0..p3 per round; the feed-forward reuses round 3's.
const uint kSimd512Rot[16] = uint[16](
     3u, 23u, 17u, 27u,
    28u, 19u, 22u,  7u,
    29u,  9u, 15u,  5u,
     4u, 13u, 10u, 25u);

// 41^k mod 257. 41 has order 256, so exponents are taken mod 256.
const int kSimd512Alpha[256] = int[256](
      1,  41, 139,  45,  46,  87, 226,  14,  60, 147, 116, 130, 190,  80, 196,  69,
      2,  82,  21,  90,  92, 174, 195,  28, 120,  37, 232,   3, 123, 160, 135, 138,
      4, 164,  42, 180, 184,  91, 133,  56, 240,  74, 207,   6, 246,  63,  13,  19,
      8,  71,  84, 103, 111, 182,   9, 112, 223, 148, 157,  12, 235, 126,  26,  38,
     16, 142, 168, 206, 222, 107,  18, 224, 189,  39,  57,  24, 213, 252,  52,  76,
     32,  27,  79, 155, 187, 214,  36, 191, 121,  78, 114,  48, 169, 247, 104, 152,
     64,  54, 158,  53, 117, 171,  72, 125, 242, 156, 228,  96,  81, 237, 208,  47,
    128, 108,  59, 106, 234,  85, 144, 250, 227,  55, 199, 192, 162, 217, 159,  94,
    256, 216, 118, 212, 211, 170,  31, 243, 197, 110, 141, 127,  67, 177,  61, 188,
    255, 175, 236, 167, 165,  83,  62, 229, 137, 220,  25, 254, 134,  97, 122, 119,
    253,  93, 215,  77,  73, 166, 124, 201,  17, 183,  50, 251,  11, 194, 244, 238,
    249, 186, 173, 154, 146,  75, 248, 145,  34, 109, 100, 245,  22, 131, 231, 219,
    241, 115,  89,  51,  35, 150, 239,  33,  68, 218, 200, 233,  44,   5, 205, 181,
    225, 230, 178, 102,  70,  43, 221,  66, 136, 179, 143, 209,  88,  10, 153, 105,
    193, 203,  99, 204, 140,  86, 185, 132,  15, 101,  29, 161, 176,  20,  49, 210,
    129, 149, 198, 151,  23, 172, 113,   7,  30, 202,  58,  65,  95,  40,  98, 163);

// The 256 message words of the final block after a 64-byte message, step
// by step: what simd512_compress_expanded derives from that block's
// expansion, which is the same for every message.
const uint kSimd512Final64W[256] = uint[256](
    0x531B1720u, 0xAC2CDE09u, 0x0B902D87u, 0x2369B1F4u,
    0x2931AA01u, 0x02E4B082u, 0xC914C914u, 0xC1DAE1A6u,
    0xF18C2B5Cu, 0x08AC306Bu, 0x27BFC914u, 0xCEDC548Du,
    0xC630C4BEu, 0xF18C4335u, 0xF0D3427Cu, 0xBE3DA380u,
    0x143C02E4u, 0xA948C630u, 0xA4F2DE09u, 0xA71D2085u,
    0xA439BD84u, 0x109FCD6Au, 0xEEA8EF61u, 0xA5AB1CE8u,
    0x0B90D4A4u, 0x3D6D039Du, 0x25944D53u, 0xBAA0E034u,
    0x5BC71E5Au, 0xB1F4F2FEu, 0x12CADE09u, 0x548D41C3u,
    0x3CB4F80Du, 0x36ECEBC4u, 0xA66443EEu, 0x43351ABDu,
    0xC7A20C49u, 0xEB0BB366u, 0xF5293F98u, 0x49B6DE09u,
    0x531B29EAu, 0x02E402E4u, 0xDB25C405u, 0x53D4E543u,
    0x0AD71720u, 0xE1A61A04u, 0xB87534C1u, 0x3EDF43EEu,
    0x213E50F0u, 0x39173EDFu, 0xA9485B0Eu, 0xEEA82EF9u,
    0x14F55771u, 0xFAF15546u, 0x3D6DD9B3u, 0xAB73B92Eu,
    0x582A48FDu, 0xEEA81892u, 0x4F7EAA01u, 0xAF10A88Fu,
    0x11581720u, 0x34C124DBu, 0xD1C0AB73u, 0x1E5AF0D3u,
    0xC34C07F3u, 0xC914143Cu, 0x599CBC12u, 0xBCCBE543u,
    0x385EF3B7u, 0x14F54C9Au, 0x0AD7C068u, 0xB64A21F7u,
    0xDEC2AF10u, 0xC6E9C121u, 0x56B8A4F2u, 0x1158D107u,
    0xEB0BA88Fu, 0x050FAABAu, 0xC293264Du, 0x548D46D2u,
    0xACE5E8E0u, 0x53D421F7u, 0xF470D279u, 0xDC974E0Cu,
    0xD6CF55FFu, 0xFD1C4F7Eu, 0x36EC36ECu, 0x3E261E5Au,
    0xEBC4FD1Cu, 0x56B839D0u, 0x5B0E21F7u, 0x58E3DF7Bu,
    0x5BC7427Cu, 0xEF613296u, 0x1158109Fu, 0x5A55E318u,
    0xA7D6B703u, 0x1158E76Eu, 0xB08255FFu, 0x50F05771u,
    0xEEA8E8E0u, 0xCB3FDB25u, 0x2E40548Du, 0xE1A60F2Du,
    0xACE5D616u, 0xFD1CFD1Cu, 0x24DB3BFBu, 0xAC2C1ABDu,
    0xF529E8E0u, 0x1E5AE5FCu, 0x478BCB3Fu, 0xC121BC12u,
    0xF4702B5Cu, 0xC293FC63u, 0xDA6CB2ADu, 0x45601FCCu,
    0xA439E1A6u, 0x4E0C0D02u, 0xED3621F7u, 0xAB73BE3Du,
    0x0E74D4A4u, 0xF754CF95u, 0xD84136ECu, 0x3124AB73u,
    0x39D03B42u, 0x0E74BCCBu, 0x0F2DBD84u, 0x41C35C80u,
    0xA4135BEDu, 0xE10E1EF2u, 0x6C4F93B1u, 0x6E2191DFu,
    0xE2E01D20u, 0xD1952E6Bu, 0x6A7D9583u, 0x131DECE3u,
    0x369CC964u, 0xFB73048Du, 0x9E9D6163u, 0x280CD7F4u,
    0xD9C6263Au, 0x1062EF9Eu, 0x2AC7D539u, 0xAD2D52D3u,
    0x0A03F5FDu, 0x197CE684u, 0xAA72558Eu, 0xDE5321ADu,
    0xF0870F79u, 0x607A9F86u, 0xAFE85018u, 0x2AC7D539u,
    0xE2E01D20u, 0x2AC7D539u, 0xC6A93957u, 0x624C9DB4u,
    0x6C4F93B1u, 0x641E9BE2u, 0x452CBAD4u, 0x263AD9C6u,
    0xC964369Cu, 0xC3053CFBu, 0x452CBAD4u, 0x95836A7Du,
    0x4AA2B55Eu, 0xAB5B54A5u, 0xAC4453BCu, 0x74808B80u,
    0xCB3634CAu, 0xFC5C03A4u, 0x4B8BB475u, 0x21ADDE53u,
    0xE2E01D20u, 0xDF3C20C4u, 0xBD8F4271u, 0xAA72558Eu,
    0xFC5C03A4u, 0x48D0B730u, 0x2AC7D539u, 0xD70B28F5u,
    0x53BCAC44u, 0x3FB6C04Au, 0x14EFEB11u, 0xDB982468u,
    0x9A1065F0u, 0xB0D14F2Fu, 0x8D5272AEu, 0xC4D73B29u,
    0x91DF6E21u, 0x949A6B66u, 0x303DCFC3u, 0x5932A6CEu,
    0x1234EDCCu, 0xF5140AECu, 0xCDF1320Fu, 0x3DE4C21Cu,
    0x48D0B730u, 0x1234EDCCu, 0x131DECE3u, 0x52D3AD2Du,
    0xE684197Cu, 0x6D3892C8u, 0x72AE8D52u, 0x6FF3900Du,
    0x73978C69u, 0xEB1114EFu, 0x15D8EA28u, 0x71C58E3Bu,
    0x90F66F0Au, 0x15D8EA28u, 0x9BE2641Eu, 0x65F09A10u,
    0xEA2815D8u, 0xBD8F4271u, 0x3A40C5C0u, 0xD9C6263Au,
    0xB38C4C74u, 0xBAD4452Cu, 0x70DC8F24u, 0xAB5B54A5u,
    0x46FEB902u, 0x1A65E59Bu, 0x0DA7F259u, 0xA32A5CD6u,
    0xD62229DEu, 0xB81947E7u, 0x6D3892C8u, 0x15D8EA28u,
    0xE59B1A65u, 0x065FF9A1u, 0xB2A34D5Du, 0x6A7D9583u,
    0x975568ABu, 0xFC5C03A4u, 0x2E6BD195u, 0x966C6994u,
    0xF2590DA7u, 0x263AD9C6u, 0x5A1BA5E5u, 0xB0D14F2Fu,
    0x975568ABu, 0x6994966Cu, 0xF1700E90u, 0xD3672C99u,
    0xCC1F33E1u, 0xFC5C03A4u, 0x452CBAD4u, 0x4E46B1BAu,
    0xF1700E90u, 0xB2A34D5Du, 0xD0AC2F54u, 0x5760A8A0u,
    0x8C697397u, 0x624C9DB4u, 0xE85617AAu, 0x95836A7Du);

// A value congruent to x mod 257, since 256 = -1: (x & 255) - (x >> 8).
// Within -3..259 after one application to anything in -770..770, and within
// -259..258 after one application to the product of a twiddle and such a
// value, so two keep a product as small as its factors.
int simd_red(int x)
{
    return (x & 255) - (x >> 8);
}

// The butterflies from stage first on, over a bit-reversed y. Stage s pairs
// entries half = 2^s apart, the j-th of each group under 41^(j * 128 / half).
// Values between butterflies are only congruent, kept within -3..259.
void simd512_ntt(inout int y[256], uint first)
{
    for (uint s = first; s < 8u; s++) {
        uint half_size = 1u << s;
        uint step = 128u >> s;
        for (uint start = 0u; start < 256u; start += 2u * half_size) {
            for (uint j = 0u; j < half_size; j++) {
                uint lo = start + j, hi = lo + half_size;
                int t = simd_red(simd_red(kSimd512Alpha[j * step] * y[hi]));
                int u = y[lo];
                y[lo] = simd_red(u + t);
                y[hi] = simd_red(u - t);
            }
        }
    }
}

// The exact residues of the transform plus X^255 (and X^253 when final)
// evaluated at 41^i: y[i] in -128..128. 41^-i is 41^(255 i), 41^-3i is
// 41^(253 i).
void simd512_expand_finish(inout int y[256], bool final_block)
{
    for (uint i = 0u; i < 256u; i++) {
        int v = y[i] + kSimd512Alpha[(255u * i) & 255u];
        if (final_block)
            v += kSimd512Alpha[(253u * i) & 255u];
        v = simd_red(v);
        if (v < 0)
            v += 257;
        if (v >= 257)
            v -= 257;
        y[i] = v <= 128 ? v : v - 257;
    }
}

// The expansion of the block's 128 bytes.
void simd512_expand(uint m[32], bool final_block, out int y[256])
{
    // Bit-reversed load; the upper 128 coefficients are zero.
    for (uint i = 0u; i < 256u; i++)
        y[i] = 0;
    for (uint i = 0u; i < 128u; i++)
        y[bitfieldReverse(i) >> 24] = int((m[i >> 2] >> (8u * (i & 3u))) & 0xffu);
    simd512_ntt(y, 0u);
    simd512_expand_finish(y, final_block);
}

// Byte j of the 64-byte block m, as a coefficient.
#define SIMD_BYTE64(m, j) int(((m)[(j) >> 2] >> (8u * ((j) & 3u))) & 0xffu)

// The expansion of a non-final block whose upper 64 bytes are zero, m being
// the lower 64, as the 256 message words the steps read: W[p] packs y[2p] and
// y[2p + 1] under 185 (rounds 0, 1), W[128 + q] packs y[q] and y[q + 128]
// under 233 (rounds 2, 3).
//
// The transform as 16 x 16, with i = i1 + 16 i2 and j = j1 + 16 j2 (j2 < 4):
// y[i] = sum over j1 of 41^(16 i2 j1) b[j1], where
// b[j1] = 41^(i1 j1) sum over j2 of byte[j] 41^(16 i1 j2). Each i1 is then a
// 16-point transform held in registers, and two adjacent i1 fill whole words
// of both packings, so only W is an array.
void simd512_expand64_packed(uint m[16], out uint W[256])
{
    for (uint e = 0u; e < 16u; e += 2u) {
        int y[32];
        [[unroll]] for (uint h = 0u; h < 2u; h++) {
            uint i1 = e + h;
            int v[16];
            [[unroll]] for (uint j1 = 0u; j1 < 16u; j1++) {
                int t = SIMD_BYTE64(m, j1);
                [[unroll]] for (uint j2 = 1u; j2 < 4u; j2++)
                    t += SIMD_BYTE64(m, j1 + 16u * j2)
                       * kSimd512Alpha[(16u * i1 * j2) & 255u];
                t = simd_red(simd_red(t));
                // Bit-reversed, for the in-place butterflies below.
                v[bitfieldReverse(j1) >> 28] =
                    simd_red(simd_red(t * kSimd512Alpha[(i1 * j1) & 255u]));
            }
            [[unroll]] for (uint st = 0u; st < 4u; st++) {
                uint half_size = 1u << st;
                [[unroll]] for (uint start = 0u; start < 16u; start += 2u * half_size) {
                    [[unroll]] for (uint j = 0u; j < half_size; j++) {
                        uint lo = start + j, hi = lo + half_size;
                        int t = simd_red(simd_red(
                            kSimd512Alpha[(16u * j * (8u >> st)) & 255u] * v[hi]));
                        int u = v[lo];
                        v[lo] = simd_red(u + t);
                        v[hi] = simd_red(u - t);
                    }
                }
            }
            // Exact residues plus X^255 at 41^i, in -128..128.
            [[unroll]] for (uint i2 = 0u; i2 < 16u; i2++) {
                int w = simd_red(v[i2]
                                 + kSimd512Alpha[(255u * (i1 + 16u * i2)) & 255u]);
                if (w < 0)
                    w += 257;
                if (w >= 257)
                    w -= 257;
                y[16u * h + i2] = w <= 128 ? w : w - 257;
            }
        }
        [[unroll]] for (uint i2 = 0u; i2 < 16u; i2++)
            W[(e >> 1) + 8u * i2] = ((uint(y[i2]) * 185u) & 0xffffu)
                                  + ((uint(y[16u + i2]) * 185u) << 16);
        [[unroll]] for (uint h = 0u; h < 2u; h++)
            [[unroll]] for (uint i2 = 0u; i2 < 8u; i2++)
                W[128u + e + h + 16u * i2] =
                    ((uint(y[16u * h + i2]) * 233u) & 0xffffu)
                  + ((uint(y[16u * h + i2 + 8u]) * 233u) << 16);
    }
}

#undef SIMD_BYTE64

uint simd_if(uint x, uint y, uint z)
{
    return ((y ^ z) & x) ^ z;
}

uint simd_maj(uint x, uint y, uint z)
{
    return (x & y) | ((x | y) & z);
}

// One step on all eight lanes: message words w, rotations r and rs, lane
// permutation number perm.
void simd512_step(inout uint s[32], uint w[8], bool fmaj, uint r, uint rs,
                  uint perm)
{
    uint ta[8];
    for (uint n = 0u; n < 8u; n++)
        ta[n] = rotl32(s[n], r);

    for (uint n = 0u; n < 8u; n++) {
        uint f = fmaj ? simd_maj(s[n], s[8u + n], s[16u + n])
                      : simd_if(s[n], s[8u + n], s[16u + n]);
        uint t = s[24u + n] + w[n] + f;
        s[n] = rotl32(t, rs) + ta[kSimd512Perm[8u * perm + n]];
        s[24u + n] = s[16u + n];
        s[16u + n] = s[8u + n];
        s[8u + n] = ta[n];
    }
}

// Step j of round i on message words w.
void simd512_round_step(inout uint s[32], uint w[8], uint i, uint j)
{
    simd512_step(s, w, j >= 4u, kSimd512Rot[4u * i + (j & 3u)],
                 kSimd512Rot[4u * i + ((j + 1u) & 3u)], (i + j) % 7u);
}

// The feed-forward, the old chaining value as message words, and the result.
void simd512_feed_forward(inout uint h[32], uint s[32])
{
    for (uint j = 0u; j < 4u; j++) {
        uint w[8];
        for (uint k = 0u; k < 8u; k++)
            w[k] = h[8u * j + k];
        simd512_step(s, w, false, kSimd512Rot[12u + j],
                     kSimd512Rot[12u + ((j + 1u) & 3u)], (4u + j) % 7u);
    }

    h = s;
}

// The 32 steps on the expansion y of block m, then the feed-forward.
void simd512_compress_expanded(inout uint h[32], uint m[32], int y[256])
{
    uint s[32];
    for (uint i = 0u; i < 32u; i++)
        s[i] = h[i] ^ m[i];

    for (uint i = 0u; i < 4u; i++) {
        // Rounds 0 and 1 pair y[2k] with y[2k + 1] under 185; rounds 2 and 3
        // pair y[k] with y[k + 128] under 233.
        uint mm = i < 2u ? 185u : 233u;
        for (uint j = 0u; j < 8u; j++) {
            uint sb = kSimd512Wsel[8u * i + j];
            uint w[8];
            for (uint k = 0u; k < 8u; k++) {
                uint lo;
                if (i < 2u)
                    lo = 16u * sb + 2u * k;
                else if (i == 2u)
                    lo = 16u * (sb - 16u) + 2u * k;
                else
                    lo = 16u * (sb - 24u) + 2u * k + 1u;
                uint hi = i < 2u ? lo + 1u : lo + 128u;
                w[k] = ((uint(y[lo]) * mm) & 0xffffu)
                     + ((uint(y[hi]) * mm) << 16);
            }
            simd512_round_step(s, w, i, j);
        }
    }

    simd512_feed_forward(h, s);
}

void simd512_compress(inout uint h[32], uint m[32], bool final_block)
{
    int y[256];
    simd512_expand(m, final_block, y);
    simd512_compress_expanded(h, m, y);
}

// A non-final block whose upper 64 bytes are zero, m being the lower 64.
void simd512_compress64(inout uint h[32], uint m[16])
{
    uint W[256];
    simd512_expand64_packed(m, W);

    uint s[32];
    for (uint i = 0u; i < 16u; i++) {
        s[i] = h[i] ^ m[i];
        s[16u + i] = h[16u + i];
    }

    for (uint i = 0u; i < 4u; i++) {
        for (uint j = 0u; j < 8u; j++) {
            // The word pairs simd512_compress_expanded() forms, by index.
            uint sb = kSimd512Wsel[8u * i + j];
            uint base = i < 2u ? 8u * sb
                      : i == 2u ? 128u + 16u * (sb - 16u)
                      : 129u + 16u * (sb - 24u);
            uint stride = i < 2u ? 1u : 2u;
            uint w[8];
            for (uint k = 0u; k < 8u; k++)
                w[k] = W[base + stride * k];
            simd512_round_step(s, w, i, j);
        }
    }

    simd512_feed_forward(h, s);
}

// The final block after a 64-byte message, which holds only the bit count,
// 512. It is the same for every message, so its message words are constants.
void simd512_compress_final64(inout uint h[32])
{
    uint s[32] = h;
    s[0] ^= 512u;

    for (uint i = 0u; i < 4u; i++) {
        for (uint j = 0u; j < 8u; j++) {
            uint w[8];
            for (uint k = 0u; k < 8u; k++)
                w[k] = kSimd512Final64W[64u * i + 8u * j + k];
            simd512_round_step(s, w, i, j);
        }
    }

    simd512_feed_forward(h, s);
}

#endif  // VKMINER_SHADERS_COMMON_SIMD512_GLSL_INCLUDED
