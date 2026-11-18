// x16rv2: one stage of the chain, from the header or from the state buffer
// back to it, or the screen that reads the last state.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Each module is one stage; the job decides which run in what order. The
// build generates one wrapper per module, defining:
//
//   X16RV2_STAGE   0..15, the stage a nibble names (x16rv2_order.h); 16 is
//                  the screen
//   X16RV2_WORDS   20 for the 80-byte header (position 0), 16 for the 64-byte
//                  state (later positions)
//
// A nonce's state is sixteen little-endian words, word w of nonce i at
// states[w * count + i]. Tiger runs inside the Keccak, Luffa and SHA-512
// stages, so those three only ever hash 64 bytes. Two nonces an invocation:
// Groestl hashes them together as bit planes. Whirlpool over 64 bytes takes
// four, bitsliced.

#ifndef VKMINER_ALGORITHMS_X16RV2_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_X16RV2_KERNEL_GLSL_INCLUDED

#define VKMINER_X11_TAIL x16rv2_unused_tail

#include "algorithms/x11/x11_kernel.glsl"
#include "shaders/common/fugue512.glsl"
#include "shaders/common/hamsi512.glsl"
#include "shaders/common/sha512.glsl"
#include "shaders/common/shabal512.glsl"
#include "shaders/common/tiger192.glsl"
#include "shaders/common/whirlpool512.glsl"
#include "shaders/common/whirlpool512_x4.glsl"

void x16rv2_unused_tail(inout uint s[16], uint nonce) {}

const uint kStage = uint(X16RV2_STAGE);
const uint kWords = uint(X16RV2_WORDS);
const uint kBits = 32u * kWords;

layout(std430, set = 0, binding = 1) buffer States { uint states[]; };

// --------------------------------------------------------------- the stages
//
// Each takes the message as twenty little-endian words of which the first
// kWords are real, and writes the 64-byte digest the same way.

// BLAKE-512: one block, the message, 0x80, the 1 bit at byte 111 and the bit
// count, under the counter.
void x16rv2_blake(uint w[20], out uint s[16])
{
    BKLANE m[16];
    for (uint i = 0u; i < 16u; i++)
        m[i] = bklane(0u, 0u);
    for (uint i = 0u; i < kWords / 2u; i++)
        m[i] = bklane(bswap32(w[2u * i + 1u]), bswap32(w[2u * i]));
    m[kWords / 2u] = bklane(0u, 0x80000000u);
    m[13] = bklane(1u, 0u);
    m[15] = bklane(kBits, 0u);

    BKLANE h[8];
    for (uint i = 0u; i < 8u; i++)
        h[i] = blake512_iv(i);
    blake512_compress(h, m, bklane(kBits, 0u));

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = bswap32(bkhi(h[i]));
        s[2u * i + 1u] = bswap32(bklo(h[i]));
    }
}

// BMW-512: one block, the message, 0x80 and the bit count, then the final
// transform.
void x16rv2_bmw(uint w[20], out uint s[16])
{
    BLANE h[16];
    BLANE m[16];
    for (uint i = 0u; i < 16u; i++) {
        h[i] = bmw512_iv(i);
        m[i] = blane(0u, 0u);
    }
    for (uint i = 0u; i < kWords / 2u; i++)
        m[i] = blane(w[2u * i], w[2u * i + 1u]);
    m[kWords / 2u] = blane(0x80u, 0u);
    m[15] = blane(kBits, 0u);

    bmw512_compress(h, m);
    bmw512_final(h);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = blo(h[8u + i]);
        s[2u * i + 1u] = bhi(h[8u + i]);
    }
}

// Byte (row i, column c) of the padded Groestl block: the message in columns
// 0..kWords/2-1, 0x80 after it, a block count of one at column 15 row 7.
uint x16rv2_groestl_byte(uint w[20], uint i, uint c)
{
    if (c < kWords / 2u)
        return (w[2u * c + (i >> 2)] >> (8u * (i & 3u))) & 0xffu;
    if (c == kWords / 2u && i == 0u)
        return 0x80u;
    if (c == 15u && i == 7u)
        return 0x01u;
    return 0u;
}

// Groestl-512 of a and b together as bit planes; x11_groestl() with the
// message length a parameter.
void x16rv2_groestl(uint a[20], uint b[20], out uint sa[16], out uint sb[16])
{
    uint s[64];
    [[unroll]] for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        [[unroll]] for (uint k = 0u; k < 8u; k++) {
            uint c = k >> 1;
            if ((k & 1u) == 0u)
                d[k] = x16rv2_groestl_byte(a, i, c)
                     | (x16rv2_groestl_byte(a, i, 4u + c) << 8)
                     | (x16rv2_groestl_byte(a, i, 8u + c) << 16)
                     | (x16rv2_groestl_byte(a, i, 12u + c) << 24);
            else
                d[k] = x16rv2_groestl_byte(b, i, c)
                     | (x16rv2_groestl_byte(b, i, 4u + c) << 8)
                     | (x16rv2_groestl_byte(b, i, 8u + c) << 16)
                     | (x16rv2_groestl_byte(b, i, 12u + c) << 24);
        }
        groestl_transpose(d);
        for (uint p = 0u; p < 8u; p++)
            s[8u * i + p] = d[p];
    }

    groestl_hash(s);

    uint rows[64];
    for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        for (uint p = 0u; p < 8u; p++)
            d[p] = s[8u * i + p];
        groestl_transpose(d);
        for (uint k = 0u; k < 8u; k++)
            rows[8u * i + k] = d[k];
    }
    for (uint v = 0u; v < 16u; v++) {
        uint c = 8u + (v >> 1), r0 = 4u * (v & 1u), sh = 8u * (c >> 2);
        uint k = 2u * (c & 3u);
        sa[v] = ((rows[8u * r0 + k] >> sh) & 0xffu)
              | (((rows[8u * (r0 + 1u) + k] >> sh) & 0xffu) << 8)
              | (((rows[8u * (r0 + 2u) + k] >> sh) & 0xffu) << 16)
              | (((rows[8u * (r0 + 3u) + k] >> sh) & 0xffu) << 24);
        k += 1u;
        sb[v] = ((rows[8u * r0 + k] >> sh) & 0xffu)
              | (((rows[8u * (r0 + 1u) + k] >> sh) & 0xffu) << 8)
              | (((rows[8u * (r0 + 2u) + k] >> sh) & 0xffu) << 16)
              | (((rows[8u * (r0 + 3u) + k] >> sh) & 0xffu) << 24);
    }
}

// JH-512: 64-byte blocks, then the 0x80 terminator and the bit count
// big-endian in the last bytes. 64 bytes pad to one more block; 80 bytes put
// the tail and the terminator in one block and the count in another.
void x16rv2_jh(uint w[20], out uint s[16])
{
    JLANE x[16];
    for (uint i = 0u; i < 16u; i++)
        x[i] = jh512_iv(i);
    JLANE m[8];
    for (uint i = 0u; i < 8u; i++)
        m[i] = jlane(w[2u * i], w[2u * i + 1u]);
    jh512_f8(x, m);

    for (uint i = 0u; i < 8u; i++)
        m[i] = jlane(0u, 0u);
    if (kWords == 20u) {
        m[0] = jlane(w[16], w[17]);
        m[1] = jlane(w[18], w[19]);
        m[2] = jlane(0x80u, 0u);
        jh512_f8(x, m);
        m[0] = jlane(0u, 0u);
        m[1] = jlane(0u, 0u);
        m[2] = jlane(0u, 0u);
        m[7] = jlane(0u, 0x80020000u);
    } else {
        m[0] = jlane(0x80u, 0u);
        m[7] = jlane(0u, 0x00020000u);
    }
    jh512_f8(x, m);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = jlo(x[8u + i]);
        s[2u * i + 1u] = jhi(x[8u + i]);
    }
}

// Keccak-512 of 64 bytes, the submission's: one block at the rate of nine
// lanes, padded 0x01 ... 0x80. Only ever behind a Tiger, so never 80 bytes.
void x16rv2_keccak(inout uint s[16])
{
    KLANE a[25];
    for (uint i = 0u; i < 8u; i++)
        a[i] = klane(s[2u * i], s[2u * i + 1u]);
    a[8] = klane(0x01u, 0x80000000u);
    for (uint i = 9u; i < 25u; i++)
        a[i] = klane(0u, 0u);

    sha3_keccakf(a);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = klo(a[i]);
        s[2u * i + 1u] = khi(a[i]);
    }
}

// Skein-512-512: one message block for 64 bytes, two for 80 (the second
// zero-filled, the tweak's position 80), then the output block.
void x16rv2_skein(uint w[20], out uint s[16])
{
    TLANE h[8];
    TLANE m[8];
    for (uint i = 0u; i < 8u; i++) {
        h[i] = skein512_512_iv(i);
        m[i] = tlane(w[2u * i], w[2u * i + 1u]);
    }
    if (kWords == 20u) {
        skein512_ubi(h, m, tlane(64u, 0u),
                     tlane(0u, kSkeinT1Msg | kSkeinT1First));
        for (uint i = 0u; i < 8u; i++)
            m[i] = tlane(0u, 0u);
        m[0] = tlane(w[16], w[17]);
        m[1] = tlane(w[18], w[19]);
        skein512_ubi(h, m, tlane(80u, 0u),
                     tlane(0u, kSkeinT1Msg | kSkeinT1Final));
    } else {
        skein512_ubi(h, m, tlane(64u, 0u),
                     tlane(0u, kSkeinT1Msg | kSkeinT1First | kSkeinT1Final));
    }
    for (uint i = 0u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(8u, 0u),
                 tlane(0u, kSkeinT1Out | kSkeinT1First | kSkeinT1Final));

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = tlo(h[i]);
        s[2u * i + 1u] = thi(h[i]);
    }
}

// Luffa-512 of 64 bytes, as x11_luffa(). Only ever behind a Tiger.
void x16rv2_luffa(inout uint s[16])
{
    x11_luffa(s);
}

// CubeHash-512: 32-byte blocks, the terminator in the block after the
// message (64 bytes) or after its last four words (80), the final rounds.
void x16rv2_cubehash(uint w[20], out uint s[16])
{
    uint x[32] = kCubehash512Iv;

    [[unroll]] for (uint b = 0u; b < 2u; b++) {
        for (uint k = 0u; k < 8u; k++)
            x[k] ^= w[8u * b + k];
        cubehash512_rounds(x, 16u);
    }
    if (kWords == 20u) {
        for (uint k = 0u; k < 4u; k++)
            x[k] ^= w[16u + k];
        x[4] ^= 0x80u;
    } else {
        x[0] ^= 0x80u;
    }
    cubehash512_rounds(x, 16u);
    x[31] ^= 1u;
    cubehash512_rounds(x, 160u);

    for (uint k = 0u; k < 16u; k++)
        s[k] = x[k];
}

// SHAvite-512: one block, the message, 0x80, the 128-bit bit count at bytes
// 110..125 and the digest size 512 at 126..127, under the counter.
void x16rv2_shavite(uint w[20], out uint s[16])
{
    uint h[16] = kShavite512Iv;
    uint m[32];
    for (uint k = 0u; k < 32u; k++)
        m[k] = 0u;
    for (uint k = 0u; k < kWords; k++)
        m[k] = w[k];
    m[kWords] = 0x80u;
    m[27] = kBits << 16;
    m[31] = 0x02000000u;
    uint cnt[4] = uint[4](kBits, 0u, 0u, 0u);

    shavite512_compress(h, m, cnt);
    s = h;
}

// SIMD-512 over 80 bytes in simd512_compress64()'s shape: a fifth j2 term
// (bytes 64..79), fully reduced, since five terms outgrow the lazy bounds.
// The final block holds only the bit count, 640.
#define X16RV2_SIMD_BYTE(m, j) int(((m)[(j) >> 2] >> (8u * ((j) & 3u))) & 0xffu)

void x16rv2_simd_expand80(uint m[20], out uint W[256])
{
    [[unroll]] for (uint e = 0u; e < 16u; e += 2u) {
        int y[32];
        [[unroll]] for (uint h = 0u; h < 2u; h++) {
            uint i1 = e + h;
            int v[16];
            [[unroll]] for (uint j1 = 0u; j1 < 16u; j1++) {
                int t = X16RV2_SIMD_BYTE(m, j1);
                [[unroll]] for (uint j2 = 1u; j2 < 5u; j2++)
                    t += X16RV2_SIMD_BYTE(m, j1 + 16u * j2)
                       * kSimd512Alpha[(16u * i1 * j2) & 255u];
                t = simd_red(simd_red(t));
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
            [[unroll]] for (uint i2 = 0u; i2 < 16u; i2++) {
                int r = simd_red(v[i2]
                                 + kSimd512Alpha[(255u * (i1 + 16u * i2)) & 255u]);
                if (r < 0)
                    r += 257;
                if (r >= 257)
                    r -= 257;
                y[16u * h + i2] = r <= 128 ? r : r - 257;
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

#undef X16RV2_SIMD_BYTE

// The final block's message words for a 640-bit message, laid out as
// kSimd512Final64W.
const uint kX16rv2SimdFinal80W[256] = uint[256](
    0xF5E2B9E7u, 0x08AC3A89u, 0xAE57D04Eu, 0xC6300E74u,
    0xCBF80681u, 0xA5AB0D02u, 0x25942594u, 0x1E5A3E26u,
    0x4E0CCE23u, 0xAB73D332u, 0xCA862594u, 0x2B5CF754u,
    0x22B0213Eu, 0x4E0CE5FCu, 0x4D53E543u, 0x1ABD0000u,
    0xB703A5ABu, 0x05C822B0u, 0x01723A89u, 0x039DC34Cu,
    0x00B91A04u, 0xB36629EAu, 0x4B284BE1u, 0x022BBFAFu,
    0xAE573124u, 0xE034A664u, 0xC85BF01Au, 0x17203CB4u,
    0xFE8EC121u, 0x0E744F7Eu, 0xB5913A89u, 0xF754E48Au,
    0xDF7B548Du, 0xD9B34844u, 0x02E4E6B5u, 0xE5FCBD84u,
    0x2422AF10u, 0x478B0FE6u, 0x51A9E25Fu, 0xEC7D3A89u,
    0xF5E2CCB1u, 0xA5ABA5ABu, 0x37A52085u, 0xF69B41C3u,
    0xAD9EB9E7u, 0x3E26BCCBu, 0x14F5D788u, 0xE1A6E6B5u,
    0xC405F3B7u, 0xDBDEE1A6u, 0x05C8FDD5u, 0x4B28D1C0u,
    0xB7BCFA38u, 0x5771F80Du, 0xE0343633u, 0x07F315AEu,
    0xFAF1EBC4u, 0x4B28BB59u, 0xF2450681u, 0x0B90050Fu,
    0xB41FB9E7u, 0xD788C7A2u, 0x2E4007F3u, 0xC1214D53u,
    0x1FCCAABAu, 0x2594B703u, 0xFC631892u, 0x194B41C3u,
    0xDB255037u, 0xB7BCEF61u, 0xAD9E1CE8u, 0x12CAC4BEu,
    0x3B420B90u, 0x23691DA1u, 0xF97F0172u, 0xB41F2D87u,
    0x478B050Fu, 0xA7D6073Au, 0x1F13C914u, 0xF754E999u,
    0x09654560u, 0xF69BC4BEu, 0x50F02EF9u, 0x3917F0D3u,
    0x334FF8C6u, 0x599CF245u, 0xD9B3D9B3u, 0xE0EDC121u,
    0x4844599Cu, 0xF97FDC97u, 0xFDD5C4BEu, 0xFBAA3BFBu,
    0xFE8EE543u, 0x4BE1D55Du, 0xB41FB366u, 0xFD1C3F98u,
    0x04561383u, 0xB41F43EEu, 0x0D02F8C6u, 0xF3B7FA38u,
    0x4B284560u, 0x27BF37A5u, 0xD107F754u, 0x3E26B1F4u,
    0x09653296u, 0x599C599Cu, 0xC7A2DEC2u, 0x08ACBD84u,
    0x51A94560u, 0xC121427Cu, 0xEA5227BFu, 0x1DA11892u,
    0x50F0CE23u, 0x1F1358E3u, 0x36EC0F2Du, 0xE827C293u,
    0x00B93E26u, 0xF0D3AFC9u, 0x49B6C4BEu, 0x07F31ABDu,
    0xB13B3124u, 0x53D42C15u, 0x34C1D9B3u, 0xD3EB07F3u,
    0xDC97DE09u, 0xB13B194Bu, 0xB1F41A04u, 0xE48AFF47u,
    0x1893E684u, 0x558EA989u, 0xF6E60831u, 0xF8B8065Fu,
    0x5760A7B7u, 0x4615B902u, 0xF5140A03u, 0x9DB46163u,
    0xC1333DE4u, 0x6FF38F24u, 0x131DEBFAu, 0xB2A34C74u,
    0x4E46B0D1u, 0x9AF9641Eu, 0xB55E49B9u, 0x21ADDD6Au,
    0x949A6A7Du, 0xA4135B04u, 0x1EF2E025u, 0x52D3AC44u,
    0x65079A10u, 0xEB111406u, 0x2468DAAFu, 0xB55E49B9u,
    0x5760A7B7u, 0xB55E49B9u, 0x3B29C3EEu, 0xECE31234u,
    0xF6E60831u, 0xEEB51062u, 0xCFC32F54u, 0xB0D14E46u,
    0x3DE4C133u, 0x3785C792u, 0xCFC32F54u, 0x0A03F514u,
    0xD53929DEu, 0x1FDBDF3Cu, 0x20C4DE53u, 0xFF170000u,
    0x3FB6BF61u, 0x70DC8E3Bu, 0xD62228F5u, 0xAC4452D3u,
    0x5760A7B7u, 0x53BCAB5Bu, 0x320FCD08u, 0x1EF2E025u,
    0x70DC8E3Bu, 0xD3672BB0u, 0xB55E49B9u, 0x4B8BB38Cu,
    0xDE5320C4u, 0xCA4D34CAu, 0x9F865F91u, 0x5018AEFFu,
    0x0E90F087u, 0x2551D9C6u, 0x01D2FD45u, 0x3957C5C0u,
    0x065FF8B8u, 0x091AF5FDu, 0xBAD44443u, 0xE3C91B4Eu,
    0x9CCB624Cu, 0x69949583u, 0x4271BCA6u, 0xC87B369Cu,
    0xD3672BB0u, 0x9CCB624Cu, 0x9DB46163u, 0xDD6A21ADu,
    0x5B04A413u, 0xF7CF0748u, 0xFD4501D2u, 0xFA8A048Du,
    0xFE2E00E9u, 0x5F919F86u, 0xA06F5EA8u, 0xFC5C02BBu,
    0x0576F9A1u, 0xA06F5EA8u, 0x1062EEB5u, 0xF0870E90u,
    0x5EA8A06Fu, 0x320FCD08u, 0xC4D73A40u, 0x4E46B0D1u,
    0x280CD70Bu, 0x2F54CFC3u, 0xFB7303A4u, 0x1FDBDF3Cu,
    0xD1952D82u, 0xA4FC5A1Bu, 0x983E66D9u, 0x17AAE76Du,
    0x4AA2B475u, 0x2C99D27Eu, 0xF7CF0748u, 0xA06F5EA8u,
    0x5A1BA4FCu, 0x90F66E21u, 0x2723D7F4u, 0xF5140A03u,
    0x0BD5F342u, 0x70DC8E3Bu, 0xB9024615u, 0x0AECF42Bu,
    0x66D9983Eu, 0xB0D14E46u, 0xE4B21A65u, 0x2551D9C6u,
    0x0BD5F342u, 0xF42B0AECu, 0x65F09927u, 0x47E7B730u,
    0x409FBE78u, 0x70DC8E3Bu, 0xCFC32F54u, 0xD8DD263Au,
    0x65F09927u, 0x2723D7F4u, 0x452CB9EBu, 0xE1F71D20u,
    0x00E9FE2Eu, 0xECE31234u, 0x5CD6A241u, 0x0A03F514u);

void x16rv2_simd_compress80(inout uint h[32], uint m[20])
{
    uint W[256];
    x16rv2_simd_expand80(m, W);

    uint s[32];
    for (uint i = 0u; i < 32u; i++)
        s[i] = i < 20u ? h[i] ^ m[i] : h[i];

    [[unroll]] for (uint i = 0u; i < 4u; i++) {
        [[unroll]] for (uint j = 0u; j < 8u; j++) {
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

void x16rv2_simd_final80(inout uint h[32])
{
    uint s[32] = h;
    s[0] ^= 640u;
    [[unroll]] for (uint i = 0u; i < 4u; i++) {
        [[unroll]] for (uint j = 0u; j < 8u; j++) {
            uint w[8];
            for (uint k = 0u; k < 8u; k++)
                w[k] = kX16rv2SimdFinal80W[64u * i + 8u * j + k];
            simd512_round_step(s, w, i, j);
        }
    }
    simd512_feed_forward(h, s);
}

// SIMD-512: the message zero-filled to a block, then a block holding only the
// bit count, under the final transform.
void x16rv2_simd(uint w[20], out uint s[16])
{
    uint h[32] = kSimd512Iv;
    if (kWords == 20u) {
        x16rv2_simd_compress80(h, w);
        x16rv2_simd_final80(h);
    } else {
        uint m[16];
        for (uint k = 0u; k < 16u; k++)
            m[k] = w[k];
        simd512_compress64(h, m);
        simd512_compress_final64(h);
    }

    for (uint k = 0u; k < 16u; k++)
        s[k] = h[k];
}

// ECHO-512: one block, the message, 0x80, the digest size 512 at bytes
// 110..111 and the 128-bit bit count at 112..127, under the counter.
void x16rv2_echo(uint w[20], out uint s[16])
{
    uint v[32];
    for (uint k = 0u; k < 32u; k++)
        v[k] = (k & 3u) == 0u ? 512u : 0u;
    uint m[32];
    for (uint k = 0u; k < 32u; k++)
        m[k] = 0u;
    for (uint k = 0u; k < kWords; k++)
        m[k] = w[k];
    m[kWords] = 0x80u;
    m[27] = 0x02000000u;
    m[28] = kBits;
    uint cnt[4] = uint[4](kBits, 0u, 0u, 0u);

    echo512_compress(v, m, cnt);
    for (uint k = 0u; k < 16u; k++)
        s[k] = v[k];
}

// Hamsi-512: eight-byte blocks, the 0x80 block, then the bit count
// big-endian under the final rounds. Unrolled so every index is a constant.
void x16rv2_hamsi(uint w[20], out uint s[16])
{
    uint h[16] = kHamsi512Iv;
    uint m[16];
    [[unroll]] for (uint b = 0u; b < kWords / 2u; b++) {
        hamsi512_expand(w[2u * b], w[2u * b + 1u], m);
        hamsi512_compress(h, m, false);
    }
    hamsi512_expand(0x80u, 0u, m);
    hamsi512_compress(h, m, false);
    hamsi512_expand(0u, bswap32(kBits), m);
    hamsi512_compress(h, m, true);

    for (uint k = 0u; k < 16u; k++)
        s[k] = bswap32(h[k]);
}

// Fugue-512: the message as big-endian words, then the 64-bit bit count, one
// TIX a word, the final rounds.
void x16rv2_fugue(uint w[20], out uint s[16])
{
    uint f[36];
    for (uint k = 0u; k < 20u; k++)
        f[k] = 0u;
    for (uint k = 0u; k < 16u; k++)
        f[20u + k] = kFugue512Iv[k];

    [[unroll]] for (uint k = 0u; k < kWords; k++)
        fugue512_word(f, bswap32(w[k]));
    fugue512_word(f, 0u);
    fugue512_word(f, kBits);
    fugue512_final(f);

    s[0] = f[1];   s[1] = f[2];   s[2] = f[3];   s[3] = f[4];
    s[4] = f[9];   s[5] = f[10];  s[6] = f[11];  s[7] = f[12];
    s[8] = f[18];  s[9] = f[19];  s[10] = f[20]; s[11] = f[21];
    s[12] = f[27]; s[13] = f[28]; s[14] = f[29]; s[15] = f[30];
    for (uint k = 0u; k < 16u; k++)
        s[k] = bswap32(s[k]);
}

// SHA-512 of 64 bytes: one block, the message, 0x80 and the bit count 512.
// Only ever behind a Tiger.
void x16rv2_sha512(inout uint s[16])
{
    SLANE w[16];
    for (uint i = 0u; i < 8u; i++)
        w[i] = slane(bswap32(s[2u * i + 1u]), bswap32(s[2u * i]));
    w[8] = slane(0u, 0x80000000u);
    for (uint i = 9u; i < 15u; i++)
        w[i] = slane(0u, 0u);
    w[15] = slane(512u, 0u);

    SLANE v[8];
    for (uint i = 0u; i < 8u; i++)
        v[i] = sha512_iv(i);
    SLANE a = v[0], b = v[1], c = v[2], d = v[3];
    SLANE e = v[4], f = v[5], g = v[6], h = v[7];

    [[unroll]] for (uint r = 0u; r < 80u; r++) {
        SLANE wr;
        if (r < 16u) {
            wr = w[r];
        } else {
            wr = sadd(sadd(w[(r - 16u) & 15u], sha512_small_s0(w[(r - 15u) & 15u])),
                      sadd(w[(r - 7u) & 15u], sha512_small_s1(w[(r - 2u) & 15u])));
            w[r & 15u] = wr;
        }
        SLANE t1 = sadd(sadd(sadd(h, sha512_big_s1(e)),
                             sadd(sha512_ch(e, f, g), sha512_k(r))), wr);
        SLANE t2 = sadd(sha512_big_s0(a), sha512_maj(a, b, c));
        h = g; g = f; f = e; e = sadd(d, t1);
        d = c; c = b; b = a; a = sadd(t1, t2);
    }
    v[0] = sadd(v[0], a); v[1] = sadd(v[1], b);
    v[2] = sadd(v[2], c); v[3] = sadd(v[3], d);
    v[4] = sadd(v[4], e); v[5] = sadd(v[5], f);
    v[6] = sadd(v[6], g); v[7] = sadd(v[7], h);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = bswap32(shi(v[i]));
        s[2u * i + 1u] = bswap32(slo(v[i]));
    }
}

// What v2 puts in front of Keccak, Luffa and SHA-512: Tiger-192 of the
// stage's input, zero-padded to 64 bytes.
void x16rv2_tiger(uint w[20], out uint s[16])
{
    uint t[6];
    tiger192_hash(w, kWords, t);
    for (uint k = 0u; k < 16u; k++)
        s[k] = k < 6u ? t[k] : 0u;
}

// This module's stage, for one nonce. Groestl is not here: it takes two.
void x16rv2_one(uint w[20], out uint s[16])
{
    if (kStage == 4u || kStage == 6u || kStage == 15u)
        x16rv2_tiger(w, s);

#if X16RV2_STAGE == 0
    x16rv2_blake(w, s);
#elif X16RV2_STAGE == 1
    x16rv2_bmw(w, s);
#elif X16RV2_STAGE == 3
    x16rv2_jh(w, s);
#elif X16RV2_STAGE == 4
    x16rv2_keccak(s);
#elif X16RV2_STAGE == 5
    x16rv2_skein(w, s);
#elif X16RV2_STAGE == 6
    x16rv2_luffa(s);
#elif X16RV2_STAGE == 7
    x16rv2_cubehash(w, s);
#elif X16RV2_STAGE == 8
    x16rv2_shavite(w, s);
#elif X16RV2_STAGE == 9
    x16rv2_simd(w, s);
#elif X16RV2_STAGE == 10
    x16rv2_echo(w, s);
#elif X16RV2_STAGE == 11
    x16rv2_hamsi(w, s);
#elif X16RV2_STAGE == 12
    x16rv2_fugue(w, s);
#elif X16RV2_STAGE == 13
    shabal512_hash(w, kWords, s);
#elif X16RV2_STAGE == 14
    whirlpool512_hash(w, kWords, s);
#elif X16RV2_STAGE == 15
    x16rv2_sha512(s);
#endif
}

// ------------------------------------------------------------------ main

// Nonce `index` of this dispatch's input: the header with its nonce at
// position 0, the state buffer after.
void x16rv2_load(uint index, out uint w[20])
{
    if (kWords == 20u) {
        for (uint k = 0u; k < 19u; k++)
            w[k] = push.header[k];
        w[19] = bswap32(push.nonce_start + index);
    } else {
        for (uint k = 0u; k < 16u; k++)
            w[k] = states[k * push.count + index];
        for (uint k = 16u; k < 20u; k++)
            w[k] = 0u;
    }
}

void x16rv2_store(uint index, uint s[16])
{
    for (uint k = 0u; k < 16u; k++)
        states[k * push.count + index] = s[k];
}

// The last state's top 64 bits against the target's; the host compares all
// 256.
void x16rv2_screen(uint index)
{
    uint s7 = states[7u * push.count + index];
    uint s6 = states[6u * push.count + index];

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(s7);

    if (s7 > push.target[1])
        return;
    if (s7 == push.target[1] && s6 > push.target[0])
        return;

    uint hash[8];
    for (uint k = 0u; k < 8u; k++)
        hash[k] = states[k * push.count + index];
    emit_candidate(push.capacity, push.nonce_start + index, hash);
}

// Nonces index and index + 1; `two` false leaves the second alone.
void x16rv2_pair(uint index, bool two)
{
#if X16RV2_STAGE == 16
    x16rv2_screen(index);
    if (two)
        x16rv2_screen(index + 1u);
#elif X16RV2_STAGE == 2
    uint a[20], b[20];
    x16rv2_load(index, a);
    if (two)
        x16rv2_load(index + 1u, b);
    else
        b = a;
    uint sa[16], sb[16];
    x16rv2_groestl(a, b, sa, sb);
    x16rv2_store(index, sa);
    if (two)
        x16rv2_store(index + 1u, sb);
#else
    for (uint h = 0u; h < 2u; h++) {
        if (h == 1u && !two)
            break;
        uint w[20];
        x16rv2_load(index + h, w);
        uint s[16];
        x16rv2_one(w, s);
        x16rv2_store(index + h, s);
    }
#endif
}

// Whirlpool over 64 bytes takes four nonces bitsliced, from index on; those
// past the batch hash a copy of the last and are not stored.
void x16rv2_quad(uint index)
{
    uint m[64];
    [[unroll]] for (uint h = 0u; h < 4u; h++) {
        uint i = min(index + h, push.count - 1u);
        [[unroll]] for (uint k = 0u; k < 16u; k++)
            m[16u * h + k] = states[k * push.count + i];
    }
    uint d[64];
    whirlpool512_x4_hash64(m, d);
    uint n = min(push.count - index, 4u);
    [[unroll]] for (uint k = 0u; k < 16u; k++) {
        uint base = k * push.count + index;
        states[base] = d[k];
        if (n > 1u)
            states[base + 1u] = d[16u + k];
        if (n > 2u)
            states[base + 2u] = d[32u + k];
        if (n > 3u)
            states[base + 3u] = d[48u + k];
    }
}

void main()
{
    // Only the tables this stage reads; every condition is a literal.
    if (kStage == 8u || kStage == 10u)
        aes_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 12u)
        fugue512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 14u && kWords == 20u)
        whirlpool512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 4u || kStage == 6u || kStage == 15u)
        tiger192_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);

    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    if (kStage == 14u && kWords == 16u) {
        for (uint k = 0u; k < kNoncesPerInvocation; k += 4u) {
            if (first + k >= push.count)
                return;
            x16rv2_quad(first + k);
        }
        return;
    }
    for (uint k = 0u; k < kNoncesPerInvocation; k += 2u) {
        uint index = first + k;
        if (index >= push.count)
            return;
        x16rv2_pair(index, k + 1u < kNoncesPerInvocation
                           && index + 1u < push.count);
    }
}

#endif  // VKMINER_ALGORITHMS_X16RV2_KERNEL_GLSL_INCLUDED
