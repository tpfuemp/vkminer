// x11: eleven chained 512-bit hashes, two nonces per pass, cut to 32 bytes.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by x11.comp and x11_32.comp; never `+` a lane. Groestl is bitsliced
// two hashes at a time, so both nonces share it and part for the last eight
// stages. This file owns every stage's padding.
//
// Header words arrive as little-endian reads of the wire; between stages a
// digest is sixteen little-endian words. Only BLAKE and Luffa need swaps.

#ifndef VKMINER_ALGORITHMS_X11_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_X11_KERNEL_GLSL_INCLUDED

// SHAvite and ECHO take AES from one T-table in workgroup memory.
#define VKMINER_AES_TABLE 1

// The push block, the bit planes and groestl_hash() are groestl's.
#define VKMINER_GROESTL_NO_MAIN 1

// Keeps SIMD's message array in registers.
#define VKMINER_SIMD512_UNROLL_EXPAND 1

#include "algorithms/groestl/groestl_kernel.glsl"
#include "shaders/common/blake512.glsl"
#include "shaders/common/bmw512.glsl"
#include "shaders/common/cubehash512.glsl"
#include "shaders/common/echo512.glsl"
#include "shaders/common/jh512.glsl"
#include "shaders/common/luffa512.glsl"
#include "shaders/common/sha3.glsl"
#include "shaders/common/shavite512.glsl"
#include "shaders/common/simd512.glsl"
#include "shaders/common/skein512.glsl"

// BLAKE-512 of the header: one block holding the 80 bytes, the 0x80
// terminator, the 1 bit at byte 111 and the bit count 640, under the counter
// 640.
void x11_blake(uint nonce, out uint s[16])
{
    BKLANE m[16];
    for (uint i = 0u; i < 9u; i++)
        m[i] = bklane(bswap32(push.header[2u * i + 1u]),
                      bswap32(push.header[2u * i]));
    m[9] = bklane(nonce, bswap32(push.header[18]));
    m[10] = bklane(0u, 0x80000000u);
    m[11] = bklane(0u, 0u);
    m[12] = bklane(0u, 0u);
    m[13] = bklane(1u, 0u);
    m[14] = bklane(0u, 0u);
    m[15] = bklane(640u, 0u);

    BKLANE h[8];
    for (uint i = 0u; i < 8u; i++)
        h[i] = blake512_iv(i);
    blake512_compress(h, m, bklane(640u, 0u));

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = bswap32(bkhi(h[i]));
        s[2u * i + 1u] = bswap32(bklo(h[i]));
    }
}

// BMW-512 of 64 bytes: one block holding the message, the 0x80 terminator and
// the bit count 512, then the final transform.
void x11_bmw(inout uint s[16])
{
    BLANE h[16];
    BLANE m[16];
    for (uint i = 0u; i < 16u; i++)
        h[i] = bmw512_iv(i);
    for (uint i = 0u; i < 8u; i++)
        m[i] = blane(s[2u * i], s[2u * i + 1u]);
    m[8] = blane(0x80u, 0u);
    for (uint i = 9u; i < 15u; i++)
        m[i] = blane(0u, 0u);
    m[15] = blane(512u, 0u);

    bmw512_compress(h, m);
    bmw512_final(h);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = blo(h[8u + i]);
        s[2u * i + 1u] = bhi(h[8u + i]);
    }
}

// Byte (row i, column c) of a 64-byte message's padded Groestl block: the
// message in columns 0..7, 0x80 at column 8 row 0 and a block count of one
// at column 15 row 7.
uint x11_groestl_byte(uint s[16], uint i, uint c)
{
    if (c < 8u)
        return (s[2u * c + (i >> 2)] >> (8u * (i & 3u))) & 0xffu;
    if (c == 8u && i == 0u)
        return 0x80u;
    if (c == 15u && i == 7u)
        return 0x01u;
    return 0u;
}

// Groestl-512 of 64 bytes, of a and b together as bit planes. Word k of row i
// holds bytes (row i, column 4n + k / 2) of hash k & 1, as in
// groestl_load80(). Unrolled so every index into a and b is a constant.
void x11_groestl(inout uint a[16], inout uint b[16])
{
    uint s[64];
    [[unroll]] for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        [[unroll]] for (uint k = 0u; k < 8u; k++) {
            uint c = k >> 1;
            if ((k & 1u) == 0u)
                d[k] = x11_groestl_byte(a, i, c)
                     | (x11_groestl_byte(a, i, 4u + c) << 8)
                     | (x11_groestl_byte(a, i, 8u + c) << 16)
                     | (x11_groestl_byte(a, i, 12u + c) << 24);
            else
                d[k] = x11_groestl_byte(b, i, c)
                     | (x11_groestl_byte(b, i, 4u + c) << 8)
                     | (x11_groestl_byte(b, i, 8u + c) << 16)
                     | (x11_groestl_byte(b, i, 12u + c) << 24);
        }
        groestl_transpose(d);
        for (uint p = 0u; p < 8u; p++)
            s[8u * i + p] = d[p];
    }

    groestl_hash(s);

    // Back to bytes. Digest word w is column 8 + w / 2, rows 4 (w & 1) to +3,
    // in word k = 2 (column & 3) + hash at byte column >> 2.
    uint rows[64];
    for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        for (uint p = 0u; p < 8u; p++)
            d[p] = s[8u * i + p];
        groestl_transpose(d);
        for (uint k = 0u; k < 8u; k++)
            rows[8u * i + k] = d[k];
    }
    for (uint w = 0u; w < 16u; w++) {
        uint c = 8u + (w >> 1), r0 = 4u * (w & 1u), sh = 8u * (c >> 2);
        uint k = 2u * (c & 3u);
        a[w] = ((rows[8u * r0 + k] >> sh) & 0xffu)
             | (((rows[8u * (r0 + 1u) + k] >> sh) & 0xffu) << 8)
             | (((rows[8u * (r0 + 2u) + k] >> sh) & 0xffu) << 16)
             | (((rows[8u * (r0 + 3u) + k] >> sh) & 0xffu) << 24);
        k += 1u;
        b[w] = ((rows[8u * r0 + k] >> sh) & 0xffu)
             | (((rows[8u * (r0 + 1u) + k] >> sh) & 0xffu) << 8)
             | (((rows[8u * (r0 + 2u) + k] >> sh) & 0xffu) << 16)
             | (((rows[8u * (r0 + 3u) + k] >> sh) & 0xffu) << 24);
    }
}

// Skein-512-512 of 64 bytes: one message block, first and final, then the
// output block.
void x11_skein(inout uint s[16])
{
    TLANE h[8];
    TLANE m[8];
    for (uint i = 0u; i < 8u; i++) {
        h[i] = skein512_512_iv(i);
        m[i] = tlane(s[2u * i], s[2u * i + 1u]);
    }
    skein512_ubi(h, m, tlane(64u, 0u),
                 tlane(0u, kSkeinT1Msg | kSkeinT1First | kSkeinT1Final));
    for (uint i = 0u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(8u, 0u),
                 tlane(0u, kSkeinT1Out | kSkeinT1First | kSkeinT1Final));

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = tlo(h[i]);
        s[2u * i + 1u] = thi(h[i]);
    }
}

// JH-512 of 64 bytes: the message block, then a block holding the 0x80
// terminator and the bit count 512 big-endian in its last bytes.
void x11_jh(inout uint s[16])
{
    JLANE x[16];
    for (uint i = 0u; i < 16u; i++)
        x[i] = jh512_iv(i);
    JLANE m[8];
    for (uint i = 0u; i < 8u; i++)
        m[i] = jlane(s[2u * i], s[2u * i + 1u]);
    jh512_f8(x, m);

    m[0] = jlane(0x80u, 0u);
    for (uint i = 1u; i < 7u; i++)
        m[i] = jlane(0u, 0u);
    m[7] = jlane(0u, 0x00020000u);
    jh512_f8(x, m);

    for (uint i = 0u; i < 8u; i++) {
        s[2u * i] = jlo(x[8u + i]);
        s[2u * i + 1u] = jhi(x[8u + i]);
    }
}

// Keccak-512 of 64 bytes, the submission's and not SHA3-512: one block at
// the rate of nine lanes, padded 0x01 ... 0x80.
void x11_keccak(inout uint s[16])
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

// Luffa-512 of 64 bytes: two message blocks, the padding block, then two
// blank blocks, each giving half the digest. The block loop is unrolled: a
// rolled one reads s[8b + k] through a chain of selects.
void x11_luffa(inout uint s[16])
{
    uint v[40] = kLuffa512Iv;
    uint m[8];
    [[unroll]] for (uint b = 0u; b < 2u; b++) {
        for (uint k = 0u; k < 8u; k++)
            m[k] = bswap32(s[8u * b + k]);
        luffa512_block(v, m);
    }
    m[0] = 0x80000000u;
    for (uint k = 1u; k < 8u; k++)
        m[k] = 0u;
    luffa512_block(v, m);

    m[0] = 0u;
    luffa512_block(v, m);
    for (uint k = 0u; k < 8u; k++)
        s[k] = bswap32(luffa512_out(v, k));
    luffa512_block(v, m);
    for (uint k = 0u; k < 8u; k++)
        s[8u + k] = bswap32(luffa512_out(v, k));
}

// CubeHash-512 of 64 bytes: two blocks, the padding block, the final rounds.
// The block loop is unrolled for the same reason as Luffa's.
void x11_cubehash(inout uint s[16])
{
    uint x[32] = kCubehash512Iv;

    [[unroll]] for (uint b = 0u; b < 2u; b++) {
        for (uint k = 0u; k < 8u; k++)
            x[k] ^= s[8u * b + k];
        cubehash512_rounds(x, 16u);
    }
    x[0] ^= 0x80u;
    cubehash512_rounds(x, 16u);
    x[31] ^= 1u;
    cubehash512_rounds(x, 160u);

    for (uint k = 0u; k < 16u; k++)
        s[k] = x[k];
}

// SHAvite-512 of 64 bytes: one block holding the message, the 0x80
// terminator, the 128-bit bit count 512 at bytes 110..125 and the digest size
// 512 at bytes 126..127, compressed under the counter 512.
void x11_shavite(inout uint s[16])
{
    uint h[16] = kShavite512Iv;
    uint m[32];
    for (uint k = 0u; k < 16u; k++)
        m[k] = s[k];
    m[16] = 0x80u;
    for (uint k = 17u; k < 32u; k++)
        m[k] = 0u;
    m[27] = 0x02000000u;
    m[31] = 0x02000000u;
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);

    shavite512_compress(h, m, cnt);
    s = h;
}

// SIMD-512 of 64 bytes: the message zero-filled to a block, then a block
// holding only the bit count, under the final transform.
void x11_simd(inout uint s[16])
{
    uint h[32] = kSimd512Iv;
    simd512_compress64(h, s);
    simd512_compress_final64(h);

    for (uint k = 0u; k < 16u; k++)
        s[k] = h[k];
}

// ECHO-512 of 64 bytes: one block holding the message, the 0x80 terminator,
// the digest size 512 at bytes 110..111 and the 128-bit bit count 512 at
// bytes 112..127, compressed under the counter 512. Every chaining word starts
// as the digest size.
void x11_echo_block(uint s[16], out uint m[32])
{
    for (uint k = 0u; k < 16u; k++)
        m[k] = s[k];
    m[16] = 0x80u;
    for (uint k = 17u; k < 32u; k++)
        m[k] = 0u;
    m[27] = 0x02000000u;
    m[28] = 512u;
}

void x11_echo(inout uint s[16])
{
    uint v[32];
    for (uint k = 0u; k < 32u; k++)
        v[k] = (k & 3u) == 0u ? 512u : 0u;
    uint m[32];
    x11_echo_block(s, m);
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);

    echo512_compress(v, m, cnt);
    for (uint k = 0u; k < 16u; k++)
        s[k] = v[k];
}

// ECHO's first BigSubWords on the words that do not depend on the message:
// the chaining value (words 0..7) and the padding block half (words 12..15),
// under the counter 512.
const uint kX11Echo0[48] = uint[48](
    0xe7e9f5f5u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0x14b8a457u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0xdbfde1ddu, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0x9ac2dea3u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0x65978b09u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0xa4213d7eu, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0x265f4382u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0x34514d9eu, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu,
    0xb134347eu, 0xea6f7e7eu, 0xbd7731bdu, 0x8a8a1968u,
    0x579f9f33u, 0xfbfbfbfbu, 0xfbfbfbfbu, 0xefefd3c7u,
    0x2cb6b661u, 0x6b23b3b3u, 0xcf93a7cfu, 0x9d9d3751u,
    0x01425eb8u, 0xf5e7e9f5u, 0xb3b36b23u, 0xb3dbe7afu);

// Digest words 6 and 7 of x11_echo(s), the two the screen reads. They are
// lanes 2 and 3 of state word 1 (column 0) and word 9 (column 2), so the last
// round needs only the eight words BigShiftRows moves into those columns, and
// one MixColumns row of each.
uvec2 x11_echo_screen(uint s[16])
{
    uint m[32];
    x11_echo_block(s, m);
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);
    uint w[64];
    for (uint k = 0u; k < 32u; k++)
        w[k] = kX11Echo0[k];
    for (uint k = 0u; k < 16u; k++) {
        w[32u + k] = m[k];
        w[48u + k] = kX11Echo0[32u + k];
    }

    // Round 0: only the message words 8..11 go through AES.
    echo512_subwords_pair(w, cnt, 0u, 8u, 9u);
    echo512_subwords_pair(w, cnt, 0u, 10u, 11u);
    echo512_shift_mix(w);
    for (uint r = 1u; r < 9u; r++)
        echo512_round(w, cnt, r);

    // Column c takes word (c + row, row) from row 0..3: words 0, 5, 10, 15
    // for column 0 and 8, 13, 2, 7 for column 2.
    echo512_subwords_pair(w, cnt, 9u, 0u, 2u);
    echo512_subwords_pair(w, cnt, 9u, 5u, 7u);
    echo512_subwords_pair(w, cnt, 9u, 8u, 10u);
    echo512_subwords_pair(w, cnt, 9u, 13u, 15u);

    uvec2 d;
    for (uint i = 2u; i < 4u; i++) {
        // MixColumns row 1: 2b + 3c + d + a, as xtime(b ^ c) ^ c ^ d ^ a.
        uint c0 = aes_xtime4(w[20u + i] ^ w[40u + i]) ^ w[40u + i] ^
                  w[60u + i] ^ w[i];
        uint c2 = aes_xtime4(w[52u + i] ^ w[8u + i]) ^ w[8u + i] ^
                  w[28u + i] ^ w[32u + i];
        // The feed-forward; the chaining value's lanes 2 and 3 start at 0.
        d[i - 2u] = m[4u + i] ^ c0 ^ c2;
    }
    return d;
}

// Stages 4 to 11 for one nonce, then the screen.
void x11_tail(inout uint s[16], uint nonce)
{
    x11_skein(s);
    x11_jh(s);
    x11_keccak(s);
    x11_luffa(s);
    x11_cubehash(s);
    x11_shavite(s);
    x11_simd(s);
    uvec2 top = x11_echo_screen(s);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(top.y);

    // A prefix of the share test; the host compares all 256 bits.
    if (top.y > push.target[1])
        return;
    if (top.y == push.target[1] && top.x > push.target[0])
        return;

    x11_echo(s);
    uint hash[8];
    for (uint k = 0u; k < 8u; k++)
        hash[k] = s[k];
    emit_candidate(push.capacity, nonce, hash);
}

// Nonces n and n + 1; `two` false hashes the second lane and drops it. Each
// loop runs its stages once in the binary for both nonces.
void x11_search(uint n, bool two)
{
    uint a[16], b[16];
    for (uint h = 0u; h < 2u; h++) {
        uint s[16];
        x11_blake(n + h, s);
        x11_bmw(s);
        if (h == 0u)
            a = s;
        else
            b = s;
    }

    x11_groestl(a, b);

    for (uint h = 0u; h < 2u; h++) {
        if (h == 1u && !two)
            break;
        uint s[16];
        if (h == 0u)
            s = a;
        else
            s = b;
        x11_tail(s, n + h);
    }
}

void main()
{
#ifdef VKMINER_AES_TABLE
    aes_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
#endif
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k += 2u) {
        uint index = first + k;
        if (index >= push.count)
            return;
        // The second lane is this invocation's and inside the dispatch, or
        // another invocation would hash the same nonce.
        x11_search(push.nonce_start + index,
                   k + 1u < kNoncesPerInvocation && index + 1u < push.count);
    }
}

#endif  // VKMINER_ALGORITHMS_X11_KERNEL_GLSL_INCLUDED
