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
// Groestl hashes them together as bit planes.

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

// SIMD-512: the message zero-filled to a block, then a block holding only the
// bit count, under the final transform.
void x16rv2_simd(uint w[20], out uint s[16])
{
    uint h[32] = kSimd512Iv;
    if (kWords == 20u) {
        uint m[32];
        for (uint k = 0u; k < 32u; k++)
            m[k] = k < 20u ? w[k] : 0u;
        simd512_compress(h, m, false);
        for (uint k = 0u; k < 32u; k++)
            m[k] = 0u;
        m[0] = kBits;
        simd512_compress(h, m, true);
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

void main()
{
    // Only the tables this stage reads; every condition is a literal.
    if (kStage == 8u || kStage == 10u)
        aes_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 12u)
        fugue512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 14u)
        whirlpool512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    if (kStage == 4u || kStage == 6u || kStage == 15u)
        tiger192_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);

    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k += 2u) {
        uint index = first + k;
        if (index >= push.count)
            return;
        x16rv2_pair(index, k + 1u < kNoncesPerInvocation
                           && index + 1u < push.count);
    }
}

#endif  // VKMINER_ALGORITHMS_X16RV2_KERNEL_GLSL_INCLUDED
