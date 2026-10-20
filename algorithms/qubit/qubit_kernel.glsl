// qubit: one nonce per invocation. Luffa, CubeHash, SHAvite, SIMD and ECHO,
// each the whole 512-bit hash of the one before, cut to 32 bytes at the end.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Only the first stage sees the 80-byte header; every later one hashes the 64
// bytes before it, with its own padding, which this file owns. The primitive
// files know no message lengths.
//
// Byte order: the host uploads header words as little-endian reads of the wire.
// Luffa reads big-endian words, the other four little-endian ones, so the only
// swaps are into and out of Luffa. Digest words come out as the little-endian
// words the host compares.

#ifndef VKMINER_ALGORITHMS_QUBIT_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_QUBIT_KERNEL_GLSL_INCLUDED

// SHAvite and ECHO take AES from one T-table in workgroup memory.
#define VKMINER_AES_TABLE 1

#include "shaders/common/bits.glsl"
#include "shaders/common/candidates.glsl"
#include "shaders/common/cubehash512.glsl"
#include "shaders/common/echo512.glsl"
#include "shaders/common/luffa512.glsl"
#include "shaders/common/shavite512.glsl"
#include "shaders/common/simd512.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by QubitPush in qubit.cpp, which asserts the layout.
layout(push_constant) uniform Push {
    uint header[19];  // header words 0..18, little-endian reads of the wire
    uint target[2];   // the top 64 bits, most significant last
    uint nonce_start;
    uint count;       // nonces to test, which is not the invocation count
    uint capacity;    // candidates the result buffer can hold
} push;

// 160 bytes, mirrored by QubitUniform: luffa512_80_precompute()'s 40 words,
// the state after the two nonce-free blocks and the third one's injection.
layout(std140, binding = 1) uniform Job {
    uvec4 v[10];
} job;

// Luffa-512 of the header: the nonce xored into the host's state, the third
// block's steps, then two blank blocks, each giving half the digest. Out as
// little-endian words.
void qubit_luffa(uint nonce, out uint s[16])
{
    uint v[40];
    for (uint k = 0u; k < 10u; k++) {
        uvec4 w = job.v[k];
        v[4u * k] = w.x; v[4u * k + 1u] = w.y;
        v[4u * k + 2u] = w.z; v[4u * k + 3u] = w.w;
    }

    // The nonce is message word 3; lane j sees it times x^j, which moves it to
    // word 3 + j, then the tweak rotates words 4..7 of lane j by j.
    v[3] ^= nonce;
    for (uint j = 1u; j < 5u; j++)
        v[9u * j + 3u] ^= rotl32(nonce, j);
    luffa512_steps(v);

    uint m[8];
    for (uint k = 0u; k < 8u; k++)
        m[k] = 0u;
    luffa512_block(v, m);
    for (uint k = 0u; k < 8u; k++)
        s[k] = bswap32(luffa512_out(v, k));
    luffa512_block(v, m);
    for (uint k = 0u; k < 8u; k++)
        s[8u + k] = bswap32(luffa512_out(v, k));
}

// CubeHash-512 of 64 bytes: two blocks, the padding block, the final rounds.
void qubit_cubehash(inout uint s[16])
{
    uint x[32] = kCubehash512Iv;

    for (uint b = 0u; b < 2u; b++) {
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
void qubit_shavite(inout uint s[16])
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
void qubit_simd(inout uint s[16])
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
void qubit_echo_block(uint s[16], out uint m[32])
{
    for (uint k = 0u; k < 16u; k++)
        m[k] = s[k];
    m[16] = 0x80u;
    for (uint k = 17u; k < 32u; k++)
        m[k] = 0u;
    m[27] = 0x02000000u;
    m[28] = 512u;
}

void qubit_echo(inout uint s[16])
{
    uint v[32];
    for (uint k = 0u; k < 32u; k++)
        v[k] = (k & 3u) == 0u ? 512u : 0u;
    uint m[32];
    qubit_echo_block(s, m);
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);

    echo512_compress(v, m, cnt);
    for (uint k = 0u; k < 16u; k++)
        s[k] = v[k];
}

// ECHO's first BigSubWords on the words that do not depend on the message:
// the chaining value (words 0..7) and the padding block half (words 12..15),
// under the counter 512.
const uint kQubitEcho0[48] = uint[48](
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

// Digest words 6 and 7 of qubit_echo(s), the two the screen reads. They are
// lanes 2 and 3 of state word 1 (column 0) and word 9 (column 2), so the last
// round needs only the eight words BigShiftRows moves into those columns, and
// one MixColumns row of each.
uvec2 qubit_echo_screen(uint s[16])
{
    uint m[32];
    qubit_echo_block(s, m);
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);
    uint w[64];
    for (uint k = 0u; k < 32u; k++)
        w[k] = kQubitEcho0[k];
    for (uint k = 0u; k < 16u; k++) {
        w[32u + k] = m[k];
        w[48u + k] = kQubitEcho0[32u + k];
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

void qubit_search(uint nonce)
{
    uint s[16];
    qubit_luffa(nonce, s);
    qubit_cubehash(s);
    qubit_shavite(s);
    qubit_simd(s);
    uvec2 top = qubit_echo_screen(s);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(top.y);

    // A prefix of the share test; the host compares all 256 bits.
    if (top.y > push.target[1])
        return;
    if (top.y == push.target[1] && top.x > push.target[0])
        return;

    qubit_echo(s);
    uint hash[8];
    for (uint k = 0u; k < 8u; k++)
        hash[k] = s[k];
    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
#ifdef VKMINER_AES_TABLE
    aes_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
#endif
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        qubit_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_QUBIT_KERNEL_GLSL_INCLUDED
