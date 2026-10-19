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
void qubit_echo(inout uint s[16])
{
    uint v[32];
    for (uint k = 0u; k < 32u; k++)
        v[k] = (k & 3u) == 0u ? 512u : 0u;
    uint m[32];
    for (uint k = 0u; k < 16u; k++)
        m[k] = s[k];
    m[16] = 0x80u;
    for (uint k = 17u; k < 32u; k++)
        m[k] = 0u;
    m[27] = 0x02000000u;
    m[28] = 512u;
    uint cnt[4] = uint[4](512u, 0u, 0u, 0u);

    echo512_compress(v, m, cnt);
    for (uint k = 0u; k < 16u; k++)
        s[k] = v[k];
}

void qubit_search(uint nonce)
{
    uint s[16];
    qubit_luffa(nonce, s);
    qubit_cubehash(s);
    qubit_shavite(s);
    qubit_simd(s);
    qubit_echo(s);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(s[7]);

    // A prefix of the share test; the host compares all 256 bits.
    if (s[7] > push.target[1])
        return;
    if (s[7] == push.target[1] && s[6] > push.target[0])
        return;

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
