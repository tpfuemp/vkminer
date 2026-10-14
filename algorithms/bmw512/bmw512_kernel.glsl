// bmw512: one nonce per invocation. BMW-512 of the header, cut to 32 bytes.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by bmw512.comp, bmw512_wide.comp and bmw512_32.comp. Header and
// padding are one block: one compression and the final transform per nonce.
// Header words are little-endian reads of the wire, earlier one low; the
// digest words are already in the order the host compares.

#ifndef VKMINER_ALGORITHMS_BMW512_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_BMW512_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/bmw512.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by Bmw512Push in bmw512.cpp, which asserts the layout.
layout(push_constant) uniform Push {
    uint header[19];  // header words 0..18, little-endian reads of the wire
    uint target[2];   // the top 64 bits, most significant last
    uint nonce_start;
    uint count;       // nonces to test, which is not the invocation count
    uint capacity;    // candidates the result buffer can hold
} push;

// 288 bytes, mirrored by Bmw512Uniform: the 35 words of
// bmw512_80_precompute() in src/core/bmw512.c, two to an entry.
layout(std140, binding = 1) uniform Job {
    uvec4 words[18];
} job;

// Word i of it. Callers pass literals, so the selection folds.
BLANE bmw512_job(uint i)
{
    uvec4 w = job.words[i >> 1u];
    return (i & 1u) == 0u ? blane(w.x, w.y) : blane(w.z, w.w);
}

// Whether Q[k] reads the nonce (the high half of M[9]). The host leaves
// exactly these terms out of its sums and the kernel adds exactly these back.
#define BMW_VAR(k) ((k) >= 16 || (k) == 2 || (k) == 4 || (k) == 11 \
                    || (k) == 12 || (k) == 15)
#define BMW_ADD_IF(k, term) if (BMW_VAR(k)) v = badd(v, term)

// f1 from the host's sum plus the terms that read the nonce. AddElement is in
// the sum except for j - 16 = 6, 9 and 15.
#define BMW_EXPAND1_JOB(j)                                                \
    {                                                                     \
        BLANE v = bmw512_job(j);                                          \
        BMW_ADD_IF((j) - 16, bmw_s1(q[(j) - 16]));                        \
        BMW_ADD_IF((j) - 15, bmw_s2(q[(j) - 15]));                        \
        BMW_ADD_IF((j) - 14, bmw_s3(q[(j) - 14]));                        \
        BMW_ADD_IF((j) - 13, bmw_s0(q[(j) - 13]));                        \
        BMW_ADD_IF((j) - 12, bmw_s1(q[(j) - 12]));                        \
        BMW_ADD_IF((j) - 11, bmw_s2(q[(j) - 11]));                        \
        BMW_ADD_IF((j) - 10, bmw_s3(q[(j) - 10]));                        \
        BMW_ADD_IF((j) -  9, bmw_s0(q[(j) -  9]));                        \
        BMW_ADD_IF((j) -  8, bmw_s1(q[(j) -  8]));                        \
        BMW_ADD_IF((j) -  7, bmw_s2(q[(j) -  7]));                        \
        BMW_ADD_IF((j) -  6, bmw_s3(q[(j) -  6]));                        \
        BMW_ADD_IF((j) -  5, bmw_s0(q[(j) -  5]));                        \
        BMW_ADD_IF((j) -  4, bmw_s1(q[(j) -  4]));                        \
        BMW_ADD_IF((j) -  3, bmw_s2(q[(j) -  3]));                        \
        BMW_ADD_IF((j) -  2, bmw_s3(q[(j) -  2]));                        \
        BMW_ADD_IF((j) -  1, bmw_s0(q[(j) -  1]));                        \
        q[j] = v;                                                         \
    }

#define BMW_EXPAND2_JOB(j, add)                                           \
    {                                                                     \
        BLANE v = badd(bmw512_job(j), add);                               \
        BMW_ADD_IF((j) - 16, q[(j) - 16]);                                \
        BMW_ADD_IF((j) - 15, brotl(q[(j) - 15],  5u));                    \
        BMW_ADD_IF((j) - 14, q[(j) - 14]);                                \
        BMW_ADD_IF((j) - 13, brotl(q[(j) - 13], 11u));                    \
        BMW_ADD_IF((j) - 12, q[(j) - 12]);                                \
        BMW_ADD_IF((j) - 11, brotl(q[(j) - 11], 27u));                    \
        BMW_ADD_IF((j) - 10, q[(j) - 10]);                                \
        BMW_ADD_IF((j) -  9, brotl(q[(j) -  9], 32u));                    \
        BMW_ADD_IF((j) -  8, q[(j) -  8]);                                \
        BMW_ADD_IF((j) -  7, brotl(q[(j) -  7], 37u));                    \
        BMW_ADD_IF((j) -  6, q[(j) -  6]);                                \
        BMW_ADD_IF((j) -  5, brotl(q[(j) -  5], 43u));                    \
        BMW_ADD_IF((j) -  4, q[(j) -  4]);                                \
        BMW_ADD_IF((j) -  3, brotl(q[(j) -  3], 53u));                    \
        v = badd(v, bmw_s4(q[(j) - 2]));                                  \
        q[j] = badd(v, bmw_s5(q[(j) - 1]));                               \
    }

// The header's compression from the job's words: only what reads the nonce
// is computed here. h is the IV and m the padded block.
void bmw512_compress_header(inout BLANE h[16], BLANE m[16])
{
    // Written out: a loop here puts q[] in local memory on NVIDIA.
    BLANE q[32];
    q[ 0] = bmw512_job( 0u); q[ 1] = bmw512_job( 1u); q[ 2] = bmw512_job( 2u);
    q[ 3] = bmw512_job( 3u); q[ 4] = bmw512_job( 4u); q[ 5] = bmw512_job( 5u);
    q[ 6] = bmw512_job( 6u); q[ 7] = bmw512_job( 7u); q[ 8] = bmw512_job( 8u);
    q[ 9] = bmw512_job( 9u); q[10] = bmw512_job(10u); q[11] = bmw512_job(11u);
    q[12] = bmw512_job(12u); q[13] = bmw512_job(13u); q[14] = bmw512_job(14u);
    q[15] = bmw512_job(15u);

    // f0: these five words are W less x[9], which sums in with one sign.
    BLANE x9 = m[9] ^ h[9];
    q[ 2] = badd(bmw_s2(badd(q[ 2], x9)), h[ 3]);
    q[ 4] = badd(bmw_s4(badd(q[ 4], x9)), h[ 5]);
    q[11] = badd(bmw_s1(badd(q[11], x9)), h[12]);
    q[12] = badd(bmw_s2(bsub(q[12], x9)), h[13]);
    q[15] = badd(bmw_s0(bsub(q[15], x9)), h[ 0]);

    // AddElement 6, 9 and 15 read rotl(M[9], 10), also with one sign each.
    BLANE r9 = brotl(m[9], 10u);
    BLANE zero = blane(0u, 0u);

    BMW_EXPAND1_JOB(16); BMW_EXPAND1_JOB(17);
    BMW_EXPAND2_JOB(18, zero); BMW_EXPAND2_JOB(19, zero);
    BMW_EXPAND2_JOB(20, zero); BMW_EXPAND2_JOB(21, zero);
    BMW_EXPAND2_JOB(22, badd(bmw512_job(32u), r9) ^ h[13]);
    BMW_EXPAND2_JOB(23, zero); BMW_EXPAND2_JOB(24, zero);
    BMW_EXPAND2_JOB(25, badd(bmw512_job(33u), r9) ^ h[0]);
    BMW_EXPAND2_JOB(26, zero); BMW_EXPAND2_JOB(27, zero);
    BMW_EXPAND2_JOB(28, zero); BMW_EXPAND2_JOB(29, zero);
    BMW_EXPAND2_JOB(30, zero);
    BMW_EXPAND2_JOB(31, bsub(bmw512_job(34u), r9) ^ h[6]);

    bmw512_f2(h, q, m);
}

void bmw512_search(uint nonce)
{
    BLANE h[16];
    BLANE m[16];
    for (uint i = 0u; i < 16u; i++)
        h[i] = bmw512_iv(i);

    // Bytes 0..79, padding bit, length 640 bits. Nonce: high half of word 9.
    for (uint i = 0u; i < 9u; i++)
        m[i] = blane(push.header[2u * i], push.header[2u * i + 1u]);
    m[9] = blane(push.header[18], bswap32(nonce));
    m[10] = blane(0x80u, 0u);
    for (uint i = 11u; i < 15u; i++)
        m[i] = blane(0u, 0u);
    m[15] = blane(640u, 0u);

    bmw512_compress_header(h, m);
    bmw512_final(h);

    // Digest words 6 and 7 are BMW word 11.
    uint top = bhi(h[11]);
    uint next = blo(h[11]);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(top);

    // A prefix of the share test; the host compares all 256 bits.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && next > push.target[0])
        return;

    uint hash[8];
    for (uint i = 0u; i < 4u; i++) {
        hash[2u * i] = blo(h[8u + i]);
        hash[2u * i + 1u] = bhi(h[8u + i]);
    }

    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        bmw512_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_BMW512_KERNEL_GLSL_INCLUDED
