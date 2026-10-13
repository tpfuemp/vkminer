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

    bmw512_compress(h, m);
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
