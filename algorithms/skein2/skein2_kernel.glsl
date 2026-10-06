// skein2: one nonce per invocation. Skein-512-512 of the header, then again.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by skein2.comp and skein2_32.comp; 64-bit words are TLANE, so never
// `+` one, use tadd().
//
// The host runs the first Skein block (header bytes 0..63, no nonce) and pushes
// the chaining value. Each nonce costs the header's second block and output
// block, then the second Skein's message block (64 bytes, first and final)
// and output block.
//
// Byte order: the tail words are little-endian reads of the wire, two to a
// Skein word, earlier one low. The digest is the first 32 output bytes, which
// are already the little-endian words the host compares.

#ifndef VKMINER_ALGORITHMS_SKEIN2_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_SKEIN2_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/skein512.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by Skein2Push in skein2.cpp, which asserts the layout.
layout(push_constant) uniform Push {
    uint midstate[16];  // the chaining value after bytes 0..63, low half first
    uint tail[3];       // header words 16..18, little-endian reads of the wire
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// The output block: an eight-byte zero counter, position 8, first and final.
void skein2_output(inout TLANE h[8])
{
    TLANE m[8];
    for (uint i = 0u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(8u, 0u),
                 tlane(0u, kSkeinT1Out | kSkeinT1First | kSkeinT1Final));
}

void skein2_search(uint nonce)
{
    TLANE h[8];
    TLANE m[8];
    for (uint i = 0u; i < 8u; i++)
        h[i] = tlane(push.midstate[2u * i], push.midstate[2u * i + 1u]);

    // First Skein, message block 2: bytes 64..79 and zeros, position 80,
    // final. The nonce is the high half of word 1.
    m[0] = tlane(push.tail[0], push.tail[1]);
    m[1] = tlane(push.tail[2], bswap32(nonce));
    for (uint i = 2u; i < 8u; i++)
        m[i] = tlane(0u, 0u);
    skein512_ubi(h, m, tlane(80u, 0u),
                 tlane(0u, kSkeinT1Msg | kSkeinT1Final));
    skein2_output(h);

    // Second Skein over those 64 bytes: one message block, first and final.
    for (uint i = 0u; i < 8u; i++) {
        m[i] = h[i];
        h[i] = skein512_512_iv(i);
    }
    skein512_ubi(h, m, tlane(64u, 0u),
                 tlane(0u, kSkeinT1Msg | kSkeinT1First | kSkeinT1Final));
    skein2_output(h);

    // Digest words 6 and 7 are Skein word 3.
    uint top = thi(h[3]);
    uint next = tlo(h[3]);

    // Compiled away unless the pipeline was built with the probe on.
    probe_best(top);

    // A prefix of the share test; the host compares all 256 bits.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && next > push.target[0])
        return;

    uint hash[8];
    for (uint i = 0u; i < 4u; i++) {
        hash[2u * i] = tlo(h[i]);
        hash[2u * i + 1u] = thi(h[i]);
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
        skein2_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_SKEIN2_KERNEL_GLSL_INCLUDED
