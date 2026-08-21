// sha3t: one nonce per invocation, three SHA3-256 each.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The body of the kernel, included by sha3t.comp and sha3t32.comp. Everything
// here is written in terms of KLANE and never says which type that is, so the
// two modules are one text rather than two copies to keep in step.
//
// There is no midstate: an 80-byte header is one absorbed block, so the
// first permutation already depends on the nonce.
//
// The byte order is blake2s.comp's. SHA3 absorbs little-endian, so the host
// sends every header word byte-reversed and the nonce is reversed here, where
// it has to keep struct work's spelling. The digest needs no swap: SHA3
// squeezes little-endian, which is already the order the target is compared in.

#ifndef VKMINER_ALGORITHMS_SHA3T_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_SHA3T_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha3.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// 120 bytes, against a guaranteed minimum of 128. Mirrored by Sha3tPush in
// sha3t.cpp, which asserts its own size and offsets.
layout(push_constant) uniform Push {
    uint block[19];    // header words 0..18, already byte-reversed
    uint target[8];    // as fulltest() compares: little-endian, most significant last
    uint nonce_start;
    uint count;        // nonces to test, which is not the invocation count
    uint capacity;     // candidates the result buffer can hold
} push;

// SHA3-256 of exactly 32 bytes, which is what the second and third hashes take:
// four lanes of message in a fresh state, and two constants of padding.
void sha3_256_32(inout KLANE a[25])
{
    KLANE d0 = a[0];
    KLANE d1 = a[1];
    KLANE d2 = a[2];
    KLANE d3 = a[3];

    for (int i = 0; i < 25; i++)
        a[i] = klane(0u, 0u);

    a[0] = d0;
    a[1] = d1;
    a[2] = d2;
    a[3] = d3;

    // FIPS 202's domain separation and pad10*1: 0x06 at byte 32, 0x80 at 135.
    a[4] = klane(0x06u, 0u);
    a[SHA3_256_RATE_LANES - 1] = klane(0u, 0x80000000u);

    sha3_keccakf(a);
}

void main()
{
    uint index = gl_GlobalInvocationID.x;
    if (index >= push.count)
        return;

    uint nonce = push.nonce_start + index;

    KLANE a[25];
    for (int i = 0; i < 25; i++)
        a[i] = klane(0u, 0u);

    // Eighty bytes is ten lanes exactly, so the nonce is the high half of the
    // tenth and the padding starts on a lane boundary in the eleventh.
    for (int i = 0; i < 9; i++)
        a[i] = klane(push.block[2 * i], push.block[2 * i + 1]);
    a[9] = klane(push.block[18], bswap32(nonce));
    a[10] = klane(0x06u, 0u);
    a[SHA3_256_RATE_LANES - 1] = klane(0u, 0x80000000u);

    sha3_keccakf(a);
    sha3_256_32(a);
    sha3_256_32(a);

    // The most significant digest word: the high half of lane 3, because the
    // digest is the first four lanes squeezed little-endian.
    uint top = khi(a[3]);

    probe_best(top);

    if (top > push.target[7])
        return;

    uint state[8];
    for (int i = 0; i < 4; i++) {
        state[2 * i] = klo(a[i]);
        state[2 * i + 1] = khi(a[i]);
    }

    // The full 256-bit comparison, most significant word first. It repeats the
    // screen deliberately: the screen decides what to skip computing, this
    // decides what is a share.
    for (int i = 7; i >= 0; i--) {
        if (state[i] > push.target[i])
            return;
        if (state[i] < push.target[i])
            break;
    }

    emit_candidate(push.capacity, nonce, state);
}

#endif  // VKMINER_ALGORITHMS_SHA3T_KERNEL_GLSL_INCLUDED
