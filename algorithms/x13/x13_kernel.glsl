// x13: x11's eleven stages un-truncated, then Hamsi-512 and Fugue-512, cut
// to 32 bytes; two nonces per pass.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by x13.comp and x13_32.comp; never `+` a lane. The first eleven
// stages, push block and two-nonce search are x11_kernel.glsl's, which calls
// x13_tail() in place of its own tail.

#ifndef VKMINER_ALGORITHMS_X13_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_X13_KERNEL_GLSL_INCLUDED

#define VKMINER_X11_TAIL x13_tail

#include "algorithms/x11/x11_kernel.glsl"
#include "shaders/common/fugue512.glsl"
#include "shaders/common/hamsi512.glsl"

// x11_echo(s) with round 0 folded: the chaining value and the padding half of
// the block are constants, so only message words 8..11 go through AES there,
// as in x11_echo_screen. All sixteen output words are kept for Hamsi.
void x13_echo(inout uint s[16])
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

    echo512_subwords_pair(w, cnt, 0u, 8u, 9u);
    echo512_subwords_pair(w, cnt, 0u, 10u, 11u);
    echo512_shift_mix(w);
    for (uint r = 1u; r < 10u; r++)
        echo512_round(w, cnt, r);

    // The feed-forward; the chaining value is 512 in lane 0 of each word.
    for (uint k = 0u; k < 16u; k++)
        s[k] = ((k & 3u) == 0u ? 512u : 0u) ^ m[k] ^ w[k] ^ w[32u + k];
}

// Hamsi-512 of 64 bytes: eight message blocks, the 0x80 block, then the bit
// count 512 under the final rounds. The loop shifts the message down so every
// index is a constant.
void x13_hamsi(inout uint s[16])
{
    uint h[16] = kHamsi512Iv;
    uint w[16] = s;
    uint m[16];
    for (uint b = 0u; b < 8u; b++) {
        hamsi512_expand(w[0], w[1], m);
        hamsi512_compress(h, m, false);
        for (uint k = 0u; k < 14u; k++)
            w[k] = w[k + 2u];
    }
    hamsi512_expand(0x80u, 0u, m);
    hamsi512_compress(h, m, false);
    hamsi512_expand(0u, 0x00020000u, m);
    hamsi512_compress(h, m, true);

    for (uint k = 0u; k < 16u; k++)
        s[k] = bswap32(h[k]);
}

// Fugue-512 of 64 bytes: sixteen words and the 64-bit bit count, three words
// a pass; a pass rotates the state by exactly 36 columns.
void x13_fugue(inout uint s[16])
{
    uint f[36];
    for (uint k = 0u; k < 20u; k++)
        f[k] = 0u;
    for (uint k = 0u; k < 16u; k++)
        f[20u + k] = kFugue512Iv[k];

    uint m[18];
    for (uint k = 0u; k < 16u; k++)
        m[k] = bswap32(s[k]);
    m[16] = 0u;
    m[17] = 512u;

    for (uint p = 0u; p < 6u; p++) {
        fugue512_word(f, m[0]);
        fugue512_word(f, m[1]);
        fugue512_word(f, m[2]);
        for (uint k = 0u; k < 15u; k++)
            m[k] = m[k + 3u];
    }
    fugue512_final(f);

    s[0] = f[1];   s[1] = f[2];   s[2] = f[3];   s[3] = f[4];
    s[4] = f[9];   s[5] = f[10];  s[6] = f[11];  s[7] = f[12];
    s[8] = f[18];  s[9] = f[19];  s[10] = f[20]; s[11] = f[21];
    s[12] = f[27]; s[13] = f[28]; s[14] = f[29]; s[15] = f[30];
    for (uint k = 0u; k < 16u; k++)
        s[k] = bswap32(s[k]);
}

// Stages 4 to 13 for one nonce, then the screen.
void x13_tail(inout uint s[16], uint nonce)
{
    x11_skein(s);
    x11_jh(s);
    x11_keccak(s);
    x11_luffa(s);
    x11_cubehash(s);
    x11_shavite(s);
    x11_simd(s);
    x13_echo(s);
    x13_hamsi(s);
    x13_fugue(s);

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
    aes_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    fugue512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
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

#endif  // VKMINER_ALGORITHMS_X13_KERNEL_GLSL_INCLUDED
