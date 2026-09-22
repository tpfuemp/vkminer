// lbry: one nonce per invocation. SHA-256d, SHA-512, two RIPEMD-160, SHA-256d.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The body of the kernel, included by lbry.comp and lbry32.comp. Everything
// touching a 64-bit word is written in terms of SLANE and never says which type
// that is, so the two modules are one text rather than two copies to keep in
// step. It is two modules and not one specialization constant because the
// int64 extension has to be declared to be used, and declaring it is what a
// device without the feature rejects. See shaders/common/sha512.glsl.
//
// ## The header is 112 bytes, not 80
//
// LBRY's block header is Bitcoin's plus a 32-byte claimtrie root: version(4) +
// prevhash(32) + merkleroot(32) + claimtrie(32) + time(4) + bits(4) +
// nonce(4). So the nonce is header word 27, landing in word 11 of the second
// SHA-256 block rather than word 3 of it.
//
// That is also why the midstate is not optional. Words 0..26 plus a 256-bit
// target plus three scalars is 152 bytes of push constants, against the 128
// Vulkan guarantees; compressing words 0..15 on the host leaves eight state
// words and eleven tail words, and the block below is 120 bytes. The
// nonce-independence that makes the midstate correct is what makes it fit.
//
// ## Byte order
//
// Every stage consumes the previous stage's digest bytes unchanged -- there is
// no swap between algorithms. The swaps below are there because SHA-2 reads and
// writes big-endian words and RIPEMD-160 little-endian ones, so the boundaries
// either side of the RIPEMD pair are the only places in this file that bswap32
// anything but the final digest. Header words need no swap at all: struct work
// already holds each as a big-endian read of the wire, which is what SHA-256's
// message schedule wants.

#ifndef VKMINER_ALGORITHMS_LBRY_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_LBRY_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha256.glsl"
#include "shaders/common/sha512.glsl"
#include "shaders/common/ripemd160.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// 120 bytes, against a guaranteed minimum of 128. Mirrored by LbryPush in
// lbry.cpp, which asserts its own size and offsets -- this block and that
// struct are one definition written in two languages.
layout(push_constant) uniform Push {
    uint midstate[8];  // SHA-256 state after header words 0..15
    uint tail[11];     // header words 16..26; word 27 is the nonce
    uint target[8];    // as fulltest() compares: little-endian, most significant last
    uint nonce_start;
    uint count;        // nonces to test, which is not the invocation count
    uint capacity;     // candidates the result buffer can hold
} push;

// SHA-256 of exactly 32 bytes from a fresh IV: one block, over half of it
// padding. Used twice here -- for the second of the opening pair and for the
// second of the closing pair -- and both times the input is a digest this
// kernel just produced, so the words go in as they are.
void lbry_sha256_32(inout uint state[8], uint message[8])
{
    uint w[16];
    for (int i = 0; i < 8; i++)
        w[i] = message[i];
    w[ 8] = 0x80000000u;   w[ 9] = 0u;
    w[10] = 0u;            w[11] = 0u;
    w[12] = 0u;            w[13] = 0u;
    w[14] = 0u;            w[15] = 0x100u;   // 256 bits

    for (int i = 0; i < 8; i++)
        state[i] = sha256_iv[i];

    sha256_compress(state, w);
}

// RIPEMD-160 of exactly 32 bytes, which is the only length lbry uses it at.
//
// `part` is four 64-bit words of the SHA-512 digest -- one half of it --
// big-endian-valued. This is the convention boundary: RIPEMD reads its message
// little-endian, so byte i of the digest becomes a different bit position, and
// the two 32-bit halves of each 64-bit word change places as well as being
// byte-reversed. Getting only the reversal and not the exchange is the
// plausible near-miss here, and it produces a digest that looks entirely
// reasonable.
void lbry_ripemd160_32(out uint h[5], SLANE part[4])
{
    uint x[16];
    for (int i = 0; i < 4; i++) {
        // The high half holds the earlier four bytes, so it supplies the
        // earlier -- lower-indexed -- RIPEMD message word.
        x[2 * i]     = bswap32(shi(part[i]));
        x[2 * i + 1] = bswap32(slo(part[i]));
    }

    // Little-endian padding for a 32-byte message: the terminator is the low
    // byte of word 8, and the bit count sits in word 14. SHA-2 would put a
    // 0x80000000 there and the length in word 15.
    x[ 8] = 0x00000080u;   x[ 9] = 0u;
    x[10] = 0u;            x[11] = 0u;
    x[12] = 0u;            x[13] = 0u;
    x[14] = 0x00000100u;   x[15] = 0u;       // 256 bits

    for (int i = 0; i < 5; i++)
        h[i] = ripemd160_iv[i];

    ripemd160_compress(h, x);
}

void main()
{
    uint index = gl_GlobalInvocationID.x;
    if (index >= push.count)
        return;

    uint nonce = push.nonce_start + index;

    // --- SHA-256, the header's second block -------------------------------
    //
    // The host compressed words 0..15 and sent the state. What is left is the
    // eleven remaining header words, the nonce, and the padding for a 112-byte
    // message: a 1 bit at byte 112 and 896 as the length.
    uint w[16];
    for (int i = 0; i < 11; i++)
        w[i] = push.tail[i];
    w[11] = nonce;
    w[12] = 0x80000000u;   w[13] = 0u;
    w[14] = 0u;            w[15] = 0x380u;   // 896 bits = 112 bytes

    uint state[8];
    for (int i = 0; i < 8; i++)
        state[i] = push.midstate[i];

    sha256_compress(state, w);

    // --- SHA-256 again, over those 32 bytes -------------------------------
    uint h1[8];
    lbry_sha256_32(h1, state);

    // --- SHA-512, over those 32 bytes -------------------------------------
    //
    // Two big-endian SHA-256 words pair into one big-endian SHA-512 word, high
    // half first. No swap: both sides of this boundary are big-endian.
    SLANE mw[16];
    for (int i = 0; i < 4; i++)
        mw[i] = slane(h1[2 * i + 1], h1[2 * i]);

    mw[4] = slane(0u, 0x80000000u);          // the 1 bit at byte 32
    for (int i = 5; i < 15; i++)
        mw[i] = slane(0u, 0u);
    mw[15] = slane(0x100u, 0u);              // 256 bits

    SLANE h2[8];
    for (int i = 0; i < 8; i++)
        h2[i] = sha512_iv(uint(i));

    sha512_compress(h2, mw);

    // --- two RIPEMD-160s, over the halves of that digest ------------------
    //
    // Independent of each other, and each of RIPEMD's own two lines is
    // independent of the other, so there are four ARX chains in flight here.
    // Low half first: lbry_hash() feeds hashA then &hashA[8], and the merged
    // CUDA kernel feeds r[0..3] then r[4..7].
    SLANE lo[4], hi[4];
    for (int i = 0; i < 4; i++) {
        lo[i] = h2[i];
        hi[i] = h2[i + 4];
    }

    uint ra[5], rb[5];
    lbry_ripemd160_32(ra, lo);
    lbry_ripemd160_32(rb, hi);

    // --- SHA-256d, over the two 20-byte digests concatenated --------------
    //
    // Forty bytes, not thirty-two: ten message words and the padding starts at
    // word 10. Back to big-endian, so every one of the ten is swapped.
    for (int i = 0; i < 5; i++) {
        w[i]     = bswap32(ra[i]);
        w[i + 5] = bswap32(rb[i]);
    }
    w[10] = 0x80000000u;   w[11] = 0u;
    w[12] = 0u;            w[13] = 0u;
    w[14] = 0u;            w[15] = 0x140u;   // 320 bits = 40 bytes

    for (int i = 0; i < 8; i++)
        state[i] = sha256_iv[i];

    sha256_compress(state, w);

    uint digest[8];
    lbry_sha256_32(digest, state);

    // The most significant word of the digest as the target is compared: the
    // state words are big-endian and fulltest() reads little-endian.
    uint top = bswap32(digest[7]);

    // The one line every nonce reaches with a finished digest word in hand,
    // which is what makes it the place to observe the search from rather than
    // the candidates it produces. Compiled away unless the pipeline was built
    // with the probe on; see candidates.glsl.
    probe_best(top);

    if (top > push.target[7])
        return;

    // The full 256-bit comparison, most significant word first. It repeats the
    // screen deliberately: the screen decides what to skip, this decides what
    // is a share. Narrowing it would cost the host's re-check of every
    // candidate its meaning.
    for (int i = 7; i >= 0; i--) {
        uint word = bswap32(digest[i]);
        if (word > push.target[i])
            return;
        if (word < push.target[i])
            break;
    }

    uint hash[8];
    for (int i = 0; i < 8; i++)
        hash[i] = bswap32(digest[i]);

    emit_candidate(push.capacity, nonce, hash);
}

#endif  // VKMINER_ALGORITHMS_LBRY_KERNEL_GLSL_INCLUDED
