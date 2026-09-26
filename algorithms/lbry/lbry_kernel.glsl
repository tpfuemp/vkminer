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

// How many consecutive nonces one invocation searches. The backend sets it and
// sizes the dispatch to match, and only for a module that declares it.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// Exactly the guaranteed minimum of 128 bytes. Mirrored by
// LbryPush in lbry.cpp, which asserts its own size and offsets -- this block
// and that struct are one definition written in two languages.
layout(push_constant) uniform Push {
    uint midstate[8];   // SHA-256 state after header words 0..15
    uint midbuffer[8];  // and after twelve rounds of the block that follows
    uint sched[10];     // that block's w[16..25], five of them short a term
    uint tail10;        // header word 26, which is w[10] and is read again
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// One SHA-256 round, FIPS 180-4 sec. 6.2.2. The working variables rotate
// through the argument list instead of being shuffled at the end of the round.
// A plain block, not `do { } while (false)`, which would be an OpLoopMerge.
#define LBRY_SHA256_ROUND(a, b, c, d, e, f, g, h, k, w)                    \
    {                                                                      \
        uint t1 = (h) + sha256_big_s1(e) + sha256_ch(e, f, g) + (k) + (w); \
        uint t2 = sha256_big_s0(a) + sha256_maj(a, b, c);                  \
        (d) += t1;                                                         \
        (h)  = t1 + t2;                                                    \
    }

// Half a turn, then the other half from where it left the names.
#define LBRY_SHA256_ROUND4(i)                                             \
    LBRY_SHA256_ROUND(a, b, c, d, e, f, g, h, sha256_k[(i) + 0], w[(i) + 0]); \
    LBRY_SHA256_ROUND(h, a, b, c, d, e, f, g, sha256_k[(i) + 1], w[(i) + 1]); \
    LBRY_SHA256_ROUND(g, h, a, b, c, d, e, f, sha256_k[(i) + 2], w[(i) + 2]); \
    LBRY_SHA256_ROUND(f, g, h, a, b, c, d, e, sha256_k[(i) + 3], w[(i) + 3])

#define LBRY_SHA256_ROUND4_SHIFTED(i)                                     \
    LBRY_SHA256_ROUND(e, f, g, h, a, b, c, d, sha256_k[(i) + 0], w[(i) + 0]); \
    LBRY_SHA256_ROUND(d, e, f, g, h, a, b, c, sha256_k[(i) + 1], w[(i) + 1]); \
    LBRY_SHA256_ROUND(c, d, e, f, g, h, a, b, sha256_k[(i) + 2], w[(i) + 2]); \
    LBRY_SHA256_ROUND(b, c, d, e, f, g, h, a, sha256_k[(i) + 3], w[(i) + 3])

#define LBRY_SHA256_ROUND8(i)                                             \
    LBRY_SHA256_ROUND4(i); LBRY_SHA256_ROUND4_SHIFTED((i) + 4)

// The same whole turn entered half a turn out, for the compression that
// resumes at round 12.
#define LBRY_SHA256_ROUND8_SHIFTED(i)                                     \
    LBRY_SHA256_ROUND4_SHIFTED(i); LBRY_SHA256_ROUND4((i) + 4)

// w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]), indexed over all
// sixty-four words so the compiler can fold the words that come from padding.
#define LBRY_SHA256_SCHED(i)                                               \
    w[i] = w[(i) - 16] + sha256_small_s0(w[(i) - 15])                      \
         + w[(i) -  7] + sha256_small_s1(w[(i) -  2])

#define LBRY_SHA256_SCHED4(i)                                              \
    LBRY_SHA256_SCHED((i) + 0); LBRY_SHA256_SCHED((i) + 1);                \
    LBRY_SHA256_SCHED((i) + 2); LBRY_SHA256_SCHED((i) + 3)

#define LBRY_SHA256_SCHED8(i)                                              \
    LBRY_SHA256_SCHED4(i); LBRY_SHA256_SCHED4((i) + 4)

// The last SHA-256 of the chain, split where the target comparison can be
// decided: rounds and schedule up to there run for every nonce.
#define LBRY_SHA256_SCHED_TO61                                             \
    LBRY_SHA256_SCHED8(16); LBRY_SHA256_SCHED8(24);                        \
    LBRY_SHA256_SCHED8(32); LBRY_SHA256_SCHED8(40);                        \
    LBRY_SHA256_SCHED8(48); LBRY_SHA256_SCHED4(56);                        \
    LBRY_SHA256_SCHED(60); LBRY_SHA256_SCHED(61)

#define LBRY_SHA256_SCHED_62_63                                            \
    LBRY_SHA256_SCHED(62); LBRY_SHA256_SCHED(63)

#define LBRY_SHA256_ROUNDS_TO59                                            \
    LBRY_SHA256_ROUND8( 0); LBRY_SHA256_ROUND8( 8);                        \
    LBRY_SHA256_ROUND8(16); LBRY_SHA256_ROUND8(24);                        \
    LBRY_SHA256_ROUND8(32); LBRY_SHA256_ROUND8(40);                        \
    LBRY_SHA256_ROUND8(48); LBRY_SHA256_ROUND4(56)

#define LBRY_SHA256_ROUNDS_60_63  LBRY_SHA256_ROUND4_SHIFTED(60)

// Compress one block, all sixty-four rounds written out. `message` is read
// only at constant indices, so each caller's padding words fold.
void lbry_sha256_block(inout uint state[8], uint message[16])
{
    uint w[64];
    w[ 0] = message[ 0];   w[ 1] = message[ 1];
    w[ 2] = message[ 2];   w[ 3] = message[ 3];
    w[ 4] = message[ 4];   w[ 5] = message[ 5];
    w[ 6] = message[ 6];   w[ 7] = message[ 7];
    w[ 8] = message[ 8];   w[ 9] = message[ 9];
    w[10] = message[10];   w[11] = message[11];
    w[12] = message[12];   w[13] = message[13];
    w[14] = message[14];   w[15] = message[15];

    LBRY_SHA256_SCHED8(16); LBRY_SHA256_SCHED8(24);
    LBRY_SHA256_SCHED8(32); LBRY_SHA256_SCHED8(40);
    LBRY_SHA256_SCHED8(48); LBRY_SHA256_SCHED8(56);

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    LBRY_SHA256_ROUND8( 0); LBRY_SHA256_ROUND8( 8);
    LBRY_SHA256_ROUND8(16); LBRY_SHA256_ROUND8(24);
    LBRY_SHA256_ROUND8(32); LBRY_SHA256_ROUND8(40);
    LBRY_SHA256_ROUND8(48); LBRY_SHA256_ROUND8(56);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// SHA-256 of exactly 32 bytes from a fresh IV: one block, over half of it
// padding. Used twice here -- for the second of the opening pair and for the
// second of the closing pair -- and both times the input is a digest this
// kernel just produced, so the words go in as they are.
void lbry_sha256_32(out uint state[8], uint message[8])
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

    lbry_sha256_block(state, w);
}

// One RIPEMD-160 step, for the unrolled form below. The five names rotate
// through the roles, and eighty steps bring them back to where they started.
// The round functions and the IV are ripemd160.glsl's.
#define LBRY_RMD_STEP(a, b, c, d, e, f, x, k, s)      \
    {                                                 \
        (a) = rotl32((a) + (f) + (x) + (k), s) + (e); \
        (c) = rotl32((c), 10u);                       \
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

    uint la = ripemd160_iv[0], lb = ripemd160_iv[1], lc = ripemd160_iv[2],
         ld = ripemd160_iv[3], le = ripemd160_iv[4];
    uint ra = ripemd160_iv[0], rb = ripemd160_iv[1], rc = ripemd160_iv[2],
         rd = ripemd160_iv[3], re = ripemd160_iv[4];

    // The left line, one row per step in the specification's order.
    // round 0, f0, k = 0x00000000u
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f0(lb, lc, ld), x[ 0], 0x00000000u, 11u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f0(la, lb, lc), x[ 1], 0x00000000u, 14u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f0(le, la, lb), x[ 2], 0x00000000u, 15u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f0(ld, le, la), x[ 3], 0x00000000u, 12u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f0(lc, ld, le), x[ 4], 0x00000000u,  5u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f0(lb, lc, ld), x[ 5], 0x00000000u,  8u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f0(la, lb, lc), x[ 6], 0x00000000u,  7u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f0(le, la, lb), x[ 7], 0x00000000u,  9u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f0(ld, le, la), x[ 8], 0x00000000u, 11u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f0(lc, ld, le), x[ 9], 0x00000000u, 13u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f0(lb, lc, ld), x[10], 0x00000000u, 14u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f0(la, lb, lc), x[11], 0x00000000u, 15u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f0(le, la, lb), x[12], 0x00000000u,  6u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f0(ld, le, la), x[13], 0x00000000u,  7u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f0(lc, ld, le), x[14], 0x00000000u,  9u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f0(lb, lc, ld), x[15], 0x00000000u,  8u);

    // round 1, f1, k = 0x5a827999u
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f1(la, lb, lc), x[ 7], 0x5a827999u,  7u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f1(le, la, lb), x[ 4], 0x5a827999u,  6u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f1(ld, le, la), x[13], 0x5a827999u,  8u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f1(lc, ld, le), x[ 1], 0x5a827999u, 13u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f1(lb, lc, ld), x[10], 0x5a827999u, 11u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f1(la, lb, lc), x[ 6], 0x5a827999u,  9u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f1(le, la, lb), x[15], 0x5a827999u,  7u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f1(ld, le, la), x[ 3], 0x5a827999u, 15u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f1(lc, ld, le), x[12], 0x5a827999u,  7u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f1(lb, lc, ld), x[ 0], 0x5a827999u, 12u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f1(la, lb, lc), x[ 9], 0x5a827999u, 15u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f1(le, la, lb), x[ 5], 0x5a827999u,  9u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f1(ld, le, la), x[ 2], 0x5a827999u, 11u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f1(lc, ld, le), x[14], 0x5a827999u,  7u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f1(lb, lc, ld), x[11], 0x5a827999u, 13u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f1(la, lb, lc), x[ 8], 0x5a827999u, 12u);

    // round 2, f2, k = 0x6ed9eba1u
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f2(le, la, lb), x[ 3], 0x6ed9eba1u, 11u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f2(ld, le, la), x[10], 0x6ed9eba1u, 13u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f2(lc, ld, le), x[14], 0x6ed9eba1u,  6u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f2(lb, lc, ld), x[ 4], 0x6ed9eba1u,  7u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f2(la, lb, lc), x[ 9], 0x6ed9eba1u, 14u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f2(le, la, lb), x[15], 0x6ed9eba1u,  9u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f2(ld, le, la), x[ 8], 0x6ed9eba1u, 13u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f2(lc, ld, le), x[ 1], 0x6ed9eba1u, 15u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f2(lb, lc, ld), x[ 2], 0x6ed9eba1u, 14u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f2(la, lb, lc), x[ 7], 0x6ed9eba1u,  8u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f2(le, la, lb), x[ 0], 0x6ed9eba1u, 13u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f2(ld, le, la), x[ 6], 0x6ed9eba1u,  6u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f2(lc, ld, le), x[13], 0x6ed9eba1u,  5u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f2(lb, lc, ld), x[11], 0x6ed9eba1u, 12u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f2(la, lb, lc), x[ 5], 0x6ed9eba1u,  7u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f2(le, la, lb), x[12], 0x6ed9eba1u,  5u);

    // round 3, f3, k = 0x8f1bbcdcu
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f3(ld, le, la), x[ 1], 0x8f1bbcdcu, 11u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f3(lc, ld, le), x[ 9], 0x8f1bbcdcu, 12u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f3(lb, lc, ld), x[11], 0x8f1bbcdcu, 14u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f3(la, lb, lc), x[10], 0x8f1bbcdcu, 15u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f3(le, la, lb), x[ 0], 0x8f1bbcdcu, 14u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f3(ld, le, la), x[ 8], 0x8f1bbcdcu, 15u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f3(lc, ld, le), x[12], 0x8f1bbcdcu,  9u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f3(lb, lc, ld), x[ 4], 0x8f1bbcdcu,  8u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f3(la, lb, lc), x[13], 0x8f1bbcdcu,  9u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f3(le, la, lb), x[ 3], 0x8f1bbcdcu, 14u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f3(ld, le, la), x[ 7], 0x8f1bbcdcu,  5u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f3(lc, ld, le), x[15], 0x8f1bbcdcu,  6u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f3(lb, lc, ld), x[14], 0x8f1bbcdcu,  8u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f3(la, lb, lc), x[ 5], 0x8f1bbcdcu,  6u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f3(le, la, lb), x[ 6], 0x8f1bbcdcu,  5u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f3(ld, le, la), x[ 2], 0x8f1bbcdcu, 12u);

    // round 4, f4, k = 0xa953fd4eu
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f4(lc, ld, le), x[ 4], 0xa953fd4eu,  9u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f4(lb, lc, ld), x[ 0], 0xa953fd4eu, 15u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f4(la, lb, lc), x[ 5], 0xa953fd4eu,  5u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f4(le, la, lb), x[ 9], 0xa953fd4eu, 11u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f4(ld, le, la), x[ 7], 0xa953fd4eu,  6u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f4(lc, ld, le), x[12], 0xa953fd4eu,  8u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f4(lb, lc, ld), x[ 2], 0xa953fd4eu, 13u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f4(la, lb, lc), x[10], 0xa953fd4eu, 12u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f4(le, la, lb), x[14], 0xa953fd4eu,  5u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f4(ld, le, la), x[ 1], 0xa953fd4eu, 12u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f4(lc, ld, le), x[ 3], 0xa953fd4eu, 13u);
    LBRY_RMD_STEP(la, lb, lc, ld, le, ripemd160_f4(lb, lc, ld), x[ 8], 0xa953fd4eu, 14u);
    LBRY_RMD_STEP(le, la, lb, lc, ld, ripemd160_f4(la, lb, lc), x[11], 0xa953fd4eu, 11u);
    LBRY_RMD_STEP(ld, le, la, lb, lc, ripemd160_f4(le, la, lb), x[ 6], 0xa953fd4eu,  8u);
    LBRY_RMD_STEP(lc, ld, le, la, lb, ripemd160_f4(ld, le, la), x[15], 0xa953fd4eu,  5u);
    LBRY_RMD_STEP(lb, lc, ld, le, la, ripemd160_f4(lc, ld, le), x[13], 0xa953fd4eu,  6u);

    // The right line: its own message order, rotates and constants, and the
    // round functions in reverse order.
    // round 0, f4, k = 0x50a28be6u
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f4(rb, rc, rd), x[ 5], 0x50a28be6u,  8u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f4(ra, rb, rc), x[14], 0x50a28be6u,  9u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f4(re, ra, rb), x[ 7], 0x50a28be6u,  9u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f4(rd, re, ra), x[ 0], 0x50a28be6u, 11u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f4(rc, rd, re), x[ 9], 0x50a28be6u, 13u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f4(rb, rc, rd), x[ 2], 0x50a28be6u, 15u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f4(ra, rb, rc), x[11], 0x50a28be6u, 15u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f4(re, ra, rb), x[ 4], 0x50a28be6u,  5u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f4(rd, re, ra), x[13], 0x50a28be6u,  7u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f4(rc, rd, re), x[ 6], 0x50a28be6u,  7u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f4(rb, rc, rd), x[15], 0x50a28be6u,  8u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f4(ra, rb, rc), x[ 8], 0x50a28be6u, 11u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f4(re, ra, rb), x[ 1], 0x50a28be6u, 14u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f4(rd, re, ra), x[10], 0x50a28be6u, 14u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f4(rc, rd, re), x[ 3], 0x50a28be6u, 12u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f4(rb, rc, rd), x[12], 0x50a28be6u,  6u);

    // round 1, f3, k = 0x5c4dd124u
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f3(ra, rb, rc), x[ 6], 0x5c4dd124u,  9u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f3(re, ra, rb), x[11], 0x5c4dd124u, 13u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f3(rd, re, ra), x[ 3], 0x5c4dd124u, 15u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f3(rc, rd, re), x[ 7], 0x5c4dd124u,  7u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f3(rb, rc, rd), x[ 0], 0x5c4dd124u, 12u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f3(ra, rb, rc), x[13], 0x5c4dd124u,  8u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f3(re, ra, rb), x[ 5], 0x5c4dd124u,  9u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f3(rd, re, ra), x[10], 0x5c4dd124u, 11u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f3(rc, rd, re), x[14], 0x5c4dd124u,  7u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f3(rb, rc, rd), x[15], 0x5c4dd124u,  7u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f3(ra, rb, rc), x[ 8], 0x5c4dd124u, 12u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f3(re, ra, rb), x[12], 0x5c4dd124u,  7u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f3(rd, re, ra), x[ 4], 0x5c4dd124u,  6u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f3(rc, rd, re), x[ 9], 0x5c4dd124u, 15u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f3(rb, rc, rd), x[ 1], 0x5c4dd124u, 13u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f3(ra, rb, rc), x[ 2], 0x5c4dd124u, 11u);

    // round 2, f2, k = 0x6d703ef3u
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f2(re, ra, rb), x[15], 0x6d703ef3u,  9u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f2(rd, re, ra), x[ 5], 0x6d703ef3u,  7u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f2(rc, rd, re), x[ 1], 0x6d703ef3u, 15u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f2(rb, rc, rd), x[ 3], 0x6d703ef3u, 11u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f2(ra, rb, rc), x[ 7], 0x6d703ef3u,  8u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f2(re, ra, rb), x[14], 0x6d703ef3u,  6u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f2(rd, re, ra), x[ 6], 0x6d703ef3u,  6u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f2(rc, rd, re), x[ 9], 0x6d703ef3u, 14u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f2(rb, rc, rd), x[11], 0x6d703ef3u, 12u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f2(ra, rb, rc), x[ 8], 0x6d703ef3u, 13u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f2(re, ra, rb), x[12], 0x6d703ef3u,  5u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f2(rd, re, ra), x[ 2], 0x6d703ef3u, 14u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f2(rc, rd, re), x[10], 0x6d703ef3u, 13u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f2(rb, rc, rd), x[ 0], 0x6d703ef3u, 13u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f2(ra, rb, rc), x[ 4], 0x6d703ef3u,  7u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f2(re, ra, rb), x[13], 0x6d703ef3u,  5u);

    // round 3, f1, k = 0x7a6d76e9u
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f1(rd, re, ra), x[ 8], 0x7a6d76e9u, 15u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f1(rc, rd, re), x[ 6], 0x7a6d76e9u,  5u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f1(rb, rc, rd), x[ 4], 0x7a6d76e9u,  8u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f1(ra, rb, rc), x[ 1], 0x7a6d76e9u, 11u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f1(re, ra, rb), x[ 3], 0x7a6d76e9u, 14u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f1(rd, re, ra), x[11], 0x7a6d76e9u, 14u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f1(rc, rd, re), x[15], 0x7a6d76e9u,  6u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f1(rb, rc, rd), x[ 0], 0x7a6d76e9u, 14u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f1(ra, rb, rc), x[ 5], 0x7a6d76e9u,  6u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f1(re, ra, rb), x[12], 0x7a6d76e9u,  9u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f1(rd, re, ra), x[ 2], 0x7a6d76e9u, 12u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f1(rc, rd, re), x[13], 0x7a6d76e9u,  9u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f1(rb, rc, rd), x[ 9], 0x7a6d76e9u, 12u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f1(ra, rb, rc), x[ 7], 0x7a6d76e9u,  5u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f1(re, ra, rb), x[10], 0x7a6d76e9u, 15u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f1(rd, re, ra), x[14], 0x7a6d76e9u,  8u);

    // round 4, f0, k = 0x00000000u
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f0(rc, rd, re), x[12], 0x00000000u,  8u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f0(rb, rc, rd), x[15], 0x00000000u,  5u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f0(ra, rb, rc), x[10], 0x00000000u, 12u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f0(re, ra, rb), x[ 4], 0x00000000u,  9u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f0(rd, re, ra), x[ 1], 0x00000000u, 12u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f0(rc, rd, re), x[ 5], 0x00000000u,  5u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f0(rb, rc, rd), x[ 8], 0x00000000u, 14u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f0(ra, rb, rc), x[ 7], 0x00000000u,  6u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f0(re, ra, rb), x[ 6], 0x00000000u,  8u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f0(rd, re, ra), x[ 2], 0x00000000u, 13u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f0(rc, rd, re), x[13], 0x00000000u,  6u);
    LBRY_RMD_STEP(ra, rb, rc, rd, re, ripemd160_f0(rb, rc, rd), x[14], 0x00000000u,  5u);
    LBRY_RMD_STEP(re, ra, rb, rc, rd, ripemd160_f0(ra, rb, rc), x[ 0], 0x00000000u, 15u);
    LBRY_RMD_STEP(rd, re, ra, rb, rc, ripemd160_f0(re, ra, rb), x[ 3], 0x00000000u, 13u);
    LBRY_RMD_STEP(rc, rd, re, ra, rb, ripemd160_f0(rd, re, ra), x[ 9], 0x00000000u, 11u);
    LBRY_RMD_STEP(rb, rc, rd, re, ra, ripemd160_f0(rc, rd, re), x[11], 0x00000000u, 11u);

    // Rotated by one position and crossing the lines -- not h[i] += l[i] + r[i].
    // Writing it that way is the classic RIPEMD bug and it still produces a
    // digest that looks entirely reasonable.
    h[0] = ripemd160_iv[1] + lc + rd;
    h[1] = ripemd160_iv[2] + ld + re;
    h[2] = ripemd160_iv[3] + le + ra;
    h[3] = ripemd160_iv[4] + la + rb;
    h[4] = ripemd160_iv[0] + lb + rc;
}

// One SHA-512 round, rotating names like the RIPEMD step above. The round
// functions, the IV and the constants are sha512.glsl's.
#define LBRY_SHA512_STEP(a, b, c, d, e, f, g, h, k, w)                    \
    {                                                                     \
        SLANE t1 = sadd(sadd(sadd(h, sha512_big_s1(e)),                   \
                             sadd(sha512_ch(e, f, g), k)),                \
                        w);                                               \
        SLANE t2 = sadd(sha512_big_s0(a), sha512_maj(a, b, c));           \
        (d) = sadd(d, t1);                                                \
        (h) = sadd(t1, t2);                                               \
    }

// One message-schedule slot, expanded in place over a named sixteen-word
// window: w[i-16] += s0(w[i-15]) + w[i-7] + s1(w[i-2]).
#define LBRY_SHA512_SCHED(wa, wb, wi, wn)                                 \
    {                                                                     \
        (wa) = sadd(sadd(wa, sha512_small_s0(wb)),                        \
                    sadd(wi, sha512_small_s1(wn)));                       \
    }

// SHA-512 of exactly 32 bytes from a fresh IV: one block, eighty rounds,
// written out so the constant padding words and IV fold.
//
// `message` is the eight big-endian SHA-256 words of the previous digest.
// Two of them pair into one big-endian SHA-512 word, high half first. No
// swap: both sides of this boundary are big-endian.
void lbry_sha512_32(out SLANE state[8], uint message[8])
{
    SLANE w0  = slane(message[1], message[0]);
    SLANE w1  = slane(message[3], message[2]);
    SLANE w2  = slane(message[5], message[4]);
    SLANE w3  = slane(message[7], message[6]);

    SLANE w4  = slane(0u, 0x80000000u);       // the 1 bit at byte 32
    SLANE w5  = slane(0u, 0u);
    SLANE w6  = slane(0u, 0u);
    SLANE w7  = slane(0u, 0u);
    SLANE w8  = slane(0u, 0u);
    SLANE w9  = slane(0u, 0u);
    SLANE w10 = slane(0u, 0u);
    SLANE w11 = slane(0u, 0u);
    SLANE w12 = slane(0u, 0u);
    SLANE w13 = slane(0u, 0u);
    SLANE w14 = slane(0u, 0u);
    SLANE w15 = slane(0x100u, 0u);           // 256 bits

    SLANE v0 = sha512_iv(0u);
    SLANE v1 = sha512_iv(1u);
    SLANE v2 = sha512_iv(2u);
    SLANE v3 = sha512_iv(3u);
    SLANE v4 = sha512_iv(4u);
    SLANE v5 = sha512_iv(5u);
    SLANE v6 = sha512_iv(6u);
    SLANE v7 = sha512_iv(7u);

    // rounds 0-15
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k( 0u), w0);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k( 1u), w1);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k( 2u), w2);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k( 3u), w3);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k( 4u), w4);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k( 5u), w5);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k( 6u), w6);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k( 7u), w7);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k( 8u), w8);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k( 9u), w9);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(10u), w10);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(11u), w11);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(12u), w12);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(13u), w13);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(14u), w14);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(15u), w15);

    // rounds 16-31
    LBRY_SHA512_SCHED(w0, w1, w9, w14);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(16u), w0);
    LBRY_SHA512_SCHED(w1, w2, w10, w15);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(17u), w1);
    LBRY_SHA512_SCHED(w2, w3, w11, w0);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(18u), w2);
    LBRY_SHA512_SCHED(w3, w4, w12, w1);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(19u), w3);
    LBRY_SHA512_SCHED(w4, w5, w13, w2);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(20u), w4);
    LBRY_SHA512_SCHED(w5, w6, w14, w3);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(21u), w5);
    LBRY_SHA512_SCHED(w6, w7, w15, w4);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(22u), w6);
    LBRY_SHA512_SCHED(w7, w8, w0, w5);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(23u), w7);
    LBRY_SHA512_SCHED(w8, w9, w1, w6);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(24u), w8);
    LBRY_SHA512_SCHED(w9, w10, w2, w7);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(25u), w9);
    LBRY_SHA512_SCHED(w10, w11, w3, w8);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(26u), w10);
    LBRY_SHA512_SCHED(w11, w12, w4, w9);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(27u), w11);
    LBRY_SHA512_SCHED(w12, w13, w5, w10);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(28u), w12);
    LBRY_SHA512_SCHED(w13, w14, w6, w11);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(29u), w13);
    LBRY_SHA512_SCHED(w14, w15, w7, w12);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(30u), w14);
    LBRY_SHA512_SCHED(w15, w0, w8, w13);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(31u), w15);

    // rounds 32-47
    LBRY_SHA512_SCHED(w0, w1, w9, w14);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(32u), w0);
    LBRY_SHA512_SCHED(w1, w2, w10, w15);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(33u), w1);
    LBRY_SHA512_SCHED(w2, w3, w11, w0);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(34u), w2);
    LBRY_SHA512_SCHED(w3, w4, w12, w1);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(35u), w3);
    LBRY_SHA512_SCHED(w4, w5, w13, w2);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(36u), w4);
    LBRY_SHA512_SCHED(w5, w6, w14, w3);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(37u), w5);
    LBRY_SHA512_SCHED(w6, w7, w15, w4);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(38u), w6);
    LBRY_SHA512_SCHED(w7, w8, w0, w5);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(39u), w7);
    LBRY_SHA512_SCHED(w8, w9, w1, w6);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(40u), w8);
    LBRY_SHA512_SCHED(w9, w10, w2, w7);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(41u), w9);
    LBRY_SHA512_SCHED(w10, w11, w3, w8);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(42u), w10);
    LBRY_SHA512_SCHED(w11, w12, w4, w9);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(43u), w11);
    LBRY_SHA512_SCHED(w12, w13, w5, w10);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(44u), w12);
    LBRY_SHA512_SCHED(w13, w14, w6, w11);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(45u), w13);
    LBRY_SHA512_SCHED(w14, w15, w7, w12);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(46u), w14);
    LBRY_SHA512_SCHED(w15, w0, w8, w13);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(47u), w15);

    // rounds 48-63
    LBRY_SHA512_SCHED(w0, w1, w9, w14);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(48u), w0);
    LBRY_SHA512_SCHED(w1, w2, w10, w15);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(49u), w1);
    LBRY_SHA512_SCHED(w2, w3, w11, w0);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(50u), w2);
    LBRY_SHA512_SCHED(w3, w4, w12, w1);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(51u), w3);
    LBRY_SHA512_SCHED(w4, w5, w13, w2);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(52u), w4);
    LBRY_SHA512_SCHED(w5, w6, w14, w3);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(53u), w5);
    LBRY_SHA512_SCHED(w6, w7, w15, w4);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(54u), w6);
    LBRY_SHA512_SCHED(w7, w8, w0, w5);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(55u), w7);
    LBRY_SHA512_SCHED(w8, w9, w1, w6);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(56u), w8);
    LBRY_SHA512_SCHED(w9, w10, w2, w7);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(57u), w9);
    LBRY_SHA512_SCHED(w10, w11, w3, w8);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(58u), w10);
    LBRY_SHA512_SCHED(w11, w12, w4, w9);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(59u), w11);
    LBRY_SHA512_SCHED(w12, w13, w5, w10);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(60u), w12);
    LBRY_SHA512_SCHED(w13, w14, w6, w11);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(61u), w13);
    LBRY_SHA512_SCHED(w14, w15, w7, w12);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(62u), w14);
    LBRY_SHA512_SCHED(w15, w0, w8, w13);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(63u), w15);

    // rounds 64-79
    LBRY_SHA512_SCHED(w0, w1, w9, w14);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(64u), w0);
    LBRY_SHA512_SCHED(w1, w2, w10, w15);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(65u), w1);
    LBRY_SHA512_SCHED(w2, w3, w11, w0);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(66u), w2);
    LBRY_SHA512_SCHED(w3, w4, w12, w1);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(67u), w3);
    LBRY_SHA512_SCHED(w4, w5, w13, w2);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(68u), w4);
    LBRY_SHA512_SCHED(w5, w6, w14, w3);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(69u), w5);
    LBRY_SHA512_SCHED(w6, w7, w15, w4);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(70u), w6);
    LBRY_SHA512_SCHED(w7, w8, w0, w5);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(71u), w7);
    LBRY_SHA512_SCHED(w8, w9, w1, w6);
    LBRY_SHA512_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(72u), w8);
    LBRY_SHA512_SCHED(w9, w10, w2, w7);
    LBRY_SHA512_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(73u), w9);
    LBRY_SHA512_SCHED(w10, w11, w3, w8);
    LBRY_SHA512_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(74u), w10);
    LBRY_SHA512_SCHED(w11, w12, w4, w9);
    LBRY_SHA512_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(75u), w11);
    LBRY_SHA512_SCHED(w12, w13, w5, w10);
    LBRY_SHA512_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(76u), w12);
    LBRY_SHA512_SCHED(w13, w14, w6, w11);
    LBRY_SHA512_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(77u), w13);
    LBRY_SHA512_SCHED(w14, w15, w7, w12);
    LBRY_SHA512_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(78u), w14);
    LBRY_SHA512_SCHED(w15, w0, w8, w13);
    LBRY_SHA512_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(79u), w15);

    // Ten whole turns, so v0..v7 hold a..h in that order again.
    state[0] = sadd(sha512_iv(0u), v0);
    state[1] = sadd(sha512_iv(1u), v1);
    state[2] = sadd(sha512_iv(2u), v2);
    state[3] = sadd(sha512_iv(3u), v3);
    state[4] = sadd(sha512_iv(4u), v4);
    state[5] = sadd(sha512_iv(5u), v5);
    state[6] = sadd(sha512_iv(6u), v6);
    state[7] = sadd(sha512_iv(7u), v7);
}

// One nonce, from the header's second SHA-256 block to the candidate buffer.
// The early returns below end this nonce, not the invocation.
void lbry_search(uint nonce)
{
    // --- SHA-256, the header's second block, resumed at round 12 ----------
    //
    // The host ran twelve rounds and ten schedule words of this block with the
    // nonce left out. Here the nonce goes back in and the remaining fifty-two
    // rounds run. w[0..9] are never read again; w[10] is, by w[26].
    uint w[64];
    w[10] = push.tail10;
    w[11] = nonce;
    w[12] = 0x80000000u;   w[13] = 0u;
    w[14] = 0u;            w[15] = 0x380u;   // 896 bits = 112 bytes

    w[16] = push.sched[0];   w[17] = push.sched[1];
    w[18] = push.sched[2];   w[19] = push.sched[3];
    w[20] = push.sched[4];   w[21] = push.sched[5];
    w[22] = push.sched[6];   w[23] = push.sched[7];
    w[24] = push.sched[8];   w[25] = push.sched[9];

    // Five of those ten are short one term: the nonce (w[11]) reaches w[18]
    // and w[25] directly, and w[20], w[22], w[24] through sigma1 of the word
    // two back.
    w[18] += nonce;
    w[20] += sha256_small_s1(w[18]);
    w[22] += sha256_small_s1(w[20]);
    w[24] += sha256_small_s1(w[22]);
    w[25] += w[18];

    LBRY_SHA256_SCHED(26); LBRY_SHA256_SCHED(27);
    LBRY_SHA256_SCHED4(28);
    LBRY_SHA256_SCHED8(32); LBRY_SHA256_SCHED8(40);
    LBRY_SHA256_SCHED8(48); LBRY_SHA256_SCHED8(56);

    // The nonce enters round 11 through t1 alone, which lands in two variables.
    uint a = push.midbuffer[0] + nonce, b = push.midbuffer[1],
         c = push.midbuffer[2],         d = push.midbuffer[3];
    uint e = push.midbuffer[4] + nonce, f = push.midbuffer[5],
         g = push.midbuffer[6],         h = push.midbuffer[7];

    LBRY_SHA256_ROUND4(12);
    LBRY_SHA256_ROUND8_SHIFTED(16); LBRY_SHA256_ROUND8_SHIFTED(24);
    LBRY_SHA256_ROUND8_SHIFTED(32); LBRY_SHA256_ROUND8_SHIFTED(40);
    LBRY_SHA256_ROUND8_SHIFTED(48); LBRY_SHA256_ROUND8_SHIFTED(56);

    // Fifty-two rounds leave the names half a turn out: feed forward from e.
    uint state[8];
    state[0] = push.midstate[0] + e;   state[1] = push.midstate[1] + f;
    state[2] = push.midstate[2] + g;   state[3] = push.midstate[3] + h;
    state[4] = push.midstate[4] + a;   state[5] = push.midstate[5] + b;
    state[6] = push.midstate[6] + c;   state[7] = push.midstate[7] + d;

    // --- SHA-256 again, over those 32 bytes -------------------------------
    uint h1[8];
    lbry_sha256_32(h1, state);

    // --- SHA-512, over those 32 bytes -------------------------------------
    SLANE h2[8];
    lbry_sha512_32(h2, h1);

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
    uint m[16];
    for (int i = 0; i < 5; i++) {
        m[i]     = bswap32(ra[i]);
        m[i + 5] = bswap32(rb[i]);
    }
    m[10] = 0x80000000u;   m[11] = 0u;
    m[12] = 0u;            m[13] = 0u;
    m[14] = 0u;            m[15] = 0x140u;   // 320 bits = 40 bytes

    for (int i = 0; i < 8; i++)
        state[i] = sha256_iv[i];

    lbry_sha256_block(state, m);

    // --- and the second of that pair, stopped at the screen ---------------
    //
    // Inlined rather than lbry_sha256_32(), because the screen needs only two
    // output words and neither needs the whole compression.
    w[0] = state[0];       w[1] = state[1];
    w[2] = state[2];       w[3] = state[3];
    w[4] = state[4];       w[5] = state[5];
    w[6] = state[6];       w[7] = state[7];
    w[ 8] = 0x80000000u;   w[ 9] = 0u;
    w[10] = 0u;            w[11] = 0u;
    w[12] = 0u;            w[13] = 0u;
    w[14] = 0u;            w[15] = 0x100u;   // 256 bits

    LBRY_SHA256_SCHED_TO61;

    a = sha256_iv[0];  b = sha256_iv[1];  c = sha256_iv[2];  d = sha256_iv[3];
    e = sha256_iv[4];  f = sha256_iv[5];  g = sha256_iv[6];  h = sha256_iv[7];

    LBRY_SHA256_ROUNDS_TO59;

    // Digest words 7 and 6 are final after the t1 of rounds 60 and 61; rounds
    // 62 and 63 do not write them.
    uint t60 = d + sha256_big_s1(a) + sha256_ch(a, b, c) + sha256_k[60] + w[60];
    uint h60 = h + t60;
    uint t61 = c + sha256_big_s1(h60) + sha256_ch(h60, a, b)
             + sha256_k[61] + w[61];

    // The most significant word of the digest as the target is compared: the
    // state words are big-endian and fulltest() reads little-endian.
    uint top = bswap32(sha256_iv[7] + h60);

    // The one line every nonce reaches with a finished digest word in hand,
    // which is what makes it the place to observe the search from rather than
    // the candidates it produces. Compiled away unless the pipeline was built
    // with the probe on; see candidates.glsl.
    probe_best(top);

    // The top 64 bits of the target: a prefix of the share test, so it keeps
    // every share. The host compares all 256 bits before submitting.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && bswap32(sha256_iv[6] + g + t61) > push.target[0])
        return;

    // Reached about as often as a candidate is found, so recomputing rounds 60
    // and 61 here costs nothing measurable.
    LBRY_SHA256_SCHED_62_63;
    LBRY_SHA256_ROUNDS_60_63;

    uint digest[8] = uint[8](
        sha256_iv[0] + a, sha256_iv[1] + b, sha256_iv[2] + c, sha256_iv[3] + d,
        sha256_iv[4] + e, sha256_iv[5] + f, sha256_iv[6] + g, sha256_iv[7] + h);

    uint hash[8];
    for (int i = 0; i < 8; i++)
        hash[i] = bswap32(digest[i]);

    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        lbry_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_LBRY_KERNEL_GLSL_INCLUDED
