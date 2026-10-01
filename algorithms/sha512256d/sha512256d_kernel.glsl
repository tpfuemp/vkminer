// sha512256d: one nonce per invocation. SHA-512/256 of the header, then again.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Included by sha512256d.comp and sha512256d32.comp. 64-bit words are SLANE,
// so one text serves both lane types; never `+` an SLANE, use sadd().
//
// Each nonce is two compressions: the 80-byte header (one padded block), then
// the 32-byte digest of it.
//
// The nonce is the low half of message word 9, so rounds 0..8 of the first
// compression, most of round 9 and a dozen schedule sums are the same for every
// nonce of the job. They do not fit in the push block beside the header, so
// each workgroup computes them once into shared memory and every invocation
// starts from round 10.
//
// Byte order: header words are big-endian reads of the wire, so two of them
// form one SHA-512 word, earlier one high. The digest's 64-bit words are split
// high half first and byte-reversed into the little-endian words the host
// compares.

#ifndef VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/sha512.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by Sha512256dPush in sha512256d.cpp, which asserts the
// layout.
layout(push_constant) uniform Push {
    uint header[19];    // header words 0..18; word 19 is the nonce
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// A round's t1 = h + S1(e) + Ch(e, f, g) + K + W. Left to right lets the
// compiler fold K into a three-input add, which is faster on some GPUs and
// slower on others, so the order is a module's choice and the tuner races them.
#ifdef SHA512256D_T1_LEFT_TO_RIGHT
#define S5D_T1(h, e, f, g, k, w)                                          \
    sadd(sadd(sadd(sadd(h, sha512_big_s1(e)), sha512_ch(e, f, g)), k), w)
#else
#define S5D_T1(h, e, f, g, k, w)                                          \
    sadd(sadd(sadd(h, sha512_big_s1(e)), sadd(sha512_ch(e, f, g), k)), w)
#endif

// One SHA-512 round. The caller rotates the names instead of shuffling values.
#define S5D_STEP(a, b, c, d, e, f, g, h, k, w)                           \
    {                                                                     \
        SLANE t1 = S5D_T1(h, e, f, g, k, w);                              \
        SLANE t2 = sadd(sha512_big_s0(a), sha512_maj(a, b, c));           \
        (d) = sadd(d, t1);                                                \
        (h) = sadd(t1, t2);                                               \
    }

// One message-schedule slot, expanded in place over a named sixteen-word
// window: w[i-16] += s0(w[i-15]) + w[i-7] + s1(w[i-2]).
#define S5D_SCHED(wa, wb, wi, wn)                                         \
    {                                                                     \
        (wa) = sadd(sadd(wa, sha512_small_s0(wb)),                        \
                    sadd(wi, sha512_small_s1(wn)));                       \
    }

// Rounds i..i+15 straight off the message.
#define S5D_ROUNDS16(i)                                                           \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  0u), w0);          \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  1u), w1);          \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) +  2u), w2);          \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) +  3u), w3);          \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) +  4u), w4);          \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) +  5u), w5);          \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) +  6u), w6);          \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) +  7u), w7);          \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  8u), w8);          \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  9u), w9);          \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) + 10u), w10);         \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) + 11u), w11);         \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) + 12u), w12);         \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) + 13u), w13);         \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) + 14u), w14);         \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) + 15u), w15)

// Rounds i..i+15 for i >= 16, each preceded by the schedule word it reads.
#define S5D_ROUNDS16_SCHED(i)                                                     \
    S5D_SCHED(w0, w1, w9, w14);                                                   \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  0u), w0);          \
    S5D_SCHED(w1, w2, w10, w15);                                                  \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  1u), w1);          \
    S5D_SCHED(w2, w3, w11, w0);                                                   \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) +  2u), w2);          \
    S5D_SCHED(w3, w4, w12, w1);                                                   \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) +  3u), w3);          \
    S5D_SCHED(w4, w5, w13, w2);                                                   \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) +  4u), w4);          \
    S5D_SCHED(w5, w6, w14, w3);                                                   \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) +  5u), w5);          \
    S5D_SCHED(w6, w7, w15, w4);                                                   \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) +  6u), w6);          \
    S5D_SCHED(w7, w8, w0, w5);                                                    \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) +  7u), w7);          \
    S5D_SCHED(w8, w9, w1, w6);                                                    \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k((i) +  8u), w8);          \
    S5D_SCHED(w9, w10, w2, w7);                                                   \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k((i) +  9u), w9);          \
    S5D_SCHED(w10, w11, w3, w8);                                                  \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k((i) + 10u), w10);         \
    S5D_SCHED(w11, w12, w4, w9);                                                  \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k((i) + 11u), w11);         \
    S5D_SCHED(w12, w13, w5, w10);                                                 \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k((i) + 12u), w12);         \
    S5D_SCHED(w13, w14, w6, w11);                                                 \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k((i) + 13u), w13);         \
    S5D_SCHED(w14, w15, w7, w12);                                                 \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k((i) + 14u), w14);         \
    S5D_SCHED(w15, w0, w8, w13);                                                  \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k((i) + 15u), w15)

// Rounds 32..47 where three of the s0 terms are the job's: words 17, 19 and 21
// do not depend on the nonce, so neither does s0 of them.
#define S5D_SCHED_S0(wa, s0b, wi, wn)                                     \
    {                                                                     \
        (wa) = sadd(sadd(wa, s0b), sadd(wi, sha512_small_s1(wn)));        \
    }

#define S5D_ROUNDS32_SCHED()                                                      \
    S5D_SCHED_S0(w0, s_pre[kPreS0W17], w9, w14);                                  \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(32u), w0);                \
    S5D_SCHED(w1, w2, w10, w15);                                                  \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(33u), w1);                \
    S5D_SCHED_S0(w2, s_pre[kPreS0W19], w11, w0);                                  \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(34u), w2);                \
    S5D_SCHED(w3, w4, w12, w1);                                                   \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(35u), w3);                \
    S5D_SCHED_S0(w4, s_pre[kPreS0W21], w13, w2);                                  \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(36u), w4);                \
    S5D_SCHED(w5, w6, w14, w3);                                                   \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(37u), w5);                \
    S5D_SCHED(w6, w7, w15, w4);                                                   \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(38u), w6);                \
    S5D_SCHED(w7, w8, w0, w5);                                                    \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(39u), w7);                \
    S5D_SCHED(w8, w9, w1, w6);                                                    \
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(40u), w8);                \
    S5D_SCHED(w9, w10, w2, w7);                                                   \
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(41u), w9);                \
    S5D_SCHED(w10, w11, w3, w8);                                                  \
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(42u), w10);               \
    S5D_SCHED(w11, w12, w4, w9);                                                  \
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(43u), w11);               \
    S5D_SCHED(w12, w13, w5, w10);                                                 \
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(44u), w12);               \
    S5D_SCHED(w13, w14, w6, w11);                                                 \
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(45u), w13);               \
    S5D_SCHED(w14, w15, w7, w12);                                                 \
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(46u), w14);               \
    S5D_SCHED(w15, w0, w8, w13);                                                  \
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(47u), w15)

// ------------------------------------------------------------ the job's part
//
// What every nonce of the job shares, written by two invocations of the
// workgroup before the barrier in main() and read by all of them after it.
//
// The state after round 9, with word 9 still to be added to the two names that
// take it (v2 and v6 at that point). Then the schedule: W17, W19 and W21 are
// whole; for W16, W18, W20, W22, W23 and W24 it is the sum of every term that
// is not the nonce's, which is all but one or two. Words 10..15 are padding and
// the compiler has them already.
const uint kPreState  = 0u;    // 8 words, v0..v7
const uint kPreW16    = 8u;    // W0 + s0(W1)                    (+ W9)
const uint kPreW17    = 9u;    // W17
const uint kPreW18    = 10u;   // W2 + s0(W3)                    (+ s1(W16))
const uint kPreW19    = 11u;   // W19
const uint kPreW20    = 12u;   // W4 + s0(W5)                    (+ s1(W18))
const uint kPreW21    = 13u;   // W21
const uint kPreW22    = 14u;   // W6 + s0(W7) + W15              (+ s1(W20))
const uint kPreW23    = 15u;   // W7 + s0(W8) + s1(W21)          (+ W16)
const uint kPreW24    = 16u;   // W8 + W17                       (+ s1(W22) + s0(W9))
const uint kPreS0W17  = 17u;   // s0(W17), for W32
const uint kPreS0W19  = 18u;   // s0(W19), for W34
const uint kPreS0W21  = 19u;   // s0(W21), for W36
const uint kPreWords  = 20u;

shared SLANE s_pre[kPreWords];

// Message word i of the first block, for i < 9.
SLANE sha512256d_header_word(uint i)
{
    return slane(push.header[2u * i + 1u], push.header[2u * i]);
}

// Rounds 0..8, and round 9 without its message word. Serial, so it runs in one
// invocation while another does the schedule.
void sha512256d_prehash_state()
{
    SLANE w0 = sha512256d_header_word(0u), w1 = sha512256d_header_word(1u);
    SLANE w2 = sha512256d_header_word(2u), w3 = sha512256d_header_word(3u);
    SLANE w4 = sha512256d_header_word(4u), w5 = sha512256d_header_word(5u);
    SLANE w6 = sha512256d_header_word(6u), w7 = sha512256d_header_word(7u);
    SLANE w8 = sha512256d_header_word(8u);

    SLANE v0 = sha512_256_iv(0u), v1 = sha512_256_iv(1u);
    SLANE v2 = sha512_256_iv(2u), v3 = sha512_256_iv(3u);
    SLANE v4 = sha512_256_iv(4u), v5 = sha512_256_iv(5u);
    SLANE v6 = sha512_256_iv(6u), v7 = sha512_256_iv(7u);

    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(0u), w0);
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(1u), w1);
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(2u), w2);
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(3u), w3);
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(4u), w4);
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(5u), w5);
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(6u), w6);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(7u), w7);
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(8u), w8);

    // Round 9 is S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, k9, w9): both
    // halves of t1 but w9, and all of t2.
    SLANE t1 = sadd(sadd(v6, sha512_big_s1(v3)),
                    sadd(sha512_ch(v3, v4, v5), sha512_k(9u)));
    SLANE t2 = sadd(sha512_big_s0(v7), sha512_maj(v7, v0, v1));

    s_pre[kPreState + 0u] = v0;
    s_pre[kPreState + 1u] = v1;
    s_pre[kPreState + 2u] = sadd(v2, t1);
    s_pre[kPreState + 3u] = v3;
    s_pre[kPreState + 4u] = v4;
    s_pre[kPreState + 5u] = v5;
    s_pre[kPreState + 6u] = sadd(t1, t2);
    s_pre[kPreState + 7u] = v7;
}

// The schedule sums, W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16] with
// every term that is a header or padding word taken here. W11..W14 are zero.
void sha512256d_prehash_schedule()
{
    SLANE w0 = sha512256d_header_word(0u), w1 = sha512256d_header_word(1u);
    SLANE w2 = sha512256d_header_word(2u), w3 = sha512256d_header_word(3u);
    SLANE w4 = sha512256d_header_word(4u), w5 = sha512256d_header_word(5u);
    SLANE w6 = sha512256d_header_word(6u), w7 = sha512256d_header_word(7u);
    SLANE w8 = sha512256d_header_word(8u);
    SLANE w10 = slane(0u, 0x80000000u);
    SLANE w15 = slane(0x280u, 0u);

    SLANE w17 = sadd(sadd(w1, sha512_small_s0(w2)),
                     sadd(w10, sha512_small_s1(w15)));
    SLANE w19 = sadd(sadd(w3, sha512_small_s0(w4)), sha512_small_s1(w17));
    SLANE w21 = sadd(sadd(w5, sha512_small_s0(w6)), sha512_small_s1(w19));

    s_pre[kPreW16] = sadd(w0, sha512_small_s0(w1));
    s_pre[kPreW17] = w17;
    s_pre[kPreW18] = sadd(w2, sha512_small_s0(w3));
    s_pre[kPreW19] = w19;
    s_pre[kPreW20] = sadd(w4, sha512_small_s0(w5));
    s_pre[kPreW21] = w21;
    s_pre[kPreW22] = sadd(sadd(w6, sha512_small_s0(w7)), w15);
    s_pre[kPreW23] = sadd(sadd(w7, sha512_small_s0(w8)), sha512_small_s1(w21));
    s_pre[kPreW24] = sadd(w8, w17);
    s_pre[kPreS0W17] = sha512_small_s0(w17);
    s_pre[kPreS0W19] = sha512_small_s0(w19);
    s_pre[kPreS0W21] = sha512_small_s0(w21);
}

// The first compression from round 10, `w9` being the nonce's word, with full
// feed-forward.
void sha512256d_first(out SLANE state[8], SLANE w9)
{
    SLANE v0 = s_pre[kPreState + 0u], v1 = s_pre[kPreState + 1u];
    SLANE v2 = sadd(s_pre[kPreState + 2u], w9), v3 = s_pre[kPreState + 3u];
    SLANE v4 = s_pre[kPreState + 4u], v5 = s_pre[kPreState + 5u];
    SLANE v6 = sadd(s_pre[kPreState + 6u], w9), v7 = s_pre[kPreState + 7u];

    SLANE w0, w1, w2, w3, w4, w5, w6, w7, w8;
    SLANE w10 = slane(0u, 0x80000000u);
    SLANE w11 = slane(0u, 0u), w12 = slane(0u, 0u);
    SLANE w13 = slane(0u, 0u), w14 = slane(0u, 0u);
    SLANE w15 = slane(0x280u, 0u);               // 640 bits = 80 bytes

    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(10u), w10);
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(11u), w11);
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(12u), w12);
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(13u), w13);
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(14u), w14);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(15u), w15);

    // W16..W24 from the job's sums; from W25 on, every term is in the window.
    w0 = sadd(s_pre[kPreW16], w9);
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(16u), w0);
    w1 = s_pre[kPreW17];
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(17u), w1);
    w2 = sadd(s_pre[kPreW18], sha512_small_s1(w0));
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(18u), w2);
    w3 = s_pre[kPreW19];
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(19u), w3);
    w4 = sadd(s_pre[kPreW20], sha512_small_s1(w2));
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(20u), w4);
    w5 = s_pre[kPreW21];
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(21u), w5);
    w6 = sadd(s_pre[kPreW22], sha512_small_s1(w4));
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(22u), w6);
    w7 = sadd(s_pre[kPreW23], w0);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(23u), w7);
    w8 = sadd(sadd(s_pre[kPreW24], sha512_small_s1(w6)), sha512_small_s0(w9));
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(24u), w8);
    S5D_SCHED(w9, w10, w2, w7);
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(25u), w9);
    S5D_SCHED(w10, w11, w3, w8);
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(26u), w10);
    S5D_SCHED(w11, w12, w4, w9);
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(27u), w11);
    S5D_SCHED(w12, w13, w5, w10);
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(28u), w12);
    S5D_SCHED(w13, w14, w6, w11);
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(29u), w13);
    S5D_SCHED(w14, w15, w7, w12);
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(30u), w14);
    S5D_SCHED(w15, w0, w8, w13);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(31u), w15);

    S5D_ROUNDS32_SCHED();
    S5D_ROUNDS16_SCHED(48u);
    S5D_ROUNDS16_SCHED(64u);

    state[0] = sadd(sha512_256_iv(0u), v0);
    state[1] = sadd(sha512_256_iv(1u), v1);
    state[2] = sadd(sha512_256_iv(2u), v2);
    state[3] = sadd(sha512_256_iv(3u), v3);
    state[4] = sadd(sha512_256_iv(4u), v4);
    state[5] = sadd(sha512_256_iv(5u), v5);
    state[6] = sadd(sha512_256_iv(6u), v6);
    state[7] = sadd(sha512_256_iv(7u), v7);
}

// ---------------------------------------------------------------- the nonce's

void sha512256d_search(uint nonce)
{
    // First pass: the job's part is in s_pre, and word 9 is nBits high and the
    // nonce low.
    SLANE state[8];
    sha512256d_first(state, slane(nonce, push.header[18]));

    // Second pass, from the IV: the first four state words, padded for a
    // 256-bit length.
    SLANE w0 = state[0], w1 = state[1], w2 = state[2], w3 = state[3];
    SLANE w4 = slane(0u, 0x80000000u);
    SLANE w5 = slane(0u, 0u), w6 = slane(0u, 0u), w7 = slane(0u, 0u);
    SLANE w8 = slane(0u, 0u), w9 = slane(0u, 0u), w10 = slane(0u, 0u);
    SLANE w11 = slane(0u, 0u), w12 = slane(0u, 0u), w13 = slane(0u, 0u);
    SLANE w14 = slane(0u, 0u);
    SLANE w15 = slane(0x100u, 0u);               // 256 bits

    SLANE v0 = sha512_256_iv(0u), v1 = sha512_256_iv(1u);
    SLANE v2 = sha512_256_iv(2u), v3 = sha512_256_iv(3u);
    SLANE v4 = sha512_256_iv(4u), v5 = sha512_256_iv(5u);
    SLANE v6 = sha512_256_iv(6u), v7 = sha512_256_iv(7u);

    S5D_ROUNDS16(0u);
    S5D_ROUNDS16_SCHED(16u);
    S5D_ROUNDS16_SCHED(32u);
    S5D_ROUNDS16_SCHED(48u);

    // Rounds 64..75, the first twelve of S5D_ROUNDS16_SCHED(64u).
    S5D_SCHED(w0, w1, w9, w14);
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(64u), w0);
    S5D_SCHED(w1, w2, w10, w15);
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(65u), w1);
    S5D_SCHED(w2, w3, w11, w0);
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(66u), w2);
    S5D_SCHED(w3, w4, w12, w1);
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(67u), w3);
    S5D_SCHED(w4, w5, w13, w2);
    S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, sha512_k(68u), w4);
    S5D_SCHED(w5, w6, w14, w3);
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(69u), w5);
    S5D_SCHED(w6, w7, w15, w4);
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(70u), w6);
    S5D_SCHED(w7, w8, w0, w5);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(71u), w7);
    S5D_SCHED(w8, w9, w1, w6);
    S5D_STEP(v0, v1, v2, v3, v4, v5, v6, v7, sha512_k(72u), w8);
    S5D_SCHED(w9, w10, w2, w7);
    S5D_STEP(v7, v0, v1, v2, v3, v4, v5, v6, sha512_k(73u), w9);
    S5D_SCHED(w10, w11, w3, w8);
    S5D_STEP(v6, v7, v0, v1, v2, v3, v4, v5, sha512_k(74u), w10);
    S5D_SCHED(w11, w12, w4, w9);
    S5D_STEP(v5, v6, v7, v0, v1, v2, v3, v4, sha512_k(75u), w11);

    // Round 76 is S5D_STEP(v4, v5, v6, v7, v0, v1, v2, v3, k76, w12), and the
    // `a` it writes is the digest's word 3 once rounds 77..79 have shifted it
    // down to `d`. That word is the screen, so neither the rest of round 76 nor
    // the three after it is needed to decide a nonce.
    S5D_SCHED(w12, w13, w5, w10);
    SLANE t1 = S5D_T1(v3, v0, v1, v2, sha512_k(76u), w12);
    SLANE t2 = sadd(sha512_big_s0(v4), sha512_maj(v4, v5, v6));
    SLANE d3 = sadd(sha512_256_iv(3u), sadd(t1, t2));

    // The most significant 64 bits of the digest: word 3, as two little-endian
    // words.
    uint top = bswap32(slo(d3));
    uint next = bswap32(shi(d3));

    // Compiled away unless the pipeline was built with the probe on; see
    // candidates.glsl.
    probe_best(top);

    // A prefix of the share test; the host compares all 256 bits.
    if (top > push.target[1])
        return;
    if (top == push.target[1] && next > push.target[0])
        return;

    // Reached about as often as a candidate is found, so the rest of the
    // compression costs nothing here.
    v7 = sadd(v7, t1);
    v3 = sadd(t1, t2);
    S5D_SCHED(w13, w14, w6, w11);
    S5D_STEP(v3, v4, v5, v6, v7, v0, v1, v2, sha512_k(77u), w13);
    S5D_SCHED(w14, w15, w7, w12);
    S5D_STEP(v2, v3, v4, v5, v6, v7, v0, v1, sha512_k(78u), w14);
    S5D_SCHED(w15, w0, w8, w13);
    S5D_STEP(v1, v2, v3, v4, v5, v6, v7, v0, sha512_k(79u), w15);

    // Ten whole turns, so v0..v7 hold a..h in that order again.
    state[0] = sadd(sha512_256_iv(0u), v0);
    state[1] = sadd(sha512_256_iv(1u), v1);
    state[2] = sadd(sha512_256_iv(2u), v2);
    state[3] = sadd(sha512_256_iv(3u), v3);

    uint hash[8];
    for (int i = 0; i < 4; i++) {
        hash[2 * i]     = bswap32(shi(state[i]));
        hash[2 * i + 1] = bswap32(slo(state[i]));
    }

    emit_candidate(push.capacity, nonce, hash);
}

void main()
{
    // The first and last invocations, so that the two halves run in different
    // subgroups wherever the workgroup has two. Every invocation reaches the
    // barrier: the ones past the end of the dispatch return after it.
    if (gl_LocalInvocationIndex == 0u)
        sha512256d_prehash_state();
    if (gl_LocalInvocationIndex == gl_WorkGroupSize.x - 1u)
        sha512256d_prehash_schedule();
    barrier();

    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k++) {
        uint index = first + k;
        if (index >= push.count)
            return;
        sha512256d_search(push.nonce_start + index);
    }
}

#endif  // VKMINER_ALGORITHMS_SHA512256D_KERNEL_GLSL_INCLUDED
