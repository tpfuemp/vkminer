// myr-gr: SHA-256 of Groestl-512 of the header, two nonces per pass.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The bitsliced Groestl half and the push block are groestl_kernel.glsl's.
// Each lane's 64-byte digest is unsliced and hashed big-endian; the SHA-256
// state is byte-reversed into the words the host compares.

#ifndef VKMINER_ALGORITHMS_MYRGR_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_MYRGR_KERNEL_GLSL_INCLUDED

#define VKMINER_GROESTL_NO_MAIN 1

#include "algorithms/groestl/groestl_kernel.glsl"
#include "shaders/common/sha256.glsl"

// One SHA-256 round; the working variables rotate through the argument list.
#define MYRGR_SHA256_ROUND(a, b, c, d, e, f, g, h, k, w)                    \
    {                                                                      \
        uint t1 = (h) + sha256_big_s1(e) + sha256_ch(e, f, g) + (k) + (w); \
        uint t2 = sha256_big_s0(a) + sha256_maj(a, b, c);                  \
        (d) += t1;                                                         \
        (h)  = t1 + t2;                                                    \
    }

#define MYRGR_SHA256_ROUND8(i)                                                 \
    MYRGR_SHA256_ROUND(a, b, c, d, e, f, g, h, sha256_k[(i) + 0], w[(i) + 0]); \
    MYRGR_SHA256_ROUND(h, a, b, c, d, e, f, g, sha256_k[(i) + 1], w[(i) + 1]); \
    MYRGR_SHA256_ROUND(g, h, a, b, c, d, e, f, sha256_k[(i) + 2], w[(i) + 2]); \
    MYRGR_SHA256_ROUND(f, g, h, a, b, c, d, e, sha256_k[(i) + 3], w[(i) + 3]); \
    MYRGR_SHA256_ROUND(e, f, g, h, a, b, c, d, sha256_k[(i) + 4], w[(i) + 4]); \
    MYRGR_SHA256_ROUND(d, e, f, g, h, a, b, c, sha256_k[(i) + 5], w[(i) + 5]); \
    MYRGR_SHA256_ROUND(c, d, e, f, g, h, a, b, sha256_k[(i) + 6], w[(i) + 6]); \
    MYRGR_SHA256_ROUND(b, c, d, e, f, g, h, a, sha256_k[(i) + 7], w[(i) + 7])

// w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]).
#define MYRGR_SHA256_SCHED(i)                                              \
    w[i] = w[(i) - 16] + sha256_small_s0(w[(i) - 15])                      \
         + w[(i) -  7] + sha256_small_s1(w[(i) -  2])

#define MYRGR_SHA256_SCHED8(i)                                             \
    MYRGR_SHA256_SCHED((i) + 0); MYRGR_SHA256_SCHED((i) + 1);              \
    MYRGR_SHA256_SCHED((i) + 2); MYRGR_SHA256_SCHED((i) + 3);              \
    MYRGR_SHA256_SCHED((i) + 4); MYRGR_SHA256_SCHED((i) + 5);              \
    MYRGR_SHA256_SCHED((i) + 6); MYRGR_SHA256_SCHED((i) + 7)

// One compression, unrolled so `w` is only indexed by constants.
void myrgr_sha256_block(inout uint state[8], inout uint w[64])
{
    MYRGR_SHA256_SCHED8(16); MYRGR_SHA256_SCHED8(24);
    MYRGR_SHA256_SCHED8(32); MYRGR_SHA256_SCHED8(40);
    MYRGR_SHA256_SCHED8(48); MYRGR_SHA256_SCHED8(56);

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    MYRGR_SHA256_ROUND8( 0); MYRGR_SHA256_ROUND8( 8);
    MYRGR_SHA256_ROUND8(16); MYRGR_SHA256_ROUND8(24);
    MYRGR_SHA256_ROUND8(32); MYRGR_SHA256_ROUND8(40);
    MYRGR_SHA256_ROUND8(48); MYRGR_SHA256_ROUND8(56);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// Nonces n and n + 1; `two` false hashes the second lane and drops it.
void myrgr_search(uint n, bool two)
{
    uint s[64];
    groestl_load80(s, bswap32(n), bswap32(n + 1u));
    groestl_hash(s);

    // Back to bytes as in groestl_search(), but all of columns 8..15.
    uint rows[64];
    for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        for (uint b = 0u; b < 8u; b++)
            d[b] = s[8u * i + b];
        groestl_transpose(d);
        for (uint k = 0u; k < 8u; k++)
            rows[8u * i + k] = d[k];
    }
    for (uint h = 0u; h < 2u; h++) {
        if (h == 1u && !two)
            break;

        uint w[64];
        for (uint i = 0u; i < 16u; i++) {
            uint c = 8u + (i >> 1), k = 2u * (c & 3u) + h, r0 = 4u * (i & 1u);
            uint sh = 8u * (c >> 2);
            w[i] = (((rows[8u * r0 + k] >> sh) & 0xffu) << 24)
                 | (((rows[8u * (r0 + 1u) + k] >> sh) & 0xffu) << 16)
                 | (((rows[8u * (r0 + 2u) + k] >> sh) & 0xffu) << 8)
                 |  ((rows[8u * (r0 + 3u) + k] >> sh) & 0xffu);
        }
        uint state[8] = sha256_iv;
        myrgr_sha256_block(state, w);

        // Padding for a 512-bit message.
        w[ 0] = 0x80000000u;   w[ 1] = 0u;   w[ 2] = 0u;   w[ 3] = 0u;
        w[ 4] = 0u;            w[ 5] = 0u;   w[ 6] = 0u;   w[ 7] = 0u;
        w[ 8] = 0u;            w[ 9] = 0u;   w[10] = 0u;   w[11] = 0u;
        w[12] = 0u;            w[13] = 0u;   w[14] = 0u;   w[15] = 512u;
        myrgr_sha256_block(state, w);

        uint hash[8];
        for (uint i = 0u; i < 8u; i++)
            hash[i] = bswap32(state[i]);
        groestl_check(n + h, hash);
    }
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k += 2u) {
        uint index = first + k;
        if (index >= push.count)
            return;
        // The second lane is this invocation's and inside the dispatch, or
        // another invocation would hash the same nonce.
        myrgr_search(push.nonce_start + index,
                     k + 1u < kNoncesPerInvocation && index + 1u < push.count);
    }
}

#endif  // VKMINER_ALGORITHMS_MYRGR_KERNEL_GLSL_INCLUDED
