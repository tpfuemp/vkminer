// SHA-256 compression, FIPS 180-4, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A deliberate line-by-line transliteration of the scalar reference in
// src/core/sha256.c. The two are checked against each other over a hundred
// thousand nonces by the differential test, and that check is only worth
// something while both can be read side by side -- so when one is changed, the
// question to answer first is why the other is not.
//
// What is different from the reference, and why:
//
//   The message schedule is a rolling window of sixteen words rather than the
//   full sixty-four. The reference keeps all of them because it is clearer; a
//   kernel cannot, because sixty-four live registers per invocation is more
//   than any GPU has and the driver would spill the array to memory. The
//   recurrence is the same one, indexed modulo 16.

#ifndef VKMINER_SHADERS_COMMON_SHA256_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHA256_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint sha256_iv[8] = uint[8](
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u);

const uint sha256_k[64] = uint[64](
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u);

uint sha256_ch(uint x, uint y, uint z)  { return (x & y) ^ (~x & z); }
uint sha256_maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }

uint sha256_big_s0(uint x)
{
    return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

uint sha256_big_s1(uint x)
{
    return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

uint sha256_small_s0(uint x)
{
    return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

uint sha256_small_s1(uint x)
{
    return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
}

// Compress one 64-byte block into `state`. The block arrives as sixteen words,
// each holding four message bytes in big-endian order -- which is exactly what
// a header word from struct work already is, so nothing is swapped on the way
// in. `w` is consumed: the schedule is expanded over it in place.
void sha256_compress(inout uint state[8], inout uint w[16])
{
    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    for (uint i = 0u; i < 64u; i++) {
        if (i >= 16u) {
            // w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]), with each
            // index taken modulo 16. The slot being written is w[i-16]'s, which
            // is why this reads as an accumulate rather than an assignment.
            w[i & 15u] += sha256_small_s0(w[(i +  1u) & 15u])
                        + w[(i + 9u) & 15u]
                        + sha256_small_s1(w[(i + 14u) & 15u]);
        }

        uint t1 = h + sha256_big_s1(e) + sha256_ch(e, f, g)
                + sha256_k[i] + w[i & 15u];
        uint t2 = sha256_big_s0(a) + sha256_maj(a, b, c);

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

#endif  // VKMINER_SHADERS_COMMON_SHA256_GLSL_INCLUDED
