// RIPEMD-160 compression, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dobbertin, Bosselaers and Preneel, 1996. Two independent 80-step lines over
// the same message block, combined only at the end -- so there are two ARX
// chains here with no dependency between them, which is most of why this
// primitive is cheap on a GPU despite the step count.
//
// ## Byte order
//
// RIPEMD-160 is little-endian, alone among this tree's primitives: SHA-2 reads
// its message and writes its digest as big-endian words, this reads and writes
// little-endian ones. So the words handed to ripemd160_compress() must already
// be little-endian-valued, and the state it returns is too.
//
// That conversion is deliberately *not* done here. Following the same rule as
// sha256.glsl, this file is the compression function and nothing else -- no
// padding, no byte swapping, no length handling. The caller owns the boundary,
// and a swap hidden inside a primitive is one nobody checks.
//
// The tables below were checked against the designers' published test vectors
// (the empty string, "abc", "message digest", the alphabet and the million-'a')
// before being written here.

#ifndef VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint ripemd160_iv[5] = uint[5](
    0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u);

// Added per round of sixteen. The left line's first and the right line's last
// are zero, which is not padding -- the design simply adds nothing there.
const uint ripemd160_kl[5] = uint[5](
    0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu);
const uint ripemd160_kr[5] = uint[5](
    0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u);

// Which message word each step reads. One row per round of sixteen.
const uint ripemd160_rl[80] = uint[80](
     0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u, 10u, 11u, 12u, 13u, 14u, 15u,
     7u,  4u, 13u,  1u, 10u,  6u, 15u,  3u, 12u,  0u,  9u,  5u,  2u, 14u, 11u,  8u,
     3u, 10u, 14u,  4u,  9u, 15u,  8u,  1u,  2u,  7u,  0u,  6u, 13u, 11u,  5u, 12u,
     1u,  9u, 11u, 10u,  0u,  8u, 12u,  4u, 13u,  3u,  7u, 15u, 14u,  5u,  6u,  2u,
     4u,  0u,  5u,  9u,  7u, 12u,  2u, 10u, 14u,  1u,  3u,  8u, 11u,  6u, 15u, 13u);

const uint ripemd160_rr[80] = uint[80](
     5u, 14u,  7u,  0u,  9u,  2u, 11u,  4u, 13u,  6u, 15u,  8u,  1u, 10u,  3u, 12u,
     6u, 11u,  3u,  7u,  0u, 13u,  5u, 10u, 14u, 15u,  8u, 12u,  4u,  9u,  1u,  2u,
    15u,  5u,  1u,  3u,  7u, 14u,  6u,  9u, 11u,  8u, 12u,  2u, 10u,  0u,  4u, 13u,
     8u,  6u,  4u,  1u,  3u, 11u, 15u,  0u,  5u, 12u,  2u, 13u,  9u,  7u, 10u, 14u,
    12u, 15u, 10u,  4u,  1u,  5u,  8u,  7u,  6u,  2u, 13u, 14u,  0u,  3u,  9u, 11u);

// How far each step rotates left.
const uint ripemd160_sl[80] = uint[80](
    11u, 14u, 15u, 12u,  5u,  8u,  7u,  9u, 11u, 13u, 14u, 15u,  6u,  7u,  9u,  8u,
     7u,  6u,  8u, 13u, 11u,  9u,  7u, 15u,  7u, 12u, 15u,  9u, 11u,  7u, 13u, 12u,
    11u, 13u,  6u,  7u, 14u,  9u, 13u, 15u, 14u,  8u, 13u,  6u,  5u, 12u,  7u,  5u,
    11u, 12u, 14u, 15u, 14u, 15u,  9u,  8u,  9u, 14u,  5u,  6u,  8u,  6u,  5u, 12u,
     9u, 15u,  5u, 11u,  6u,  8u, 13u, 12u,  5u, 12u, 13u, 14u, 11u,  8u,  5u,  6u);

const uint ripemd160_sr[80] = uint[80](
     8u,  9u,  9u, 11u, 13u, 15u, 15u,  5u,  7u,  7u,  8u, 11u, 14u, 14u, 12u,  6u,
     9u, 13u, 15u,  7u, 12u,  8u,  9u, 11u,  7u,  7u, 12u,  7u,  6u, 15u, 13u, 11u,
     9u,  7u, 15u, 11u,  8u,  6u,  6u, 14u, 12u, 13u,  5u, 14u, 13u, 13u,  7u,  5u,
    15u,  5u,  8u, 11u, 14u, 14u,  6u, 14u,  6u,  9u, 12u,  9u, 12u,  5u, 15u,  8u,
     8u,  5u, 12u,  9u, 12u,  5u, 14u,  6u,  8u, 13u,  6u,  5u, 15u, 13u, 11u, 11u);

// The five round functions. The left line uses them in order 0..4 and the right
// line in the reverse order, which is the whole of the difference between the
// two lines apart from the tables above.
uint ripemd160_f(uint round, uint x, uint y, uint z)
{
    if (round == 0u) return x ^ y ^ z;
    if (round == 1u) return (x & y) | (~x & z);
    if (round == 2u) return (x | ~y) ^ z;
    if (round == 3u) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

// Compress one 64-byte block into `h`. The block arrives as sixteen words, each
// holding four message bytes in *little*-endian order -- see the note at the
// top; this is the opposite of sha256_compress()'s convention and the two are
// used either side of a swap in the same kernel.
void ripemd160_compress(inout uint h[5], uint x[16])
{
    uint al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

    for (uint j = 0u; j < 80u; j++) {
        uint round = j >> 4u;

        // The two lines are independent; a driver is free to interleave them
        // and on every device measured so far it does.
        uint tl = al + ripemd160_f(round, bl, cl, dl)
                + x[ripemd160_rl[j]] + ripemd160_kl[round];
        tl = rotl32(tl, ripemd160_sl[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10u); cl = bl; bl = tl;

        uint tr = ar + ripemd160_f(4u - round, br, cr, dr)
                + x[ripemd160_rr[j]] + ripemd160_kr[round];
        tr = rotl32(tr, ripemd160_sr[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10u); cr = br; br = tr;
    }

    // The combination is rotated by one position, and crosses the lines. It is
    // not h[i] += left[i] + right[i]. Writing it that way is the classic RIPEMD
    // bug and it still produces a digest that looks entirely reasonable.
    uint t = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

#endif  // VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED
