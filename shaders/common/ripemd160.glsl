// RIPEMD-160 building blocks, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dobbertin, Bosselaers and Preneel, 1996. Two independent 80-step lines over
// the same message block, combined only at the end -- so there are two ARX
// chains here with no dependency between them, which is most of why this
// primitive is cheap on a GPU despite the step count.
//
// This file holds the initial value and the five round functions. The step
// schedule is written out as immediates in algorithms/lbry/lbry_kernel.glsl,
// the one kernel that uses it.
//
// ## Byte order
//
// RIPEMD-160 is little-endian, alone among this tree's primitives: SHA-2 reads
// its message and writes its digest as big-endian words, this reads and writes
// little-endian ones. So the message words a caller feeds the steps must
// already be little-endian-valued, and the state that comes out is too.
//
// That conversion is deliberately *not* done here. Following the same rule as
// sha256.glsl, this file is the primitive and nothing else -- no padding, no
// byte swapping, no length handling. The caller owns the boundary, and a swap
// hidden inside a primitive is one nobody checks.

#ifndef VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint ripemd160_iv[5] = uint[5](
    0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u);

// The five round functions. The left line uses them in order 0..4 and the right
// line in the reverse order, which is the whole of the difference between the
// two lines apart from the step schedule.
uint ripemd160_f0(uint x, uint y, uint z) { return x ^ y ^ z; }
uint ripemd160_f1(uint x, uint y, uint z) { return (x & y) | (~x & z); }
uint ripemd160_f2(uint x, uint y, uint z) { return (x | ~y) ^ z; }
uint ripemd160_f3(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
uint ripemd160_f4(uint x, uint y, uint z) { return x ^ (y | ~z); }

#endif  // VKMINER_SHADERS_COMMON_RIPEMD160_GLSL_INCLUDED
