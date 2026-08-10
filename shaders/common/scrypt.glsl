// Salsa20/8 and scryptBlockMix -- the arithmetic half of scrypt.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The memory half is not here, because it cannot be: ROMix indexes a buffer the
// kernel declares, and a header that named one would decide the kernel's
// resource layout for it. What is here is everything that is pure arithmetic on
// sixteen or thirty-two words, which is the part worth having written once.
//
// ⚠️ block_mix below is specialized to r = 1 and the general function's final
// even/odd shuffle is therefore absent, because at r = 1 it is the identity. The
// scalar reference in scrypt.cpp does the general thing and this does not, which
// is the one place the two implementations the differential test compares are
// not line-for-line -- so if r ever stops being 1, this is what breaks and it
// will break silently.

#ifndef VKMINER_SHADERS_COMMON_SCRYPT_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SCRYPT_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

// One Salsa20 quarter-round, in the order the specification writes it: the
// operand naming is the specification's (a, b, c, d), and the four call sites
// per half-round are what carry the column-vs-row permutation. A macro rather
// than a function because every argument is written through.
#define SALSA_QR(a, b, c, d)     \
    b ^= rotl32(a + d,  7u);     \
    c ^= rotl32(b + a,  9u);     \
    d ^= rotl32(c + b, 13u);     \
    a ^= rotl32(d + c, 18u)

// The Salsa20/8 core: eight rounds over sixteen words, then the input added
// back. Eight rounds is four passes of the column/row pair.
void salsa20_8(inout uint block[16])
{
    uint x[16];
    for (int i = 0; i < 16; i++)
        x[i] = block[i];

    for (int i = 0; i < 4; i++) {
        SALSA_QR(x[ 0], x[ 4], x[ 8], x[12]);
        SALSA_QR(x[ 5], x[ 9], x[13], x[ 1]);
        SALSA_QR(x[10], x[14], x[ 2], x[ 6]);
        SALSA_QR(x[15], x[ 3], x[ 7], x[11]);

        SALSA_QR(x[ 0], x[ 1], x[ 2], x[ 3]);
        SALSA_QR(x[ 5], x[ 6], x[ 7], x[ 4]);
        SALSA_QR(x[10], x[11], x[ 8], x[ 9]);
        SALSA_QR(x[15], x[12], x[13], x[14]);
    }

    for (int i = 0; i < 16; i++)
        block[i] += x[i];
}

// scryptBlockMix at r = 1, RFC 7914 §4. The two halves of a 128-byte block go
// in and come back replaced: the first half is Salsa20/8 of the two halves
// XORed, and the second is Salsa20/8 of that against the original second half.
void block_mix(inout uint b0[16], inout uint b1[16])
{
    uint x[16];
    for (int k = 0; k < 16; k++)
        x[k] = b1[k] ^ b0[k];
    salsa20_8(x);

    // Against the *original* b1, which is why the result lands in a second
    // array instead of being written back over it.
    uint y[16];
    for (int k = 0; k < 16; k++)
        y[k] = x[k] ^ b1[k];
    salsa20_8(y);

    for (int k = 0; k < 16; k++) {
        b0[k] = x[k];
        b1[k] = y[k];
    }
}

#endif  // VKMINER_SHADERS_COMMON_SCRYPT_GLSL_INCLUDED
