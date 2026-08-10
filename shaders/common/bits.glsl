// Bit operations every hash kernel needs and GLSL does not have.
// SPDX-License-Identifier: GPL-3.0-or-later

// The guard does not end in a double underscore the way this project's C++
// headers do: GLSL reserves consecutive underscores anywhere in a name, and
// glslangValidator warns about every one of them on every build.
#ifndef VKMINER_SHADERS_COMMON_BITS_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_BITS_GLSL_INCLUDED

// GLSL's own rotate is bitfieldRotate, which is signed-aware and which several
// drivers lower into worse code than the shift pair below. Written out because
// this is the single hottest expression in a SHA-256 kernel.
//
// Undefined for n == 0 or n == 32, as a shift by the full width is: every
// caller here passes a compile-time constant in 1..31.
uint rotr32(uint x, uint n)
{
    return (x >> n) | (x << (32u - n));
}

// The other direction, on the same terms and for the same reason. Salsa20 is
// specified entirely in left rotates, and spelling them as rotr32(x, 32u - n)
// would make every line of it something to decode rather than something to
// compare against the specification.
uint rotl32(uint x, uint n)
{
    return (x << n) | (x >> (32u - n));
}

// Reverse the four bytes of a word.
//
// This is not the header endianness hazard -- the block header is normalized on
// the host before it is ever uploaded, and the shader never sees a wire byte.
// It is the digest's own byte order: SHA-256 is defined over big-endian words,
// and the comparison against the target is over those words read back as
// little-endian, so the swap happens to a value the shader itself produced and
// there is no host-side moment at which it could have been done instead.
uint bswap32(uint x)
{
    return (x >> 24)
         | ((x >>  8) & 0x0000ff00u)
         | ((x <<  8) & 0x00ff0000u)
         | (x  << 24);
}

#endif  // VKMINER_SHADERS_COMMON_BITS_GLSL_INCLUDED
