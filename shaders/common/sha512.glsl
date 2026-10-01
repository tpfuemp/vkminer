// SHA-512 building blocks, FIPS 180-4, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SHA-512 is SHA-256 with 64-bit words, eighty rounds, different rotation
// amounts and a different initial value. This file holds the word type, the
// constants and the round functions; the rounds themselves are written out in
// the kernels that use them, algorithms/lbry/lbry_kernel.glsl and
// algorithms/sha512256d/sha512256d_kernel.glsl. The functions are named as in
// shaders/common/sha256.glsl so the two can be read against each other.
//
// The 64-bit word is the difficulty. shaderInt64 is an optional Vulkan feature
// and Mali and Adreno frequently lack it, so this file is written over a lane
// typedef and compiled twice: once with SLANE as a native uint64_t, once as a
// uvec2 pair. A third build, VKMINER_SHA512_WIDE_ADD, keeps the pair but adds
// through uint64_t, and is what the shaderInt64 modules use. Which module a
// device gets is decided in Algorithm::kernel(), not by a specialization
// constant -- Int64 is an OpCapability declared at module scope, so a driver
// without the feature rejects the whole module however unreachable the 64-bit
// code is.
//
// ## The one rule for editing this file
//
// Never write `a + b` on an SLANE. Use sadd().
//
// In the uint64_t build `+` is a 64-bit add. In the uvec2 build it is two
// independent 32-bit adds and the carry is silently dropped, which is wrong in
// a way that still produces plausible-looking digests. `&`, `|`, `^` and `~`
// are componentwise and so are correct in both builds; addition is the only
// operator that is not, and it is the one SHA-512 uses most.
//
// shaders/common/sha3.glsl has the same lane problem and solves it the same
// way with its own KLANE. The two are deliberately separate typedefs: an
// algorithm that needs both primitives -- x16rv2 does -- would otherwise have
// two different definitions of one macro name in one translation unit.

#ifndef VKMINER_SHADERS_COMMON_SHA512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHA512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

#ifdef VKMINER_SHA512_INT64

#define SLANE uint64_t

SLANE slane(uint lo, uint hi) { return uint64_t(lo) | (uint64_t(hi) << 32); }
uint  slo(SLANE x)            { return uint(x); }
uint  shi(SLANE x)            { return uint(x >> 32); }

SLANE sadd(SLANE a, SLANE b)  { return a + b; }
SLANE sshr(SLANE x, uint n)   { return x >> n; }

SLANE srotr(SLANE x, uint n)
{
    return n == 0u ? x : (x >> n) | (x << (64u - n));
}

#else

#define SLANE uvec2   // .x is the low half, .y the high half

SLANE slane(uint lo, uint hi) { return uvec2(lo, hi); }
uint  slo(SLANE x)            { return x.x; }
uint  shi(SLANE x)            { return x.y; }

#ifdef VKMINER_SHA512_WIDE_ADD

// Pairs for the rotates, a 64-bit integer for the add: a uint64_t rotate may
// not become funnel shifts, and uaddCarry() may not become the hardware carry.
// The packs are bitcasts. Needs shaderInt64.
SLANE sadd(SLANE a, SLANE b)
{
    return unpackUint2x32(packUint2x32(a) + packUint2x32(b));
}

#else

// The carry is the whole point of this function existing. uaddCarry() returns
// it from the add itself, which a driver can lower to one add-with-carry.
SLANE sadd(SLANE a, SLANE b)
{
    uint carry;
    uint lo = uaddCarry(a.x, b.x, carry);
    return uvec2(lo, a.y + b.y + carry);
}

#endif

SLANE sshr(SLANE x, uint n)
{
    if (n == 0u)
        return x;
    if (n >= 32u)
        return uvec2(n == 32u ? x.y : (x.y >> (n - 32u)), 0u);
    return uvec2((x.x >> n) | (x.y << (32u - n)), x.y >> n);
}

// Rotating by n is a half-swap when n >= 32, then a funnel shift by n mod 32.
// Every amount SHA-512 uses is a compile-time constant, so the branches fold.
SLANE srotr(SLANE x, uint n)
{
    SLANE v = (n >= 32u) ? x.yx : x;
    uint s = n & 31u;
    return s == 0u ? v
                   : uvec2((v.x >> s) | (v.y << (32u - s)),
                           (v.y >> s) | (v.x << (32u - s)));
}

#endif

// The tables are stored as 32-bit halves, high word first, so that each pair
// reads left to right as the 64-bit constant the standard publishes. They are
// generated from the definition -- the fractional parts of the square roots of
// the first eight primes, and the cube roots of the first eighty -- so a typo
// in a listing cannot get in.
const uint sha512_iv_words[16] = uint[16](
    0x6a09e667u, 0xf3bcc908u, 0xbb67ae85u, 0x84caa73bu,
    0x3c6ef372u, 0xfe94f82bu, 0xa54ff53au, 0x5f1d36f1u,
    0x510e527fu, 0xade682d1u, 0x9b05688cu, 0x2b3e6c1fu,
    0x1f83d9abu, 0xfb41bd6bu, 0x5be0cd19u, 0x137e2179u);

const uint sha512_k_words[160] = uint[160](
    0x428a2f98u, 0xd728ae22u, 0x71374491u, 0x23ef65cdu,
    0xb5c0fbcfu, 0xec4d3b2fu, 0xe9b5dba5u, 0x8189dbbcu,
    0x3956c25bu, 0xf348b538u, 0x59f111f1u, 0xb605d019u,
    0x923f82a4u, 0xaf194f9bu, 0xab1c5ed5u, 0xda6d8118u,
    0xd807aa98u, 0xa3030242u, 0x12835b01u, 0x45706fbeu,
    0x243185beu, 0x4ee4b28cu, 0x550c7dc3u, 0xd5ffb4e2u,
    0x72be5d74u, 0xf27b896fu, 0x80deb1feu, 0x3b1696b1u,
    0x9bdc06a7u, 0x25c71235u, 0xc19bf174u, 0xcf692694u,
    0xe49b69c1u, 0x9ef14ad2u, 0xefbe4786u, 0x384f25e3u,
    0x0fc19dc6u, 0x8b8cd5b5u, 0x240ca1ccu, 0x77ac9c65u,
    0x2de92c6fu, 0x592b0275u, 0x4a7484aau, 0x6ea6e483u,
    0x5cb0a9dcu, 0xbd41fbd4u, 0x76f988dau, 0x831153b5u,
    0x983e5152u, 0xee66dfabu, 0xa831c66du, 0x2db43210u,
    0xb00327c8u, 0x98fb213fu, 0xbf597fc7u, 0xbeef0ee4u,
    0xc6e00bf3u, 0x3da88fc2u, 0xd5a79147u, 0x930aa725u,
    0x06ca6351u, 0xe003826fu, 0x14292967u, 0x0a0e6e70u,
    0x27b70a85u, 0x46d22ffcu, 0x2e1b2138u, 0x5c26c926u,
    0x4d2c6dfcu, 0x5ac42aedu, 0x53380d13u, 0x9d95b3dfu,
    0x650a7354u, 0x8baf63deu, 0x766a0abbu, 0x3c77b2a8u,
    0x81c2c92eu, 0x47edaee6u, 0x92722c85u, 0x1482353bu,
    0xa2bfe8a1u, 0x4cf10364u, 0xa81a664bu, 0xbc423001u,
    0xc24b8b70u, 0xd0f89791u, 0xc76c51a3u, 0x0654be30u,
    0xd192e819u, 0xd6ef5218u, 0xd6990624u, 0x5565a910u,
    0xf40e3585u, 0x5771202au, 0x106aa070u, 0x32bbd1b8u,
    0x19a4c116u, 0xb8d2d0c8u, 0x1e376c08u, 0x5141ab53u,
    0x2748774cu, 0xdf8eeb99u, 0x34b0bcb5u, 0xe19b48a8u,
    0x391c0cb3u, 0xc5c95a63u, 0x4ed8aa4au, 0xe3418acbu,
    0x5b9cca4fu, 0x7763e373u, 0x682e6ff3u, 0xd6b2b8a3u,
    0x748f82eeu, 0x5defb2fcu, 0x78a5636fu, 0x43172f60u,
    0x84c87814u, 0xa1f0ab72u, 0x8cc70208u, 0x1a6439ecu,
    0x90befffau, 0x23631e28u, 0xa4506cebu, 0xde82bde9u,
    0xbef9a3f7u, 0xb2c67915u, 0xc67178f2u, 0xe372532bu,
    0xca273eceu, 0xea26619cu, 0xd186b8c7u, 0x21c0c207u,
    0xeada7dd6u, 0xcde0eb1eu, 0xf57d4f7fu, 0xee6ed178u,
    0x06f067aau, 0x72176fbau, 0x0a637dc5u, 0xa2c898a6u,
    0x113f9804u, 0xbef90daeu, 0x1b710b35u, 0x131c471bu,
    0x28db77f5u, 0x23047d84u, 0x32caab7bu, 0x40c72493u,
    0x3c9ebe0au, 0x15c9bebcu, 0x431d67c4u, 0x9c100d4cu,
    0x4cc5d4beu, 0xcb3e42b6u, 0x597f299cu, 0xfc657e2au,
    0x5fcb6fabu, 0x3ad6faecu, 0x6c44198cu, 0x4a475817u);

// SHA-512/256's initial value, FIPS 180-4 5.3.6.2. With the four-word digest,
// the only difference from SHA-512.
const uint sha512_256_iv_words[16] = uint[16](
    0x22312194u, 0xfc2bf72cu, 0x9f555fa3u, 0xc84c64c2u,
    0x2393b86bu, 0x6f53b151u, 0x96387719u, 0x5940eabdu,
    0x96283ee2u, 0xa88effe3u, 0xbe5e1e25u, 0x53863992u,
    0x2b0199fcu, 0x2c85b8aau, 0x0eb72ddcu, 0x81c52ca2u);

SLANE sha512_iv(uint i)
{
    return slane(sha512_iv_words[2u * i + 1u], sha512_iv_words[2u * i]);
}

SLANE sha512_256_iv(uint i)
{
    return slane(sha512_256_iv_words[2u * i + 1u], sha512_256_iv_words[2u * i]);
}

SLANE sha512_k(uint i)
{
    return slane(sha512_k_words[2u * i + 1u], sha512_k_words[2u * i]);
}

SLANE sha512_ch(SLANE x, SLANE y, SLANE z)  { return (x & y) ^ (~x & z); }
SLANE sha512_maj(SLANE x, SLANE y, SLANE z) { return (x & y) ^ (x & z) ^ (y & z); }

SLANE sha512_big_s0(SLANE x)
{
    return srotr(x, 28u) ^ srotr(x, 34u) ^ srotr(x, 39u);
}

SLANE sha512_big_s1(SLANE x)
{
    return srotr(x, 14u) ^ srotr(x, 18u) ^ srotr(x, 41u);
}

SLANE sha512_small_s0(SLANE x)
{
    return srotr(x, 1u) ^ srotr(x, 8u) ^ sshr(x, 7u);
}

SLANE sha512_small_s1(SLANE x)
{
    return srotr(x, 19u) ^ srotr(x, 61u) ^ sshr(x, 6u);
}

#endif  // VKMINER_SHADERS_COMMON_SHA512_GLSL_INCLUDED
