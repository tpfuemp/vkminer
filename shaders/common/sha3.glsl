// Keccak-f[1600], FIPS 202, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The permutation and nothing else: what gets absorbed, how it is padded and
// how many times it is squeezed are the algorithm's business, and sha3d, sha3t
// and keccak differ in exactly those and in nothing here.
//
// A lane is KLANE, not uint64_t, because shaderInt64 is optional and Mali and
// Adreno often lack it. This text compiles into two modules -- 64-bit lanes, or
// pairs of 32-bit words -- and the algorithm picks one off DeviceInfo::int64.
// A specialization constant cannot make that choice: Int64 is an
// OpCapability, declared for the whole module, and a device without the feature
// rejects the module whatever the constant leaves reachable.

#ifndef VKMINER_SHADERS_COMMON_SHA3_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHA3_GLSL_INCLUDED

#ifdef VKMINER_SHA3_INT64

// The includer declares the extension, because an #extension directive belongs
// at the top of the compilation unit and this file is not it.
#define KLANE uint64_t

KLANE klane(uint lo, uint hi)
{
    return uint64_t(lo) | (uint64_t(hi) << 32);
}

uint klo(KLANE x) { return uint(x); }
uint khi(KLANE x) { return uint(x >> 32); }

// n is a rho offset, so it is a compile-time constant at every call site. The
// zero case is not decoration: lane 0 is not rotated at all, and a shift by the
// full width of the type is undefined rather than a no-op.
KLANE krotl(KLANE x, uint n)
{
    return n == 0u ? x : (x << n) | (x >> (64u - n));
}

#else

// A lane as (low half, high half). Nothing below this line knows which type it
// was compiled with: xor, and, and complement are componentwise on a uvec2 and
// mean the same thing either way, and the rest goes through the functions here.
#define KLANE uvec2

KLANE klane(uint lo, uint hi) { return uvec2(lo, hi); }

uint klo(KLANE x) { return x.x; }
uint khi(KLANE x) { return x.y; }

// A rotate by 32 or more is a swap of the halves followed by a smaller rotate,
// and a rotate by a multiple of 32 is the swap alone -- which is also the guard
// that keeps every shift below the width of the word it applies to.
KLANE krotl(KLANE x, uint n)
{
    KLANE v = (n >= 32u) ? x.yx : x;
    uint s = n & 31u;

    return s == 0u ? v : uvec2((v.x << s) | (v.y >> (32u - s)),
                               (v.y << s) | (v.x >> (32u - s)));
}

#endif  // VKMINER_SHA3_INT64

// FIPS 202 sec. 3.2.2, as (low half, high half) so that the table reads the same
// whichever lane type it is compiled for. Only lane 0 takes one, once a round.
const uvec2 sha3_rc[24] = uvec2[24](
    uvec2(0x00000001u, 0x00000000u), uvec2(0x00008082u, 0x00000000u),
    uvec2(0x0000808au, 0x80000000u), uvec2(0x80008000u, 0x80000000u),
    uvec2(0x0000808bu, 0x00000000u), uvec2(0x80000001u, 0x00000000u),
    uvec2(0x80008081u, 0x80000000u), uvec2(0x00008009u, 0x80000000u),
    uvec2(0x0000008au, 0x00000000u), uvec2(0x00000088u, 0x00000000u),
    uvec2(0x80008009u, 0x00000000u), uvec2(0x8000000au, 0x00000000u),
    uvec2(0x8000808bu, 0x00000000u), uvec2(0x0000008bu, 0x80000000u),
    uvec2(0x00008089u, 0x80000000u), uvec2(0x00008003u, 0x80000000u),
    uvec2(0x00008002u, 0x80000000u), uvec2(0x00000080u, 0x80000000u),
    uvec2(0x0000800au, 0x00000000u), uvec2(0x8000000au, 0x80000000u),
    uvec2(0x80008081u, 0x80000000u), uvec2(0x00008080u, 0x80000000u),
    uvec2(0x80000001u, 0x00000000u), uvec2(0x80008008u, 0x80000000u));

// The rotation offsets of rho (FIPS 202 sec. 3.2.2), indexed x + 5y as the state
// is. Written out rather than computed from the triangular recurrence, so it
// can be read against the table in the standard.
const uint sha3_rho[25] = uint[25](
     0u,  1u, 62u, 28u, 27u,
    36u, 44u,  6u, 55u, 20u,
     3u, 10u, 43u, 25u, 39u,
    41u, 45u, 15u, 21u,  8u,
    18u,  2u, 61u, 56u, 14u);

// One permutation, in place: 24 rounds of theta, rho, pi, chi, iota, each
// written as the standard writes it. The loops have compile-time bounds, so a
// shader compiler unrolls whatever it wants to unroll.
void sha3_keccakf(inout KLANE a[25])
{
    for (int r = 0; r < 24; r++) {
        KLANE c[5];
        KLANE d[5];
        KLANE b[25];

        // theta
        for (int x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++)
            d[x] = c[(x + 4) % 5] ^ krotl(c[(x + 1) % 5], 1u);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 25; y += 5)
                a[x + y] ^= d[x];

        // rho and pi, which are one move: the lane at (x, y) is rotated by its
        // own offset and lands at (y, 2x + 3y).
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    krotl(a[x + 5 * y], sha3_rho[x + 5 * y]);

        // chi, along each row
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                a[y + x] = b[y + x]
                         ^ ((~b[y + (x + 1) % 5]) & b[y + (x + 2) % 5]);

        // iota
        a[0] ^= klane(sha3_rc[r].x, sha3_rc[r].y);
    }
}

// The 1088-bit rate of SHA3-256 and Keccak-256: seventeen lanes of the state
// are message, the other eight are capacity and are never touched by input.
#define SHA3_256_RATE_LANES 17

#endif  // VKMINER_SHADERS_COMMON_SHA3_GLSL_INCLUDED
