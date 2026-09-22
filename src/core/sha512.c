/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar FIPS 180-4 SHA-512.
 *
 * SHA-512 is SHA-256 with 64-bit words, eighty rounds, different rotation
 * amounts and a different initial value. This file is written to look like
 * src/core/sha256.c for that reason: the two are meant to be read against each
 * other, and a difference between them should be a difference in the standard.
 *
 * Like that one, this is deliberately the plainest implementation that can be
 * checked against the standard's own test vectors by reading it. It is the
 * oracle the GPU kernel is differentially tested against, so it must never be
 * optimized -- a shared bug between reference and kernel is invisible.
 */

#include "core/sha512.h"

#include <string.h>

#define ROTR64( x, n )  ( ( (x) >> (n) ) | ( (x) << ( 64 - (n) ) ) )

#define CH( x, y, z )   ( ( (x) & (y) ) ^ ( ~(x) & (z) ) )
#define MAJ( x, y, z )  ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define BIG_S0( x )     ( ROTR64( x, 28 ) ^ ROTR64( x, 34 ) ^ ROTR64( x, 39 ) )
#define BIG_S1( x )     ( ROTR64( x, 14 ) ^ ROTR64( x, 18 ) ^ ROTR64( x, 41 ) )
#define SMALL_S0( x )   ( ROTR64( x,  1 ) ^ ROTR64( x,  8 ) ^ ( (x) >>  7 ) )
#define SMALL_S1( x )   ( ROTR64( x, 19 ) ^ ROTR64( x, 61 ) ^ ( (x) >>  6 ) )

/* The fractional parts of the square roots of the first eight primes. */
static const uint64_t sha512_iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

/* ...and the cube roots of the first eighty. */
static const uint64_t sha512_k[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

static uint64_t be64dec( const void *p )
{
    const unsigned char *b = (const unsigned char *)p;
    return ( (uint64_t)b[0] << 56 ) | ( (uint64_t)b[1] << 48 )
         | ( (uint64_t)b[2] << 40 ) | ( (uint64_t)b[3] << 32 )
         | ( (uint64_t)b[4] << 24 ) | ( (uint64_t)b[5] << 16 )
         | ( (uint64_t)b[6] <<  8 ) |   (uint64_t)b[7];
}

static void be64enc_local( void *p, uint64_t v )
{
    unsigned char *b = (unsigned char *)p;
    b[0] = (unsigned char)( v >> 56 ); b[1] = (unsigned char)( v >> 48 );
    b[2] = (unsigned char)( v >> 40 ); b[3] = (unsigned char)( v >> 32 );
    b[4] = (unsigned char)( v >> 24 ); b[5] = (unsigned char)( v >> 16 );
    b[6] = (unsigned char)( v >>  8 ); b[7] = (unsigned char)v;
}

static void sha512_compress( uint64_t state[8], const unsigned char block[128] )
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    int i;

    for ( i = 0; i < 16; i++ )
        w[i] = be64dec( block + i * 8 );
    for ( i = 16; i < 80; i++ )
        w[i] = SMALL_S1( w[i - 2] ) + w[i - 7]
             + SMALL_S0( w[i - 15] ) + w[i - 16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for ( i = 0; i < 80; i++ )
    {
        uint64_t t1 = h + BIG_S1( e ) + CH( e, f, g ) + sha512_k[i] + w[i];
        uint64_t t2 = BIG_S0( a ) + MAJ( a, b, c );

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha512_full( void *hash, const void *data, size_t len )
{
    uint64_t state[8];
    unsigned char block[128];
    const unsigned char *p = (const unsigned char *)data;
    size_t remaining = len;
    int i;

    for ( i = 0; i < 8; i++ )
        state[i] = sha512_iv[i];

    while ( remaining >= 128 )
    {
        sha512_compress( state, p );
        p += 128;
        remaining -= 128;
    }

    /* The tail, the 0x80 terminator and a 128-bit big-endian bit count. The
     * high 64 bits of that count are always zero here: this is a miner, and
     * nothing it hashes is 2 exabytes long.  */
    memset( block, 0, sizeof block );
    memcpy( block, p, remaining );
    block[remaining] = 0x80;

    if ( remaining >= 112 )
    {
        sha512_compress( state, block );
        memset( block, 0, sizeof block );
    }

    be64enc_local( block + 120, (uint64_t)len << 3 );
    sha512_compress( state, block );

    for ( i = 0; i < 8; i++ )
        be64enc_local( (unsigned char *)hash + i * 8, state[i] );
}
