/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar RIPEMD-160 (Dobbertin, Bosselaers and Preneel, 1996).
 *
 * Two independent 80-step lines over the same message block, combined only at
 * the end. The two lines differ in nothing but their message-word order, their
 * rotation amounts, their added constants, and the order the five round
 * functions are used in -- all four of which are the tables below.
 *
 * This hash is little-endian, alone in this tree: it reads its message words
 * and writes its digest words least significant byte first. lbry puts a
 * RIPEMD-160 between two SHA-2 stages, so there is a byte swap on each side of
 * it. That swap belongs to the caller; this file takes and returns bytes, the
 * one representation that cannot be ambiguous.
 *
 * Like src/core/sha256.c, this is the plainest implementation that can be
 * checked against the published test vectors by reading it. It is the oracle
 * the GPU kernel is differentially tested against, so it must never be
 * optimized -- a shared bug between reference and kernel is invisible.
 */

#include "core/ripemd160.h"

#include <string.h>

#define ROTL32( x, n )  ( ( (x) << (n) ) | ( (x) >> ( 32 - (n) ) ) )

/* Added once per round of sixteen steps. The left line's first constant and
 * the right line's last are zero: the design adds nothing there.  */
static const uint32_t kl[5] = {
    0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
};
static const uint32_t kr[5] = {
    0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
};

/* Which message word each step reads; one row per round of sixteen. */
static const unsigned char rl[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};
static const unsigned char rr[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
};

/* How far each step rotates left. */
static const unsigned char sl[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
};
static const unsigned char sr[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
};

/* The left line uses these in order 0..4, the right line in reverse. */
static uint32_t f( int round, uint32_t x, uint32_t y, uint32_t z )
{
    switch ( round )
    {
        case 0:  return x ^ y ^ z;
        case 1:  return ( x & y ) | ( ~x & z );
        case 2:  return ( x | ~y ) ^ z;
        case 3:  return ( x & z ) | ( y & ~z );
        default: return x ^ ( y | ~z );
    }
}

static uint32_t le32dec_local( const void *p )
{
    const unsigned char *b = (const unsigned char *)p;
    return (uint32_t)b[0] | ( (uint32_t)b[1] << 8 )
         | ( (uint32_t)b[2] << 16 ) | ( (uint32_t)b[3] << 24 );
}

static void le32enc_local( void *p, uint32_t v )
{
    unsigned char *b = (unsigned char *)p;
    b[0] = (unsigned char)v;         b[1] = (unsigned char)( v >> 8 );
    b[2] = (unsigned char)( v >> 16 ); b[3] = (unsigned char)( v >> 24 );
}

static void ripemd160_compress( uint32_t h[5], const unsigned char block[64] )
{
    uint32_t x[16];
    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    uint32_t t;
    int j;

    for ( j = 0; j < 16; j++ )
        x[j] = le32dec_local( block + j * 4 );

    for ( j = 0; j < 80; j++ )
    {
        int round = j >> 4;

        t = al + f( round, bl, cl, dl ) + x[rl[j]] + kl[round];
        t = ROTL32( t, sl[j] ) + el;
        al = el; el = dl; dl = ROTL32( cl, 10 ); cl = bl; bl = t;

        t = ar + f( 4 - round, br, cr, dr ) + x[rr[j]] + kr[round];
        t = ROTL32( t, sr[j] ) + er;
        ar = er; er = dr; dr = ROTL32( cr, 10 ); cr = br; br = t;
    }

    /* The combination is rotated by one position and crosses the two
     * lines. It is not h[i] += left[i] + right[i]; writing it that way is the
     * classic RIPEMD bug and still produces a plausible-looking digest.  */
    t    = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = t;
}

void ripemd160_full( void *hash, const void *data, size_t len )
{
    uint32_t h[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    unsigned char block[64];
    const unsigned char *p = (const unsigned char *)data;
    size_t remaining = len;
    int i;

    while ( remaining >= 64 )
    {
        ripemd160_compress( h, p );
        p += 64;
        remaining -= 64;
    }

    /* The tail, the 0x80 terminator and a 64-bit *little*-endian bit count --
     * the length goes at the low end of the final block, where SHA-2 puts it
     * at the high end.  */
    memset( block, 0, sizeof block );
    memcpy( block, p, remaining );
    block[remaining] = 0x80;

    if ( remaining >= 56 )
    {
        ripemd160_compress( h, block );
        memset( block, 0, sizeof block );
    }

    le32enc_local( block + 56, (uint32_t)( len << 3 ) );
    le32enc_local( block + 60, (uint32_t)( len >> 29 ) );
    ripemd160_compress( h, block );

    for ( i = 0; i < 5; i++ )
        le32enc_local( (unsigned char *)hash + i * 4, h[i] );
}
