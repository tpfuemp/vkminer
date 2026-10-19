/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar SIMD-512, the round 2 SHA-3 submission (Leurent, Bouillaguet and
 * Fouque, tweaked 2009), which is what coins use. Round 1 had other
 * permutations in the step function.
 *
 * Thirty-two little-endian words, four registers A, B, C, D of eight. A
 * 128-byte block is expanded by a 256-point number-theoretic transform over
 * Z/257 into 256 values, which become 128 words; the block is xored into the
 * state, four rounds of eight steps use the words, and four more steps feed
 * the old state forward. The transform is computed here as the plain sum, no
 * butterflies: this is the oracle the kernels are tested against.
 */

#include "core/simd512.h"

#include <string.h>

static const uint32_t simd512_iv[32] = {
    0x0BA16B95, 0x72F999AD, 0x9FECC2AE, 0xBA3264FC,
    0x5E894929, 0x8E9F30E5, 0x2F1DAA37, 0xF0F2C558,
    0xAC506643, 0xA90635A5, 0xE25B878B, 0xAAB7878F,
    0x88817F7A, 0x0A02892B, 0x559A7550, 0x598F657E,
    0x7EEF60A1, 0x6B70E3E8, 0x9C1714D1, 0xB958E2A8,
    0xAB02675E, 0xED1C014F, 0xCD8D65BB, 0xFDB7A257,
    0x09254899, 0xD699C7BC, 0x9019B6DC, 0x2B9022E4,
    0x8FA14956, 0x21BF9BD3, 0xB94D0943, 0x6FFDDC22
};

/* Which group of sixteen transform values feeds each step, by round. */
static const int simd512_wsel[4][8] = {
    {  4,  6,  0,  2,  7,  5,  3,  1 },
    { 15, 11, 12,  8,  9, 13, 10, 14 },
    { 17, 18, 23, 20, 22, 21, 16, 19 },
    { 30, 24, 25, 31, 27, 29, 28, 26 }
};

/* The seven permutations of the eight lanes; step j of round i uses
 * (i + j) mod 7, and the feed-forward steps 4, 5, 6 and 0. */
static const int simd512_perm[7][8] = {
    { 1, 0, 3, 2, 5, 4, 7, 6 },
    { 6, 7, 4, 5, 2, 3, 0, 1 },
    { 2, 3, 0, 1, 6, 7, 4, 5 },
    { 3, 2, 1, 0, 7, 6, 5, 4 },
    { 5, 4, 7, 6, 1, 0, 3, 2 },
    { 7, 6, 5, 4, 3, 2, 1, 0 },
    { 4, 5, 6, 7, 0, 1, 2, 3 }
};

/* Rotations per round, p0..p3; step j takes (p[j mod 4], p[(j + 1) mod 4]). */
static const unsigned simd512_rot[5][4] = {
    {  3, 23, 17, 27 },
    { 28, 19, 22,  7 },
    { 29,  9, 15,  5 },
    {  4, 13, 10, 25 },
    {  4, 13, 10, 25 }  /* the feed-forward */
};

static uint32_t rotl( uint32_t x, unsigned n )
{
    return ( x << n ) | ( x >> ( 32 - n ) );
}

static uint32_t le32( const unsigned char *b )
{
    return (uint32_t)b[0] | ( (uint32_t)b[1] << 8 )
         | ( (uint32_t)b[2] << 16 ) | ( (uint32_t)b[3] << 24 );
}

void simd512_expand( int32_t y[256], const unsigned char msg[128], int final )
{
    int alpha[256];
    int i, j;

    /* 41^k mod 257; 41 has order 256, so exponents reduce mod 256. */
    alpha[0] = 1;
    for ( i = 1; i < 256; i++ )
        alpha[i] = alpha[i - 1] * 41 % 257;

    /* y_i is the message, bytes as coefficients, plus X^255 (and X^253 in
     * the final block), evaluated at 41^i. The sum is at most 128 * 255 *
     * 256 before the terms, well inside an int, so it is reduced once. */
    for ( i = 0; i < 256; i++ ) {
        int s = 0;
        for ( j = 0; j < 128; j++ )
            s += msg[j] * alpha[( i * j ) & 255];
        s += alpha[( i * 255 ) & 255];
        if ( final )
            s += alpha[( i * 253 ) & 255];
        s %= 257;

        /* The centred representative, -128..128. */
        y[i] = s <= 128 ? s : s - 257;
    }
}

static uint32_t simd_if( uint32_t x, uint32_t y, uint32_t z )
{
    return ( ( y ^ z ) & x ) ^ z;
}

static uint32_t simd_maj( uint32_t x, uint32_t y, uint32_t z )
{
    return ( x & y ) | ( ( x | y ) & z );
}

/* One step on all eight lanes. */
static void simd512_step( uint32_t s[4][8], const uint32_t w[8], int fmaj,
                          unsigned r, unsigned rs, const int perm[8] )
{
    uint32_t ta[8];
    int n;

    for ( n = 0; n < 8; n++ )
        ta[n] = rotl( s[0][n], r );

    for ( n = 0; n < 8; n++ ) {
        uint32_t f = fmaj ? simd_maj( s[0][n], s[1][n], s[2][n] )
                          : simd_if( s[0][n], s[1][n], s[2][n] );
        uint32_t t = s[3][n] + w[n] + f;
        s[0][n] = rotl( t, rs ) + ta[perm[n]];
        s[3][n] = s[2][n];
        s[2][n] = s[1][n];
        s[1][n] = ta[n];
    }
}

void simd512_compress( uint32_t h[32], const unsigned char msg[128], int final )
{
    int32_t y[256];
    uint32_t s[4][8];
    uint32_t w[8];
    int i, j, k;

    simd512_expand( y, msg, final );

    for ( i = 0; i < 32; i++ )
        s[i >> 3][i & 7] = h[i] ^ le32( msg + 4 * i );

    for ( i = 0; i < 4; i++ ) {
        /* Rounds 0 and 1 pair y[2k] with y[2k + 1] under 185; rounds 2
         * and 3 pair y[k] with y[k + 128] under 233. */
        const uint32_t mm = i < 2 ? 185 : 233;
        for ( j = 0; j < 8; j++ ) {
            int sb = simd512_wsel[i][j];
            for ( k = 0; k < 8; k++ ) {
                int lo, hi;
                if ( i < 2 ) {
                    lo = 16 * sb + 2 * k;
                    hi = lo + 1;
                } else if ( i == 2 ) {
                    lo = 16 * ( sb - 16 ) + 2 * k;
                    hi = lo + 128;
                } else {
                    lo = 16 * ( sb - 24 ) + 2 * k + 1;
                    hi = lo + 128;
                }
                w[k] = ( ( (uint32_t)y[lo] * mm ) & 0xFFFF )
                     + ( ( (uint32_t)y[hi] * mm ) << 16 );
            }
            simd512_step( s, w, j >= 4, simd512_rot[i][j & 3],
                          simd512_rot[i][( j + 1 ) & 3],
                          simd512_perm[( i + j ) % 7] );
        }
    }

    /* The feed-forward: the old chaining value as message words. */
    for ( j = 0; j < 4; j++ )
        simd512_step( s, &h[8 * j], 0, simd512_rot[4][j],
                      simd512_rot[4][( j + 1 ) & 3],
                      simd512_perm[( 4 + j ) % 7] );

    for ( i = 0; i < 32; i++ )
        h[i] = s[i >> 3][i & 7];
}

void simd512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[128];
    uint64_t bits = (uint64_t)len * 8;
    uint32_t h[32];
    size_t rem = len % 128;
    int i;

    memcpy( h, simd512_iv, sizeof h );

    for ( ; len >= 128; in += 128, len -= 128 )
        simd512_compress( h, in, 0 );

    /* A partial block is zero-filled, no padding bit. Then one more block
     * holding only the 64-bit bit count, under the final transform. */
    if ( rem > 0 ) {
        memset( last, 0, sizeof last );
        memcpy( last, in, rem );
        simd512_compress( h, last, 0 );
    }
    memset( last, 0, sizeof last );
    for ( i = 0; i < 8; i++ )
        last[i] = (unsigned char)( bits >> ( 8 * i ) );
    simd512_compress( h, last, 1 );

    for ( i = 0; i < 16; i++ ) {
        out[4 * i]     = (unsigned char)h[i];
        out[4 * i + 1] = (unsigned char)( h[i] >> 8 );
        out[4 * i + 2] = (unsigned char)( h[i] >> 16 );
        out[4 * i + 3] = (unsigned char)( h[i] >> 24 );
    }
}
