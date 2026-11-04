/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Whirlpool, the final version (Barreto and Rijmen, ISO/IEC 10118-3),
 * which is what coins use. A Miyaguchi-Preneel compression around a ten-round
 * block cipher on an 8x8 byte matrix. The S-box, the round constants and the
 * row mixing are all computed from their definitions rather than taken from
 * tables. The oracle the kernels are tested against, so it stays plain.
 */

#include "core/whirlpool512.h"

#include <string.h>

/* The mini-boxes E and R; E^-1 is found by search.  */
static const uint8_t whirlpool_e[16] = {
    0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3,
    0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0
};

static const uint8_t whirlpool_r[16] = {
    0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf,
    0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0
};

static uint8_t whirlpool_e_inv( uint8_t x )
{
    uint8_t i;

    for ( i = 0; whirlpool_e[i] != x; i++ )
        ;
    return i;
}

uint8_t whirlpool512_sbox( uint8_t x )
{
    uint8_t h = whirlpool_e[x >> 4];
    uint8_t l = whirlpool_e_inv( x & 0xf );
    uint8_t r = whirlpool_r[h ^ l];

    return (uint8_t)( ( whirlpool_e[h ^ r] << 4 ) | whirlpool_e_inv( l ^ r ) );
}

/* a times b modulo x^8 + x^4 + x^3 + x^2 + 1.  */
static uint8_t whirlpool_gmul( uint8_t a, uint8_t b )
{
    uint8_t p = 0;

    for ( ; b; b >>= 1 ) {
        if ( b & 1 )
            p ^= a;
        a = (uint8_t)( ( a << 1 ) ^ ( ( a & 0x80 ) ? 0x1d : 0 ) );
    }
    return p;
}

/* The first row of the circulant MixRows matrix.  */
static const uint8_t whirlpool_c[8] = { 1, 1, 4, 1, 8, 5, 2, 9 };

/* One round function rho[k]: S-box on every byte, column j shifted down by j,
 * each row times the circulant matrix, then the key.  */
static void whirlpool_round( uint8_t s[8][8], const uint8_t k[8][8] )
{
    uint8_t t[8][8];
    int i, j, n;

    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ )
            t[i][j] = whirlpool512_sbox( s[( i - j + 8 ) % 8][j] );

    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ ) {
            uint8_t v = 0;
            for ( n = 0; n < 8; n++ )
                v ^= whirlpool_gmul( t[i][n], whirlpool_c[( j - n + 8 ) % 8] );
            s[i][j] = v ^ k[i][j];
        }
}

static void whirlpool_compress( uint8_t h[8][8], const unsigned char *block )
{
    uint8_t key[8][8], s[8][8], rc[8][8];
    int r, i, j;

    memcpy( key, h, sizeof key );
    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ )
            s[i][j] = block[8 * i + j] ^ key[i][j];

    for ( r = 1; r <= 10; r++ ) {
        /* Round r's constant: S-box entries 8(r-1) onward in row 0.  */
        memset( rc, 0, sizeof rc );
        for ( j = 0; j < 8; j++ )
            rc[0][j] = whirlpool512_sbox( (uint8_t)( 8 * ( r - 1 ) + j ) );

        whirlpool_round( key, (const uint8_t (*)[8])rc );
        whirlpool_round( s, (const uint8_t (*)[8])key );
    }

    for ( i = 0; i < 8; i++ )
        for ( j = 0; j < 8; j++ )
            h[i][j] ^= s[i][j] ^ block[8 * i + j];
}

void whirlpool512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *p = (const unsigned char *)data;
    const uint64_t bits = (uint64_t)len * 8u;
    unsigned char last[128];
    uint8_t h[8][8];
    size_t rest, total, i;

    memset( h, 0, sizeof h );
    for ( rest = len; rest >= 64; p += 64, rest -= 64 )
        whirlpool_compress( h, p );

    /* 0x80, zeros to 32 bytes short of a block, then a 256-bit big-endian
     * bit count, of which only the low 64 bits are ever nonzero here.  */
    total = rest < 32 ? 64 : 128;
    memset( last, 0, sizeof last );
    memcpy( last, p, rest );
    last[rest] = 0x80;
    for ( i = 0; i < 8; i++ )
        last[total - 1 - i] = (unsigned char)( bits >> ( 8 * i ) );

    whirlpool_compress( h, last );
    if ( total == 128 )
        whirlpool_compress( h, last + 64 );

    memcpy( hash, h, 64 );
}
