/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar BMW-512 (Blue Midnight Wish), the round 2 SHA-3 submission
 * (Gligoroski et al., 2009), which is what coins use.
 *
 * A compression is f0 (Q[0..15] from M ^ H), f1 (Q[16..31]) and f2 (the fold
 * back to sixteen words). The digest is the last eight words of one more
 * compression, of the state under a constant chaining value. The oracle the
 * kernels are tested against, so it stays plain: tables and loops.
 */

#include "core/bmw512.h"

#include <string.h>

static uint64_t rotl( uint64_t x, unsigned n )
{
    return ( x << n ) | ( x >> ( 64 - n ) );
}

static uint64_t s0( uint64_t x )
{
    return ( x >> 1 ) ^ ( x << 3 ) ^ rotl( x, 4 ) ^ rotl( x, 37 );
}

static uint64_t s1( uint64_t x )
{
    return ( x >> 1 ) ^ ( x << 2 ) ^ rotl( x, 13 ) ^ rotl( x, 43 );
}

static uint64_t s2( uint64_t x )
{
    return ( x >> 2 ) ^ ( x << 1 ) ^ rotl( x, 19 ) ^ rotl( x, 53 );
}

static uint64_t s3( uint64_t x )
{
    return ( x >> 2 ) ^ ( x << 2 ) ^ rotl( x, 28 ) ^ rotl( x, 59 );
}

static uint64_t s4( uint64_t x ) { return ( x >> 1 ) ^ x; }
static uint64_t s5( uint64_t x ) { return ( x >> 2 ) ^ x; }

static uint64_t s_( int i, uint64_t x )
{
    switch ( i )
    {
    case 0: return s0( x );
    case 1: return s1( x );
    case 2: return s2( x );
    case 3: return s3( x );
    default: return s4( x );
    }
}

/* f0: W[i] sums five words of M ^ H; w_minus marks the subtracted ones. */
static const int w_index[16][5] = {
    {  5,  7, 10, 13, 14 }, {  6,  8, 11, 14, 15 }, {  0,  7,  9, 12, 15 },
    {  0,  1,  8, 10, 13 }, {  1,  2,  9, 11, 14 }, {  3,  2, 10, 12, 15 },
    {  4,  0,  3, 11, 13 }, {  1,  4,  5, 12, 14 }, {  2,  5,  6, 13, 15 },
    {  0,  3,  6,  7, 14 }, {  8,  1,  4,  7, 15 }, {  8,  0,  2,  5,  9 },
    {  1,  3,  6,  9, 10 }, {  2,  4,  7, 10, 11 }, {  3,  5,  8, 11, 12 },
    { 12,  4,  6,  9, 13 },
};

static const int w_minus[16][5] = {
    { 0, 1, 0, 0, 0 }, { 0, 1, 0, 0, 1 }, { 0, 0, 0, 1, 0 },
    { 0, 1, 0, 1, 0 }, { 0, 0, 0, 1, 1 }, { 0, 1, 0, 1, 0 },
    { 0, 1, 1, 1, 0 }, { 0, 1, 1, 1, 1 }, { 0, 1, 1, 0, 1 },
    { 0, 1, 0, 1, 0 }, { 0, 1, 1, 1, 0 }, { 0, 1, 1, 1, 0 },
    { 0, 0, 1, 1, 0 }, { 0, 0, 0, 0, 0 }, { 0, 1, 0, 1, 1 },
    { 0, 1, 1, 1, 0 },
};

/* AddElement(i): rotl(M[k], k + 1) for k = i, i+3, i+10, plus K, xor H. */
static uint64_t add_element( const uint64_t m[16], const uint64_t h[16],
                             int i )
{
    const int a = i, b = ( i + 3 ) % 16, c = ( i + 10 ) % 16;
    const uint64_t k = (uint64_t)( i + 16 ) * 0x0555555555555555ull;

    return ( rotl( m[a], a + 1 ) + rotl( m[b], b + 1 ) - rotl( m[c], c + 1 )
             + k ) ^ h[( i + 7 ) % 16];
}

/* h' = f2(f1(f0(h, m)), m). */
static void compress( uint64_t out[16], const uint64_t h[16],
                      const uint64_t m[16] )
{
    static const unsigned r[8] = { 0, 5, 11, 27, 32, 37, 43, 53 };
    uint64_t x[16], q[32], xl, xh;
    int i, j;

    /* f0 */
    for ( i = 0; i < 16; i++ )
        x[i] = m[i] ^ h[i];
    for ( i = 0; i < 16; i++ )
    {
        uint64_t w = x[w_index[i][0]];
        for ( j = 1; j < 5; j++ )
            w = w_minus[i][j] ? w - x[w_index[i][j]] : w + x[w_index[i][j]];
        q[i] = s_( i % 5, w ) + h[( i + 1 ) % 16];
    }

    /* f1: expand1 for the first two, expand2 for the rest. */
    for ( i = 16; i < 18; i++ )
    {
        uint64_t v = add_element( m, h, i - 16 );
        for ( j = 0; j < 16; j++ )
            v += s_( ( j + 1 ) % 4, q[i - 16 + j] );
        q[i] = v;
    }
    for ( i = 18; i < 32; i++ )
    {
        uint64_t v = add_element( m, h, i - 16 );
        for ( j = 0; j < 14; j += 2 )
            v += q[i - 16 + j] + rotl( q[i - 15 + j], r[j / 2 + 1] );
        q[i] = v + s4( q[i - 2] ) + s5( q[i - 1] );
    }

    /* f2 */
    xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];
    xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30] ^ q[31];

    out[0] = ( ( xh << 5 ) ^ ( q[16] >> 5 ) ^ m[0] ) + ( xl ^ q[24] ^ q[0] );
    out[1] = ( ( xh >> 7 ) ^ ( q[17] << 8 ) ^ m[1] ) + ( xl ^ q[25] ^ q[1] );
    out[2] = ( ( xh >> 5 ) ^ ( q[18] << 5 ) ^ m[2] ) + ( xl ^ q[26] ^ q[2] );
    out[3] = ( ( xh >> 1 ) ^ ( q[19] << 5 ) ^ m[3] ) + ( xl ^ q[27] ^ q[3] );
    out[4] = ( ( xh >> 3 ) ^   q[20]        ^ m[4] ) + ( xl ^ q[28] ^ q[4] );
    out[5] = ( ( xh << 6 ) ^ ( q[21] >> 6 ) ^ m[5] ) + ( xl ^ q[29] ^ q[5] );
    out[6] = ( ( xh >> 4 ) ^ ( q[22] << 6 ) ^ m[6] ) + ( xl ^ q[30] ^ q[6] );
    out[7] = ( ( xh >> 11 ) ^ ( q[23] << 2 ) ^ m[7] ) + ( xl ^ q[31] ^ q[7] );

    out[ 8] = rotl( out[4],  9 ) + ( xh ^ q[24] ^ m[ 8] )
            + ( ( xl << 8 ) ^ q[23] ^ q[ 8] );
    out[ 9] = rotl( out[5], 10 ) + ( xh ^ q[25] ^ m[ 9] )
            + ( ( xl >> 6 ) ^ q[16] ^ q[ 9] );
    out[10] = rotl( out[6], 11 ) + ( xh ^ q[26] ^ m[10] )
            + ( ( xl << 6 ) ^ q[17] ^ q[10] );
    out[11] = rotl( out[7], 12 ) + ( xh ^ q[27] ^ m[11] )
            + ( ( xl << 4 ) ^ q[18] ^ q[11] );
    out[12] = rotl( out[0], 13 ) + ( xh ^ q[28] ^ m[12] )
            + ( ( xl >> 3 ) ^ q[19] ^ q[12] );
    out[13] = rotl( out[1], 14 ) + ( xh ^ q[29] ^ m[13] )
            + ( ( xl >> 4 ) ^ q[20] ^ q[13] );
    out[14] = rotl( out[2], 15 ) + ( xh ^ q[30] ^ m[14] )
            + ( ( xl >> 7 ) ^ q[21] ^ q[14] );
    out[15] = rotl( out[3], 16 ) + ( xh ^ q[31] ^ m[15] )
            + ( ( xl >> 2 ) ^ q[22] ^ q[15] );
}

static uint64_t dec64le( const uint8_t *p )
{
    uint64_t v = 0;
    int k;

    for ( k = 7; k >= 0; k-- )
        v = ( v << 8 ) | p[k];
    return v;
}

static void compress_bytes( uint64_t h[16], const uint8_t block[128] )
{
    uint64_t m[16];
    int i;

    for ( i = 0; i < 16; i++ )
        m[i] = dec64le( block + 8 * i );
    compress( h, h, m );
}

void bmw512_full( void *hash, const void *data, size_t len )
{
    const uint8_t *msg = (const uint8_t *)data;
    uint8_t block[128], *out = (uint8_t *)hash;
    uint64_t h[16], fin[16], d[16];
    size_t done = 0;
    int i, k;

    /* IV: the bytes 0x80, 0x81, .. 0xff, read as big-endian words. */
    for ( i = 0; i < 16; i++ )
        h[i] = 0x8081828384858687ull + (uint64_t)i * 0x0808080808080808ull;

    while ( len - done >= 128 )
    {
        compress_bytes( h, msg + done );
        done += 128;
    }

    /* Padding: a one bit, zeros, the 64-bit little-endian bit count. */
    memset( block, 0, sizeof block );
    memcpy( block, msg + done, len - done );
    block[len - done] = 0x80;
    if ( len - done > 119 )
    {
        compress_bytes( h, block );
        memset( block, 0, sizeof block );
    }
    for ( k = 0; k < 8; k++ )
        block[120 + k] = (uint8_t)( ( (uint64_t)len * 8 ) >> ( 8 * k ) );
    compress_bytes( h, block );

    /* Final transform: the state as message, under 0xaaaa..aaa0 + i. */
    for ( i = 0; i < 16; i++ )
        fin[i] = 0xaaaaaaaaaaaaaaa0ull + (uint64_t)i;
    compress( d, fin, h );

    for ( i = 0; i < 8; i++ )
        for ( k = 0; k < 8; k++ )
            out[8 * i + k] = (uint8_t)( d[8 + i] >> ( 8 * k ) );
}
