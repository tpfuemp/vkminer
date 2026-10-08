/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Groestl-512, from "Groestl -- a SHA-3 candidate", the final round 3
 * specification (Gauravaram et al., 2011). The original round 1 version had
 * different round constants and ShiftBytes offsets; coins use this one.
 *
 * The state is an 8x16 byte matrix, filled column by column. Compression is
 * h' = P(h ^ m) ^ Q(m) ^ h, the output transform P(x) ^ x, and the digest its
 * last 64 bytes. The oracle the GPU kernels are tested against, so it stays
 * plain: byte loops, GF(2^8) arithmetic, and an S-box computed rather than
 * stored.
 */

#include "core/groestl512.h"

#include <string.h>

#define ROWS    8
#define COLS    16
#define ROUNDS  14

/* Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, the AES field. */
static uint8_t gf_mul( uint8_t a, uint8_t b )
{
    uint8_t r = 0;
    int i;

    for ( i = 0; i < 8; i++ )
    {
        if ( b & 1 )
            r ^= a;
        b >>= 1;
        a = (uint8_t)( ( a << 1 ) ^ ( ( a & 0x80 ) ? 0x1b : 0 ) );
    }
    return r;
}

uint8_t groestl512_sbox( uint8_t x )
{
    uint8_t inv = 1, sq = x, s;
    int i;

    /* The inverse is x^254 (and 0 maps to 0): bits 1..7 of 254 are set. */
    for ( i = 1; i < 8; i++ )
    {
        sq = gf_mul( sq, sq );
        inv = gf_mul( inv, sq );
    }

    /* Affine map: s = inv ^ rotl(inv,1..4) ^ 0x63. */
    s = inv;
    for ( i = 1; i <= 4; i++ )
        s ^= (uint8_t)( ( inv << i ) | ( inv >> ( 8 - i ) ) );
    return s ^ 0x63;
}

/* ShiftBytes offsets per row, spec table 3 for the 1024-bit permutations. */
static const int shift_p[ROWS] = { 0, 1, 2, 3, 4, 5, 6, 11 };
static const int shift_q[ROWS] = { 1, 3, 5, 11, 0, 2, 4, 6 };

/* MixBytes circulant row, spec 3.4.4. */
static const uint8_t mix_b[ROWS] = { 2, 2, 3, 4, 5, 3, 5, 7 };

/* P1024 (q == 0) or Q1024 (q == 1) on a[row][col]. */
static void permute( uint8_t a[ROWS][COLS], int q )
{
    uint8_t t[ROWS][COLS];
    int r, i, j, k;

    for ( r = 0; r < ROUNDS; r++ )
    {
        /* AddRoundConstant, spec 3.4.1. */
        for ( j = 0; j < COLS; j++ )
            if ( !q )
                a[0][j] ^= (uint8_t)( ( j << 4 ) ^ r );
            else
            {
                for ( i = 0; i < ROWS - 1; i++ )
                    a[i][j] ^= 0xff;
                a[ROWS - 1][j] ^= (uint8_t)( 0xff ^ ( j << 4 ) ^ r );
            }

        for ( i = 0; i < ROWS; i++ )
            for ( j = 0; j < COLS; j++ )
                a[i][j] = groestl512_sbox( a[i][j] );

        for ( i = 0; i < ROWS; i++ )
        {
            const int s = q ? shift_q[i] : shift_p[i];
            for ( j = 0; j < COLS; j++ )
                t[i][j] = a[i][( j + s ) % COLS];
        }

        for ( j = 0; j < COLS; j++ )
            for ( i = 0; i < ROWS; i++ )
            {
                uint8_t v = 0;
                for ( k = 0; k < ROWS; k++ )
                    v ^= gf_mul( mix_b[( k - i + ROWS ) % ROWS], t[k][j] );
                a[i][j] = v;
            }
    }
}

static void to_matrix( uint8_t a[ROWS][COLS], const uint8_t *bytes )
{
    int k;

    for ( k = 0; k < ROWS * COLS; k++ )
        a[k % ROWS][k / ROWS] = bytes[k];
}

static void from_matrix( uint8_t *bytes, uint8_t a[ROWS][COLS] )
{
    int k;

    for ( k = 0; k < ROWS * COLS; k++ )
        bytes[k] = a[k % ROWS][k / ROWS];
}

/* h = P(h ^ m) ^ Q(m) ^ h, on 128-byte strings. */
static void compress( uint8_t h[128], const uint8_t m[128] )
{
    uint8_t hm[128], p[ROWS][COLS], q[ROWS][COLS], pb[128], qb[128];
    int k;

    for ( k = 0; k < 128; k++ )
        hm[k] = h[k] ^ m[k];
    to_matrix( p, hm );
    to_matrix( q, m );
    permute( p, 0 );
    permute( q, 1 );
    from_matrix( pb, p );
    from_matrix( qb, q );
    for ( k = 0; k < 128; k++ )
        h[k] ^= pb[k] ^ qb[k];
}

void groestl512_full( void *hash, const void *data, size_t len )
{
    const uint8_t *msg = (const uint8_t *)data;
    uint8_t h[128], block[128], p[ROWS][COLS], pb[128];
    size_t done = 0, blocks;
    int k;

    /* IV: the digest length in bits, 512, in the last bytes. */
    memset( h, 0, sizeof h );
    h[126] = 0x02;

    while ( len - done >= 128 )
    {
        compress( h, msg + done );
        done += 128;
    }

    /* Padding, spec 3.6: a one bit, zeros, and the 64-bit big-endian count
     * of blocks including this padding, in one block or two. */
    blocks = len / 128 + ( ( len % 128 ) <= 119 ? 1 : 2 );
    memset( block, 0, sizeof block );
    memcpy( block, msg + done, len - done );
    block[len - done] = 0x80;
    if ( len - done > 119 )
    {
        compress( h, block );
        memset( block, 0, sizeof block );
    }
    for ( k = 0; k < 8; k++ )
        block[127 - k] = (uint8_t)( (uint64_t)blocks >> ( 8 * k ) );
    compress( h, block );

    /* Output transform and truncation to the last 64 bytes. */
    to_matrix( p, h );
    permute( p, 0 );
    from_matrix( pb, p );
    for ( k = 0; k < 64; k++ )
        ( (uint8_t *)hash )[k] = pb[64 + k] ^ h[64 + k];
}
