/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar CubeHash16/32-512, the round 2 SHA-3 submission (Bernstein, 2009):
 * sixteen rounds per 32-byte block and ten times sixteen to finish, which is
 * what coins use. Round 1's CubeHash8/1 has other parameters and another IV.
 *
 * The state is 32 words, little-endian. A block is xored into words 0..7.
 * The oracle the kernels are tested against, so it stays plain.
 */

#include "core/cubehash512.h"

#include <string.h>

/* The IV for h = 512, r = 16, b = 32: the state after ten times sixteen
 * rounds from (64, 32, 16, 0, ...). Stored rather than computed, as every
 * implementation does. */
static const uint32_t cubehash512_iv[32] = {
    0x2AEA2A61, 0x50F494D4, 0x2D538B8B, 0x4167D83E,
    0x3FEE2313, 0xC701CF8C, 0xCC39968E, 0x50AC5695,
    0x4D42C787, 0xA647A8B3, 0x97CF0BEF, 0x825B4537,
    0xEEF864D2, 0xF22090C4, 0xD0E5CD33, 0xA23911AE,
    0xFCD398D9, 0x148FE485, 0x1B017BEF, 0xB6444532,
    0x6A536159, 0x2FF5781C, 0x91FA7934, 0x0DBADEA9,
    0xD65C8A2B, 0xA5A70E75, 0xB1C62456, 0xBC796576,
    0x1921C8F7, 0xE7989AF1, 0x7795D246, 0xD43E3B44
};

static uint32_t rotl( uint32_t x, unsigned n )
{
    return ( x << n ) | ( x >> ( 32 - n ) );
}

static void swap( uint32_t *x, int i, int j )
{
    uint32_t t = x[i];
    x[i] = x[j];
    x[j] = t;
}

/* One round, the ten steps of the specification in order. */
static void cubehash_round( uint32_t x[32] )
{
    int i;

    for ( i = 0; i < 16; i++ ) x[16 + i] += x[i];
    for ( i = 0; i < 16; i++ ) x[i] = rotl( x[i], 7 );
    for ( i = 0; i < 8; i++ )  swap( x, i, i + 8 );
    for ( i = 0; i < 16; i++ ) x[i] ^= x[16 + i];
    for ( i = 0; i < 16; i++ ) if ( !( i & 2 ) ) swap( x, 16 + i, 16 + ( i ^ 2 ) );
    for ( i = 0; i < 16; i++ ) x[16 + i] += x[i];
    for ( i = 0; i < 16; i++ ) x[i] = rotl( x[i], 11 );
    for ( i = 0; i < 16; i++ ) if ( !( i & 4 ) ) swap( x, i, i ^ 4 );
    for ( i = 0; i < 16; i++ ) x[i] ^= x[16 + i];
    for ( i = 0; i < 16; i++ ) if ( !( i & 1 ) ) swap( x, 16 + i, 16 + ( i ^ 1 ) );
}

void cubehash512_block( uint32_t x[32], const unsigned char block[32] )
{
    int i;

    for ( i = 0; i < 8; i++ )
        x[i] ^=   (uint32_t)block[4 * i]
              | ( (uint32_t)block[4 * i + 1] << 8 )
              | ( (uint32_t)block[4 * i + 2] << 16 )
              | ( (uint32_t)block[4 * i + 3] << 24 );
    for ( i = 0; i < 16; i++ )
        cubehash_round( x );
}

void cubehash512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[32];
    uint32_t x[32];
    int i;

    memcpy( x, cubehash512_iv, sizeof x );

    for ( ; len >= 32; in += 32, len -= 32 )
        cubehash512_block( x, in );

    /* A 1 bit, then zeros to the block: always one more block. */
    memset( last, 0, sizeof last );
    memcpy( last, in, len );
    last[len] = 0x80;
    cubehash512_block( x, last );

    x[31] ^= 1;
    for ( i = 0; i < 160; i++ )
        cubehash_round( x );

    for ( i = 0; i < 16; i++ ) {
        out[4 * i]     = (unsigned char)x[i];
        out[4 * i + 1] = (unsigned char)( x[i] >> 8 );
        out[4 * i + 2] = (unsigned char)( x[i] >> 16 );
        out[4 * i + 3] = (unsigned char)( x[i] >> 24 );
    }
}
