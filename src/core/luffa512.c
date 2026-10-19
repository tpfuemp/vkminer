/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Luffa-512, the round 2 SHA-3 submission ("Luffa v2", De Canniere,
 * Sato and Watanabe, 2009), which is what coins use. Version 1 had other
 * tweaks and constants.
 *
 * Five 256-bit lanes of eight big-endian words. A 32-byte block goes in
 * through the message injection MI, then each lane takes eight steps of its
 * own permutation. The message ends with a 0x80 byte and zeros to the block,
 * always one more block; two blank blocks follow, each giving 32 bytes of
 * digest as the xor of the five lanes. The oracle the kernels are tested
 * against, so it stays plain.
 */

#include "core/luffa512.h"

#include <string.h>

static const uint32_t luffa512_iv[5][8] = {
    { 0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465,
      0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb },
    { 0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3,
      0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581 },
    { 0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05,
      0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7 },
    { 0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67,
      0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce },
    { 0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363,
      0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea }
};

/* Step constants per lane: [lane][0][step] goes into word 0, [lane][1][step]
 * into word 4. */
static const uint32_t luffa512_rc[5][2][8] = {
    { { 0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e,
        0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12 },
      { 0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f,
        0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d } },
    { { 0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51,
        0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e },
      { 0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28,
        0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704 } },
    { { 0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a,
        0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434 },
      { 0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7,
        0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7 } },
    { { 0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe,
        0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208 },
      { 0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be,
        0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355 } },
    { { 0xf0d2e9e3, 0xac11d7fa, 0x1bcb66f2, 0x6f2d9bc9,
        0x78602649, 0x8edae952, 0x3b6ba548, 0xedae9520 },
      { 0x5090d577, 0x2d1925ab, 0xb46496ac, 0xd1925ab0,
        0x29131ab6, 0x0fc053c3, 0x3f014f0c, 0xfc053c31 } }
};

static uint32_t rotl( uint32_t x, unsigned n )
{
    return ( x << n ) | ( x >> ( 32 - n ) );
}

/* Multiplication by x in GF(2^8)^32, words as coefficients: a shift by one
 * word, folding word 7 back in at 0, 1, 3 and 4. */
static void mul2( uint32_t d[8], const uint32_t s[8] )
{
    uint32_t t = s[7];
    d[7] = s[6];
    d[6] = s[5];
    d[5] = s[4];
    d[4] = s[3] ^ t;
    d[3] = s[2] ^ t;
    d[2] = s[1];
    d[1] = s[0] ^ t;
    d[0] = t;
}

static void xor8( uint32_t d[8], const uint32_t a[8], const uint32_t b[8] )
{
    int i;
    for ( i = 0; i < 8; i++ )
        d[i] = a[i] ^ b[i];
}

/* The message injection, specification 3.2 for w = 5. */
static void luffa512_mi( uint32_t v[5][8], const uint32_t m[8] )
{
    uint32_t a[8], b[8], mm[8];
    int j;

    xor8( a, v[0], v[1] );
    xor8( a, a, v[2] );
    xor8( a, a, v[3] );
    xor8( a, a, v[4] );
    mul2( a, a );
    for ( j = 0; j < 5; j++ )
        xor8( v[j], v[j], a );

    mul2( b, v[0] );
    xor8( b, b, v[1] );
    mul2( v[1], v[1] ); xor8( v[1], v[1], v[2] );
    mul2( v[2], v[2] ); xor8( v[2], v[2], v[3] );
    mul2( v[3], v[3] ); xor8( v[3], v[3], v[4] );
    mul2( v[4], v[4] ); xor8( v[4], v[4], v[0] );
    mul2( v[0], b );    xor8( v[0], v[0], v[4] );
    mul2( v[4], v[4] ); xor8( v[4], v[4], v[3] );
    mul2( v[3], v[3] ); xor8( v[3], v[3], v[2] );
    mul2( v[2], v[2] ); xor8( v[2], v[2], v[1] );
    mul2( v[1], v[1] ); xor8( v[1], v[1], b );

    memcpy( mm, m, sizeof mm );
    for ( j = 0; j < 5; j++ ) {
        xor8( v[j], v[j], mm );
        if ( j < 4 )
            mul2( mm, mm );
    }
}

/* SubCrumb on four words, the bitsliced 4-bit S-box. */
static void sub_crumb( uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3 )
{
    uint32_t t = *a0;
    *a0 |= *a1;
    *a2 ^= *a3;
    *a1 = ~*a1;
    *a0 ^= *a3;
    *a3 &= t;
    *a1 ^= *a3;
    *a3 ^= *a2;
    *a2 &= *a0;
    *a0 = ~*a0;
    *a2 ^= *a1;
    *a1 |= *a3;
    t ^= *a1;
    *a3 ^= *a2;
    *a2 &= *a1;
    *a1 ^= *a0;
    *a0 = t;
}

static void mix_word( uint32_t *u, uint32_t *v )
{
    *v ^= *u;
    *u = rotl( *u, 2 ) ^ *v;
    *v = rotl( *v, 14 ) ^ *u;
    *u = rotl( *u, 10 ) ^ *v;
    *v = rotl( *v, 1 );
}

/* The permutation of lane j: the tweak, then eight steps. */
static void luffa512_permute( uint32_t x[8], int j )
{
    int r, k;

    if ( j > 0 )
        for ( k = 4; k < 8; k++ )
            x[k] = rotl( x[k], (unsigned)j );

    for ( r = 0; r < 8; r++ ) {
        sub_crumb( &x[0], &x[1], &x[2], &x[3] );
        sub_crumb( &x[5], &x[6], &x[7], &x[4] );
        for ( k = 0; k < 4; k++ )
            mix_word( &x[k], &x[k + 4] );
        x[0] ^= luffa512_rc[j][0][r];
        x[4] ^= luffa512_rc[j][1][r];
    }
}

void luffa512_block( uint32_t v[5][8], const unsigned char block[32] )
{
    uint32_t m[8];
    int j;

    for ( j = 0; j < 8; j++ )
        m[j] = ( (uint32_t)block[4 * j] << 24 )
             | ( (uint32_t)block[4 * j + 1] << 16 )
             | ( (uint32_t)block[4 * j + 2] << 8 )
             |   (uint32_t)block[4 * j + 3];

    luffa512_mi( v, m );
    for ( j = 0; j < 5; j++ )
        luffa512_permute( v[j], j );
}

void luffa512_80_precompute( uint32_t out[40], const unsigned char data[80] )
{
    uint32_t v[5][8];
    uint32_t m[8];
    int j, k;

    memcpy( v, luffa512_iv, sizeof v );
    luffa512_block( v, data );
    luffa512_block( v, data + 32 );

    /* Bytes 64..75, the nonce as zero, the 0x80 terminator.  */
    for ( j = 0; j < 3; j++ )
        m[j] = ( (uint32_t)data[64 + 4 * j] << 24 )
             | ( (uint32_t)data[65 + 4 * j] << 16 )
             | ( (uint32_t)data[66 + 4 * j] << 8 )
             |   (uint32_t)data[67 + 4 * j];
    m[3] = 0;
    m[4] = 0x80000000u;
    m[5] = m[6] = m[7] = 0;
    luffa512_mi( v, m );

    for ( j = 0; j < 5; j++ )
        for ( k = 0; k < 8; k++ )
            out[8 * j + k] = ( j > 0 && k >= 4 )
                           ? rotl( v[j][k], (unsigned)j ) : v[j][k];
}

void luffa512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[32];
    uint32_t v[5][8];
    int i, k;

    memcpy( v, luffa512_iv, sizeof v );

    for ( ; len >= 32; in += 32, len -= 32 )
        luffa512_block( v, in );

    memset( last, 0, sizeof last );
    memcpy( last, in, len );
    last[len] = 0x80;
    luffa512_block( v, last );

    /* Two blank blocks, 32 bytes of digest after each. */
    memset( last, 0, sizeof last );
    for ( i = 0; i < 2; i++ ) {
        luffa512_block( v, last );
        for ( k = 0; k < 8; k++ ) {
            uint32_t w = v[0][k] ^ v[1][k] ^ v[2][k] ^ v[3][k] ^ v[4][k];
            out[32 * i + 4 * k]     = (unsigned char)( w >> 24 );
            out[32 * i + 4 * k + 1] = (unsigned char)( w >> 16 );
            out[32 * i + 4 * k + 2] = (unsigned char)( w >> 8 );
            out[32 * i + 4 * k + 3] = (unsigned char)w;
        }
    }
}
