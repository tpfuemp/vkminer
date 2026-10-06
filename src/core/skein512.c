/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Skein-512-512, from "The Skein Hash Function Family", version 1.3
 * (Ferguson et al., 2010).
 *
 * Threefish-512 in UBI mode: configuration, message and output blocks, each
 * with a 128-bit tweak (byte position, type, first/final). Version 1.2 had
 * different rotation constants; coins use 1.3.
 *
 * The oracle the GPU kernel is tested against, so it stays plain: tables,
 * loops, and the configuration block computed rather than stored.
 */

#include "core/skein512.h"

#include <string.h>

#define ROTL64( x, n )  ( ( (x) << (n) ) | ( (x) >> ( 64 - (n) ) ) )

/* Key schedule parity constant, spec 3.3.2. */
#define SKEIN_C240  UINT64_C(0x1BD11BDAA9FC1A22)

/* Block types, spec table 6. */
#define TYPE_CFG  4
#define TYPE_MSG  48
#define TYPE_OUT  63

/* Threefish-512 rotation constants, spec table 4 (version 1.3), indexed by
 * round mod 8 and then by MIX within the round. */
static const int skein512_rot[8][4] = {
    { 46, 36, 19, 37 },
    { 33, 27, 14, 42 },
    { 17, 49, 36, 39 },
    { 44,  9, 54, 56 },
    { 39, 30, 34, 24 },
    { 13, 50, 10, 17 },
    { 25, 29, 39, 43 },
    {  8, 35, 56, 22 }
};

/* The word permutation after every round, spec table 3: word i of the next
 * round is word skein512_perm[i] of this one. */
static const int skein512_perm[8] = { 2, 1, 4, 7, 6, 5, 0, 3 };

static uint64_t le64dec_local( const void *p )
{
    const unsigned char *b = (const unsigned char *)p;
    return   (uint64_t)b[0]         | ( (uint64_t)b[1] <<  8 )
         | ( (uint64_t)b[2] << 16 ) | ( (uint64_t)b[3] << 24 )
         | ( (uint64_t)b[4] << 32 ) | ( (uint64_t)b[5] << 40 )
         | ( (uint64_t)b[6] << 48 ) | ( (uint64_t)b[7] << 56 );
}

static void le64enc_local( void *p, uint64_t v )
{
    unsigned char *b = (unsigned char *)p;
    int i;

    for ( i = 0; i < 8; i++ )
        b[i] = (unsigned char)( v >> ( 8 * i ) );
}

/* Threefish-512: encrypt `p` under `key` and `tweak`, 72 rounds, a subkey
 * added before every fourth and after the last. */
static void threefish512( uint64_t out[8], const uint64_t key[8],
                          const uint64_t tweak[2], const uint64_t p[8] )
{
    uint64_t k[9], t[3], v[8], f[8];
    int d, i, s;

    k[8] = SKEIN_C240;
    for ( i = 0; i < 8; i++ )
    {
        k[i] = key[i];
        k[8] ^= key[i];
    }
    t[0] = tweak[0];
    t[1] = tweak[1];
    t[2] = tweak[0] ^ tweak[1];

    for ( i = 0; i < 8; i++ )
        v[i] = p[i];

    for ( d = 0; d < 72; d++ )
    {
        if ( d % 4 == 0 )
        {
            s = d / 4;
            for ( i = 0; i < 8; i++ )
                v[i] += k[( s + i ) % 9];
            v[5] += t[s % 3];
            v[6] += t[( s + 1 ) % 3];
            v[7] += (uint64_t)s;
        }

        for ( i = 0; i < 4; i++ )
        {
            uint64_t x0 = v[2 * i], x1 = v[2 * i + 1];
            f[2 * i] = x0 + x1;
            f[2 * i + 1] = ROTL64( x1, skein512_rot[d % 8][i] ) ^ f[2 * i];
        }

        for ( i = 0; i < 8; i++ )
            v[i] = f[skein512_perm[i]];
    }

    s = 18;
    for ( i = 0; i < 8; i++ )
        out[i] = v[i] + k[( s + i ) % 9];
    out[5] += t[s % 3];
    out[6] += t[( s + 1 ) % 3];
    out[7] += (uint64_t)s;
}

/* UBI, spec 3.4: fold `len` bytes of type `type` into `h`. An empty message is
 * one block of zeros. */
static void ubi512( uint64_t h[8], const unsigned char *data, size_t len,
                    int type )
{
    size_t done = 0;
    int first = 1;

    do
    {
        unsigned char block[64];
        uint64_t m[8], tweak[2], c[8];
        size_t take = len - done > 64 ? 64 : len - done;
        int final;
        int i;

        memset( block, 0, sizeof block );
        memcpy( block, data + done, take );
        done += take;
        final = done == len;

        for ( i = 0; i < 8; i++ )
            m[i] = le64dec_local( block + i * 8 );

        /* Byte position including this block; type in bits 120..125, first
         * in 126, final in 127. */
        tweak[0] = (uint64_t)done;
        tweak[1] = ( (uint64_t)type << 56 )
                 | ( (uint64_t)first << 62 )
                 | ( (uint64_t)final << 63 );

        threefish512( c, h, tweak, m );
        for ( i = 0; i < 8; i++ )
            h[i] = c[i] ^ m[i];

        first = 0;
    } while ( done < len );
}

void skein512_iv( uint64_t iv[8] )
{
    /* Spec 3.5.2: the schema identifier "SHA3", version 1, the output length
     * in bits, and zero tree parameters, 32 bytes in all. */
    unsigned char config[32];
    int i;

    memset( config, 0, sizeof config );
    config[0] = 'S';
    config[1] = 'H';
    config[2] = 'A';
    config[3] = '3';
    config[4] = 1;
    le64enc_local( config + 8, 512 );

    for ( i = 0; i < 8; i++ )
        iv[i] = 0;
    ubi512( iv, config, sizeof config, TYPE_CFG );
}

/* Not ubi512(), which would mark this block final: more message follows. */
void skein512_midstate( uint64_t h[8], const unsigned char block[64] )
{
    uint64_t m[8], tweak[2], c[8];
    int i;

    skein512_iv( h );

    for ( i = 0; i < 8; i++ )
        m[i] = le64dec_local( block + i * 8 );
    tweak[0] = 64;
    tweak[1] = ( (uint64_t)TYPE_MSG << 56 ) | ( (uint64_t)1 << 62 );

    threefish512( c, h, tweak, m );
    for ( i = 0; i < 8; i++ )
        h[i] = c[i] ^ m[i];
}

void skein512_full( void *hash, const void *data, size_t len )
{
    uint64_t h[8];
    unsigned char counter[8];
    int i;

    skein512_iv( h );
    ubi512( h, (const unsigned char *)data, len, TYPE_MSG );

    /* Output stage, spec 3.5.3: a 64-bit zero counter, one block's worth. */
    memset( counter, 0, sizeof counter );
    ubi512( h, counter, sizeof counter, TYPE_OUT );

    for ( i = 0; i < 8; i++ )
        le64enc_local( (unsigned char *)hash + i * 8, h[i] );
}
