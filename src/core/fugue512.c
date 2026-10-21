/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Fugue-512, the round 2 SHA-3 submission (Halevi, Hall and Jutla,
 * 2009), which is what coins use. A 36-word state takes one big-endian word
 * at a time. SMIX is written from its definition rather than from tables.
 * The oracle the kernels are tested against, so it stays plain.
 */

#include "core/fugue512.h"

#include "core/groestl512.h"

#include <stdint.h>
#include <string.h>

static const uint32_t fugue512_iv[16] = {
    0x8807a57e, 0xe616af75, 0xc5d3e4db, 0xac9ab027,
    0xd915f117, 0xb6eecc54, 0x06e8020b, 0x4a92efd1,
    0xaac6e2c9, 0xddb21398, 0xcae65838, 0x437f203f,
    0x25ea78e7, 0x951fddd6, 0xda6ed11d, 0xe13e3567
};

/* The circulant column mixing, row k by byte i of a column, byte 0 being
 * the most significant.  */
static const uint8_t fugue_n[4][4] = {
    { 1, 4, 7, 1 }, { 1, 1, 4, 7 }, { 7, 1, 1, 4 }, { 4, 7, 1, 1 }
};

/* a times b in AES's field.  */
static uint8_t gmul( uint8_t a, uint8_t b )
{
    uint8_t p = 0;

    for ( ; b; b >>= 1 ) {
        if ( b & 1 )
            p ^= a;
        a = (uint8_t)( ( a << 1 ) ^ ( ( a & 0x80 ) ? 0x1b : 0 ) );
    }
    return p;
}

/* Rotates the state right by n columns: column c moves to c + n.  */
static void fugue_ror( uint32_t s[36], int n )
{
    uint32_t t[36];
    int c;

    for ( c = 0; c < 36; c++ )
        t[( c + n ) % 36] = s[c];
    memcpy( s, t, sizeof t );
}

static void fugue_cmix( uint32_t s[36] )
{
    s[0] ^= s[4];
    s[1] ^= s[5];
    s[2] ^= s[6];
    s[18] ^= s[4];
    s[19] ^= s[5];
    s[20] ^= s[6];
}

/* Columns 0..3 through the S-box and the super-mix. Output column n takes
 * byte k from column n + k.  */
static void fugue_smix( uint32_t s[36] )
{
    uint8_t u[4][4];  /* [column][byte] after the S-box */
    uint32_t out[4];
    int n, k, i, j;

    for ( j = 0; j < 4; j++ )
        for ( i = 0; i < 4; i++ )
            u[j][i] = groestl512_sbox( (uint8_t)( s[j] >> ( 24 - 8 * i ) ) );

    for ( n = 0; n < 4; n++ ) {
        out[n] = 0;
        for ( k = 0; k < 4; k++ ) {
            uint8_t v = 0, rest = 0;

            j = ( n + k ) & 3;
            for ( i = 0; i < 4; i++ )
                v ^= gmul( fugue_n[k][i], u[j][i] );
            for ( i = 0; i < 4; i++ )
                if ( i != k )
                    rest ^= u[i][k];
            v ^= gmul( fugue_n[j][k], rest );
            out[n] |= (uint32_t)v << ( 24 - 8 * k );
        }
    }
    memcpy( s, out, sizeof out );
}

/* One message word: TIX, then four sub-rounds.  */
static void fugue_word( uint32_t s[36], uint32_t w )
{
    int r;

    s[22] ^= s[0];
    s[0] = w;
    s[8] ^= s[0];
    s[1] ^= s[24];
    s[4] ^= s[27];
    s[7] ^= s[30];

    for ( r = 0; r < 4; r++ ) {
        fugue_ror( s, 3 );
        fugue_cmix( s );
        fugue_smix( s );
    }
}

void fugue512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    uint64_t bits = (uint64_t)len * 8;
    uint32_t s[36];
    int i, r;
    static const int kOut[16] = {
        1, 2, 3, 4, 9, 10, 11, 12, 18, 19, 20, 21, 27, 28, 29, 30
    };

    memset( s, 0, sizeof s );
    memcpy( s + 20, fugue512_iv, sizeof fugue512_iv );

    for ( ; len >= 4; in += 4, len -= 4 )
        fugue_word( s, ( (uint32_t)in[0] << 24 ) | ( (uint32_t)in[1] << 16 )
                     | ( (uint32_t)in[2] << 8 ) | in[3] );
    if ( len ) {
        uint32_t w = 0;
        for ( i = 0; i < (int)len; i++ )
            w |= (uint32_t)in[i] << ( 24 - 8 * i );
        fugue_word( s, w );
    }
    fugue_word( s, (uint32_t)( bits >> 32 ) );
    fugue_word( s, (uint32_t)bits );

    for ( r = 0; r < 32; r++ ) {
        fugue_ror( s, 3 );
        fugue_cmix( s );
        fugue_smix( s );
    }

    /* The final transform: 13 rounds of four folds and SMIXes, rotating by
     * 9, 9, 9 and 8 columns.  */
    for ( r = 0; r < 13; r++ ) {
        static const int kFold[4][3] = {
            { 9, 18, 27 }, { 10, 18, 27 }, { 10, 19, 27 }, { 10, 19, 28 }
        };
        int q;

        for ( q = 0; q < 4; q++ ) {
            s[4] ^= s[0];
            s[kFold[q][0]] ^= s[0];
            s[kFold[q][1]] ^= s[0];
            s[kFold[q][2]] ^= s[0];
            fugue_ror( s, q == 3 ? 8 : 9 );
            fugue_smix( s );
        }
    }
    s[4] ^= s[0];
    s[9] ^= s[0];
    s[18] ^= s[0];
    s[27] ^= s[0];

    for ( i = 0; i < 16; i++ ) {
        uint32_t w = s[kOut[i]];
        out[4 * i]     = (unsigned char)( w >> 24 );
        out[4 * i + 1] = (unsigned char)( w >> 16 );
        out[4 * i + 2] = (unsigned char)( w >> 8 );
        out[4 * i + 3] = (unsigned char)w;
    }
}
