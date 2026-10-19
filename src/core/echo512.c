/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar ECHO-512, the round 2 SHA-3 submission (Benadjila et al., 2009),
 * which is what coins use; round 1 differs in the salt handling.
 *
 * A 4x4 matrix of 128-bit words, column by column: the 1024-bit chaining
 * value in words 0..7 and a 128-byte block in words 8..15. Ten rounds of
 * BigSubWords (two AES rounds per word, the first keyed with the bit counter,
 * which counts up word by word), BigShiftRows and BigMixColumns, then the
 * chaining value takes the xor of both halves and the block. The oracle the
 * kernels are tested against, so it stays plain.
 */

#include "core/echo512.h"

#include "core/aes_round.h"

#include <string.h>

static uint32_t le32( const unsigned char *b )
{
    return (uint32_t)b[0] | ( (uint32_t)b[1] << 8 )
         | ( (uint32_t)b[2] << 16 ) | ( (uint32_t)b[3] << 24 );
}

static void put_le32( unsigned char *b, uint32_t v )
{
    b[0] = (unsigned char)v;
    b[1] = (unsigned char)( v >> 8 );
    b[2] = (unsigned char)( v >> 16 );
    b[3] = (unsigned char)( v >> 24 );
}

static uint8_t xtime( uint8_t a )
{
    return (uint8_t)( ( a << 1 ) ^ ( ( a & 0x80 ) ? 0x1b : 0 ) );
}

static uint8_t byte_of( const uint32_t w[4], int i )
{
    return (uint8_t)( w[i >> 2] >> ( 8 * ( i & 3 ) ) );
}

void echo512_compress( uint32_t v[8][4], const unsigned char msg[128],
                       const uint32_t cnt[4] )
{
    uint32_t w[16][4], t[16][4];
    uint32_t k[4];
    int r, n, c, row, i;

    memcpy( w, v, 8 * sizeof w[0] );
    for ( n = 0; n < 8; n++ )
        for ( i = 0; i < 4; i++ )
            w[8 + n][i] = le32( msg + 16 * n + 4 * i );

    memcpy( k, cnt, sizeof k );

    for ( r = 0; r < 10; r++ ) {
        /* BigSubWords; the key is the counter, one more for every word. */
        for ( n = 0; n < 16; n++ ) {
            aes_round_le( w[n], k );
            aes_round_le( w[n], NULL );
            if ( ++k[0] == 0 && ++k[1] == 0 && ++k[2] == 0 )
                ++k[3];
        }

        /* BigShiftRows: word (column c, row) from column c + row. */
        for ( c = 0; c < 4; c++ )
            for ( row = 0; row < 4; row++ )
                memcpy( t[4 * c + row], w[4 * ( ( c + row ) & 3 ) + row],
                        sizeof t[0] );

        /* BigMixColumns: AES MixColumns down each column, byte by byte. */
        for ( c = 0; c < 4; c++ ) {
            uint32_t out[4][4];
            memset( out, 0, sizeof out );
            for ( i = 0; i < 16; i++ ) {
                uint8_t a[4], all;
                for ( row = 0; row < 4; row++ )
                    a[row] = byte_of( t[4 * c + row], i );
                all = (uint8_t)( a[0] ^ a[1] ^ a[2] ^ a[3] );
                for ( row = 0; row < 4; row++ ) {
                    uint8_t b = (uint8_t)( a[row] ^ all ^ xtime(
                        (uint8_t)( a[row] ^ a[( row + 1 ) & 3] ) ) );
                    out[row][i >> 2] |= (uint32_t)b << ( 8 * ( i & 3 ) );
                }
            }
            memcpy( w[4 * c], out, sizeof out );
        }
    }

    for ( n = 0; n < 8; n++ )
        for ( i = 0; i < 4; i++ )
            v[n][i] ^= le32( msg + 16 * n + 4 * i ) ^ w[n][i] ^ w[8 + n][i];
}

void echo512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[128];
    uint64_t done = 0;
    uint32_t v[8][4], cnt[4] = { 0, 0, 0, 0 };
    size_t rem = len % 128;
    int n, i;

    /* Every word of the IV is the digest size in bits. */
    memset( v, 0, sizeof v );
    for ( n = 0; n < 8; n++ )
        v[n][0] = 512;

    for ( ; len >= 128; in += 128, len -= 128 ) {
        done += 1024;
        cnt[0] = (uint32_t)done;
        cnt[1] = (uint32_t)( done >> 32 );
        echo512_compress( v, in, cnt );
    }

    /* A 0x80 byte and zeros, then in the last 18 bytes the digest size, 16
     * bits, and the 128-bit bit count. A block with no message bits in it is
     * compressed under a zero counter. */
    done += (uint64_t)rem * 8;
    memset( last, 0, sizeof last );
    memcpy( last, in, rem );
    last[rem] = 0x80;
    cnt[0] = (uint32_t)done;
    cnt[1] = (uint32_t)( done >> 32 );
    if ( rem == 0 ) {
        cnt[0] = cnt[1] = 0;
    } else if ( rem + 1 > 110 ) {
        echo512_compress( v, last, cnt );
        memset( last, 0, sizeof last );
        cnt[0] = cnt[1] = 0;
    }
    last[110] = 0x00;
    last[111] = 0x02;
    put_le32( last + 112, (uint32_t)done );
    put_le32( last + 116, (uint32_t)( done >> 32 ) );
    echo512_compress( v, last, cnt );

    for ( n = 0; n < 4; n++ )
        for ( i = 0; i < 4; i++ )
            put_le32( out + 16 * n + 4 * i, v[n][i] );
}
