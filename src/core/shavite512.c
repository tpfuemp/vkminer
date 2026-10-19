/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar SHAvite-3-512, the round 2 SHA-3 submission (Biham and Dunkelman,
 * tweaked 2009), which is what coins use. Round 1 had another key schedule
 * and counter placement; the November 2009 "BugFix" reference byte-swaps the
 * AES rounds and has other IVs, and is not this either.
 *
 * Sixteen little-endian words of chaining value, four 128-bit quarters. A
 * 128-byte block expands, with the 128-bit bit counter, into 448 words of
 * round keys; fourteen Feistel rounds of four keyed AES rounds each, then a
 * feed-forward. The oracle the kernels are tested against, so it stays plain.
 */

#include "core/shavite512.h"

#include "core/aes_round.h"

#include <string.h>

static const uint32_t shavite512_iv[16] = {
    0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
    0xD1901A06, 0x430AE307, 0xB29F5CD1, 0xDF07FBFC,
    0x8E45D73D, 0x681AB538, 0xBDE86578, 0xDD577E47,
    0xE275EADE, 0x502D9FCD, 0xB9357178, 0x022A4B9A
};

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

/* The message expansion: 448 words from 32 of message, the counter mixed in
 * at four places, each with its words in another order and one inverted. */
static void shavite512_expand( uint32_t rk[448], const unsigned char msg[128],
                               const uint32_t cnt[4] )
{
    int u, s, i;

    for ( u = 0; u < 32; u++ )
        rk[u] = le32( msg + 4 * u );

    u = 32;
    for ( ;; ) {
        /* Eight nonlinear quarters: an AES round of the words 31..28 back,
         * rotated by one word, xored with the four just before. */
        for ( s = 0; s < 8; s++ ) {
            uint32_t x[4];
            x[0] = rk[u - 31];
            x[1] = rk[u - 30];
            x[2] = rk[u - 29];
            x[3] = rk[u - 32];
            aes_round_le( x, NULL );
            for ( i = 0; i < 4; i++ )
                rk[u + i] = x[i] ^ rk[u - 4 + i];

            if ( u == 32 ) {
                rk[32] ^= cnt[0]; rk[33] ^= cnt[1];
                rk[34] ^= cnt[2]; rk[35] ^= ~cnt[3];
            } else if ( u == 164 ) {
                rk[164] ^= cnt[3]; rk[165] ^= cnt[2];
                rk[166] ^= cnt[1]; rk[167] ^= ~cnt[0];
            } else if ( u == 316 ) {
                rk[316] ^= cnt[2]; rk[317] ^= cnt[3];
                rk[318] ^= cnt[0]; rk[319] ^= ~cnt[1];
            } else if ( u == 440 ) {
                rk[440] ^= cnt[1]; rk[441] ^= cnt[0];
                rk[442] ^= cnt[3]; rk[443] ^= ~cnt[2];
            }
            u += 4;
        }
        if ( u == 448 )
            break;

        /* Eight linear quarters. */
        for ( s = 0; s < 8; s++ ) {
            rk[u + 0] = rk[u - 32] ^ rk[u - 7];
            rk[u + 1] = rk[u - 31] ^ rk[u - 6];
            rk[u + 2] = rk[u - 30] ^ rk[u - 5];
            rk[u + 3] = rk[u - 29] ^ rk[u - 4];
            u += 4;
        }
    }
}

void shavite512_compress( uint32_t h[16], const unsigned char msg[128],
                          const uint32_t cnt[4] )
{
    uint32_t rk[448];
    uint32_t p[4][4];  /* the four quarters */
    int r, q, i, k, u = 0;

    shavite512_expand( rk, msg, cnt );
    memcpy( p, h, sizeof p );

    for ( r = 0; r < 14; r++ ) {
        /* Quarter 0 takes F of quarter 1, and quarter 2 of quarter 3. */
        for ( q = 0; q < 4; q += 2 ) {
            uint32_t x[4];
            for ( i = 0; i < 4; i++ )
                x[i] = p[q + 1][i] ^ rk[u++];
            for ( k = 0; k < 3; k++ ) {
                aes_round_le( x, &rk[u] );
                u += 4;
            }
            aes_round_le( x, NULL );
            for ( i = 0; i < 4; i++ )
                p[q][i] ^= x[i];
        }

        /* Rotate the quarters: (0, 1, 2, 3) becomes (3, 0, 1, 2). */
        {
            uint32_t t[4];
            memcpy( t, p[3], sizeof t );
            memmove( p[1], p[0], 3 * sizeof p[0] );
            memcpy( p[0], t, sizeof t );
        }
    }

    for ( i = 0; i < 16; i++ )
        h[i] ^= p[i >> 2][i & 3];
}

void shavite512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[128];
    uint64_t bits = (uint64_t)len * 8;
    uint64_t done = 0;
    uint32_t h[16], cnt[4] = { 0, 0, 0, 0 };
    size_t rem = len % 128;
    int i;

    memcpy( h, shavite512_iv, sizeof h );

    for ( ; len >= 128; in += 128, len -= 128 ) {
        done += 1024;
        cnt[0] = (uint32_t)done;
        cnt[1] = (uint32_t)( done >> 32 );
        shavite512_compress( h, in, cnt );
    }

    /* A 0x80 byte, zeros, then the 128-bit bit count and the digest size in
     * bits, 16 bits, all little-endian, in the last 18 bytes. A block with no
     * message bits in it is compressed under a zero counter. */
    memset( last, 0, sizeof last );
    memcpy( last, in, rem );
    last[rem] = 0x80;
    cnt[0] = (uint32_t)bits;
    cnt[1] = (uint32_t)( bits >> 32 );
    if ( rem == 0 ) {
        cnt[0] = cnt[1] = 0;
    } else if ( rem >= 110 ) {
        shavite512_compress( h, last, cnt );
        memset( last, 0, sizeof last );
        cnt[0] = cnt[1] = 0;
    }
    put_le32( last + 110, (uint32_t)bits );
    put_le32( last + 114, (uint32_t)( bits >> 32 ) );
    last[126] = 0x00;
    last[127] = 0x02;
    shavite512_compress( h, last, cnt );

    for ( i = 0; i < 16; i++ )
        put_le32( out + 4 * i, h[i] );
}
