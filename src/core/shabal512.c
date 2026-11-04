/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Shabal-512, the round 2 SHA-3 submission (Bresson et al., 2008),
 * which is what coins use. Little-endian 64-byte blocks into a 12-word A, and
 * 16-word B and C that swap after every block. The initial state is not
 * copied from anywhere: it is the two prefix blocks the specification defines
 * it by, run from zero. The oracle the kernels are tested against, so it
 * stays plain.
 */

#include "core/shabal512.h"

#include <string.h>

#define ROTL32( x, n )  ( ( (x) << (n) ) | ( (x) >> ( 32 - (n) ) ) )

typedef struct {
    uint32_t a[12], b[16], c[16];
    uint64_t w;
} shabal_state;

static void shabal_xor_w( shabal_state *s )
{
    s->a[0] ^= (uint32_t)s->w;
    s->a[1] ^= (uint32_t)( s->w >> 32 );
}

/* The keyed permutation P_{M,C}: three passes of sixteen word updates, B
 * rotated by 17 first, then 36 additions of C into A.  */
static void shabal_permute( shabal_state *s, const uint32_t m[16] )
{
    int i, j;

    for ( i = 0; i < 16; i++ )
        s->b[i] = ROTL32( s->b[i], 17 );

    for ( j = 0; j < 3; j++ )
        for ( i = 0; i < 16; i++ ) {
            int k = ( 16 * j + i ) % 12;
            int prev = ( k + 11 ) % 12;
            uint32_t v = ROTL32( s->a[prev], 15 ) * 5u;
            uint32_t u = ( s->a[k] ^ v ^ s->c[( 24 - i ) % 16] ) * 3u;

            s->a[k] = u ^ s->b[( i + 13 ) % 16]
                    ^ ( s->b[( i + 9 ) % 16] & ~s->b[( i + 6 ) % 16] )
                    ^ m[i];
            s->b[i] = ~( ROTL32( s->b[i], 1 ) ^ s->a[k] );
        }

    for ( j = 0; j < 36; j++ )
        s->a[j % 12] += s->c[( j + 3 ) % 16];
}

static void shabal_swap_bc( shabal_state *s )
{
    uint32_t t[16];

    memcpy( t, s->b, sizeof t );
    memcpy( s->b, s->c, sizeof t );
    memcpy( s->c, t, sizeof t );
}

/* One message block: add into B, the counter into A, permute, subtract from
 * C, swap, count.  */
static void shabal_block( shabal_state *s, const uint32_t m[16] )
{
    int i;

    for ( i = 0; i < 16; i++ )
        s->b[i] += m[i];
    shabal_xor_w( s );
    shabal_permute( s, m );
    for ( i = 0; i < 16; i++ )
        s->c[i] -= m[i];
    shabal_swap_bc( s );
    s->w++;
}

static void shabal_decode( uint32_t m[16], const unsigned char *p )
{
    int i;

    for ( i = 0; i < 16; i++ )
        m[i] = (uint32_t)p[4 * i] | ( (uint32_t)p[4 * i + 1] << 8 )
             | ( (uint32_t)p[4 * i + 2] << 16 )
             | ( (uint32_t)p[4 * i + 3] << 24 );
}

static uint32_t shabal_iv_words[44];
static int shabal_iv_ready;

/* Zero state, counter -1, then the blocks (512, 513, ..., 543) split in two:
 * the output size in bits and the fifteen numbers after it, then the next
 * sixteen. The counter leaves at 1, where every message starts.  */
const uint32_t *shabal512_iv( void )
{
    if ( !shabal_iv_ready ) {
        shabal_state s;
        uint32_t m[16];
        int i, n;

        memset( &s, 0, sizeof s );
        s.w = (uint64_t)-1;
        for ( n = 0; n < 2; n++ ) {
            for ( i = 0; i < 16; i++ )
                m[i] = 512u + 16u * (uint32_t)n + (uint32_t)i;
            shabal_block( &s, m );
        }
        memcpy( shabal_iv_words, s.a, sizeof s.a );
        memcpy( shabal_iv_words + 12, s.b, sizeof s.b );
        memcpy( shabal_iv_words + 28, s.c, sizeof s.c );
        shabal_iv_ready = 1;
    }
    return shabal_iv_words;
}

void shabal512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *p = (const unsigned char *)data;
    const uint32_t *iv = shabal512_iv();
    unsigned char last[64];
    unsigned char *out = (unsigned char *)hash;
    shabal_state s;
    uint32_t m[16];
    int i;

    memcpy( s.a, iv, sizeof s.a );
    memcpy( s.b, iv + 12, sizeof s.b );
    memcpy( s.c, iv + 28, sizeof s.c );
    s.w = 1;

    for ( ; len >= 64; p += 64, len -= 64 ) {
        shabal_decode( m, p );
        shabal_block( &s, m );
    }

    /* The final block: 0x80 and zeros, always present. It is added and
     * permuted, then permuted three more times under the same counter with
     * B and C swapped in between, and never subtracted.  */
    memset( last, 0, sizeof last );
    memcpy( last, p, len );
    last[len] = 0x80;
    shabal_decode( m, last );

    for ( i = 0; i < 16; i++ )
        s.b[i] += m[i];
    shabal_xor_w( &s );
    shabal_permute( &s, m );
    for ( i = 0; i < 3; i++ ) {
        shabal_swap_bc( &s );
        shabal_xor_w( &s );
        shabal_permute( &s, m );
    }

    for ( i = 0; i < 16; i++ ) {
        out[4 * i]     = (unsigned char)s.b[i];
        out[4 * i + 1] = (unsigned char)( s.b[i] >> 8 );
        out[4 * i + 2] = (unsigned char)( s.b[i] >> 16 );
        out[4 * i + 3] = (unsigned char)( s.b[i] >> 24 );
    }
}
