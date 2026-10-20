/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar Keccak-512, the round 3 SHA-3 submission: Keccak-f[1600] at a rate
 * of 72 bytes (nine lanes), padded with 0x01 ... 0x80. FIPS 202's SHA3-512
 * has the same rate and the same permutation and pads with 0x06, so the two
 * disagree on every input; sha3t is the other one.
 *
 * Lanes are little-endian. The oracle the kernels are tested against, so it
 * stays plain.
 */

#include "core/keccak512.h"

#include <string.h>

#define ROTL64( x, n )  ( ( (x) << (n) ) | ( (x) >> ( 64 - (n) ) ) )

#define KECCAK512_RATE  72

static const uint64_t keccak_rc[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

/* Rho offsets, indexed x + 5y. */
static const int keccak_rho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Keccak-f[1600]: 24 rounds of theta, rho and pi, chi, iota. */
static void keccakf( uint64_t a[25] )
{
    int r, x, y;

    for ( r = 0; r < 24; r++ ) {
        uint64_t c[5], b[25];

        for ( x = 0; x < 5; x++ )
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for ( x = 0; x < 5; x++ ) {
            uint64_t d = c[( x + 4 ) % 5] ^ ROTL64( c[( x + 1 ) % 5], 1 );
            for ( y = 0; y < 25; y += 5 )
                a[x + y] ^= d;
        }

        for ( x = 0; x < 5; x++ )
            for ( y = 0; y < 5; y++ ) {
                uint64_t v = a[x + 5 * y];
                int n = keccak_rho[x + 5 * y];
                b[y + 5 * ( ( 2 * x + 3 * y ) % 5 )] = n ? ROTL64( v, n ) : v;
            }

        for ( y = 0; y < 25; y += 5 )
            for ( x = 0; x < 5; x++ )
                a[y + x] = b[y + x]
                         ^ ( ~b[y + ( x + 1 ) % 5] & b[y + ( x + 2 ) % 5] );

        a[0] ^= keccak_rc[r];
    }
}

static void keccak_absorb( uint64_t a[25], const unsigned char *block )
{
    int i, k;

    for ( i = 0; i < KECCAK512_RATE / 8; i++ ) {
        uint64_t v = 0;
        for ( k = 7; k >= 0; k-- )
            v = ( v << 8 ) | block[8 * i + k];
        a[i] ^= v;
    }
    keccakf( a );
}

void keccak512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[KECCAK512_RATE];
    uint64_t a[25];
    int i, k;

    memset( a, 0, sizeof a );

    for ( ; len >= KECCAK512_RATE; in += KECCAK512_RATE, len -= KECCAK512_RATE )
        keccak_absorb( a, in );

    memset( last, 0, sizeof last );
    memcpy( last, in, len );
    last[len] ^= 0x01;
    last[KECCAK512_RATE - 1] ^= 0x80;
    keccak_absorb( a, last );

    for ( i = 0; i < 8; i++ )
        for ( k = 0; k < 8; k++ )
            out[8 * i + k] = (unsigned char)( a[i] >> ( 8 * k ) );
}
