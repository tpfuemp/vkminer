/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar HeavyHash, as Optical Bitcoin (OBTC) defines it:
 *
 *     seed        = SHA3-256( header[4..35] )         the previous block hash
 *     matrix      = xoshiro256++( seed ), sixteen 4-bit entries per draw,
 *                   drawn again until the matrix is nonsingular
 *     first       = SHA3-256( header )
 *     product[i]  = ( sum_j matrix[i][j] * nibble[j] ) >> 10
 *     digest      = SHA3-256( first ^ pack( product ) )
 *
 * nibble[2b] is the high half of byte b of `first`, nibble[2b + 1] the low
 * half; pack() is the inverse. The largest sum is 64 * 15 * 15 = 14400, so
 * every product fits a nibble. The oracle for the kernels, so it stays plain.
 */

#include "core/heavyhash.h"

#include <string.h>

/* ------------------------------------------------------------------ SHA3 */

static const uint64_t kRc[24] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull,
    0x8000000080008000ull, 0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull, 0x000000000000008aull,
    0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull,
    0x8000000000008003ull, 0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull, 0x8000000080008081ull,
    0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull,
};

/* FIPS 202 sec. 3.2.2, indexed x + 5y as the state is. */
static const unsigned kRho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

static uint64_t rotl64( uint64_t x, unsigned n )
{
    /* A shift by the full width is undefined, not a no-op. */
    return n == 0 ? x : ( x << n ) | ( x >> ( 64 - n ) );
}

static void keccakf( uint64_t a[25] )
{
    for ( int r = 0; r < 24; r++ )
    {
        uint64_t c[5], d[5], b[25];

        for ( int x = 0; x < 5; x++ )
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for ( int x = 0; x < 5; x++ )
            d[x] = c[( x + 4 ) % 5] ^ rotl64( c[( x + 1 ) % 5], 1 );
        for ( int x = 0; x < 5; x++ )
            for ( int y = 0; y < 25; y += 5 )
                a[x + y] ^= d[x];

        /* rho and pi: (x, y) is rotated by its offset and lands at
         * (y, 2x + 3y). */
        for ( int x = 0; x < 5; x++ )
            for ( int y = 0; y < 5; y++ )
                b[y + 5 * ( ( 2 * x + 3 * y ) % 5 )] =
                    rotl64( a[x + 5 * y], kRho[x + 5 * y] );

        for ( int y = 0; y < 25; y += 5 )
            for ( int x = 0; x < 5; x++ )
                a[y + x] = b[y + x]
                         ^ ( ~b[y + ( x + 1 ) % 5] & b[y + ( x + 2 ) % 5] );

        a[0] ^= kRc[r];
    }
}

void heavyhash_sha3_256( unsigned char out[32], const void *in, size_t len )
{
    const unsigned char *p = (const unsigned char *)in;
    uint64_t a[25] = { 0 };

    for ( size_t i = 0; i < len; i++ )
        a[i / 8] ^= (uint64_t)p[i] << ( 8 * ( i % 8 ) );

    /* 0x06 is SHA3's; Keccak-256 would put 0x01 here and differ nowhere else. */
    a[len / 8] ^= (uint64_t)0x06 << ( 8 * ( len % 8 ) );
    a[16] ^= 0x8000000000000000ull;

    keccakf( a );

    for ( size_t i = 0; i < 32; i++ )
        out[i] = (unsigned char)( a[i / 8] >> ( 8 * ( i % 8 ) ) );
}

/* ---------------------------------------------------------------- matrix */

static uint64_t le64( const unsigned char *p )
{
    uint64_t v = 0;
    for ( int i = 7; i >= 0; i-- )
        v = ( v << 8 ) | p[i];
    return v;
}

/* xoshiro256++: the scrambler is rotl(s0 + s3, 23) + s0. xoshiro256** has the
 * same state update and changes every entry. */
static uint64_t xoshiro( uint64_t s[4] )
{
    const uint64_t result = rotl64( s[0] + s[3], 23 ) + s[0];
    const uint64_t t = s[1] << 17;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl64( s[3], 45 );

    return result;
}

/* Rank over GF(p) by row reduction. Entries start below 16, so no reduction is
 * needed on the way in, and p < 2^31 keeps every product inside 64 bits. */
static int rank_mod( const uint8_t m[64][64], uint32_t p )
{
    uint32_t a[64][64];
    int row = 0;

    for ( int i = 0; i < 64; i++ )
        for ( int j = 0; j < 64; j++ )
            a[i][j] = m[i][j];

    for ( int col = 0; col < 64 && row < 64; col++ )
    {
        int pivot = -1;
        for ( int r = row; r < 64; r++ )
            if ( a[r][col] ) { pivot = r; break; }
        if ( pivot < 0 )
            continue;

        if ( pivot != row )
            for ( int c = 0; c < 64; c++ )
            {
                uint32_t t = a[row][c];
                a[row][c] = a[pivot][c];
                a[pivot][c] = t;
            }

        /* The inverse by Fermat: a^(p-2). */
        uint64_t inv = 1, base = a[row][col];
        for ( uint32_t e = p - 2; e; e >>= 1 )
        {
            if ( e & 1 )
                inv = inv * base % p;
            base = base * base % p;
        }

        for ( int r = row + 1; r < 64; r++ )
        {
            if ( !a[r][col] )
                continue;
            const uint64_t f = (uint64_t)a[r][col] * inv % p;
            for ( int c = col; c < 64; c++ )
                a[r][c] = (uint32_t)( ( a[r][c] + p - f * a[row][c] % p ) % p );
        }
        row++;
    }
    return row;
}

/* Exact, where the daemon uses a floating-point SVD: full rank modulo a prime
 * means nonsingular over the rationals, and a second prime guards the ~1/p
 * chance of a false "singular". */
int heavyhash_full_rank( const uint8_t matrix[64][64] )
{
    return rank_mod( matrix, 2147483647u ) == 64
        || rank_mod( matrix, 2147483629u ) == 64;
}

void heavyhash_matrix_from_seed( uint8_t matrix[64][64],
                                 const unsigned char seed[32] )
{
    uint64_t s[4];
    for ( int i = 0; i < 4; i++ )
        s[i] = le64( seed + 8 * i );

    /* A rejected matrix advances the stream; no reseed. (The cast: C will not
     * add const to a pointer to an array implicitly.) */
    do {
        for ( int i = 0; i < 64; i++ )
            for ( int j = 0; j < 64; j += 16 )
            {
                const uint64_t value = xoshiro( s );
                for ( int k = 0; k < 16; k++ )
                    matrix[i][j + k] = (uint8_t)( ( value >> ( 4 * k ) ) & 0xF );
            }
    } while ( !heavyhash_full_rank( (const uint8_t (*)[64])matrix ) );
}

void heavyhash_matrix( uint8_t matrix[64][64], const void *header80 )
{
    unsigned char seed[32];

    heavyhash_sha3_256( seed, (const unsigned char *)header80 + 4, 32 );
    heavyhash_matrix_from_seed( matrix, seed );
}

/* ------------------------------------------------------------------ core */

void heavyhash_core( unsigned char out[32], const uint8_t matrix[64][64],
                     const void *data, size_t len )
{
    unsigned char first[32], xored[32];
    uint32_t nibble[64], product[64];

    heavyhash_sha3_256( first, data, len );

    for ( int b = 0; b < 32; b++ )
    {
        nibble[2 * b] = first[b] >> 4;
        nibble[2 * b + 1] = first[b] & 0xF;
    }

    for ( int i = 0; i < 64; i++ )
    {
        uint32_t sum = 0;
        for ( int j = 0; j < 64; j++ )
            sum += matrix[i][j] * nibble[j];
        product[i] = sum >> 10;
    }

    for ( int b = 0; b < 32; b++ )
        xored[b] = (unsigned char)( first[b]
                                  ^ ( ( product[2 * b] << 4 ) | product[2 * b + 1] ) );

    heavyhash_sha3_256( out, xored, sizeof xored );
}
