/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar BLAKE-512, the final SHA-3 submission (Aumasson et al., 2010):
 * sixteen rounds of G over a 4x4 state of 64-bit words. Round 1's BLAKE-64
 * had fourteen rounds; coins use sixteen.
 *
 * Not BLAKE2b, which changes the constants, rotations, counter and padding.
 *
 * Message words, length and digest are big-endian. The oracle the kernels are
 * tested against, so it stays plain.
 */

#include "core/blake512.h"

#include <string.h>

#define ROTR64( x, n )  ( ( (x) >> (n) ) | ( (x) << ( 64 - (n) ) ) )

/* SHA-512's IV, which BLAKE-512 reuses. */
static const uint64_t blake512_iv[8] = {
    UINT64_C(0x6A09E667F3BCC908), UINT64_C(0xBB67AE8584CAA73B),
    UINT64_C(0x3C6EF372FE94F82B), UINT64_C(0xA54FF53A5F1D36F1),
    UINT64_C(0x510E527FADE682D1), UINT64_C(0x9B05688C2B3E6C1F),
    UINT64_C(0x1F83D9ABFB41BD6B), UINT64_C(0x5BE0CD19137E2179)
};

/* The first digits of pi. */
static const uint64_t blake512_c[16] = {
    UINT64_C(0x243F6A8885A308D3), UINT64_C(0x13198A2E03707344),
    UINT64_C(0xA4093822299F31D0), UINT64_C(0x082EFA98EC4E6C89),
    UINT64_C(0x452821E638D01377), UINT64_C(0xBE5466CF34E90C6C),
    UINT64_C(0xC0AC29B7C97C50DD), UINT64_C(0x3F84D5B5B5470917),
    UINT64_C(0x9216D5D98979FB1B), UINT64_C(0xD1310BA698DFB5AC),
    UINT64_C(0x2FFD72DBD01ADFB7), UINT64_C(0xB8E1AFED6A267E96),
    UINT64_C(0xBA7C9045F12C7F99), UINT64_C(0x24A19947B3916CF7),
    UINT64_C(0x0801F2E2858EFC16), UINT64_C(0x636920D871574E69)
};

/* Round r uses permutation r mod 10. */
static const unsigned char blake512_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static uint64_t be64dec_local( const unsigned char *b )
{
    uint64_t v = 0;
    int i;

    for ( i = 0; i < 8; i++ )
        v = ( v << 8 ) | b[i];
    return v;
}

static void be64enc_local( unsigned char *b, uint64_t v )
{
    int i;

    for ( i = 7; i >= 0; i-- ) {
        b[i] = (unsigned char)v;
        v >>= 8;
    }
}

/* G on columns or diagonals; i is the G's index within the round, 0..7. */
static void blake512_g( uint64_t v[16], const uint64_t m[16],
                        const unsigned char *s, int i,
                        int a, int b, int c, int d )
{
    v[a] += v[b] + ( m[s[2 * i]] ^ blake512_c[s[2 * i + 1]] );
    v[d] = ROTR64( v[d] ^ v[a], 32 );
    v[c] += v[d];
    v[b] = ROTR64( v[b] ^ v[c], 25 );
    v[a] += v[b] + ( m[s[2 * i + 1]] ^ blake512_c[s[2 * i]] );
    v[d] = ROTR64( v[d] ^ v[a], 16 );
    v[c] += v[d];
    v[b] = ROTR64( v[b] ^ v[c], 11 );
}

/* One 128-byte block under the bit counter t, the message bits hashed up to
 * and including this block (zero for a block of padding only). The counter's
 * high 64 bits are always zero here. No salt. */
static void blake512_compress( uint64_t h[8], const unsigned char block[128],
                               uint64_t t )
{
    uint64_t m[16], v[16];
    int i, r;

    for ( i = 0; i < 16; i++ )
        m[i] = be64dec_local( block + 8 * i );

    for ( i = 0; i < 8; i++ )
        v[i] = h[i];
    for ( i = 0; i < 4; i++ )
        v[8 + i] = blake512_c[i];
    v[12] = t ^ blake512_c[4];
    v[13] = t ^ blake512_c[5];
    v[14] = blake512_c[6];
    v[15] = blake512_c[7];

    for ( r = 0; r < 16; r++ ) {
        const unsigned char *s = blake512_sigma[r % 10];

        blake512_g( v, m, s, 0, 0, 4,  8, 12 );
        blake512_g( v, m, s, 1, 1, 5,  9, 13 );
        blake512_g( v, m, s, 2, 2, 6, 10, 14 );
        blake512_g( v, m, s, 3, 3, 7, 11, 15 );
        blake512_g( v, m, s, 4, 0, 5, 10, 15 );
        blake512_g( v, m, s, 5, 1, 6, 11, 12 );
        blake512_g( v, m, s, 6, 2, 7,  8, 13 );
        blake512_g( v, m, s, 7, 3, 4,  9, 14 );
    }

    for ( i = 0; i < 8; i++ )
        h[i] ^= v[i] ^ v[8 + i];
}

void blake512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[128];
    uint64_t h[8];
    uint64_t bits = 0;
    int i;

    memcpy( h, blake512_iv, sizeof h );

    for ( ; len >= 128; in += 128, len -= 128 ) {
        bits += 1024;
        blake512_compress( h, in, bits );
    }

    /* 0x80, zeros, a 1 bit just before the 128-bit length. When that does
     * not fit, the length goes in a block of its own, whose counter is zero
     * because it holds no message bits; so is an empty remainder's. */
    bits += 8 * (uint64_t)len;
    memset( last, 0, sizeof last );
    memcpy( last, in, len );
    last[len] = 0x80;
    if ( len >= 112 ) {
        blake512_compress( h, last, bits );
        memset( last, 0, sizeof last );
    }
    last[111] |= 0x01;
    be64enc_local( last + 120, bits );
    blake512_compress( h, last, ( len == 0 || len >= 112 ) ? 0 : bits );

    for ( i = 0; i < 8; i++ )
        be64enc_local( out + 8 * i, h[i] );
}
