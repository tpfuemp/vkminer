/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar JH-512, the round 3 SHA-3 submission (Wu, 2011): a 1024-bit state,
 * each 64-byte block xored into its first half, 42 rounds of E8, and the
 * block xored into its second half. The digest is the last 64 bytes.
 *
 * The designer's bitsliced form: sixteen 64-bit words read little-endian, the
 * constants byte-swapped to match. Words 2k and 2k + 1 are the high and low
 * halves of the specification's 128-bit word k.
 *
 * The oracle the kernels are tested against, so it stays plain.
 */

#include "core/jh512.h"

#include <string.h>

/* E8's 42 round constants, four words each, as the specification prints them
 * (big-endian). Round r: even-word high, even low, odd high, odd low. */
static const uint64_t jh512_c[168] = {
    UINT64_C(0x72d5dea2df15f867), UINT64_C(0x7b84150ab7231557),
    UINT64_C(0x81abd6904d5a87f6), UINT64_C(0x4e9f4fc5c3d12b40),
    UINT64_C(0xea983ae05c45fa9c), UINT64_C(0x03c5d29966b2999a),
    UINT64_C(0x660296b4f2bb538a), UINT64_C(0xb556141a88dba231),
    UINT64_C(0x03a35a5c9a190edb), UINT64_C(0x403fb20a87c14410),
    UINT64_C(0x1c051980849e951d), UINT64_C(0x6f33ebad5ee7cddc),
    UINT64_C(0x10ba139202bf6b41), UINT64_C(0xdc786515f7bb27d0),
    UINT64_C(0x0a2c813937aa7850), UINT64_C(0x3f1abfd2410091d3),
    UINT64_C(0x422d5a0df6cc7e90), UINT64_C(0xdd629f9c92c097ce),
    UINT64_C(0x185ca70bc72b44ac), UINT64_C(0xd1df65d663c6fc23),
    UINT64_C(0x976e6c039ee0b81a), UINT64_C(0x2105457e446ceca8),
    UINT64_C(0xeef103bb5d8e61fa), UINT64_C(0xfd9697b294838197),
    UINT64_C(0x4a8e8537db03302f), UINT64_C(0x2a678d2dfb9f6a95),
    UINT64_C(0x8afe7381f8b8696c), UINT64_C(0x8ac77246c07f4214),
    UINT64_C(0xc5f4158fbdc75ec4), UINT64_C(0x75446fa78f11bb80),
    UINT64_C(0x52de75b7aee488bc), UINT64_C(0x82b8001e98a6a3f4),
    UINT64_C(0x8ef48f33a9a36315), UINT64_C(0xaa5f5624d5b7f989),
    UINT64_C(0xb6f1ed207c5ae0fd), UINT64_C(0x36cae95a06422c36),
    UINT64_C(0xce2935434efe983d), UINT64_C(0x533af974739a4ba7),
    UINT64_C(0xd0f51f596f4e8186), UINT64_C(0x0e9dad81afd85a9f),
    UINT64_C(0xa7050667ee34626a), UINT64_C(0x8b0b28be6eb91727),
    UINT64_C(0x47740726c680103f), UINT64_C(0xe0a07e6fc67e487b),
    UINT64_C(0x0d550aa54af8a4c0), UINT64_C(0x91e3e79f978ef19e),
    UINT64_C(0x8676728150608dd4), UINT64_C(0x7e9e5a41f3e5b062),
    UINT64_C(0xfc9f1fec4054207a), UINT64_C(0xe3e41a00cef4c984),
    UINT64_C(0x4fd794f59dfa95d8), UINT64_C(0x552e7e1124c354a5),
    UINT64_C(0x5bdf7228bdfe6e28), UINT64_C(0x78f57fe20fa5c4b2),
    UINT64_C(0x05897cefee49d32e), UINT64_C(0x447e9385eb28597f),
    UINT64_C(0x705f6937b324314a), UINT64_C(0x5e8628f11dd6e465),
    UINT64_C(0xc71b770451b920e7), UINT64_C(0x74fe43e823d4878a),
    UINT64_C(0x7d29e8a3927694f2), UINT64_C(0xddcb7a099b30d9c1),
    UINT64_C(0x1d1b30fb5bdc1be0), UINT64_C(0xda24494ff29c82bf),
    UINT64_C(0xa4e7ba31b470bfff), UINT64_C(0x0d324405def8bc48),
    UINT64_C(0x3baefc3253bbd339), UINT64_C(0x459fc3c1e0298ba0),
    UINT64_C(0xe5c905fdf7ae090f), UINT64_C(0x947034124290f134),
    UINT64_C(0xa271b701e344ed95), UINT64_C(0xe93b8e364f2f984a),
    UINT64_C(0x88401d63a06cf615), UINT64_C(0x47c1444b8752afff),
    UINT64_C(0x7ebb4af1e20ac630), UINT64_C(0x4670b6c5cc6e8ce6),
    UINT64_C(0xa4d5a456bd4fca00), UINT64_C(0xda9d844bc83e18ae),
    UINT64_C(0x7357ce453064d1ad), UINT64_C(0xe8a6ce68145c2567),
    UINT64_C(0xa3da8cf2cb0ee116), UINT64_C(0x33e906589a94999a),
    UINT64_C(0x1f60b220c26f847b), UINT64_C(0xd1ceac7fa0d18518),
    UINT64_C(0x32595ba18ddd19d3), UINT64_C(0x509a1cc0aaa5b446),
    UINT64_C(0x9f3d6367e4046bba), UINT64_C(0xf6ca19ab0b56ee7e),
    UINT64_C(0x1fb179eaa9282174), UINT64_C(0xe9bdf7353b3651ee),
    UINT64_C(0x1d57ac5a7550d376), UINT64_C(0x3a46c2fea37d7001),
    UINT64_C(0xf735c1af98a4d842), UINT64_C(0x78edec209e6b6779),
    UINT64_C(0x41836315ea3adba8), UINT64_C(0xfac33b4d32832c83),
    UINT64_C(0xa7403b1f1c2747f3), UINT64_C(0x5940f034b72d769a),
    UINT64_C(0xe73e4e6cd2214ffd), UINT64_C(0xb8fd8d39dc5759ef),
    UINT64_C(0x8d9b0c492b49ebda), UINT64_C(0x5ba2d74968f3700d),
    UINT64_C(0x7d3baed07a8d5584), UINT64_C(0xf5a5e9f0e4f88e65),
    UINT64_C(0xa0b8a2f436103b53), UINT64_C(0x0ca8079e753eec5a),
    UINT64_C(0x9168949256e8884f), UINT64_C(0x5bb05c55f8babc4c),
    UINT64_C(0xe3bb3b99f387947b), UINT64_C(0x75daf4d6726b1c5d),
    UINT64_C(0x64aeac28dc34b36d), UINT64_C(0x6c34a550b828db71),
    UINT64_C(0xf861e2f2108d512a), UINT64_C(0xe3db643359dd75fc),
    UINT64_C(0x1cacbcf143ce3fa2), UINT64_C(0x67bbd13c02e843b0),
    UINT64_C(0x330a5bca8829a175), UINT64_C(0x7f34194db416535c),
    UINT64_C(0x923b94c30e794d1e), UINT64_C(0x797475d7b6eeaf3f),
    UINT64_C(0xeaa8d4f7be1a3921), UINT64_C(0x5cf47e094c232751),
    UINT64_C(0x26a32453ba323cd2), UINT64_C(0x44a3174a6da6d5ad),
    UINT64_C(0xb51d3ea6aff2c908), UINT64_C(0x83593d98916b3c56),
    UINT64_C(0x4cf87ca17286604d), UINT64_C(0x46e23ecc086ec7f6),
    UINT64_C(0x2f9833b3b1bc765e), UINT64_C(0x2bd666a5efc4e62a),
    UINT64_C(0x06f4b6e8bec1d436), UINT64_C(0x74ee8215bcef2163),
    UINT64_C(0xfdc14e0df453c969), UINT64_C(0xa77d5ac406585826),
    UINT64_C(0x7ec1141606e0fa16), UINT64_C(0x7e90af3d28639d3f),
    UINT64_C(0xd2c9f2e3009bd20c), UINT64_C(0x5faace30b7d40c30),
    UINT64_C(0x742a5116f2e03298), UINT64_C(0x0deb30d8e3cef89a),
    UINT64_C(0x4bc59e7bb5f17992), UINT64_C(0xff51e66e048668d3),
    UINT64_C(0x9b234d57e6966731), UINT64_C(0xcce6a6f3170a7505),
    UINT64_C(0xb17681d913326cce), UINT64_C(0x3c175284f805a262),
    UINT64_C(0xf42bcbb378471547), UINT64_C(0xff46548223936a48),
    UINT64_C(0x38df58074e5e6565), UINT64_C(0xf2fc7c89fc86508e),
    UINT64_C(0x31702e44d00bca86), UINT64_C(0xf04009a23078474e),
    UINT64_C(0x65a0ee39d1f73883), UINT64_C(0xf75ee937e42c3abd),
    UINT64_C(0x2197b2260113f86f), UINT64_C(0xa344edd1ef9fdee7),
    UINT64_C(0x8ba0df15762592d9), UINT64_C(0x3c85f7f612dc42be),
    UINT64_C(0xd8a7ec7cab27b07e), UINT64_C(0x538d7ddaaa3ea8de),
    UINT64_C(0xaa25ce93bd0269d8), UINT64_C(0x5af643fd1a7308f9),
    UINT64_C(0xc05fefda174a19a5), UINT64_C(0x974d66334cfd216a),
    UINT64_C(0x35b49831db411570), UINT64_C(0xea1e0fbbedcd549b),
    UINT64_C(0x9ad063a151974072), UINT64_C(0xf6759dbf91476fe2)
};

/* H(0) for a 512-bit digest: the state after one block of zeros from the
 * 1024-bit word whose first two bytes are 512. Stored, as every implementation
 * does; the test vectors would fail without it. Big-endian, like the
 * constants. */
static const uint64_t jh512_iv[16] = {
    UINT64_C(0x6fd14b963e00aa17), UINT64_C(0x636a2e057a15d543),
    UINT64_C(0x8a225e8d0c97ef0b), UINT64_C(0xe9341259f2b3c361),
    UINT64_C(0x891da0c1536f801e), UINT64_C(0x2aa9056bea2b6d80),
    UINT64_C(0x588eccdb2075baa6), UINT64_C(0xa90f3a76baf83bf7),
    UINT64_C(0x0169e60541e34a69), UINT64_C(0x46b58a8e2e6fe65a),
    UINT64_C(0x1047a7d0c1843c24), UINT64_C(0x3b6e71b12d5ac199),
    UINT64_C(0xcf57f6ec9db1f856), UINT64_C(0xa706887c5716b156),
    UINT64_C(0xe3c2fcdfe68517fb), UINT64_C(0x545a4678cc8cdd4b)
};

static uint64_t bswap64_local( uint64_t x )
{
    uint64_t v = 0;
    int i;

    for ( i = 0; i < 8; i++ ) {
        v = ( v << 8 ) | ( x & 0xff );
        x >>= 8;
    }
    return v;
}

static uint64_t le64dec_local( const unsigned char *b )
{
    uint64_t v = 0;
    int i;

    for ( i = 7; i >= 0; i-- )
        v = ( v << 8 ) | b[i];
    return v;
}

static void le64enc_local( unsigned char *b, uint64_t v )
{
    int i;

    for ( i = 0; i < 8; i++ ) {
        b[i] = (unsigned char)v;
        v >>= 8;
    }
}

/* The two 4-bit S-boxes on bit planes x0..x3, S1 where c has a 1 and S0
 * where it has a 0. */
static void jh_sbox( uint64_t *x0, uint64_t *x1, uint64_t *x2, uint64_t *x3,
                     uint64_t c )
{
    uint64_t t;

    *x3 = ~*x3;
    *x0 ^= c & ~*x2;
    t = c ^ ( *x0 & *x1 );
    *x0 ^= *x2 & *x3;
    *x3 ^= ~*x1 & *x2;
    *x1 ^= *x0 & *x2;
    *x2 ^= *x0 & ~*x3;
    *x0 ^= *x1 | *x3;
    *x3 ^= *x1 & *x2;
    *x1 ^= t & *x0;
    *x2 ^= t;
}

/* The MDS code L on two nibbles' bit planes, a0..a3 and b0..b3. */
static void jh_linear( uint64_t *a0, uint64_t *a1, uint64_t *a2, uint64_t *a3,
                       uint64_t *b0, uint64_t *b1, uint64_t *b2, uint64_t *b3 )
{
    *b0 ^= *a1;
    *b1 ^= *a2;
    *b2 ^= *a3 ^ *a0;
    *b3 ^= *a0;
    *a0 ^= *b1;
    *a1 ^= *b2;
    *a2 ^= *b3 ^ *b0;
    *a3 ^= *b0;
}

/* Swaps of adjacent groups of 1, 2, 4, 8, 16 and 32 bits; the seventh swap,
 * of the two halves of a 128-bit word, is done by the caller. */
static uint64_t jh_swap( uint64_t x, int k )
{
    static const uint64_t mask[6] = {
        UINT64_C(0x5555555555555555), UINT64_C(0x3333333333333333),
        UINT64_C(0x0F0F0F0F0F0F0F0F), UINT64_C(0x00FF00FF00FF00FF),
        UINT64_C(0x0000FFFF0000FFFF), UINT64_C(0x00000000FFFFFFFF)
    };
    int n = 1 << k;

    return ( ( x & mask[k] ) << n ) | ( ( x >> n ) & mask[k] );
}

/* E8: 42 rounds, each the S-boxes, L, and permutation r mod 7 on the odd
 * 128-bit words. */
static void jh_e8( uint64_t h[16] )
{
    int r, i;

    for ( r = 0; r < 42; r++ ) {
        uint64_t c[4];

        for ( i = 0; i < 4; i++ )
            c[i] = bswap64_local( jh512_c[4 * r + i] );

        /* Even words 0, 2, 4, 6, then odd 1, 3, 5, 7; each a high and a
         * low half. */
        for ( i = 0; i < 2; i++ ) {
            jh_sbox( &h[0 + i], &h[4 + i], &h[8 + i], &h[12 + i], c[i] );
            jh_sbox( &h[2 + i], &h[6 + i], &h[10 + i], &h[14 + i], c[2 + i] );
            jh_linear( &h[0 + i], &h[4 + i], &h[8 + i], &h[12 + i],
                       &h[2 + i], &h[6 + i], &h[10 + i], &h[14 + i] );
        }

        for ( i = 2; i < 16; i += 4 ) {
            if ( r % 7 == 6 ) {
                uint64_t t = h[i];
                h[i] = h[i + 1];
                h[i + 1] = t;
            } else {
                h[i] = jh_swap( h[i], r % 7 );
                h[i + 1] = jh_swap( h[i + 1], r % 7 );
            }
        }
    }
}

/* F8: one 64-byte block. */
static void jh_f8( uint64_t h[16], const unsigned char block[64] )
{
    uint64_t m[8];
    int i;

    for ( i = 0; i < 8; i++ ) {
        m[i] = le64dec_local( block + 8 * i );
        h[i] ^= m[i];
    }
    jh_e8( h );
    for ( i = 0; i < 8; i++ )
        h[8 + i] ^= m[i];
}

void jh512_full( void *hash, const void *data, size_t len )
{
    const unsigned char *in = (const unsigned char *)data;
    unsigned char *out = (unsigned char *)hash;
    unsigned char last[64];
    uint64_t h[16];
    uint64_t bits = 8 * (uint64_t)len;
    int i;

    for ( i = 0; i < 16; i++ )
        h[i] = bswap64_local( jh512_iv[i] );

    for ( ; len >= 64; in += 64, len -= 64 )
        jh_f8( h, in );

    /* 0x80, zeros, and the 128-bit length big-endian in the last 16 bytes,
     * with at least 384 zero bits between: a whole block after a message
     * that ends on a block boundary, otherwise the rest of this block and
     * one more. */
    memset( last, 0, sizeof last );
    memcpy( last, in, len );
    last[len] = 0x80;
    if ( len != 0 ) {
        jh_f8( h, last );
        memset( last, 0, sizeof last );
    }
    for ( i = 0; i < 8; i++ )
        last[63 - i] = (unsigned char)( bits >> ( 8 * i ) );
    jh_f8( h, last );

    for ( i = 0; i < 8; i++ )
        le64enc_local( out + 8 * i, h[8 + i] );
}
