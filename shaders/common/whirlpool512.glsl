// Whirlpool, the final ISO version, over a 64- or 80-byte message.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state is eight rows of eight bytes, each row a uvec2 holding the row's
// bytes as a little-endian 64-bit value (.x the low half), so message and
// digest words are little-endian reads like every other x11-family stage.
// Nothing here adds, so the pair needs no 64-bit build. One table in
// workgroup memory, rotated per column: call whirlpool512_table_load() first.
// src/core/whirlpool512.c is the scalar reference; the constants below were
// generated from it.

#ifndef VKMINER_SHADERS_COMMON_WHIRLPOOL512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_WHIRLPOOL512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

// T0[x] is S(x) times the MixRows row (1, 1, 4, 1, 8, 5, 2, 9), byte k of the
// row in byte k of the value; T_n is T0 rotated left by n bytes. As low, high
// pairs.
const uint kWhirlpool512T0[512] = uint[512](
    0x18601818u, 0xd83078c0u, 0x238c2323u, 0x2646af05u, 0xc63fc6c6u, 0xb891f97eu,
    0xe887e8e8u, 0xfbcd6f13u, 0x87268787u, 0xcb13a14cu, 0xb8dab8b8u, 0x116d62a9u,
    0x01040101u, 0x09020508u, 0x4f214f4fu, 0x0d9e6e42u, 0x36d83636u, 0x9b6ceeadu,
    0xa6a2a6a6u, 0xff510459u, 0xd26fd2d2u, 0x0cb9bddeu, 0xf5f3f5f5u, 0x0ef706fbu,
    0x79f97979u, 0x96f280efu, 0x6fa16f6fu, 0x30dece5fu, 0x917e9191u, 0x6d3feffcu,
    0x52555252u, 0xf8a407aau, 0x609d6060u, 0x47c0fd27u, 0xbccabcbcu, 0x35657689u,
    0x9b569b9bu, 0x372bcdacu, 0x8e028e8eu, 0x8a018c04u, 0xa3b6a3a3u, 0xd25b1571u,
    0x0c300c0cu, 0x6c183c60u, 0x7bf17b7bu, 0x84f68affu, 0x35d43535u, 0x806ae1b5u,
    0x1d741d1du, 0xf53a69e8u, 0xe0a7e0e0u, 0xb3dd4753u, 0xd77bd7d7u, 0x21b3acf6u,
    0xc22fc2c2u, 0x9c99ed5eu, 0x2eb82e2eu, 0x435c966du, 0x4b314b4bu, 0x29967a62u,
    0xfedffefeu, 0x5de121a3u, 0x57415757u, 0xd5ae1682u, 0x15541515u, 0xbd2a41a8u,
    0x77c17777u, 0xe8eeb69fu, 0x37dc3737u, 0x926eeba5u, 0xe5b3e5e5u, 0x9ed7567bu,
    0x9f469f9fu, 0x1323d98cu, 0xf0e7f0f0u, 0x23fd17d3u, 0x4a354a4au, 0x20947f6au,
    0xda4fdadau, 0x44a9959eu, 0x587d5858u, 0xa2b025fau, 0xc903c9c9u, 0xcf8fca06u,
    0x29a42929u, 0x7c528d55u, 0x0a280a0au, 0x5a142250u, 0xb1feb1b1u, 0x507f4fe1u,
    0xa0baa0a0u, 0xc95d1a69u, 0x6bb16b6bu, 0x14d6da7fu, 0x852e8585u, 0xd917ab5cu,
    0xbdcebdbdu, 0x3c677381u, 0x5d695d5du, 0x8fba34d2u, 0x10401010u, 0x90205080u,
    0xf4f7f4f4u, 0x07f503f3u, 0xcb0bcbcbu, 0xdd8bc016u, 0x3ef83e3eu, 0xd37cc6edu,
    0x05140505u, 0x2d0a1128u, 0x67816767u, 0x78cee61fu, 0xe4b7e4e4u, 0x97d55373u,
    0x279c2727u, 0x024ebb25u, 0x41194141u, 0x73825832u, 0x8b168b8bu, 0xa70b9d2cu,
    0xa7a6a7a7u, 0xf6530151u, 0x7de97d7du, 0xb2fa94cfu, 0x956e9595u, 0x4937fbdcu,
    0xd847d8d8u, 0x56ad9f8eu, 0xfbcbfbfbu, 0x70eb308bu, 0xee9feeeeu, 0xcdc17123u,
    0x7ced7c7cu, 0xbbf891c7u, 0x66856666u, 0x71cce317u, 0xdd53ddddu, 0x7ba78ea6u,
    0x175c1717u, 0xaf2e4bb8u, 0x47014747u, 0x458e4602u, 0x9e429e9eu, 0x1a21dc84u,
    0xca0fcacau, 0xd489c51eu, 0x2db42d2du, 0x585a9975u, 0xbfc6bfbfu, 0x2e637991u,
    0x071c0707u, 0x3f0e1b38u, 0xad8eadadu, 0xac472301u, 0x5a755a5au, 0xb0b42feau,
    0x83368383u, 0xef1bb56cu, 0x33cc3333u, 0xb666ff85u, 0x63916363u, 0x5cc6f23fu,
    0x02080202u, 0x12040a10u, 0xaa92aaaau, 0x93493839u, 0x71d97171u, 0xdee2a8afu,
    0xc807c8c8u, 0xc68dcf0eu, 0x19641919u, 0xd1327dc8u, 0x49394949u, 0x3b927072u,
    0xd943d9d9u, 0x5faf9a86u, 0xf2eff2f2u, 0x31f91dc3u, 0xe3abe3e3u, 0xa8db484bu,
    0x5b715b5bu, 0xb9b62ae2u, 0x881a8888u, 0xbc0d9234u, 0x9a529a9au, 0x3e29c8a4u,
    0x26982626u, 0x0b4cbe2du, 0x32c83232u, 0xbf64fa8du, 0xb0fab0b0u, 0x597d4ae9u,
    0xe983e9e9u, 0xf2cf6a1bu, 0x0f3c0f0fu, 0x771e3378u, 0xd573d5d5u, 0x33b7a6e6u,
    0x803a8080u, 0xf41dba74u, 0xbec2bebeu, 0x27617c99u, 0xcd13cdcdu, 0xeb87de26u,
    0x34d03434u, 0x8968e4bdu, 0x483d4848u, 0x3290757au, 0xffdbffffu, 0x54e324abu,
    0x7af57a7au, 0x8df48ff7u, 0x907a9090u, 0x643deaf4u, 0x5f615f5fu, 0x9dbe3ec2u,
    0x20802020u, 0x3d40a01du, 0x68bd6868u, 0x0fd0d567u, 0x1a681a1au, 0xca3472d0u,
    0xae82aeaeu, 0xb7412c19u, 0xb4eab4b4u, 0x7d755ec9u, 0x544d5454u, 0xcea8199au,
    0x93769393u, 0x7f3be5ecu, 0x22882222u, 0x2f44aa0du, 0x648d6464u, 0x63c8e907u,
    0xf1e3f1f1u, 0x2aff12dbu, 0x73d17373u, 0xcce6a2bfu, 0x12481212u, 0x82245a90u,
    0x401d4040u, 0x7a805d3au, 0x08200808u, 0x48102840u, 0xc32bc3c3u, 0x959be856u,
    0xec97ececu, 0xdfc57b33u, 0xdb4bdbdbu, 0x4dab9096u, 0xa1bea1a1u, 0xc05f1f61u,
    0x8d0e8d8du, 0x9107831cu, 0x3df43d3du, 0xc87ac9f5u, 0x97669797u, 0x5b33f1ccu,
    0x00000000u, 0x00000000u, 0xcf1bcfcfu, 0xf983d436u, 0x2bac2b2bu, 0x6e568745u,
    0x76c57676u, 0xe1ecb397u, 0x82328282u, 0xe619b064u, 0xd67fd6d6u, 0x28b1a9feu,
    0x1b6c1b1bu, 0xc33677d8u, 0xb5eeb5b5u, 0x74775bc1u, 0xaf86afafu, 0xbe432911u,
    0x6ab56a6au, 0x1dd4df77u, 0x505d5050u, 0xeaa00dbau, 0x45094545u, 0x578a4c12u,
    0xf3ebf3f3u, 0x38fb18cbu, 0x30c03030u, 0xad60f09du, 0xef9befefu, 0xc4c3742bu,
    0x3ffc3f3fu, 0xda7ec3e5u, 0x55495555u, 0xc7aa1c92u, 0xa2b2a2a2u, 0xdb591079u,
    0xea8feaeau, 0xe9c96503u, 0x65896565u, 0x6acaec0fu, 0xbad2babau, 0x036968b9u,
    0x2fbc2f2fu, 0x4a5e9365u, 0xc027c0c0u, 0x8e9de74eu, 0xde5fdedeu, 0x60a181beu,
    0x1c701c1cu, 0xfc386ce0u, 0xfdd3fdfdu, 0x46e72ebbu, 0x4d294d4du, 0x1f9a6452u,
    0x92729292u, 0x7639e0e4u, 0x75c97575u, 0xfaeabc8fu, 0x06180606u, 0x360c1e30u,
    0x8a128a8au, 0xae099824u, 0xb2f2b2b2u, 0x4b7940f9u, 0xe6bfe6e6u, 0x85d15963u,
    0x0e380e0eu, 0x7e1c3670u, 0x1f7c1f1fu, 0xe73e63f8u, 0x62956262u, 0x55c4f737u,
    0xd477d4d4u, 0x3ab5a3eeu, 0xa89aa8a8u, 0x814d3229u, 0x96629696u, 0x5231f4c4u,
    0xf9c3f9f9u, 0x62ef3a9bu, 0xc533c5c5u, 0xa397f666u, 0x25942525u, 0x104ab135u,
    0x59795959u, 0xabb220f2u, 0x842a8484u, 0xd015ae54u, 0x72d57272u, 0xc5e4a7b7u,
    0x39e43939u, 0xec72ddd5u, 0x4c2d4c4cu, 0x1698615au, 0x5e655e5eu, 0x94bc3bcau,
    0x78fd7878u, 0x9ff085e7u, 0x38e03838u, 0xe570d8ddu, 0x8c0a8c8cu, 0x98058614u,
    0xd163d1d1u, 0x17bfb2c6u, 0xa5aea5a5u, 0xe4570b41u, 0xe2afe2e2u, 0xa1d94d43u,
    0x61996161u, 0x4ec2f82fu, 0xb3f6b3b3u, 0x427b45f1u, 0x21842121u, 0x3442a515u,
    0x9c4a9c9cu, 0x0825d694u, 0x1e781e1eu, 0xee3c66f0u, 0x43114343u, 0x61865222u,
    0xc73bc7c7u, 0xb193fc76u, 0xfcd7fcfcu, 0x4fe52bb3u, 0x04100404u, 0x24081420u,
    0x51595151u, 0xe3a208b2u, 0x995e9999u, 0x252fc7bcu, 0x6da96d6du, 0x22dac44fu,
    0x0d340d0du, 0x651a3968u, 0xfacffafau, 0x79e93583u, 0xdf5bdfdfu, 0x69a384b6u,
    0x7ee57e7eu, 0xa9fc9bd7u, 0x24902424u, 0x1948b43du, 0x3bec3b3bu, 0xfe76d7c5u,
    0xab96ababu, 0x9a4b3d31u, 0xce1fceceu, 0xf081d13eu, 0x11441111u, 0x99225588u,
    0x8f068f8fu, 0x8303890cu, 0x4e254e4eu, 0x049c6b4au, 0xb7e6b7b7u, 0x667351d1u,
    0xeb8bebebu, 0xe0cb600bu, 0x3cf03c3cu, 0xc178ccfdu, 0x813e8181u, 0xfd1fbf7cu,
    0x946a9494u, 0x4035fed4u, 0xf7fbf7f7u, 0x1cf30cebu, 0xb9deb9b9u, 0x186f67a1u,
    0x134c1313u, 0x8b265f98u, 0x2cb02c2cu, 0x51589c7du, 0xd36bd3d3u, 0x05bbb8d6u,
    0xe7bbe7e7u, 0x8cd35c6bu, 0x6ea56e6eu, 0x39dccb57u, 0xc437c4c4u, 0xaa95f36eu,
    0x030c0303u, 0x1b060f18u, 0x56455656u, 0xdcac138au, 0x440d4444u, 0x5e88491au,
    0x7fe17f7fu, 0xa0fe9edfu, 0xa99ea9a9u, 0x884f3721u, 0x2aa82a2au, 0x6754824du,
    0xbbd6bbbbu, 0x0a6b6db1u, 0xc123c1c1u, 0x879fe246u, 0x53515353u, 0xf1a602a2u,
    0xdc57dcdcu, 0x72a58baeu, 0x0b2c0b0bu, 0x53162758u, 0x9d4e9d9du, 0x0127d39cu,
    0x6cad6c6cu, 0x2bd8c147u, 0x31c43131u, 0xa462f595u, 0x74cd7474u, 0xf3e8b987u,
    0xf6fff6f6u, 0x15f109e3u, 0x46054646u, 0x4c8c430au, 0xac8aacacu, 0xa5452609u,
    0x891e8989u, 0xb50f973cu, 0x14501414u, 0xb42844a0u, 0xe1a3e1e1u, 0xbadf425bu,
    0x16581616u, 0xa62c4eb0u, 0x3ae83a3au, 0xf774d2cdu, 0x69b96969u, 0x06d2d06fu,
    0x09240909u, 0x41122d48u, 0x70dd7070u, 0xd7e0ada7u, 0xb6e2b6b6u, 0x6f7154d9u,
    0xd067d0d0u, 0x1ebdb7ceu, 0xed93ededu, 0xd6c77e3bu, 0xcc17ccccu, 0xe285db2eu,
    0x42154242u, 0x6884572au, 0x985a9898u, 0x2c2dc2b4u, 0xa4aaa4a4u, 0xed550e49u,
    0x28a02828u, 0x7550885du, 0x5c6d5c5cu, 0x86b831dau, 0xf8c7f8f8u, 0x6bed3f93u,
    0x86228686u, 0xc211a444u);

// Round r's constant, row 0 only: S-box entries 8r..8r+7. As low, high pairs.
const uint kWhirlpool512Rc[20] = uint[20](
    0xe8c62318u, 0x4f01b887u, 0xf5d2a636u, 0x52916f79u,
    0x8e9bbc60u, 0x357b0ca3u, 0xc2d7e01du, 0x57fe4b2eu,
    0xe5377715u, 0xda4af09fu, 0x0a29c958u, 0x856ba0b1u,
    0xf4105dbdu, 0x67053ecbu, 0x8b4127e4u, 0xd8957da7u,
    0x667ceefbu, 0x9e4717ddu, 0x07bf2dcau, 0x33835aadu);

shared uvec2 whirlpool_t0[256];

// Fills the table, lane `lane` of `width`, and waits for the workgroup.
void whirlpool512_table_load(uint lane, uint width)
{
    for (uint i = lane; i < 256u; i += width)
        whirlpool_t0[i] = uvec2(kWhirlpool512T0[2u * i],
                                kWhirlpool512T0[2u * i + 1u]);
    barrier();
}

// Rotates a 64-bit pair left by n bytes, n in 0..7.
uvec2 whirlpool512_rotl_bytes(uvec2 v, uint n)
{
    if (n >= 4u)
        v = v.yx;
    uint s = 8u * (n & 3u);
    if (s == 0u)
        return v;
    return uvec2((v.x << s) | (v.y >> (32u - s)),
                 (v.y << s) | (v.x >> (32u - s)));
}

// Byte n of a row, n in 0..7.
uint whirlpool512_byte(uvec2 v, uint n)
{
    return ((n < 4u ? v.x : v.y) >> (8u * (n & 3u))) & 0xffu;
}

// The round function without its key: S-box, column n shifted down by n, and
// MixRows, as eight table lookups per row.
void whirlpool512_rho(uvec2 s[8], out uvec2 t[8])
{
    for (uint i = 0u; i < 8u; i++) {
        uvec2 r = uvec2(0u);
        for (uint n = 0u; n < 8u; n++)
            r ^= whirlpool512_rotl_bytes(
                whirlpool_t0[whirlpool512_byte(s[(i - n) & 7u], n)], n);
        t[i] = r;
    }
}

// Miyaguchi-Preneel: the block enciphered under the chaining value, which is
// itself run through the rounds as the key schedule.
void whirlpool512_compress(inout uvec2 h[8], uvec2 m[8])
{
    uvec2 k[8] = h;
    uvec2 s[8], t[8];
    for (uint i = 0u; i < 8u; i++)
        s[i] = m[i] ^ k[i];

    for (uint r = 0u; r < 10u; r++) {
        whirlpool512_rho(k, t);
        k = t;
        k[0] ^= uvec2(kWhirlpool512Rc[2u * r], kWhirlpool512Rc[2u * r + 1u]);
        whirlpool512_rho(s, t);
        for (uint i = 0u; i < 8u; i++)
            s[i] = t[i] ^ k[i];
    }

    for (uint i = 0u; i < 8u; i++)
        h[i] ^= s[i] ^ m[i];
}

// Whirlpool of the first `words` words of `msg`, 16 or 20; a constant at
// every call site. Either way two compressions: the first 64 bytes, then the
// rest with 0x80 after it and the 256-bit big-endian bit count, whose only
// nonzero bytes are the last two.
void whirlpool512_hash(uint msg[20], uint words, out uint h[16])
{
    uvec2 st[8], m[8];
    for (uint i = 0u; i < 8u; i++) {
        st[i] = uvec2(0u);
        m[i] = uvec2(msg[2u * i], msg[2u * i + 1u]);
    }
    whirlpool512_compress(st, m);

    uint w[16];
    for (uint k = 0u; k < 16u; k++)
        w[k] = k + 16u < words ? msg[k + 16u] : 0u;
    w[words - 16u] = 0x80u;
    uint bits = 32u * words;
    w[15] = ((bits >> 8) << 16) | ((bits & 0xffu) << 24);
    for (uint i = 0u; i < 8u; i++)
        m[i] = uvec2(w[2u * i], w[2u * i + 1u]);
    whirlpool512_compress(st, m);

    for (uint i = 0u; i < 8u; i++) {
        h[2u * i] = st[i].x;
        h[2u * i + 1u] = st[i].y;
    }
}

#endif  // VKMINER_SHADERS_COMMON_WHIRLPOOL512_GLSL_INCLUDED
