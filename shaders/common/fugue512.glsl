// Fugue-512, the round 2 SHA-3 submission: one 32-bit word at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state is 36 big-endian words, s[0] being column 0. The caller owns
// padding and output. src/core/fugue512.c is the scalar reference. SMIX reads
// four 256-word tables from workgroup memory: call fugue512_table_load() first.

#ifndef VKMINER_SHADERS_COMMON_FUGUE512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_FUGUE512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint kFugue512Iv[16] = uint[16](
    0x8807a57eu, 0xe616af75u, 0xc5d3e4dbu, 0xac9ab027u,
    0xd915f117u, 0xb6eecc54u, 0x06e8020bu, 0x4a92efd1u,
    0xaac6e2c9u, 0xddb21398u, 0xcae65838u, 0x437f203fu,
    0x25ea78e7u, 0x951fddd6u, 0xda6ed11du, 0xe13e3567u);

// Mix0[x] is the column S(x) times (1, 1, 7, 4), most significant byte
// first; the other three tables are its rotations.
const uint kFugue512Mix0[256] = uint[256](
    0x63633297u, 0x7c7c6febu, 0x77775ec7u, 0x7b7b7af7u, 0xf2f2e8e5u, 0x6b6b0ab7u,
    0x6f6f16a7u, 0xc5c56d39u, 0x303090c0u, 0x01010704u, 0x67672e87u, 0x2b2bd1acu,
    0xfefeccd5u, 0xd7d71371u, 0xabab7c9au, 0x767659c3u, 0xcaca4005u, 0x8282a33eu,
    0xc9c94909u, 0x7d7d68efu, 0xfafad0c5u, 0x5959947fu, 0x4747ce07u, 0xf0f0e6edu,
    0xadad6e82u, 0xd4d41a7du, 0xa2a243beu, 0xafaf608au, 0x9c9cf946u, 0xa4a451a6u,
    0x727245d3u, 0xc0c0762du, 0xb7b728eau, 0xfdfdc5d9u, 0x9393d47au, 0x2626f298u,
    0x363682d8u, 0x3f3fbdfcu, 0xf7f7f3f1u, 0xcccc521du, 0x34348cd0u, 0xa5a556a2u,
    0xe5e58db9u, 0xf1f1e1e9u, 0x71714cdfu, 0xd8d83e4du, 0x313197c4u, 0x15156b54u,
    0x04041c10u, 0xc7c76331u, 0x2323e98cu, 0xc3c37f21u, 0x18184860u, 0x9696cf6eu,
    0x05051b14u, 0x9a9aeb5eu, 0x0707151cu, 0x12127e48u, 0x8080ad36u, 0xe2e298a5u,
    0xebeba781u, 0x2727f59cu, 0xb2b233feu, 0x757550cfu, 0x09093f24u, 0x8383a43au,
    0x2c2cc4b0u, 0x1a1a4668u, 0x1b1b416cu, 0x6e6e11a3u, 0x5a5a9d73u, 0xa0a04db6u,
    0x5252a553u, 0x3b3ba1ecu, 0xd6d61475u, 0xb3b334fau, 0x2929dfa4u, 0xe3e39fa1u,
    0x2f2fcdbcu, 0x8484b126u, 0x5353a257u, 0xd1d10169u, 0x00000000u, 0xededb599u,
    0x2020e080u, 0xfcfcc2ddu, 0xb1b13af2u, 0x5b5b9a77u, 0x6a6a0db3u, 0xcbcb4701u,
    0xbebe17ceu, 0x3939afe4u, 0x4a4aed33u, 0x4c4cff2bu, 0x5858937bu, 0xcfcf5b11u,
    0xd0d0066du, 0xefefbb91u, 0xaaaa7b9eu, 0xfbfbd7c1u, 0x4343d217u, 0x4d4df82fu,
    0x333399ccu, 0x8585b622u, 0x4545c00fu, 0xf9f9d9c9u, 0x02020e08u, 0x7f7f66e7u,
    0x5050ab5bu, 0x3c3cb4f0u, 0x9f9ff04au, 0xa8a87596u, 0x5151ac5fu, 0xa3a344bau,
    0x4040db1bu, 0x8f8f800au, 0x9292d37eu, 0x9d9dfe42u, 0x3838a8e0u, 0xf5f5fdf9u,
    0xbcbc19c6u, 0xb6b62feeu, 0xdada3045u, 0x2121e784u, 0x10107040u, 0xffffcbd1u,
    0xf3f3efe1u, 0xd2d20865u, 0xcdcd5519u, 0x0c0c2430u, 0x1313794cu, 0xececb29du,
    0x5f5f8667u, 0x9797c86au, 0x4444c70bu, 0x1717655cu, 0xc4c46a3du, 0xa7a758aau,
    0x7e7e61e3u, 0x3d3db3f4u, 0x6464278bu, 0x5d5d886fu, 0x19194f64u, 0x737342d7u,
    0x60603b9bu, 0x8181aa32u, 0x4f4ff627u, 0xdcdc225du, 0x2222ee88u, 0x2a2ad6a8u,
    0x9090dd76u, 0x88889516u, 0x4646c903u, 0xeeeebc95u, 0xb8b805d6u, 0x14146c50u,
    0xdede2c55u, 0x5e5e8163u, 0x0b0b312cu, 0xdbdb3741u, 0xe0e096adu, 0x32329ec8u,
    0x3a3aa6e8u, 0x0a0a3628u, 0x4949e43fu, 0x06061218u, 0x2424fc90u, 0x5c5c8f6bu,
    0xc2c27825u, 0xd3d30f61u, 0xacac6986u, 0x62623593u, 0x9191da72u, 0x9595c662u,
    0xe4e48abdu, 0x797974ffu, 0xe7e783b1u, 0xc8c84e0du, 0x373785dcu, 0x6d6d18afu,
    0x8d8d8e02u, 0xd5d51d79u, 0x4e4ef123u, 0xa9a97292u, 0x6c6c1fabu, 0x5656b943u,
    0xf4f4fafdu, 0xeaeaa085u, 0x6565208fu, 0x7a7a7df3u, 0xaeae678eu, 0x08083820u,
    0xbaba0bdeu, 0x787873fbu, 0x2525fb94u, 0x2e2ecab8u, 0x1c1c5470u, 0xa6a65faeu,
    0xb4b421e6u, 0xc6c66435u, 0xe8e8ae8du, 0xdddd2559u, 0x747457cbu, 0x1f1f5d7cu,
    0x4b4bea37u, 0xbdbd1ec2u, 0x8b8b9c1au, 0x8a8a9b1eu, 0x70704bdbu, 0x3e3ebaf8u,
    0xb5b526e2u, 0x66662983u, 0x4848e33bu, 0x0303090cu, 0xf6f6f4f5u, 0x0e0e2a38u,
    0x61613c9fu, 0x35358bd4u, 0x5757be47u, 0xb9b902d2u, 0x8686bf2eu, 0xc1c17129u,
    0x1d1d5374u, 0x9e9ef74eu, 0xe1e191a9u, 0xf8f8decdu, 0x9898e556u, 0x11117744u,
    0x696904bfu, 0xd9d93949u, 0x8e8e870eu, 0x9494c166u, 0x9b9bec5au, 0x1e1e5a78u,
    0x8787b82au, 0xe9e9a989u, 0xcece5c15u, 0x5555b04fu, 0x2828d8a0u, 0xdfdf2b51u,
    0x8c8c8906u, 0xa1a14ab2u, 0x89899212u, 0x0d0d2334u, 0xbfbf10cau, 0xe6e684b5u,
    0x4242d513u, 0x686803bbu, 0x4141dc1fu, 0x9999e252u, 0x2d2dc3b4u, 0x0f0f2d3cu,
    0xb0b03df6u, 0x5454b74bu, 0xbbbb0cdau, 0x16166258u);

shared uint fugue_mix[1024];

// Fills the tables, lane `lane` of `width`, and waits for the workgroup.
void fugue512_table_load(uint lane, uint width)
{
    for (uint i = lane; i < 256u; i += width) {
        uint t = kFugue512Mix0[i];
        fugue_mix[i] = t;
        fugue_mix[256u + i] = rotr32(t, 8u);
        fugue_mix[512u + i] = rotl32(t, 16u);
        fugue_mix[768u + i] = rotl32(t, 8u);
    }
    barrier();
}

#define FUGUE_MIX(r, x) fugue_mix[256u * (r) + (x)]

// Columns 0..3 through the S-box and the super-mix.
void fugue512_smix(inout uint s[36])
{
    uint x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3];
    uint t;
    uint r0 = 0u, r1 = 0u, r2 = 0u, r3 = 0u;

    uint c0 = FUGUE_MIX(0u, x0 >> 24);
    t = FUGUE_MIX(1u, (x0 >> 16) & 0xffu); c0 ^= t; r1 ^= t;
    t = FUGUE_MIX(2u, (x0 >> 8) & 0xffu);  c0 ^= t; r2 ^= t;
    t = FUGUE_MIX(3u, x0 & 0xffu);         c0 ^= t; r3 ^= t;

    t = FUGUE_MIX(0u, x1 >> 24);           uint c1 = t; r0 ^= t;
    t = FUGUE_MIX(1u, (x1 >> 16) & 0xffu); c1 ^= t;
    t = FUGUE_MIX(2u, (x1 >> 8) & 0xffu);  c1 ^= t; r2 ^= t;
    t = FUGUE_MIX(3u, x1 & 0xffu);         c1 ^= t; r3 ^= t;

    t = FUGUE_MIX(0u, x2 >> 24);           uint c2 = t; r0 ^= t;
    t = FUGUE_MIX(1u, (x2 >> 16) & 0xffu); c2 ^= t; r1 ^= t;
    t = FUGUE_MIX(2u, (x2 >> 8) & 0xffu);  c2 ^= t;
    t = FUGUE_MIX(3u, x2 & 0xffu);         c2 ^= t; r3 ^= t;

    t = FUGUE_MIX(0u, x3 >> 24);           uint c3 = t; r0 ^= t;
    t = FUGUE_MIX(1u, (x3 >> 16) & 0xffu); c3 ^= t; r1 ^= t;
    t = FUGUE_MIX(2u, (x3 >> 8) & 0xffu);  c3 ^= t; r2 ^= t;
    t = FUGUE_MIX(3u, x3 & 0xffu);         c3 ^= t;

    s[0] = ((c0 ^ r0) & 0xff000000u) | ((c1 ^ r1) & 0x00ff0000u)
         | ((c2 ^ r2) & 0x0000ff00u) | ((c3 ^ r3) & 0x000000ffu);
    s[1] = ((c1 ^ (r0 << 8)) & 0xff000000u) | ((c2 ^ (r1 << 8)) & 0x00ff0000u)
         | ((c3 ^ (r2 << 8)) & 0x0000ff00u) | ((c0 ^ (r3 >> 24)) & 0x000000ffu);
    s[2] = ((c2 ^ (r0 << 16)) & 0xff000000u) | ((c3 ^ (r1 << 16)) & 0x00ff0000u)
         | ((c0 ^ (r2 >> 16)) & 0x0000ff00u) | ((c1 ^ (r3 >> 16)) & 0x000000ffu);
    s[3] = ((c3 ^ (r0 << 24)) & 0xff000000u) | ((c0 ^ (r1 >> 8)) & 0x00ff0000u)
         | ((c1 ^ (r2 >> 8)) & 0x0000ff00u) | ((c2 ^ (r3 >> 8)) & 0x000000ffu);
}

#undef FUGUE_MIX

// Rotates the state right by n columns: column c moves to c + n.
void fugue512_ror(inout uint s[36], uint n)
{
    uint t[36] = s;
    for (uint c = 0u; c < 36u; c++)
        s[c] = t[(c + 36u - n) % 36u];
}

// ROR3, CMIX and SMIX: the sub-round both the input and the final rounds use.
void fugue512_sub(inout uint s[36])
{
    fugue512_ror(s, 3u);
    s[0] ^= s[4];
    s[1] ^= s[5];
    s[2] ^= s[6];
    s[18] ^= s[4];
    s[19] ^= s[5];
    s[20] ^= s[6];
    fugue512_smix(s);
}

// One message word: TIX, then four sub-rounds.
void fugue512_word(inout uint s[36], uint w)
{
    s[22] ^= s[0];
    s[0] = w;
    s[8] ^= s[0];
    s[1] ^= s[24];
    s[4] ^= s[27];
    s[7] ^= s[30];
    [[unroll]] for (uint r = 0u; r < 4u; r++)
        fugue512_sub(s);
}

// After the last word: 32 sub-rounds, then the 13 final rounds, unrolled.
void fugue512_final(inout uint s[36])
{
    [[unroll]] for (uint r = 0u; r < 32u; r++)
        fugue512_sub(s);

    [[unroll]] for (uint r = 0u; r < 13u; r++) {
        s[4] ^= s[0]; s[9] ^= s[0]; s[18] ^= s[0]; s[27] ^= s[0];
        fugue512_ror(s, 9u);
        fugue512_smix(s);
        s[4] ^= s[0]; s[10] ^= s[0]; s[18] ^= s[0]; s[27] ^= s[0];
        fugue512_ror(s, 9u);
        fugue512_smix(s);
        s[4] ^= s[0]; s[10] ^= s[0]; s[19] ^= s[0]; s[27] ^= s[0];
        fugue512_ror(s, 9u);
        fugue512_smix(s);
        s[4] ^= s[0]; s[10] ^= s[0]; s[19] ^= s[0]; s[28] ^= s[0];
        fugue512_ror(s, 8u);
        fugue512_smix(s);
    }
    s[4] ^= s[0]; s[9] ^= s[0]; s[18] ^= s[0]; s[27] ^= s[0];
}

#endif  // VKMINER_SHADERS_COMMON_FUGUE512_GLSL_INCLUDED
