// JH-512, the round 3 SHA-3 submission: one 64-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The bitsliced form the designer published, over sixteen JLANEs: words 2k and
// 2k + 1 are the high and low halves of the specification's 128-bit word k,
// each read little-endian from the state's bytes. Every operation is bitwise,
// so a 2x32 lane costs exactly what a 64-bit one does, and the 32-bit swap is
// a swap of the halves. No padding here; the caller owns it.
// src/core/jh512.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_JH512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_JH512_GLSL_INCLUDED

#ifdef VKMINER_JH_INT64

// The includer declares the extension.
#define JLANE uint64_t

JLANE jlane(uint lo, uint hi) { return uint64_t(lo) | (uint64_t(hi) << 32); }
uint  jlo(JLANE x)            { return uint(x); }
uint  jhi(JLANE x)            { return uint(x >> 32); }

// Groups of 2^k bits traded with their neighbours, k < 6.
JLANE jh_swap(JLANE x, uint k, uint mask)
{
    uint n = 1u << k;
    JLANE m = jlane(mask, mask);
    return k == 5u ? (x << 32) | (x >> 32) : ((x & m) << n) | ((x >> n) & m);
}

#else

#define JLANE uvec2   // .x is the low half, .y the high half

JLANE jlane(uint lo, uint hi) { return uvec2(lo, hi); }
uint  jlo(JLANE x)            { return x.x; }
uint  jhi(JLANE x)            { return x.y; }

JLANE jh_swap(JLANE x, uint k, uint mask)
{
    uint n = 1u << k;
    return k == 5u ? x.yx : ((x & mask) << n) | ((x >> n) & mask);
}

#endif  // VKMINER_JH_INT64

// E8's round constants, four words per round: even high, even low, odd high,
// odd low. The specification's values byte-swapped, as (low, high).
const uvec2 kJh512C[168] = uvec2[168](
    uvec2(0xa2ded572u, 0x67f815dfu), uvec2(0x0a15847bu, 0x571523b7u),
    uvec2(0x90d6ab81u, 0xf6875a4du), uvec2(0xc54f9f4eu, 0x402bd1c3u),
    uvec2(0xe03a98eau, 0x9cfa455cu), uvec2(0x99d2c503u, 0x9a99b266u),
    uvec2(0xb4960266u, 0x8a53bbf2u), uvec2(0x1a1456b5u, 0x31a2db88u),
    uvec2(0x5c5aa303u, 0xdb0e199au), uvec2(0x0ab23f40u, 0x1044c187u),
    uvec2(0x8019051cu, 0x1d959e84u), uvec2(0xadeb336fu, 0xdccde75eu),
    uvec2(0x9213ba10u, 0x416bbf02u), uvec2(0x156578dcu, 0xd027bbf7u),
    uvec2(0x39812c0au, 0x5078aa37u), uvec2(0xd2bf1a3fu, 0xd3910041u),
    uvec2(0x0d5a2d42u, 0x907eccf6u), uvec2(0x9c9f62ddu, 0xce97c092u),
    uvec2(0x0ba75c18u, 0xac442bc7u), uvec2(0xd665dfd1u, 0x23fcc663u),
    uvec2(0x036c6e97u, 0x1ab8e09eu), uvec2(0x7e450521u, 0xa8ec6c44u),
    uvec2(0xbb03f1eeu, 0xfa618e5du), uvec2(0xb29796fdu, 0x97818394u),
    uvec2(0x37858e4au, 0x2f3003dbu), uvec2(0x2d8d672au, 0x956a9ffbu),
    uvec2(0x8173fe8au, 0x6c69b8f8u), uvec2(0x4672c78au, 0x14427fc0u),
    uvec2(0x8f15f4c5u, 0xc45ec7bdu), uvec2(0xa76f4475u, 0x80bb118fu),
    uvec2(0xb775de52u, 0xbc88e4aeu), uvec2(0x1e00b882u, 0xf4a3a698u),
    uvec2(0x338ff48eu, 0x1563a3a9u), uvec2(0x24565faau, 0x89f9b7d5u),
    uvec2(0x20edf1b6u, 0xfde05a7cu), uvec2(0x5ae9ca36u, 0x362c4206u),
    uvec2(0x433529ceu, 0x3d98fe4eu), uvec2(0x74f93a53u, 0xa74b9a73u),
    uvec2(0x591ff5d0u, 0x86814e6fu), uvec2(0x81ad9d0eu, 0x9f5ad8afu),
    uvec2(0x670605a7u, 0x6a6234eeu), uvec2(0xbe280b8bu, 0x2717b96eu),
    uvec2(0x26077447u, 0x3f1080c6u), uvec2(0x6f7ea0e0u, 0x7b487ec6u),
    uvec2(0xa50a550du, 0xc0a4f84au), uvec2(0x9fe7e391u, 0x9ef18e97u),
    uvec2(0x81727686u, 0xd48d6050u), uvec2(0x415a9e7eu, 0x62b0e5f3u),
    uvec2(0xec1f9ffcu, 0x7a205440u), uvec2(0x001ae4e3u, 0x84c9f4ceu),
    uvec2(0xf594d74fu, 0xd895fa9du), uvec2(0x117e2e55u, 0xa554c324u),
    uvec2(0x2872df5bu, 0x286efebdu), uvec2(0xe27ff578u, 0xb2c4a50fu),
    uvec2(0xef7c8905u, 0x2ed349eeu), uvec2(0x85937e44u, 0x7f5928ebu),
    uvec2(0x37695f70u, 0x4a3124b3u), uvec2(0xf128865eu, 0x65e4d61du),
    uvec2(0x04771bc7u, 0xe720b951u), uvec2(0xe843fe74u, 0x8a87d423u),
    uvec2(0xa3e8297du, 0xf2947692u), uvec2(0x097acbddu, 0xc1d9309bu),
    uvec2(0xfb301b1du, 0xe01bdc5bu), uvec2(0x4f4924dau, 0xbf829cf2u),
    uvec2(0x31bae7a4u, 0xffbf70b4u), uvec2(0x0544320du, 0x48bcf8deu),
    uvec2(0x32fcae3bu, 0x39d3bb53u), uvec2(0xc1c39f45u, 0xa08b29e0u),
    uvec2(0xfd05c9e5u, 0x0f09aef7u), uvec2(0x12347094u, 0x34f19042u),
    uvec2(0x01b771a2u, 0x95ed44e3u), uvec2(0x368e3be9u, 0x4a982f4fu),
    uvec2(0x631d4088u, 0x15f66ca0u), uvec2(0x4b44c147u, 0xffaf5287u),
    uvec2(0xf14abb7eu, 0x30c60ae2u), uvec2(0xc5b67046u, 0xe68c6eccu),
    uvec2(0x56a4d5a4u, 0x00ca4fbdu), uvec2(0x4b849ddau, 0xae183ec8u),
    uvec2(0x45ce5773u, 0xadd16430u), uvec2(0x68cea6e8u, 0x67255c14u),
    uvec2(0xf28cdaa3u, 0x16e10ecbu), uvec2(0x5806e933u, 0x9a99949au),
    uvec2(0x20b2601fu, 0x7b846fc2u), uvec2(0x7facced1u, 0x1885d1a0u),
    uvec2(0xa15b5932u, 0xd319dd8du), uvec2(0xc01c9a50u, 0x46b4a5aau),
    uvec2(0x67633d9fu, 0xba6b04e4u), uvec2(0xab19caf6u, 0x7eee560bu),
    uvec2(0xea79b11fu, 0x742128a9u), uvec2(0x35f7bde9u, 0xee51363bu),
    uvec2(0x5aac571du, 0x76d35075u), uvec2(0xfec2463au, 0x01707da3u),
    uvec2(0xafc135f7u, 0x42d8a498u), uvec2(0x20eced78u, 0x79676b9eu),
    uvec2(0x15638341u, 0xa8db3aeau), uvec2(0x4d3bc3fau, 0x832c8332u),
    uvec2(0x1f3b40a7u, 0xf347271cu), uvec2(0x34f04059u, 0x9a762db7u),
    uvec2(0x6c4e3ee7u, 0xfd4f21d2u), uvec2(0x398dfdb8u, 0xef5957dcu),
    uvec2(0x490c9b8du, 0xdaeb492bu), uvec2(0x49d7a25bu, 0x0d70f368u),
    uvec2(0xd0ae3b7du, 0x84558d7au), uvec2(0xf0e9a5f5u, 0x658ef8e4u),
    uvec2(0xf4a2b8a0u, 0x533b1036u), uvec2(0x9e07a80cu, 0x5aec3e75u),
    uvec2(0x92946891u, 0x4f88e856u), uvec2(0x555cb05bu, 0x4cbcbaf8u),
    uvec2(0x993bbbe3u, 0x7b9487f3u), uvec2(0xd6f4da75u, 0x5d1c6b72u),
    uvec2(0x28acae64u, 0x6db334dcu), uvec2(0x50a5346cu, 0x71db28b8u),
    uvec2(0xf2e261f8u, 0x2a518d10u), uvec2(0x3364dbe3u, 0xfc75dd59u),
    uvec2(0xf1bcac1cu, 0xa23fce43u), uvec2(0x3cd1bb67u, 0xb043e802u),
    uvec2(0xca5b0a33u, 0x75a12988u), uvec2(0x4d19347fu, 0x5c5316b4u),
    uvec2(0xc3943b92u, 0x1e4d790eu), uvec2(0xd7757479u, 0x3fafeeb6u),
    uvec2(0xf7d4a8eau, 0x21391abeu), uvec2(0x097ef45cu, 0x5127234cu),
    uvec2(0x5324a326u, 0xd23c32bau), uvec2(0x4a17a344u, 0xadd5a66du),
    uvec2(0xa63e1db5u, 0x08c9f2afu), uvec2(0x983d5983u, 0x563c6b91u),
    uvec2(0xa17cf84cu, 0x4d608672u), uvec2(0xcc3ee246u, 0xf6c76e08u),
    uvec2(0xb333982fu, 0x5e76bcb1u), uvec2(0xa566d62bu, 0x2ae6c4efu),
    uvec2(0xe8b6f406u, 0x36d4c1beu), uvec2(0x1582ee74u, 0x6321efbcu),
    uvec2(0x0d4ec1fdu, 0x69c953f4u), uvec2(0xc45a7da7u, 0x26585806u),
    uvec2(0x1614c17eu, 0x16fae006u), uvec2(0x3daf907eu, 0x3f9d6328u),
    uvec2(0xe3f2c9d2u, 0x0cd29b00u), uvec2(0x30ceaa5fu, 0x300cd4b7u),
    uvec2(0x16512a74u, 0x9832e0f2u), uvec2(0xd830eb0du, 0x9af8cee3u),
    uvec2(0x7b9ec54bu, 0x9279f1b5u), uvec2(0x6ee651ffu, 0xd3688604u),
    uvec2(0x574d239bu, 0x316796e6u), uvec2(0xf3a6e6ccu, 0x05750a17u),
    uvec2(0xd98176b1u, 0xce6c3213u), uvec2(0x8452173cu, 0x62a205f8u),
    uvec2(0xb3cb2bf4u, 0x47154778u), uvec2(0x825446ffu, 0x486a9323u),
    uvec2(0x0758df38u, 0x65655e4eu), uvec2(0x897cfcf2u, 0x8e5086fcu),
    uvec2(0x442e7031u, 0x86ca0bd0u), uvec2(0xa20940f0u, 0x4e477830u),
    uvec2(0x39eea065u, 0x8338f7d1u), uvec2(0x37e95ef7u, 0xbd3a2ce4u),
    uvec2(0x26b29721u, 0x6ff81301u), uvec2(0xd1ed44a3u, 0xe7de9fefu),
    uvec2(0x15dfa08bu, 0xd9922576u), uvec2(0xf6f7853cu, 0xbe42dc12u),
    uvec2(0x7ceca7d8u, 0x7eb027abu), uvec2(0xda7d8d53u, 0xdea83eaau),
    uvec2(0x93ce25aau, 0xd86902bdu), uvec2(0xfd43f65au, 0xf908731au),
    uvec2(0xdaef5fc0u, 0xa5194a17u), uvec2(0x33664d97u, 0x6a21fd4cu),
    uvec2(0x3198b435u, 0x701541dbu), uvec2(0xbb0f1eeau, 0x9b54cdedu),
    uvec2(0xa163d09au, 0x72409751u), uvec2(0xbf9d75f6u, 0xe26f4791u));

// H(0) for a 512-bit digest, the same way round.
const uvec2 kJh512Iv[16] = uvec2[16](
    uvec2(0x964bd16fu, 0x17aa003eu), uvec2(0x052e6a63u, 0x43d5157au),
    uvec2(0x8d5e228au, 0x0bef970cu), uvec2(0x591234e9u, 0x61c3b3f2u),
    uvec2(0xc1a01d89u, 0x1e806f53u), uvec2(0x6b05a92au, 0x806d2beau),
    uvec2(0xdbcc8e58u, 0xa6ba7520u), uvec2(0x763a0fa9u, 0xf73bf8bau),
    uvec2(0x05e66901u, 0x694ae341u), uvec2(0x8e8ab546u, 0x5ae66f2eu),
    uvec2(0xd0a74710u, 0x243c84c1u), uvec2(0xb1716e3bu, 0x99c15a2du),
    uvec2(0xecf657cfu, 0x56f8b19du), uvec2(0x7c8806a7u, 0x56b11657u),
    uvec2(0xdffcc2e3u, 0xfb1785e6u), uvec2(0x78465a54u, 0x4bdd8cccu));

JLANE jh512_iv(uint i) { return jlane(kJh512Iv[i].x, kJh512Iv[i].y); }

// The two 4-bit S-boxes on bit planes x0..x3: S1 where c has a 1, S0 where it
// has a 0.
#define JH_SBOX(x0, x1, x2, x3, c)                                            {                                                                             JLANE t;                                                                  x3 = ~x3;                                                                 x0 ^= (c) & ~x2;                                                          t = (c) ^ (x0 & x1);                                                      x0 ^= x2 & x3;                                                            x3 ^= ~x1 & x2;                                                           x1 ^= x0 & x2;                                                            x2 ^= x0 & ~x3;                                                           x0 ^= x1 | x3;                                                            x3 ^= x1 & x2;                                                            x1 ^= t & x0;                                                             x2 ^= t;                                                              }

// The MDS code L on two nibbles' bit planes.
#define JH_LINEAR(a0, a1, a2, a3, b0, b1, b2, b3)                             {                                                                             b0 ^= a1;                                                                 b1 ^= a2;                                                                 b2 ^= a3 ^ a0;                                                            b3 ^= a0;                                                                 a0 ^= b1;                                                                 a1 ^= b2;                                                                 a2 ^= b3 ^ b0;                                                            a3 ^= b0;                                                             }

// Masks for the six bit swaps, k = 0..5.
#define JH_MASK(k) ((k) == 0 ? 0x55555555u : (k) == 1 ? 0x33333333u :                           (k) == 2 ? 0x0f0f0f0fu : (k) == 3 ? 0x00ff00ffu :                           (k) == 4 ? 0x0000ffffu : 0xffffffffu)

// Round r with permutation k = r mod 7 on the odd words. r and k are literals,
// so every constant and every swap folds; 6 is the swap of halves, done by
// trading the two words.
#define JH_ROUND(r, k)                                                        {                                                                             JLANE c0 = jlane(kJh512C[4 * (r) + 0].x, kJh512C[4 * (r) + 0].y);          JLANE c1 = jlane(kJh512C[4 * (r) + 1].x, kJh512C[4 * (r) + 1].y);          JLANE c2 = jlane(kJh512C[4 * (r) + 2].x, kJh512C[4 * (r) + 2].y);          JLANE c3 = jlane(kJh512C[4 * (r) + 3].x, kJh512C[4 * (r) + 3].y);          JH_SBOX(x[0], x[4], x[ 8], x[12], c0);                                    JH_SBOX(x[1], x[5], x[ 9], x[13], c1);                                    JH_SBOX(x[2], x[6], x[10], x[14], c2);                                    JH_SBOX(x[3], x[7], x[11], x[15], c3);                                    JH_LINEAR(x[0], x[4], x[ 8], x[12], x[2], x[6], x[10], x[14]);            JH_LINEAR(x[1], x[5], x[ 9], x[13], x[3], x[7], x[11], x[15]);            if ((k) == 6) {                                                               JLANE t;                                                                  t = x[ 2]; x[ 2] = x[ 3]; x[ 3] = t;                                      t = x[ 6]; x[ 6] = x[ 7]; x[ 7] = t;                                      t = x[10]; x[10] = x[11]; x[11] = t;                                      t = x[14]; x[14] = x[15]; x[15] = t;                                  } else {                                                                      x[ 2] = jh_swap(x[ 2], k, JH_MASK(k));                                    x[ 3] = jh_swap(x[ 3], k, JH_MASK(k));                                    x[ 6] = jh_swap(x[ 6], k, JH_MASK(k));                                    x[ 7] = jh_swap(x[ 7], k, JH_MASK(k));                                    x[10] = jh_swap(x[10], k, JH_MASK(k));                                    x[11] = jh_swap(x[11], k, JH_MASK(k));                                    x[14] = jh_swap(x[14], k, JH_MASK(k));                                    x[15] = jh_swap(x[15], k, JH_MASK(k));                                }                                                                     }

// E8: 42 rounds, written out so that every constant is a literal index.
void jh512_e8(inout JLANE x[16])
{
    JH_ROUND( 0, 0);
    JH_ROUND( 1, 1);
    JH_ROUND( 2, 2);
    JH_ROUND( 3, 3);
    JH_ROUND( 4, 4);
    JH_ROUND( 5, 5);
    JH_ROUND( 6, 6);
    JH_ROUND( 7, 0);
    JH_ROUND( 8, 1);
    JH_ROUND( 9, 2);
    JH_ROUND(10, 3);
    JH_ROUND(11, 4);
    JH_ROUND(12, 5);
    JH_ROUND(13, 6);
    JH_ROUND(14, 0);
    JH_ROUND(15, 1);
    JH_ROUND(16, 2);
    JH_ROUND(17, 3);
    JH_ROUND(18, 4);
    JH_ROUND(19, 5);
    JH_ROUND(20, 6);
    JH_ROUND(21, 0);
    JH_ROUND(22, 1);
    JH_ROUND(23, 2);
    JH_ROUND(24, 3);
    JH_ROUND(25, 4);
    JH_ROUND(26, 5);
    JH_ROUND(27, 6);
    JH_ROUND(28, 0);
    JH_ROUND(29, 1);
    JH_ROUND(30, 2);
    JH_ROUND(31, 3);
    JH_ROUND(32, 4);
    JH_ROUND(33, 5);
    JH_ROUND(34, 6);
    JH_ROUND(35, 0);
    JH_ROUND(36, 1);
    JH_ROUND(37, 2);
    JH_ROUND(38, 3);
    JH_ROUND(39, 4);
    JH_ROUND(40, 5);
    JH_ROUND(41, 6);
}

// F8: one block, xored into the first half before E8 and the second after.
void jh512_f8(inout JLANE x[16], JLANE m[8])
{
    for (uint i = 0u; i < 8u; i++)
        x[i] ^= m[i];
    jh512_e8(x);
    for (uint i = 0u; i < 8u; i++)
        x[8u + i] ^= m[i];
}

#endif  // VKMINER_SHADERS_COMMON_JH512_GLSL_INCLUDED
