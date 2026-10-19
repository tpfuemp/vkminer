// AES encryption rounds for the SHA-3 candidates built on them, two blocks at a
// time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A block is four columns, each a little-endian word (byte r is row r), and
// x[0..3] and x[4..7] are two independent blocks. By default SubBytes is the
// bitsliced Boyar-Peralta circuit groestl uses, with ShiftRows and MixColumns
// on the packed bytes. A kernel that defines VKMINER_AES_TABLE gets T-tables
// in workgroup memory instead. src/core/aes_round.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_AES_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_AES_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/groestl512_bs.glsl"

// Swaps bit b of byte (word k, lane p) with bit k of byte (word b, lane p):
// eight words of four bytes in, plane b = bit b of every byte out. Its own
// inverse.
void aes_transpose(inout uint d[8])
{
    uint t;
#define AES_SWAP(x, y, m, n)                                               \
    t = (d[x] ^ (d[y] << (n))) & (m); d[x] ^= t; d[y] ^= t >> (n)
    AES_SWAP(0, 1, 0xaaaaaaaau, 1); AES_SWAP(2, 3, 0xaaaaaaaau, 1);
    AES_SWAP(4, 5, 0xaaaaaaaau, 1); AES_SWAP(6, 7, 0xaaaaaaaau, 1);
    AES_SWAP(0, 2, 0xccccccccu, 2); AES_SWAP(1, 3, 0xccccccccu, 2);
    AES_SWAP(4, 6, 0xccccccccu, 2); AES_SWAP(5, 7, 0xccccccccu, 2);
    AES_SWAP(0, 4, 0xf0f0f0f0u, 4); AES_SWAP(1, 5, 0xf0f0f0f0u, 4);
    AES_SWAP(2, 6, 0xf0f0f0f0u, 4); AES_SWAP(3, 7, 0xf0f0f0f0u, 4);
#undef AES_SWAP
}

// The S-box on all 32 bytes of the eight words.
void aes_sub_bytes(inout uint x[8])
{
    aes_transpose(x);
    groestl_bs_sbox(x);
    aes_transpose(x);
}

// Each byte times x in GF(2^8).
uint aes_xtime4(uint a)
{
    return ((a & 0x7f7f7f7fu) << 1) ^ (((a >> 7) & 0x01010101u) * 0x1bu);
}

// One column through MixColumns: 2a_r + 3a_{r+1} + a_{r+2} + a_{r+3}.
uint aes_mix_column(uint a)
{
    uint r1 = rotr32(a, 8u);
    return aes_xtime4(a ^ r1) ^ r1 ^ rotr32(a, 16u) ^ rotr32(a, 24u);
}

#ifdef VKMINER_AES_TABLE
// VKMINER_AES_TABLE 1 keeps T0 alone and rotates it, 4 keeps all four
// tables. Every invocation calls aes_table_load() before the first round.
// T0[x] is the column S(x) times (2, 1, 1, 3), low byte first.
const uint kAesT0[256] = uint[256](
    0xa56363c6u, 0x847c7cf8u, 0x997777eeu, 0x8d7b7bf6u, 0x0df2f2ffu, 0xbd6b6bd6u,
    0xb16f6fdeu, 0x54c5c591u, 0x50303060u, 0x03010102u, 0xa96767ceu, 0x7d2b2b56u,
    0x19fefee7u, 0x62d7d7b5u, 0xe6abab4du, 0x9a7676ecu, 0x45caca8fu, 0x9d82821fu,
    0x40c9c989u, 0x877d7dfau, 0x15fafaefu, 0xeb5959b2u, 0xc947478eu, 0x0bf0f0fbu,
    0xecadad41u, 0x67d4d4b3u, 0xfda2a25fu, 0xeaafaf45u, 0xbf9c9c23u, 0xf7a4a453u,
    0x967272e4u, 0x5bc0c09bu, 0xc2b7b775u, 0x1cfdfde1u, 0xae93933du, 0x6a26264cu,
    0x5a36366cu, 0x413f3f7eu, 0x02f7f7f5u, 0x4fcccc83u, 0x5c343468u, 0xf4a5a551u,
    0x34e5e5d1u, 0x08f1f1f9u, 0x937171e2u, 0x73d8d8abu, 0x53313162u, 0x3f15152au,
    0x0c040408u, 0x52c7c795u, 0x65232346u, 0x5ec3c39du, 0x28181830u, 0xa1969637u,
    0x0f05050au, 0xb59a9a2fu, 0x0907070eu, 0x36121224u, 0x9b80801bu, 0x3de2e2dfu,
    0x26ebebcdu, 0x6927274eu, 0xcdb2b27fu, 0x9f7575eau, 0x1b090912u, 0x9e83831du,
    0x742c2c58u, 0x2e1a1a34u, 0x2d1b1b36u, 0xb26e6edcu, 0xee5a5ab4u, 0xfba0a05bu,
    0xf65252a4u, 0x4d3b3b76u, 0x61d6d6b7u, 0xceb3b37du, 0x7b292952u, 0x3ee3e3ddu,
    0x712f2f5eu, 0x97848413u, 0xf55353a6u, 0x68d1d1b9u, 0x00000000u, 0x2cededc1u,
    0x60202040u, 0x1ffcfce3u, 0xc8b1b179u, 0xed5b5bb6u, 0xbe6a6ad4u, 0x46cbcb8du,
    0xd9bebe67u, 0x4b393972u, 0xde4a4a94u, 0xd44c4c98u, 0xe85858b0u, 0x4acfcf85u,
    0x6bd0d0bbu, 0x2aefefc5u, 0xe5aaaa4fu, 0x16fbfbedu, 0xc5434386u, 0xd74d4d9au,
    0x55333366u, 0x94858511u, 0xcf45458au, 0x10f9f9e9u, 0x06020204u, 0x817f7ffeu,
    0xf05050a0u, 0x443c3c78u, 0xba9f9f25u, 0xe3a8a84bu, 0xf35151a2u, 0xfea3a35du,
    0xc0404080u, 0x8a8f8f05u, 0xad92923fu, 0xbc9d9d21u, 0x48383870u, 0x04f5f5f1u,
    0xdfbcbc63u, 0xc1b6b677u, 0x75dadaafu, 0x63212142u, 0x30101020u, 0x1affffe5u,
    0x0ef3f3fdu, 0x6dd2d2bfu, 0x4ccdcd81u, 0x140c0c18u, 0x35131326u, 0x2fececc3u,
    0xe15f5fbeu, 0xa2979735u, 0xcc444488u, 0x3917172eu, 0x57c4c493u, 0xf2a7a755u,
    0x827e7efcu, 0x473d3d7au, 0xac6464c8u, 0xe75d5dbau, 0x2b191932u, 0x957373e6u,
    0xa06060c0u, 0x98818119u, 0xd14f4f9eu, 0x7fdcdca3u, 0x66222244u, 0x7e2a2a54u,
    0xab90903bu, 0x8388880bu, 0xca46468cu, 0x29eeeec7u, 0xd3b8b86bu, 0x3c141428u,
    0x79dedea7u, 0xe25e5ebcu, 0x1d0b0b16u, 0x76dbdbadu, 0x3be0e0dbu, 0x56323264u,
    0x4e3a3a74u, 0x1e0a0a14u, 0xdb494992u, 0x0a06060cu, 0x6c242448u, 0xe45c5cb8u,
    0x5dc2c29fu, 0x6ed3d3bdu, 0xefacac43u, 0xa66262c4u, 0xa8919139u, 0xa4959531u,
    0x37e4e4d3u, 0x8b7979f2u, 0x32e7e7d5u, 0x43c8c88bu, 0x5937376eu, 0xb76d6ddau,
    0x8c8d8d01u, 0x64d5d5b1u, 0xd24e4e9cu, 0xe0a9a949u, 0xb46c6cd8u, 0xfa5656acu,
    0x07f4f4f3u, 0x25eaeacfu, 0xaf6565cau, 0x8e7a7af4u, 0xe9aeae47u, 0x18080810u,
    0xd5baba6fu, 0x887878f0u, 0x6f25254au, 0x722e2e5cu, 0x241c1c38u, 0xf1a6a657u,
    0xc7b4b473u, 0x51c6c697u, 0x23e8e8cbu, 0x7cdddda1u, 0x9c7474e8u, 0x211f1f3eu,
    0xdd4b4b96u, 0xdcbdbd61u, 0x868b8b0du, 0x858a8a0fu, 0x907070e0u, 0x423e3e7cu,
    0xc4b5b571u, 0xaa6666ccu, 0xd8484890u, 0x05030306u, 0x01f6f6f7u, 0x120e0e1cu,
    0xa36161c2u, 0x5f35356au, 0xf95757aeu, 0xd0b9b969u, 0x91868617u, 0x58c1c199u,
    0x271d1d3au, 0xb99e9e27u, 0x38e1e1d9u, 0x13f8f8ebu, 0xb398982bu, 0x33111122u,
    0xbb6969d2u, 0x70d9d9a9u, 0x898e8e07u, 0xa7949433u, 0xb69b9b2du, 0x221e1e3cu,
    0x92878715u, 0x20e9e9c9u, 0x49cece87u, 0xff5555aau, 0x78282850u, 0x7adfdfa5u,
    0x8f8c8c03u, 0xf8a1a159u, 0x80898909u, 0x170d0d1au, 0xdabfbf65u, 0x31e6e6d7u,
    0xc6424284u, 0xb86868d0u, 0xc3414182u, 0xb0999929u, 0x772d2d5au, 0x110f0f1eu,
    0xcbb0b07bu, 0xfc5454a8u, 0xd6bbbb6du, 0x3a16162cu);

#if VKMINER_AES_TABLE == 4
shared uint aes_t[1024];
#define AES_T(r, x) aes_t[256u * (r) + (x)]
#else
shared uint aes_t[256];
#define AES_T(r, x) rotl32(aes_t[x], 8u * (r))
#endif

// Fills the tables, lane `lane` of `width`, and waits for the workgroup.
void aes_table_load(uint lane, uint width)
{
    for (uint i = lane; i < 256u; i += width) {
#if VKMINER_AES_TABLE == 4
        for (uint r = 0u; r < 4u; r++)
            aes_t[256u * r + i] = rotl32(kAesT0[i], 8u * r);
#else
        aes_t[i] = kAesT0[i];
#endif
    }
    barrier();
}

// One output column: row r from the column r places on, through T_r.
uint aes_tcol(uint a, uint b, uint c, uint d)
{
    return AES_T(0u, a & 0xffu) ^ AES_T(1u, (b >> 8) & 0xffu)
         ^ AES_T(2u, (c >> 16) & 0xffu) ^ AES_T(3u, d >> 24);
}

// One unkeyed AES round on both blocks; the caller xors any round key.
void aes_round2(inout uint x[8])
{
    for (uint b = 0u; b < 8u; b += 4u) {
        uint c0 = x[b], c1 = x[b + 1u], c2 = x[b + 2u], c3 = x[b + 3u];
        x[b]      = aes_tcol(c0, c1, c2, c3);
        x[b + 1u] = aes_tcol(c1, c2, c3, c0);
        x[b + 2u] = aes_tcol(c2, c3, c0, c1);
        x[b + 3u] = aes_tcol(c3, c0, c1, c2);
    }
}

#else  // VKMINER_AES_TABLE

// ShiftRows and MixColumns of the block at x[b..b + 3], after SubBytes.
#define AES_SHIFT_MIX(x, b)                                                 \
    {                                                                       \
        uint c0_ = x[(b) + 0], c1_ = x[(b) + 1];                            \
        uint c2_ = x[(b) + 2], c3_ = x[(b) + 3];                            \
        x[(b) + 0] = aes_mix_column((c0_ & 0x000000ffu) | (c1_ & 0x0000ff00u) \
                                  | (c2_ & 0x00ff0000u) | (c3_ & 0xff000000u)); \
        x[(b) + 1] = aes_mix_column((c1_ & 0x000000ffu) | (c2_ & 0x0000ff00u) \
                                  | (c3_ & 0x00ff0000u) | (c0_ & 0xff000000u)); \
        x[(b) + 2] = aes_mix_column((c2_ & 0x000000ffu) | (c3_ & 0x0000ff00u) \
                                  | (c0_ & 0x00ff0000u) | (c1_ & 0xff000000u)); \
        x[(b) + 3] = aes_mix_column((c3_ & 0x000000ffu) | (c0_ & 0x0000ff00u) \
                                  | (c1_ & 0x00ff0000u) | (c2_ & 0xff000000u)); \
    }

// One unkeyed AES round on both blocks; the caller xors any round key.
void aes_round2(inout uint x[8])
{
    aes_sub_bytes(x);
    AES_SHIFT_MIX(x, 0);
    AES_SHIFT_MIX(x, 4);
}

#endif  // VKMINER_AES_TABLE

#endif  // VKMINER_SHADERS_COMMON_AES_GLSL_INCLUDED
