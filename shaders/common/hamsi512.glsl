// Hamsi-512, the round 2 SHA-3 submission: one 8-byte block at a time.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The chaining value is sixteen big-endian words. A block arrives as two
// little-endian words, so bit i of (lo, hi) is message bit i. The caller owns
// padding and output. src/core/hamsi512.c is the scalar reference.

#ifndef VKMINER_SHADERS_COMMON_HAMSI512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_HAMSI512_GLSL_INCLUDED

#include "shaders/common/bits.glsl"

const uint kHamsi512Iv[16] = uint[16](
    0x73746565u, 0x6c706172u, 0x6b204172u, 0x656e6265u,
    0x72672031u, 0x302c2062u, 0x75732032u, 0x3434362cu,
    0x20422d33u, 0x30303120u, 0x4c657576u, 0x656e2d48u,
    0x65766572u, 0x6c65652cu, 0x2042656cu, 0x6769756du);

const uint kHamsi512AlphaN[32] = uint[32](
    0xff00f0f0u, 0xccccaaaau, 0xf0f0ccccu, 0xff00aaaau,
    0xccccaaaau, 0xf0f0ff00u, 0xaaaaccccu, 0xf0f0ff00u,
    0xf0f0ccccu, 0xaaaaff00u, 0xccccff00u, 0xaaaaf0f0u,
    0xaaaaf0f0u, 0xff00ccccu, 0xccccf0f0u, 0xff00aaaau,
    0xccccaaaau, 0xff00f0f0u, 0xff00aaaau, 0xf0f0ccccu,
    0xf0f0ff00u, 0xccccaaaau, 0xf0f0ff00u, 0xaaaaccccu,
    0xaaaaff00u, 0xf0f0ccccu, 0xaaaaf0f0u, 0xccccff00u,
    0xff00ccccu, 0xaaaaf0f0u, 0xff00aaaau, 0xccccf0f0u);

const uint kHamsi512AlphaF[32] = uint[32](
    0xcaf9639cu, 0x0ff0f9c0u, 0x639c0ff0u, 0xcaf9f9c0u,
    0x0ff0f9c0u, 0x639ccaf9u, 0xf9c00ff0u, 0x639ccaf9u,
    0x639c0ff0u, 0xf9c0caf9u, 0x0ff0caf9u, 0xf9c0639cu,
    0xf9c0639cu, 0xcaf90ff0u, 0x0ff0639cu, 0xcaf9f9c0u,
    0x0ff0f9c0u, 0xcaf9639cu, 0xcaf9f9c0u, 0x639c0ff0u,
    0x639ccaf9u, 0x0ff0f9c0u, 0x639ccaf9u, 0xf9c00ff0u,
    0xf9c0caf9u, 0x639c0ff0u, 0xf9c0639cu, 0x0ff0caf9u,
    0xcaf90ff0u, 0xf9c0639cu, 0xcaf9f9c0u, 0x0ff0639cu);

// Row i of the generator matrix, added to m when bit i of w is set.
#define HAMSI512_ROW(w, i, t0, t1, t2, t3, t4, t5, t6, t7,                  \
                     t8, t9, ta, tb, tc, td, te, tf)                        \
    {                                                                       \
        uint d_ = 0u - (((w) >> ((i) & 31u)) & 1u);                         \
        m[0] ^= d_ & t0;  m[1] ^= d_ & t1;  m[2] ^= d_ & t2;                \
        m[3] ^= d_ & t3;  m[4] ^= d_ & t4;  m[5] ^= d_ & t5;                \
        m[6] ^= d_ & t6;  m[7] ^= d_ & t7;  m[8] ^= d_ & t8;                \
        m[9] ^= d_ & t9;  m[10] ^= d_ & ta; m[11] ^= d_ & tb;               \
        m[12] ^= d_ & tc; m[13] ^= d_ & td; m[14] ^= d_ & te;               \
        m[15] ^= d_ & tf;                                                   \
    }

// The block's sixteen expanded words.
void hamsi512_expand(uint lo, uint hi, out uint m[16])
{
    for (uint k = 0u; k < 16u; k++)
        m[k] = 0u;
    HAMSI512_ROW(lo, 0u,
                 0xef0b0270u, 0x3afd0000u, 0x5dae0000u, 0x69490000u,
                 0x9b0f3c06u, 0x4405b5f9u, 0x66140a51u, 0x924f5d0au,
                 0xc96b0030u, 0xe7250000u, 0x2f840000u, 0x264f0000u,
                 0x08695bf9u, 0x6dfcf137u, 0x509f6984u, 0x9e69af68u)
    HAMSI512_ROW(lo, 1u,
                 0xc96b0030u, 0xe7250000u, 0x2f840000u, 0x264f0000u,
                 0x08695bf9u, 0x6dfcf137u, 0x509f6984u, 0x9e69af68u,
                 0x26600240u, 0xddd80000u, 0x722a0000u, 0x4f060000u,
                 0x936667ffu, 0x29f944ceu, 0x368b63d5u, 0x0c26f262u)
    HAMSI512_ROW(lo, 2u,
                 0x145a3c00u, 0xb9e90000u, 0x61270000u, 0xf1610000u,
                 0xce613d6cu, 0xb0493d78u, 0x47a96720u, 0xe18e24c5u,
                 0x23671400u, 0xc8b90000u, 0xf4c70000u, 0xfb750000u,
                 0x73cd2465u, 0xf8a6a549u, 0x02c40a3fu, 0xdc24e61fu)
    HAMSI512_ROW(lo, 3u,
                 0x23671400u, 0xc8b90000u, 0xf4c70000u, 0xfb750000u,
                 0x73cd2465u, 0xf8a6a549u, 0x02c40a3fu, 0xdc24e61fu,
                 0x373d2800u, 0x71500000u, 0x95e00000u, 0x0a140000u,
                 0xbdac1909u, 0x48ef9831u, 0x456d6d1fu, 0x3daac2dau)
    HAMSI512_ROW(lo, 4u,
                 0x54285c00u, 0xeaed0000u, 0xc5d60000u, 0xa1c50000u,
                 0xb3a26770u, 0x94a5c4e1u, 0x6bb0419du, 0x551b3782u,
                 0x9cbb1800u, 0xb0d30000u, 0x92510000u, 0xed930000u,
                 0x593a4345u, 0xe114d5f4u, 0x430633dau, 0x78cace29u)
    HAMSI512_ROW(lo, 5u,
                 0x9cbb1800u, 0xb0d30000u, 0x92510000u, 0xed930000u,
                 0x593a4345u, 0xe114d5f4u, 0x430633dau, 0x78cace29u,
                 0xc8934400u, 0x5a3e0000u, 0x57870000u, 0x4c560000u,
                 0xea982435u, 0x75b11115u, 0x28b67247u, 0x2dd1f9abu)
    HAMSI512_ROW(lo, 6u,
                 0x29449c00u, 0x64e70000u, 0xf24b0000u, 0xc2f30000u,
                 0x0ede4e8fu, 0x56c23745u, 0xf3e04259u, 0x8d0d9ec4u,
                 0x466d0c00u, 0x08620000u, 0xdd5d0000u, 0xbadd0000u,
                 0x6a927942u, 0x441f2b93u, 0x218ace6fu, 0xbf2c0be2u)
    HAMSI512_ROW(lo, 7u,
                 0x466d0c00u, 0x08620000u, 0xdd5d0000u, 0xbadd0000u,
                 0x6a927942u, 0x441f2b93u, 0x218ace6fu, 0xbf2c0be2u,
                 0x6f299000u, 0x6c850000u, 0x2f160000u, 0x782e0000u,
                 0x644c37cdu, 0x12dd1cd6u, 0xd26a8c36u, 0x32219526u)
    HAMSI512_ROW(lo, 8u,
                 0xf6800005u, 0x3443c000u, 0x24070000u, 0x8f3d0000u,
                 0x21373bfbu, 0x0ab8d5aeu, 0xcdc58b19u, 0xd795ba31u,
                 0xa67f0001u, 0x71378000u, 0x19fc0000u, 0x96db0000u,
                 0x3a8b6dfdu, 0xebcaaef3u, 0x2c6d478fu, 0xac8e6c88u)
    HAMSI512_ROW(lo, 9u,
                 0xa67f0001u, 0x71378000u, 0x19fc0000u, 0x96db0000u,
                 0x3a8b6dfdu, 0xebcaaef3u, 0x2c6d478fu, 0xac8e6c88u,
                 0x50ff0004u, 0x45744000u, 0x3dfb0000u, 0x19e60000u,
                 0x1bbc5606u, 0xe1727b5du, 0xe1a8cc96u, 0x7b1bd6b9u)
    HAMSI512_ROW(lo, 10u,
                 0xf7750009u, 0xcf3cc000u, 0xc3d60000u, 0x04920000u,
                 0x029519a9u, 0xf8e836bau, 0x7a87f14eu, 0x9e16981au,
                 0xd46a0000u, 0x8dc8c000u, 0xa5af0000u, 0x4a290000u,
                 0xfc4e427au, 0xc9b4866cu, 0x98369604u, 0xf746c320u)
    HAMSI512_ROW(lo, 11u,
                 0xd46a0000u, 0x8dc8c000u, 0xa5af0000u, 0x4a290000u,
                 0xfc4e427au, 0xc9b4866cu, 0x98369604u, 0xf746c320u,
                 0x231f0009u, 0x42f40000u, 0x66790000u, 0x4ebb0000u,
                 0xfedb5bd3u, 0x315cb0d6u, 0xe2b1674au, 0x69505b3au)
    HAMSI512_ROW(lo, 12u,
                 0x774400f0u, 0xf15a0000u, 0xf5b20000u, 0x34140000u,
                 0x89377e8cu, 0x5a8bec25u, 0x0bc3cd1eu, 0xcf3775cbu,
                 0xf46c0050u, 0x96180000u, 0x14a50000u, 0x031f0000u,
                 0x42947eb8u, 0x66bf7e19u, 0x9ca470d2u, 0x8a341574u)
    HAMSI512_ROW(lo, 13u,
                 0xf46c0050u, 0x96180000u, 0x14a50000u, 0x031f0000u,
                 0x42947eb8u, 0x66bf7e19u, 0x9ca470d2u, 0x8a341574u,
                 0x832800a0u, 0x67420000u, 0xe1170000u, 0x370b0000u,
                 0xcba30034u, 0x3c34923cu, 0x9767bdccu, 0x450360bfu)
    HAMSI512_ROW(lo, 14u,
                 0xe8870170u, 0x9d720000u, 0x12db0000u, 0xd4220000u,
                 0xf2886b27u, 0xa921e543u, 0x4ef8b518u, 0x618813b1u,
                 0xb4370060u, 0x0c4c0000u, 0x56c20000u, 0x5cae0000u,
                 0x94541f3fu, 0x3b3ef825u, 0x1b365f3du, 0xf3d45758u)
    HAMSI512_ROW(lo, 15u,
                 0xb4370060u, 0x0c4c0000u, 0x56c20000u, 0x5cae0000u,
                 0x94541f3fu, 0x3b3ef825u, 0x1b365f3du, 0xf3d45758u,
                 0x5cb00110u, 0x913e0000u, 0x44190000u, 0x888c0000u,
                 0x66dc7418u, 0x921f1d66u, 0x55ceea25u, 0x925c44e9u)
    HAMSI512_ROW(lo, 16u,
                 0x0c720000u, 0x49e50f00u, 0x42790000u, 0x5cea0000u,
                 0x33aa301au, 0x15822514u, 0x95a34b7bu, 0xb44b0090u,
                 0xfe220000u, 0xa7580500u, 0x25d10000u, 0xf7600000u,
                 0x893178dau, 0x1fd4f860u, 0x4ed0a315u, 0xa123ff9fu)
    HAMSI512_ROW(lo, 17u,
                 0xfe220000u, 0xa7580500u, 0x25d10000u, 0xf7600000u,
                 0x893178dau, 0x1fd4f860u, 0x4ed0a315u, 0xa123ff9fu,
                 0xf2500000u, 0xeebd0a00u, 0x67a80000u, 0xab8a0000u,
                 0xba9b48c0u, 0x0a56dd74u, 0xdb73e86eu, 0x1568ff0fu)
    HAMSI512_ROW(lo, 18u,
                 0x45180000u, 0xa5b51700u, 0xf96a0000u, 0x3b480000u,
                 0x1ecc142cu, 0x231395d6u, 0x16bca6b0u, 0xdf33f4dfu,
                 0xb83d0000u, 0x16710600u, 0x379a0000u, 0xf5b10000u,
                 0x228161acu, 0xae48f145u, 0x66241616u, 0xc5c1eb3eu)
    HAMSI512_ROW(lo, 19u,
                 0xb83d0000u, 0x16710600u, 0x379a0000u, 0xf5b10000u,
                 0x228161acu, 0xae48f145u, 0x66241616u, 0xc5c1eb3eu,
                 0xfd250000u, 0xb3c41100u, 0xcef00000u, 0xcef90000u,
                 0x3c4d7580u, 0x8d5b6493u, 0x7098b0a6u, 0x1af21fe1u)
    HAMSI512_ROW(lo, 20u,
                 0x75a40000u, 0xc28b2700u, 0x94a40000u, 0x90f50000u,
                 0xfb7857e0u, 0x49ce0baeu, 0x1767c483u, 0xaedf667eu,
                 0xd1660000u, 0x1bbc0300u, 0x9eec0000u, 0xf6940000u,
                 0x03024527u, 0xcf70fcf2u, 0xb4431b17u, 0x857f3c2bu)
    HAMSI512_ROW(lo, 21u,
                 0xd1660000u, 0x1bbc0300u, 0x9eec0000u, 0xf6940000u,
                 0x03024527u, 0xcf70fcf2u, 0xb4431b17u, 0x857f3c2bu,
                 0xa4c20000u, 0xd9372400u, 0x0a480000u, 0x66610000u,
                 0xf87a12c7u, 0x86bef75cu, 0xa324df94u, 0x2ba05a55u)
    HAMSI512_ROW(lo, 22u,
                 0x75c90003u, 0x0e10c000u, 0xd1200000u, 0xbaea0000u,
                 0x8bc42f3eu, 0x8758b757u, 0xbb28761du, 0x00b72e2bu,
                 0xeecf0001u, 0x6f564000u, 0xf33e0000u, 0xa79e0000u,
                 0xbdb57219u, 0xb711ebc5u, 0x4a3b40bau, 0xfeabf254u)
    HAMSI512_ROW(lo, 23u,
                 0xeecf0001u, 0x6f564000u, 0xf33e0000u, 0xa79e0000u,
                 0xbdb57219u, 0xb711ebc5u, 0x4a3b40bau, 0xfeabf254u,
                 0x9b060002u, 0x61468000u, 0x221e0000u, 0x1d740000u,
                 0x36715d27u, 0x30495c92u, 0xf11336a7u, 0xfe1cdc7fu)
    HAMSI512_ROW(lo, 24u,
                 0x86790000u, 0x3f390002u, 0xe19ae000u, 0x98560000u,
                 0x9565670eu, 0x4e88c8eau, 0xd3dd4944u, 0x161ddab9u,
                 0x30b70000u, 0xe5d00000u, 0xf4f46000u, 0x42c40000u,
                 0x63b83d6au, 0x78ba9460u, 0x21afa1eau, 0xb0a51834u)
    HAMSI512_ROW(lo, 25u,
                 0x30b70000u, 0xe5d00000u, 0xf4f46000u, 0x42c40000u,
                 0x63b83d6au, 0x78ba9460u, 0x21afa1eau, 0xb0a51834u,
                 0xb6ce0000u, 0xdae90002u, 0x156e8000u, 0xda920000u,
                 0xf6dd5a64u, 0x36325c8au, 0xf272e8aeu, 0xa6b8c28du)
    HAMSI512_ROW(lo, 26u,
                 0x14190000u, 0x23ca003cu, 0x50df0000u, 0x44b60000u,
                 0x1b6c67b0u, 0x3cf3ac75u, 0x61e610b0u, 0xdbcadb80u,
                 0xe3430000u, 0x3a4e0014u, 0xf2c60000u, 0xaa4e0000u,
                 0xdb1e42a6u, 0x256bbe15u, 0x123db156u, 0x3a4e99d7u)
    HAMSI512_ROW(lo, 27u,
                 0xe3430000u, 0x3a4e0014u, 0xf2c60000u, 0xaa4e0000u,
                 0xdb1e42a6u, 0x256bbe15u, 0x123db156u, 0x3a4e99d7u,
                 0xf75a0000u, 0x19840028u, 0xa2190000u, 0xeef80000u,
                 0xc0722516u, 0x19981260u, 0x73dba1e6u, 0xe1844257u)
    HAMSI512_ROW(lo, 28u,
                 0x54500000u, 0x0671005cu, 0x25ae0000u, 0x6a1e0000u,
                 0x2ea54edfu, 0x664e8512u, 0xbfba18c3u, 0x7e715d17u,
                 0xbc8d0000u, 0xfc3b0018u, 0x19830000u, 0xd10b0000u,
                 0xae1878c4u, 0x42a69856u, 0x0012da37u, 0x2c3b504eu)
    HAMSI512_ROW(lo, 29u,
                 0xbc8d0000u, 0xfc3b0018u, 0x19830000u, 0xd10b0000u,
                 0xae1878c4u, 0x42a69856u, 0x0012da37u, 0x2c3b504eu,
                 0xe8dd0000u, 0xfa4a0044u, 0x3c2d0000u, 0xbb150000u,
                 0x80bd361bu, 0x24e81d44u, 0xbfa8c2f4u, 0x524a0d59u)
    HAMSI512_ROW(lo, 30u,
                 0x69510000u, 0xd4e1009cu, 0xc3230000u, 0xac2f0000u,
                 0xe4950baeu, 0xcea415dcu, 0x87ec287cu, 0xbce1a3ceu,
                 0xc6730000u, 0xaf8d000cu, 0xa4c10000u, 0x218d0000u,
                 0x23111587u, 0x7913512fu, 0x1d28ac88u, 0x378dd173u)
    HAMSI512_ROW(lo, 31u,
                 0xc6730000u, 0xaf8d000cu, 0xa4c10000u, 0x218d0000u,
                 0x23111587u, 0x7913512fu, 0x1d28ac88u, 0x378dd173u,
                 0xaf220000u, 0x7b6c0090u, 0x67e20000u, 0x8da20000u,
                 0xc7841e29u, 0xb7b744f3u, 0x9ac484f4u, 0x8b6c72bdu)
    HAMSI512_ROW(hi, 32u,
                 0xcc140000u, 0xa5630000u, 0x5ab90780u, 0x3b500000u,
                 0x4bd013ffu, 0x879b3418u, 0x694348c1u, 0xca5a87feu,
                 0x819e0000u, 0xec570000u, 0x66320280u, 0x95f30000u,
                 0x5da92802u, 0x48f43cbcu, 0xe65aa22du, 0x8e67b7fau)
    HAMSI512_ROW(hi, 33u,
                 0x819e0000u, 0xec570000u, 0x66320280u, 0x95f30000u,
                 0x5da92802u, 0x48f43cbcu, 0xe65aa22du, 0x8e67b7fau,
                 0x4d8a0000u, 0x49340000u, 0x3c8b0500u, 0xaea30000u,
                 0x16793bfdu, 0xcf6f08a4u, 0x8f19eaecu, 0x443d3004u)
    HAMSI512_ROW(hi, 34u,
                 0x78230000u, 0x12fc0000u, 0xa93a0b80u, 0x90a50000u,
                 0x713e2879u, 0x7ee98924u, 0xf08ca062u, 0x636f8babu,
                 0x02af0000u, 0xb7280000u, 0xba1c0300u, 0x56980000u,
                 0xba8d45d3u, 0x8048c667u, 0xa95c149au, 0xf4f6ea7bu)
    HAMSI512_ROW(hi, 35u,
                 0x02af0000u, 0xb7280000u, 0xba1c0300u, 0x56980000u,
                 0xba8d45d3u, 0x8048c667u, 0xa95c149au, 0xf4f6ea7bu,
                 0x7a8c0000u, 0xa5d40000u, 0x13260880u, 0xc63d0000u,
                 0xcbb36daau, 0xfea14f43u, 0x59d0b4f8u, 0x979961d0u)
    HAMSI512_ROW(hi, 36u,
                 0xac480000u, 0x1ba60000u, 0x45fb1380u, 0x03430000u,
                 0x5a85316au, 0x1fb250b6u, 0xfe72c7feu, 0x91e478f6u,
                 0x1e4e0000u, 0xdecf0000u, 0x6df80180u, 0x77240000u,
                 0xec47079eu, 0xf4a0694eu, 0xcda31812u, 0x98aa496eu)
    HAMSI512_ROW(hi, 37u,
                 0x1e4e0000u, 0xdecf0000u, 0x6df80180u, 0x77240000u,
                 0xec47079eu, 0xf4a0694eu, 0xcda31812u, 0x98aa496eu,
                 0xb2060000u, 0xc5690000u, 0x28031200u, 0x74670000u,
                 0xb6c236f4u, 0xeb1239f8u, 0x33d1dfecu, 0x094e3198u)
    HAMSI512_ROW(hi, 38u,
                 0xaec30000u, 0x9c4f0001u, 0x79d1e000u, 0x2c150000u,
                 0x45cc75b3u, 0x6650b736u, 0xab92f78fu, 0xa312567bu,
                 0xdb250000u, 0x09290000u, 0x49aac000u, 0x81e10000u,
                 0xcafe6b59u, 0x42793431u, 0x43566b76u, 0xe86cba2eu)
    HAMSI512_ROW(hi, 39u,
                 0xdb250000u, 0x09290000u, 0x49aac000u, 0x81e10000u,
                 0xcafe6b59u, 0x42793431u, 0x43566b76u, 0xe86cba2eu,
                 0x75e60000u, 0x95660001u, 0x307b2000u, 0xadf40000u,
                 0x8f321eeau, 0x24298307u, 0xe8c49cf9u, 0x4b7eec55u)
    HAMSI512_ROW(hi, 40u,
                 0x58430000u, 0x807e0000u, 0x78330001u, 0xc66b3800u,
                 0xe7375cdcu, 0x79ad3fddu, 0xac73fe6fu, 0x3a4479b1u,
                 0x1d5a0000u, 0x2b720000u, 0x488d0000u, 0xaf611800u,
                 0x25cb2ec5u, 0xc879bfd0u, 0x81a20429u, 0x1e7536a6u)
    HAMSI512_ROW(hi, 41u,
                 0x1d5a0000u, 0x2b720000u, 0x488d0000u, 0xaf611800u,
                 0x25cb2ec5u, 0xc879bfd0u, 0x81a20429u, 0x1e7536a6u,
                 0x45190000u, 0xab0c0000u, 0x30be0001u, 0x690a2000u,
                 0xc2fc7219u, 0xb1d4800du, 0x2dd1fa46u, 0x24314f17u)
    HAMSI512_ROW(hi, 42u,
                 0xa53b0000u, 0x14260000u, 0x4e30001eu, 0x7cae0000u,
                 0x8f9e0dd5u, 0x78dfaa3du, 0xf73168d8u, 0x0b1b4946u,
                 0x07ed0000u, 0xb2500000u, 0x8774000au, 0x970d0000u,
                 0x437223aeu, 0x48c76ea4u, 0xf4786222u, 0x9075b1ceu)
    HAMSI512_ROW(hi, 43u,
                 0x07ed0000u, 0xb2500000u, 0x8774000au, 0x970d0000u,
                 0x437223aeu, 0x48c76ea4u, 0xf4786222u, 0x9075b1ceu,
                 0xa2d60000u, 0xa6760000u, 0xc9440014u, 0xeba30000u,
                 0xccec2e7bu, 0x3018c499u, 0x03490afau, 0x9b6ef888u)
    HAMSI512_ROW(hi, 44u,
                 0x88980000u, 0x1f940000u, 0x7fcf002eu, 0xfb4e0000u,
                 0xf158079au, 0x61ae9167u, 0xa895706cu, 0xe6107494u,
                 0x0bc20000u, 0xdb630000u, 0x7e88000cu, 0x15860000u,
                 0x91fd48f3u, 0x7581bb43u, 0xf460449eu, 0xd8b61463u)
    HAMSI512_ROW(hi, 45u,
                 0x0bc20000u, 0xdb630000u, 0x7e88000cu, 0x15860000u,
                 0x91fd48f3u, 0x7581bb43u, 0xf460449eu, 0xd8b61463u,
                 0x835a0000u, 0xc4f70000u, 0x01470022u, 0xeec80000u,
                 0x60a54f69u, 0x142f2a24u, 0x5cf534f2u, 0x3ea660f7u)
    HAMSI512_ROW(hi, 46u,
                 0x52500000u, 0x29540000u, 0x6a61004eu, 0xf0ff0000u,
                 0x9a317eecu, 0x452341ceu, 0xcf568fe5u, 0x5303130fu,
                 0x538d0000u, 0xa9fc0000u, 0x9ef70006u, 0x56ff0000u,
                 0x0ae4004eu, 0x92c5cdf9u, 0xa9444018u, 0x7f975691u)
    HAMSI512_ROW(hi, 47u,
                 0x538d0000u, 0xa9fc0000u, 0x9ef70006u, 0x56ff0000u,
                 0x0ae4004eu, 0x92c5cdf9u, 0xa9444018u, 0x7f975691u,
                 0x01dd0000u, 0x80a80000u, 0xf4960048u, 0xa6000000u,
                 0x90d57ea2u, 0xd7e68c37u, 0x6612cffdu, 0x2c94459eu)
    HAMSI512_ROW(hi, 48u,
                 0xe6280000u, 0x4c4b0000u, 0xa8550000u, 0xd3d002e0u,
                 0xd86130b8u, 0x98a7b0dau, 0x289506b4u, 0xd75a4897u,
                 0xf0c50000u, 0x59230000u, 0x45820000u, 0xe18d00c0u,
                 0x3b6d0631u, 0xc2ed5699u, 0xcbe0fe1cu, 0x56a7b19fu)
    HAMSI512_ROW(hi, 49u,
                 0xf0c50000u, 0x59230000u, 0x45820000u, 0xe18d00c0u,
                 0x3b6d0631u, 0xc2ed5699u, 0xcbe0fe1cu, 0x56a7b19fu,
                 0x16ed0000u, 0x15680000u, 0xedd70000u, 0x325d0220u,
                 0xe30c3689u, 0x5a4ae643u, 0xe375f8a8u, 0x81fdf908u)
    HAMSI512_ROW(hi, 50u,
                 0xb4310000u, 0x77330000u, 0xb15d0000u, 0x7fd004e0u,
                 0x78a26138u, 0xd116c35du, 0xd256d489u, 0x4e6f74deu,
                 0xe3060000u, 0xbdc10000u, 0x87130000u, 0xbff20060u,
                 0x2eba0a1au, 0x8db53751u, 0x73c5ab06u, 0x5bd61539u)
    HAMSI512_ROW(hi, 51u,
                 0xe3060000u, 0xbdc10000u, 0x87130000u, 0xbff20060u,
                 0x2eba0a1au, 0x8db53751u, 0x73c5ab06u, 0x5bd61539u,
                 0x57370000u, 0xcaf20000u, 0x364e0000u, 0xc0220480u,
                 0x56186b22u, 0x5ca3f40cu, 0xa1937f8fu, 0x15b961e7u)
    HAMSI512_ROW(hi, 52u,
                 0x02f20000u, 0xa2810000u, 0x873f0000u, 0xe36c7800u,
                 0x1e1d74efu, 0x073d2bd6u, 0xc4c23237u, 0x7f32259eu,
                 0xbadd0000u, 0x13ad0000u, 0xb7e70000u, 0xf7282800u,
                 0xdf45144du, 0x361ac33au, 0xea5a8d14u, 0x2a2c18f0u)
    HAMSI512_ROW(hi, 53u,
                 0xbadd0000u, 0x13ad0000u, 0xb7e70000u, 0xf7282800u,
                 0xdf45144du, 0x361ac33au, 0xea5a8d14u, 0x2a2c18f0u,
                 0xb82f0000u, 0xb12c0000u, 0x30d80000u, 0x14445000u,
                 0xc15860a2u, 0x3127e8ecu, 0x2e98bf23u, 0x551e3d6eu)
    HAMSI512_ROW(hi, 54u,
                 0x1e6c0000u, 0xc4420000u, 0x8a2e0000u, 0xbcb6b800u,
                 0x2c4413b6u, 0x8bfdd3dau, 0x6a0c1bc8u, 0xb99dc2ebu,
                 0x92560000u, 0x1eda0000u, 0xea510000u, 0xe8b13000u,
                 0xa93556a5u, 0xebfb6199u, 0xb15c2254u, 0x33c5244fu)
    HAMSI512_ROW(hi, 55u,
                 0x92560000u, 0x1eda0000u, 0xea510000u, 0xe8b13000u,
                 0xa93556a5u, 0xebfb6199u, 0xb15c2254u, 0x33c5244fu,
                 0x8c3a0000u, 0xda980000u, 0x607f0000u, 0x54078800u,
                 0x85714513u, 0x6006b243u, 0xdb50399cu, 0x8a58e6a4u)
    HAMSI512_ROW(hi, 56u,
                 0x033d0000u, 0x08b30000u, 0xf33a0000u, 0x3ac20007u,
                 0x51298a50u, 0x6b6e661fu, 0x0ea5cfe3u, 0xe6da7ffeu,
                 0xa8da0000u, 0x96be0000u, 0x5c1d0000u, 0x07da0002u,
                 0x7d669583u, 0x1f98708au, 0xbb668808u, 0xda878000u)
    HAMSI512_ROW(hi, 57u,
                 0xa8da0000u, 0x96be0000u, 0x5c1d0000u, 0x07da0002u,
                 0x7d669583u, 0x1f98708au, 0xbb668808u, 0xda878000u,
                 0xabe70000u, 0x9e0d0000u, 0xaf270000u, 0x3d180005u,
                 0x2c4f1fd3u, 0x74f61695u, 0xb5c347ebu, 0x3c5dfffeu)
    HAMSI512_ROW(hi, 58u,
                 0x01930000u, 0xe7820000u, 0xedfb0000u, 0xcf0c000bu,
                 0x8dd08d58u, 0xbca3b42eu, 0x063661e1u, 0x536f9e7bu,
                 0x92280000u, 0xdc850000u, 0x57fa0000u, 0x56dc0003u,
                 0xbae92316u, 0x5aefa30cu, 0x90cef752u, 0x7b1675d7u)
    HAMSI512_ROW(hi, 59u,
                 0x92280000u, 0xdc850000u, 0x57fa0000u, 0x56dc0003u,
                 0xbae92316u, 0x5aefa30cu, 0x90cef752u, 0x7b1675d7u,
                 0x93bb0000u, 0x3b070000u, 0xba010000u, 0x99d00008u,
                 0x3739ae4eu, 0xe64c1722u, 0x96f896b3u, 0x2879ebacu)
    HAMSI512_ROW(hi, 60u,
                 0x5fa80000u, 0x56030000u, 0x43ae0000u, 0x64f30013u,
                 0x257e86bfu, 0x1311944eu, 0x541e95bfu, 0x8ea4db69u,
                 0x00440000u, 0x7f480000u, 0xda7c0000u, 0x2a230001u,
                 0x3badc9ccu, 0xa9b69c87u, 0x030a9e60u, 0xbe0a679eu)
    HAMSI512_ROW(hi, 61u,
                 0x00440000u, 0x7f480000u, 0xda7c0000u, 0x2a230001u,
                 0x3badc9ccu, 0xa9b69c87u, 0x030a9e60u, 0xbe0a679eu,
                 0x5fec0000u, 0x294b0000u, 0x99d20000u, 0x4ed00012u,
                 0x1ed34f73u, 0xbaa708c9u, 0x57140bdfu, 0x30aebcf7u)
    HAMSI512_ROW(hi, 62u,
                 0xee930000u, 0xd6070000u, 0x92c10000u, 0x2b9801e0u,
                 0x9451287cu, 0x3b6cfb57u, 0x45312374u, 0x201f6a64u,
                 0x7b280000u, 0x57420000u, 0xa9e50000u, 0x634300a0u,
                 0x9edb442fu, 0x6d9995bbu, 0x27f83b03u, 0xc7ff60f0u)
    HAMSI512_ROW(hi, 63u,
                 0x7b280000u, 0x57420000u, 0xa9e50000u, 0x634300a0u,
                 0x9edb442fu, 0x6d9995bbu, 0x27f83b03u, 0xc7ff60f0u,
                 0x95bb0000u, 0x81450000u, 0x3b240000u, 0x48db0140u,
                 0x0a8a6c53u, 0x56f56eecu, 0x62c91877u, 0xe7e00a94u)
}

#undef HAMSI512_ROW

// The S-box on one column, bitsliced over its four words.
void hamsi512_sbox(inout uint a, inout uint b, inout uint c, inout uint d)
{
    uint t = a;
    a &= c;
    a ^= d;
    c ^= b;
    c ^= a;
    d |= t;
    d ^= b;
    t ^= c;
    b = d;
    d |= t;
    d ^= a;
    a &= b;
    t ^= a;
    b ^= d;
    b ^= t;
    a = c;
    c = b;
    b = d;
    d = ~t;
}

void hamsi512_l(inout uint a, inout uint b, inout uint c, inout uint d)
{
    a = rotl32(a, 13u);
    c = rotl32(c, 3u);
    b ^= a ^ c;
    d ^= c ^ (a << 3);
    b = rotl32(b, 1u);
    d = rotl32(d, 7u);
    a ^= b ^ d;
    c ^= d ^ (b << 7);
    a = rotl32(a, 5u);
    c = rotl32(c, 22u);
}

// One round on the 32-word state, after the constants are added.
void hamsi512_round(inout uint s[32])
{
    for (uint k = 0u; k < 8u; k++)
        hamsi512_sbox(s[k], s[k + 8u], s[k + 16u], s[k + 24u]);
    hamsi512_l(s[0x00], s[0x09], s[0x12], s[0x1b]);
    hamsi512_l(s[0x01], s[0x0a], s[0x13], s[0x1c]);
    hamsi512_l(s[0x02], s[0x0b], s[0x14], s[0x1d]);
    hamsi512_l(s[0x03], s[0x0c], s[0x15], s[0x1e]);
    hamsi512_l(s[0x04], s[0x0d], s[0x16], s[0x1f]);
    hamsi512_l(s[0x05], s[0x0e], s[0x17], s[0x18]);
    hamsi512_l(s[0x06], s[0x0f], s[0x10], s[0x19]);
    hamsi512_l(s[0x07], s[0x08], s[0x11], s[0x1a]);
    hamsi512_l(s[0x00], s[0x02], s[0x05], s[0x07]);
    hamsi512_l(s[0x10], s[0x13], s[0x15], s[0x16]);
    hamsi512_l(s[0x09], s[0x0b], s[0x0c], s[0x0e]);
    hamsi512_l(s[0x19], s[0x1a], s[0x1c], s[0x1f]);
}

// One block into h: six rounds, or the final twelve. State words 0..7 and
// 16..23 fold back into h.
void hamsi512_compress(inout uint h[16], uint m[16], bool final_block)
{
    uint s[32];
    s[0x00] = m[0];  s[0x01] = m[1];  s[0x02] = h[0];  s[0x03] = h[1];
    s[0x04] = m[2];  s[0x05] = m[3];  s[0x06] = h[2];  s[0x07] = h[3];
    s[0x08] = h[4];  s[0x09] = h[5];  s[0x0a] = m[4];  s[0x0b] = m[5];
    s[0x0c] = h[6];  s[0x0d] = h[7];  s[0x0e] = m[6];  s[0x0f] = m[7];
    s[0x10] = m[8];  s[0x11] = m[9];  s[0x12] = h[8];  s[0x13] = h[9];
    s[0x14] = m[10]; s[0x15] = m[11]; s[0x16] = h[10]; s[0x17] = h[11];
    s[0x18] = h[12]; s[0x19] = h[13]; s[0x1a] = m[12]; s[0x1b] = m[13];
    s[0x1c] = h[14]; s[0x1d] = h[15]; s[0x1e] = m[14]; s[0x1f] = m[15];

    uint rounds = final_block ? 12u : 6u;
    for (uint r = 0u; r < rounds; r++) {
        for (uint k = 0u; k < 32u; k++)
            s[k] ^= final_block ? kHamsi512AlphaF[k] : kHamsi512AlphaN[k];
        s[1] ^= r;
        hamsi512_round(s);
    }

    for (uint k = 0u; k < 8u; k++) {
        h[k] ^= s[k];
        h[8u + k] ^= s[16u + k];
    }
}

#endif  // VKMINER_SHADERS_COMMON_HAMSI512_GLSL_INCLUDED
