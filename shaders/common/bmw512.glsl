// BMW-512 (round 2) compression and final transform, for compute kernels.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Padding and lengths are the caller's. The final transform is separate so a
// hash chain can use the compression alone. src/core/bmw512.c is the reference.
//
// A word is BLANE: uint64_t, or a uvec2 pair (VKMINER_BMW_WIDE_ADD: added
// through uint64_t). Use badd()/bsub(), never `+`/`-`: a pair drops the carry.
// Every array index below is a literal, so Q stays in registers.

#ifndef VKMINER_SHADERS_COMMON_BMW512_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_BMW512_GLSL_INCLUDED

#ifdef VKMINER_BMW_INT64

// The includer declares the int64 extension.
#define BLANE uint64_t

BLANE blane(uint lo, uint hi) { return uint64_t(lo) | (uint64_t(hi) << 32); }
uint  blo(BLANE x)            { return uint(x); }
uint  bhi(BLANE x)            { return uint(x >> 32); }

BLANE badd(BLANE a, BLANE b)  { return a + b; }
BLANE bsub(BLANE a, BLANE b)  { return a - b; }

// n is constant: 1..31 for shifts, 1..63 for rotl.
BLANE bshl(BLANE x, uint n)   { return x << n; }
BLANE bshr(BLANE x, uint n)   { return x >> n; }
BLANE brotl(BLANE x, uint n)  { return (x << n) | (x >> (64u - n)); }

#else

#define BLANE uvec2   // .x is the low half, .y the high half

BLANE blane(uint lo, uint hi) { return uvec2(lo, hi); }
uint  blo(BLANE x)            { return x.x; }
uint  bhi(BLANE x)            { return x.y; }

#ifdef VKMINER_BMW_WIDE_ADD

// The packs are bitcasts. Needs shaderInt64; the includer declares it.
BLANE badd(BLANE a, BLANE b)
{
    return unpackUint2x32(packUint2x32(a) + packUint2x32(b));
}

BLANE bsub(BLANE a, BLANE b)
{
    return unpackUint2x32(packUint2x32(a) - packUint2x32(b));
}

#else

BLANE badd(BLANE a, BLANE b)
{
    uint carry;
    uint lo = uaddCarry(a.x, b.x, carry);
    return uvec2(lo, a.y + b.y + carry);
}

BLANE bsub(BLANE a, BLANE b)
{
    uint borrow;
    uint lo = usubBorrow(a.x, b.x, borrow);
    return uvec2(lo, a.y - b.y - borrow);
}

#endif  // VKMINER_BMW_WIDE_ADD

// n is constant, so the branches fold; shifts take 1..31.
BLANE bshl(BLANE x, uint n)
{
    return uvec2(x.x << n, (x.y << n) | (x.x >> (32u - n)));
}

BLANE bshr(BLANE x, uint n)
{
    return uvec2((x.x >> n) | (x.y << (32u - n)), x.y >> n);
}

// 32 or more swaps the halves first.
BLANE brotl(BLANE x, uint n)
{
    BLANE v = (n >= 32u) ? x.yx : x;
    uint s = n & 31u;
    return s == 0u ? v
                   : uvec2((v.x << s) | (v.y >> (32u - s)),
                           (v.y << s) | (v.x >> (32u - s)));
}

#endif  // VKMINER_BMW_INT64

BLANE bmw_s0(BLANE x)
{
    return bshr(x, 1u) ^ bshl(x, 3u) ^ brotl(x, 4u) ^ brotl(x, 37u);
}

BLANE bmw_s1(BLANE x)
{
    return bshr(x, 1u) ^ bshl(x, 2u) ^ brotl(x, 13u) ^ brotl(x, 43u);
}

BLANE bmw_s2(BLANE x)
{
    return bshr(x, 2u) ^ bshl(x, 1u) ^ brotl(x, 19u) ^ brotl(x, 53u);
}

BLANE bmw_s3(BLANE x)
{
    return bshr(x, 2u) ^ bshl(x, 2u) ^ brotl(x, 28u) ^ brotl(x, 59u);
}

BLANE bmw_s4(BLANE x) { return bshr(x, 1u) ^ x; }
BLANE bmw_s5(BLANE x) { return bshr(x, 2u) ^ x; }

// IV: the bytes 0x80..0xff as big-endian words.
BLANE bmw512_iv(uint i)
{
    uint b = 0x80818283u + i * 0x08080808u;
    return blane(b + 0x04040404u, b);
}

// AddElement's K(j) = j * 0x0555555555555555, j = 16..31, as (low, high).
const uvec2 bmw512_k_words[16] = uvec2[16](
    uvec2(0x55555550u, 0x55555555u), uvec2(0xaaaaaaa5u, 0x5aaaaaaau),
    uvec2(0xfffffffau, 0x5fffffffu), uvec2(0x5555554fu, 0x65555555u),
    uvec2(0xaaaaaaa4u, 0x6aaaaaaau), uvec2(0xfffffff9u, 0x6fffffffu),
    uvec2(0x5555554eu, 0x75555555u), uvec2(0xaaaaaaa3u, 0x7aaaaaaau),
    uvec2(0xfffffff8u, 0x7fffffffu), uvec2(0x5555554du, 0x85555555u),
    uvec2(0xaaaaaaa2u, 0x8aaaaaaau), uvec2(0xfffffff7u, 0x8fffffffu),
    uvec2(0x5555554cu, 0x95555555u), uvec2(0xaaaaaaa1u, 0x9aaaaaaau),
    uvec2(0xfffffff6u, 0x9fffffffu), uvec2(0x5555554bu, 0xa5555555u));

// f0: Q[i] = s_(i mod 5)(W[i]) + H[i+1], W[i] a signed sum of five x = M ^ H.
#define BMW_F0(i, s, i0, op1, i1, op2, i2, op3, i3, op4, i4)              \
    q[i] = badd(s(op4(op3(op2(op1(x[i0], x[i1]), x[i2]), x[i3]), x[i4])),  \
                h[((i) + 1) % 16])

// AddElement(i): rotl(M[k], k + 1) for k = i, i+3, i+10, plus K, xor H[i+7].
#define BMW_ADD_ELT(i)                                                    \
    (badd(bsub(badd(brotl(m[i], (i) + 1u),                                \
                    brotl(m[((i) + 3) % 16], ((i) + 3) % 16 + 1u)),       \
               brotl(m[((i) + 10) % 16], ((i) + 10) % 16 + 1u)),          \
          blane(bmw512_k_words[i].x, bmw512_k_words[i].y))                \
     ^ h[((i) + 7) % 16])

// f1, expand1: s1, s2, s3, s0 cycling over the previous sixteen Q.
#define BMW_EXPAND1(j)                                                    \
    {                                                                     \
        BLANE v = BMW_ADD_ELT((j) - 16);                                  \
        v = badd(v, bmw_s1(q[(j) - 16])); v = badd(v, bmw_s2(q[(j) - 15])); \
        v = badd(v, bmw_s3(q[(j) - 14])); v = badd(v, bmw_s0(q[(j) - 13])); \
        v = badd(v, bmw_s1(q[(j) - 12])); v = badd(v, bmw_s2(q[(j) - 11])); \
        v = badd(v, bmw_s3(q[(j) - 10])); v = badd(v, bmw_s0(q[(j) -  9])); \
        v = badd(v, bmw_s1(q[(j) -  8])); v = badd(v, bmw_s2(q[(j) -  7])); \
        v = badd(v, bmw_s3(q[(j) -  6])); v = badd(v, bmw_s0(q[(j) -  5])); \
        v = badd(v, bmw_s1(q[(j) -  4])); v = badd(v, bmw_s2(q[(j) -  3])); \
        v = badd(v, bmw_s3(q[(j) -  2])); v = badd(v, bmw_s0(q[(j) -  1])); \
        q[j] = v;                                                         \
    }

// f1, expand2: alternate Q rotated by r1..r7, the last two through s4, s5.
#define BMW_EXPAND2(j)                                                    \
    {                                                                     \
        BLANE v = BMW_ADD_ELT((j) - 16);                                  \
        v = badd(v, q[(j) - 16]); v = badd(v, brotl(q[(j) - 15],  5u));   \
        v = badd(v, q[(j) - 14]); v = badd(v, brotl(q[(j) - 13], 11u));   \
        v = badd(v, q[(j) - 12]); v = badd(v, brotl(q[(j) - 11], 27u));   \
        v = badd(v, q[(j) - 10]); v = badd(v, brotl(q[(j) -  9], 32u));   \
        v = badd(v, q[(j) -  8]); v = badd(v, brotl(q[(j) -  7], 37u));   \
        v = badd(v, q[(j) -  6]); v = badd(v, brotl(q[(j) -  5], 43u));   \
        v = badd(v, q[(j) -  4]); v = badd(v, brotl(q[(j) -  3], 53u));   \
        v = badd(v, bmw_s4(q[(j) - 2])); v = badd(v, bmw_s5(q[(j) - 1])); \
        q[j] = v;                                                         \
    }

// f0: Q[0..15]. The rest of q is left as it was.
void bmw512_f0(inout BLANE q[32], BLANE h[16], BLANE m[16])
{
    BLANE x[16];
    for (uint i = 0u; i < 16u; i++)
        x[i] = m[i] ^ h[i];

    BMW_F0( 0, bmw_s0,  5, bsub,  7, badd, 10, badd, 13, badd, 14);
    BMW_F0( 1, bmw_s1,  6, bsub,  8, badd, 11, badd, 14, bsub, 15);
    BMW_F0( 2, bmw_s2,  0, badd,  7, badd,  9, bsub, 12, badd, 15);
    BMW_F0( 3, bmw_s3,  0, bsub,  1, badd,  8, bsub, 10, badd, 13);
    BMW_F0( 4, bmw_s4,  1, badd,  2, badd,  9, bsub, 11, bsub, 14);
    BMW_F0( 5, bmw_s0,  3, bsub,  2, badd, 10, bsub, 12, badd, 15);
    BMW_F0( 6, bmw_s1,  4, bsub,  0, bsub,  3, bsub, 11, badd, 13);
    BMW_F0( 7, bmw_s2,  1, bsub,  4, bsub,  5, bsub, 12, bsub, 14);
    BMW_F0( 8, bmw_s3,  2, bsub,  5, bsub,  6, badd, 13, bsub, 15);
    BMW_F0( 9, bmw_s4,  0, bsub,  3, badd,  6, bsub,  7, badd, 14);
    BMW_F0(10, bmw_s0,  8, bsub,  1, bsub,  4, bsub,  7, badd, 15);
    BMW_F0(11, bmw_s1,  8, bsub,  0, bsub,  2, bsub,  5, badd,  9);
    BMW_F0(12, bmw_s2,  1, badd,  3, bsub,  6, bsub,  9, badd, 10);
    BMW_F0(13, bmw_s3,  2, badd,  4, badd,  7, badd, 10, badd, 11);
    BMW_F0(14, bmw_s4,  3, bsub,  5, badd,  8, bsub, 11, bsub, 12);
    BMW_F0(15, bmw_s0, 12, bsub,  4, bsub,  6, bsub,  9, badd, 13);
}

// f2: the fold of q back into h; m is the block.
void bmw512_f2(inout BLANE h[16], BLANE q[32], BLANE m[16])
{
    BLANE xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];
    BLANE xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30]
                  ^ q[31];

    h[0] = badd(bshl(xh,  5u) ^ bshr(q[16], 5u) ^ m[0], xl ^ q[24] ^ q[0]);
    h[1] = badd(bshr(xh,  7u) ^ bshl(q[17], 8u) ^ m[1], xl ^ q[25] ^ q[1]);
    h[2] = badd(bshr(xh,  5u) ^ bshl(q[18], 5u) ^ m[2], xl ^ q[26] ^ q[2]);
    h[3] = badd(bshr(xh,  1u) ^ bshl(q[19], 5u) ^ m[3], xl ^ q[27] ^ q[3]);
    h[4] = badd(bshr(xh,  3u) ^ q[20]           ^ m[4], xl ^ q[28] ^ q[4]);
    h[5] = badd(bshl(xh,  6u) ^ bshr(q[21], 6u) ^ m[5], xl ^ q[29] ^ q[5]);
    h[6] = badd(bshr(xh,  4u) ^ bshl(q[22], 6u) ^ m[6], xl ^ q[30] ^ q[6]);
    h[7] = badd(bshr(xh, 11u) ^ bshl(q[23], 2u) ^ m[7], xl ^ q[31] ^ q[7]);

    h[ 8] = badd(badd(brotl(h[4],  9u), xh ^ q[24] ^ m[ 8]),
                 bshl(xl, 8u) ^ q[23] ^ q[ 8]);
    h[ 9] = badd(badd(brotl(h[5], 10u), xh ^ q[25] ^ m[ 9]),
                 bshr(xl, 6u) ^ q[16] ^ q[ 9]);
    h[10] = badd(badd(brotl(h[6], 11u), xh ^ q[26] ^ m[10]),
                 bshl(xl, 6u) ^ q[17] ^ q[10]);
    h[11] = badd(badd(brotl(h[7], 12u), xh ^ q[27] ^ m[11]),
                 bshl(xl, 4u) ^ q[18] ^ q[11]);
    h[12] = badd(badd(brotl(h[0], 13u), xh ^ q[28] ^ m[12]),
                 bshr(xl, 3u) ^ q[19] ^ q[12]);
    h[13] = badd(badd(brotl(h[1], 14u), xh ^ q[29] ^ m[13]),
                 bshr(xl, 4u) ^ q[20] ^ q[13]);
    h[14] = badd(badd(brotl(h[2], 15u), xh ^ q[30] ^ m[14]),
                 bshr(xl, 7u) ^ q[21] ^ q[14]);
    h[15] = badd(badd(brotl(h[3], 16u), xh ^ q[31] ^ m[15]),
                 bshr(xl, 2u) ^ q[22] ^ q[15]);
}

// h = f2(f1(f0(h, m)), m): one compression of the 128-byte block m.
void bmw512_compress(inout BLANE h[16], BLANE m[16])
{
    BLANE q[32];
    bmw512_f0(q, h, m);

    BMW_EXPAND1(16); BMW_EXPAND1(17);
    BMW_EXPAND2(18); BMW_EXPAND2(19); BMW_EXPAND2(20); BMW_EXPAND2(21);
    BMW_EXPAND2(22); BMW_EXPAND2(23); BMW_EXPAND2(24); BMW_EXPAND2(25);
    BMW_EXPAND2(26); BMW_EXPAND2(27); BMW_EXPAND2(28); BMW_EXPAND2(29);
    BMW_EXPAND2(30); BMW_EXPAND2(31);

    bmw512_f2(h, q, m);
}

// Final transform: compress the state as a message under 0xaaaa..aaa0 + i.
// The digest is h[8..15].
void bmw512_final(inout BLANE h[16])
{
    BLANE m[16] = h;
    for (uint i = 0u; i < 16u; i++)
        h[i] = blane(0xaaaaaaa0u + i, 0xaaaaaaaau);
    bmw512_compress(h, m);
}

#endif  // VKMINER_SHADERS_COMMON_BMW512_GLSL_INCLUDED
