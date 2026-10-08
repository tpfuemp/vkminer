// groestl: two nonces per pass, bitsliced. Groestl-512 of the header, twice.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Each pass hashes nonces n and n + 1 together as bit planes (see
// shaders/common/groestl512_bs.glsl): two Groestl-512s of one block each, the
// 80-byte header and then the 64-byte digest. The result is the first 32
// bytes of the second.
//
// Byte order: the host uploads header words as little-endian reads of the wire.
// The nonce is a host-order value and is swapped here. Digest words come out as
// the little-endian words the host compares.

#ifndef VKMINER_ALGORITHMS_GROESTL_KERNEL_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_GROESTL_KERNEL_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/groestl512_bs.glsl"
#include "shaders/common/candidates.glsl"

layout(local_size_x_id = 0) in;

// Consecutive nonces per invocation, set by the backend; groestl.cpp asks for
// two, one pass.
layout(constant_id = 5) const uint kNoncesPerInvocation = 1u;

// 96 bytes. Mirrored by GroestlPush in groestl.cpp and MyrgrPush in myrgr.cpp,
// which assert the layout.
layout(push_constant) uniform Push {
    uint header[19];    // header words 0..18, little-endian reads of the wire
    uint target[2];     // the top 64 bits, most significant last
    uint nonce_start;
    uint count;         // nonces to test, which is not the invocation count
    uint capacity;      // candidates the result buffer can hold
} push;

// Swaps index bits (word k) and (bit position): eight words of four bytes in,
// eight bit planes out. Its own inverse.
void groestl_transpose(inout uint d[8])
{
    uint t;
#define GROESTL_SWAP(x, y, m, n)                                           \
    t = (d[x] ^ (d[y] << (n))) & (m); d[x] ^= t; d[y] ^= t >> (n)
    GROESTL_SWAP(0, 1, 0xaaaaaaaau, 1); GROESTL_SWAP(2, 3, 0xaaaaaaaau, 1);
    GROESTL_SWAP(4, 5, 0xaaaaaaaau, 1); GROESTL_SWAP(6, 7, 0xaaaaaaaau, 1);
    GROESTL_SWAP(0, 2, 0xccccccccu, 2); GROESTL_SWAP(1, 3, 0xccccccccu, 2);
    GROESTL_SWAP(4, 6, 0xccccccccu, 2); GROESTL_SWAP(5, 7, 0xccccccccu, 2);
    GROESTL_SWAP(0, 4, 0xf0f0f0f0u, 4); GROESTL_SWAP(1, 5, 0xf0f0f0f0u, 4);
    GROESTL_SWAP(2, 6, 0xf0f0f0f0u, 4); GROESTL_SWAP(3, 7, 0xf0f0f0f0u, 4);
#undef GROESTL_SWAP
}

// Byte (row i, column c) of one hash's padded 80-byte block: the header, the
// 0x80 terminator in column 10 and a block count of one at byte 127.
uint groestl_msg_byte(uint i, uint c, uint nonce_le)
{
    uint w = 0u;
    if (c < 9u)
        w = push.header[2u * c + (i >> 2)];
    else if (c == 9u)
        w = (i < 4u) ? push.header[18] : nonce_le;
    else if (c == 10u)
        w = (i < 4u) ? 0x80u : 0u;
    else if (c == 15u)
        w = (i < 4u) ? 0u : 0x01000000u;
    return (w >> (8u * (i & 3u))) & 0xffu;
}

// Word k of row i holds bytes (row i, column 4n + k / 2) of hash k & 1;
// transposed, that is the row's eight bit planes.
void groestl_load80(out uint s[64], uint n0, uint n1)
{
    for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        for (uint k = 0u; k < 8u; k++) {
            uint n = (k & 1u) == 0u ? n0 : n1;
            uint c = k >> 1;
            d[k] = groestl_msg_byte(i, c, n)
                 | (groestl_msg_byte(i, 4u + c, n) << 8)
                 | (groestl_msg_byte(i, 8u + c, n) << 16)
                 | (groestl_msg_byte(i, 12u + c, n) << 24);
        }
        groestl_transpose(d);
        for (uint b = 0u; b < 8u; b++)
            s[8u * i + b] = d[b];
    }
}

// Groestl-512 of the block in s: s becomes P(H) ^ H, the digest in columns
// 8..15, with H = P(m ^ IV) ^ Q(m) ^ IV. The three permutations share one
// loop so the round body is in the binary once.
void groestl_hash(inout uint s[64])
{
    uint m[64] = s;
    for (uint p = 0u; p < 3u; p++) {
        if (p == 0u) {
            s[49] ^= 0xc0000000u;          // IV: column 15 row 6 = 0x02
        } else if (p == 1u) {
            for (uint k = 0u; k < 64u; k++) {
                uint v = m[k];
                m[k] = s[k];
                s[k] = v;
            }
        } else {
            for (uint k = 0u; k < 64u; k++) {
                s[k] ^= m[k];
                m[k] = s[k];
            }
            s[49] ^= 0xc0000000u;
            m[49] ^= 0xc0000000u;
        }
        for (uint r = 0u; r < 14u; r++)
            groestl_bs_round(s, r, p == 1u);
    }
    for (uint k = 0u; k < 64u; k++)
        s[k] ^= m[k];
}

void groestl_check(uint nonce, uint hash[8])
{
    // Compiled away unless the pipeline was built with the probe on.
    probe_best(hash[7]);

    // A prefix of the share test; the host compares all 256 bits.
    if (hash[7] > push.target[1])
        return;
    if (hash[7] == push.target[1] && hash[6] > push.target[0])
        return;

    emit_candidate(push.capacity, nonce, hash);
}

// myr-gr includes the above and brings its own search and main().
#ifndef VKMINER_GROESTL_NO_MAIN

// Nonces n and n + 1; `two` false hashes the second lane and drops it.
void groestl_search(uint n, bool two)
{
    uint s[64];
    groestl_load80(s, bswap32(n), bswap32(n + 1u));
    for (uint pass = 0u; pass < 2u; pass++) {
        if (pass == 1u) {
            // Digest columns 8..15 become message columns 0..7, then the
            // padding for 64 bytes.
            for (uint k = 0u; k < 64u; k++)
                s[k] >>= 16;
            s[7] |= 0x00030000u;           // column 8 row 0 = 0x80
            s[56] |= 0xc0000000u;          // column 15 row 7 = 0x01
        }
        groestl_hash(s);
    }

    // Back to bytes. Digest word w is column 8 + w / 2, rows 4 (w & 1) to +3;
    // word k = 2 (column & 3) + hash, byte column >> 2 = 2.
    uint rows[64];
    for (uint i = 0u; i < 8u; i++) {
        uint d[8];
        for (uint b = 0u; b < 8u; b++)
            d[b] = s[8u * i + b];
        groestl_transpose(d);
        for (uint k = 0u; k < 8u; k++)
            rows[8u * i + k] = d[k];
    }
    for (uint h = 0u; h < 2u; h++) {
        if (h == 1u && !two)
            break;
        uint hash[8];
        for (uint w = 0u; w < 8u; w++) {
            uint c = 8u + (w >> 1), k = 2u * (c & 3u) + h, r0 = 4u * (w & 1u);
            hash[w] = ((rows[8u * r0 + k] >> 16) & 0xffu)
                    | (((rows[8u * (r0 + 1u) + k] >> 16) & 0xffu) << 8)
                    | (((rows[8u * (r0 + 2u) + k] >> 16) & 0xffu) << 16)
                    | (((rows[8u * (r0 + 3u) + k] >> 16) & 0xffu) << 24);
        }
        groestl_check(n + h, hash);
    }
}

void main()
{
    uint first = gl_GlobalInvocationID.x * kNoncesPerInvocation;
    for (uint k = 0u; k < kNoncesPerInvocation; k += 2u) {
        uint index = first + k;
        if (index >= push.count)
            return;
        // The second lane is this invocation's and inside the dispatch, or
        // another invocation would hash the same nonce.
        groestl_search(push.nonce_start + index,
                       k + 1u < kNoncesPerInvocation && index + 1u < push.count);
    }
}

#endif  // VKMINER_GROESTL_NO_MAIN

#endif  // VKMINER_ALGORITHMS_GROESTL_KERNEL_GLSL_INCLUDED
