/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_LUFFA512_H__
#define VKMINER_LUFFA512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Luffa-512, version 2 of the specification. Digest is 64 bytes.  */
void luffa512_full( void *hash, const void *data, size_t len );

/* One 32-byte block into the five lanes: injection, then the permutation.  */
void luffa512_block( uint32_t v[5][8], const unsigned char block[32] );

/* The third block of an 80-byte message, up to its steps, with the nonce
 * (big-endian word 19) read as zero: the first two blocks, then the injection
 * and tweak of the third, as five lanes of eight words. The nonce n enters
 * linearly from there, as rotl(n, j) at word 3 + j of lane j.  */
void luffa512_80_precompute( uint32_t out[40], const unsigned char data[80] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_LUFFA512_H__ */
