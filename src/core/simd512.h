/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SIMD512_H__
#define VKMINER_SIMD512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar SIMD-512, the round 2 specification. Digest is 64 bytes.  */
void simd512_full( void *hash, const void *data, size_t len );

/* One 128-byte block into the 32-word state; final selects the last
 * block's transform tweak.  */
void simd512_compress( uint32_t h[32], const unsigned char msg[128], int final );

/* The message expansion alone: the 256 transform values, each -128..128.  */
void simd512_expand( int32_t y[256], const unsigned char msg[128], int final );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SIMD512_H__ */
