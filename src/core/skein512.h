/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SKEIN512_H__
#define VKMINER_SKEIN512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Skein-512-512, specification version 1.3. Digest is 64 bytes.  */
void skein512_full( void *hash, const void *data, size_t len );

/* Skein-512-512's IV, computed from the configuration block.  */
void skein512_iv( uint64_t iv[8] );

/* The chaining value after the first 64 bytes of a longer message.  */
void skein512_midstate( uint64_t h[8], const unsigned char block[64] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SKEIN512_H__ */
