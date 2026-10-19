/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SHAVITE512_H__
#define VKMINER_SHAVITE512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar SHAvite-3-512, the round 2 specification. Digest is 64 bytes.  */
void shavite512_full( void *hash, const void *data, size_t len );

/* One 128-byte block under the 128-bit bit counter cnt, least significant
 * word first.  */
void shavite512_compress( uint32_t h[16], const unsigned char msg[128],
                          const uint32_t cnt[4] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHAVITE512_H__ */
