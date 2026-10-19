/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_ECHO512_H__
#define VKMINER_ECHO512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar ECHO-512, the round 2 specification. Digest is 64 bytes.  */
void echo512_full( void *hash, const void *data, size_t len );

/* One 128-byte block into the eight 128-bit chaining words, under the
 * 128-bit bit counter cnt, least significant word first.  */
void echo512_compress( uint32_t v[8][4], const unsigned char msg[128],
                       const uint32_t cnt[4] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_ECHO512_H__ */
