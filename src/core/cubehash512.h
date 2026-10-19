/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_CUBEHASH512_H__
#define VKMINER_CUBEHASH512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar CubeHash16/32-512, the round 2 parameters. Digest is 64 bytes.  */
void cubehash512_full( void *hash, const void *data, size_t len );

/* One 32-byte block into the 32-word state: the xor and sixteen rounds.  */
void cubehash512_block( uint32_t x[32], const unsigned char block[32] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_CUBEHASH512_H__ */
