/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_KECCAK512_H__
#define VKMINER_KECCAK512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Keccak-512 as submitted to the SHA-3 competition (round 3): rate 576
 * bits and the 0x01 padding. Not SHA3-512, which pads with 0x06. Digest is 64
 * bytes.  */
void keccak512_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_KECCAK512_H__ */
