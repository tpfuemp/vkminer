/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_GROESTL512_H__
#define VKMINER_GROESTL512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Groestl-512, the final (round 3, tweaked) specification. Digest is
 * 64 bytes.  */
void groestl512_full( void *hash, const void *data, size_t len );

/* The AES S-box, computed from its definition: the GF(2^8) inverse, then the
 * affine map.  */
uint8_t groestl512_sbox( uint8_t x );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_GROESTL512_H__ */
