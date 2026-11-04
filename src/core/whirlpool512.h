/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_WHIRLPOOL512_H__
#define VKMINER_WHIRLPOOL512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Whirlpool, the final ISO/IEC 10118-3 version. Digest is 64 bytes.  */
void whirlpool512_full( void *hash, const void *data, size_t len );

/* The S-box, built from the specification's three 4-bit mini-boxes.  */
uint8_t whirlpool512_sbox( uint8_t x );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_WHIRLPOOL512_H__ */
