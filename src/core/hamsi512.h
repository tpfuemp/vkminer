/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_HAMSI512_H__
#define VKMINER_HAMSI512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Hamsi-512, the round 2 SHA-3 submission. Digest is 64 bytes.  */
void hamsi512_full( void *hash, const void *data, size_t len );

/* Row i of the message expansion: the sixteen words message bit i adds,
 * bit i being bit i & 7 of byte i >> 3 of an 8-byte block.  */
extern const uint32_t hamsi512_expand_rows[64][16];

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_HAMSI512_H__ */
