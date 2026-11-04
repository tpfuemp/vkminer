/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_TIGER192_H__
#define VKMINER_TIGER192_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Tiger, the original 1996 hash with 0x01 padding (not Tiger2).
 * Digest is 24 bytes.  */
void tiger192_full( void *hash, const void *data, size_t len );

/* The four S-boxes, 256 words each, back to back. Generated on first use by
 * the designers' own procedure; the kernels carry the same words.  */
const uint64_t *tiger192_sboxes( void );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_TIGER192_H__ */
