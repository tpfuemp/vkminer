/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SHABAL512_H__
#define VKMINER_SHABAL512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Shabal-512, the round 2 SHA-3 submission. Digest is 64 bytes.  */
void shabal512_full( void *hash, const void *data, size_t len );

/* The state after the two prefix blocks: A[12], then B[16], then C[16].
 * Derived on first use from the specification's own construction; the
 * kernels carry the same 44 words as constants.  */
const uint32_t *shabal512_iv( void );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHABAL512_H__ */
