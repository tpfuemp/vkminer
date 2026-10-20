/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_BLAKE512_H__
#define VKMINER_BLAKE512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar BLAKE-512, the final SHA-3 submission: sixteen rounds. Not BLAKE2b,
 * which has other constants, rotations and padding. Digest is 64 bytes.  */
void blake512_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_BLAKE512_H__ */
