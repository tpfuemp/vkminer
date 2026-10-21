/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_FUGUE512_H__
#define VKMINER_FUGUE512_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar Fugue-512, the round 2 SHA-3 submission. Digest is 64 bytes.  */
void fugue512_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_FUGUE512_H__ */
