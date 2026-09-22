/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_RIPEMD160_H__
#define VKMINER_RIPEMD160_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar RIPEMD-160. Digest is 20 bytes, little-endian.
 *
 * Little-endian, unlike every other hash in this tree. See the note in
 * src/core/ripemd160.c.  */
void ripemd160_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_RIPEMD160_H__ */
