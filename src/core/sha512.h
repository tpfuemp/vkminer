/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SHA512_H__
#define VKMINER_SHA512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar FIPS 180-4 SHA-512. Digest is 64 bytes, big-endian.
 *
 * The oracle the GPU kernel is differentially tested against; see the note in
 * src/core/sha512.c about why it must stay slow and obvious.  */
void sha512_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHA512_H__ */
