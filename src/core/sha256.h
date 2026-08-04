/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_SHA256_H__
#define VKMINER_SHA256_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar FIPS 180-4 SHA-256. Digest is 32 bytes, big-endian, as Bitcoin
 * uses it.
 *
 * This is deliberately the plainest implementation that can be checked
 * against the standard's own test vectors by reading it. It is the oracle
 * the GPU kernel is differentially tested against, so it must never be
 * optimized -- a shared bug between reference and kernel is invisible.  */
void sha256_full( void *hash, const void *data, size_t len );

/* SHA-256 applied twice, the Bitcoin "hash256". */
void sha256d( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHA256_H__ */
