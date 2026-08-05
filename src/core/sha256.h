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

/* The state after compressing one 64-byte block from the initial value, where
 * the block is given as sixteen words each holding four message bytes in
 * big-endian order.
 *
 * This exists because the first block of an 80-byte block header holds no
 * nonce, so its compression is the same for every nonce in a dispatch and is
 * done once on the host instead of a few billion times on the device. It is
 * not an optimization of the reference: the reference still hashes all eighty
 * bytes, and the differential test is what says the two agree.  */
void sha256_midstate( uint32_t state[8], const uint32_t words[16] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHA256_H__ */
