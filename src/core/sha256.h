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

/* The same idea carried one block further into the nonce-bearing block.
 *
 * Of that block's sixteen words only w[3] is the nonce; w[0..2] are the last
 * three header words and the rest is padding. So rounds 0..2 depend on nothing
 * per-nonce at all, and round 3 and message words 16..19 depend on the nonce
 * only *affinely* -- the nonce enters each of them once, through an addition
 * or through sigma0, and never through a rotation of a sum. Compute them here
 * at a nonce of zero and the device recovers any nonce by adding it back.
 *
 * Outputs, given the midstate over header words 0..15 and words 16..18:
 *   advanced[0..7]  the working variables a..h entering round 4, where
 *                   advanced[0] and advanced[4] are bases the device adds the
 *                   nonce to and the other six are the same for every nonce;
 *   sched[0..3]     message words w[16..19], where w[18] takes the nonce
 *                   through sigma0 and w[19] adds it.
 *
 * Like sha256_midstate(), not an optimization of the reference.  */
void sha256_advance_nonce_block( uint32_t advanced[8], uint32_t sched[4],
                                 const uint32_t state[8],
                                 const uint32_t tail[3] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_SHA256_H__ */
