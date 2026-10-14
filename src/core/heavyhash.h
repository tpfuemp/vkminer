/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_HEAVYHASH_H__
#define VKMINER_HEAVYHASH_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar HeavyHash, Optical Bitcoin's proof of work. matrix[i][j] is row i,
 * column j, each entry 0..15.                                               */

/* SHA3-256 (FIPS 202 padding, 0x06) of a message shorter than its 136-byte
 * rate, which is every message this algorithm hashes.                       */
void heavyhash_sha3_256( unsigned char out[32], const void *in, size_t len );

/* The job-constant half: the matrix an 80-byte header is mined against, from
 * header bytes 4..35 (the previous block hash) and nothing else.           */
void heavyhash_matrix( uint8_t matrix[64][64], const void *header80 );

/* The same from a 32-byte seed rather than a header, so that the generator can
 * be tested apart from where its seed comes from.                          */
void heavyhash_matrix_from_seed( uint8_t matrix[64][64],
                                 const unsigned char seed[32] );

/* Whether a matrix of 4-bit entries is nonsingular.                         */
int heavyhash_full_rank( const uint8_t matrix[64][64] );

/* The nonce-dependent half over `len` bytes of message: SHA3-256, the matrix
 * product, SHA3-256. Mining always passes 80; the length exists so that the
 * daemon's own short vectors can run as they are written.                  */
void heavyhash_core( unsigned char out[32], const uint8_t matrix[64][64],
                     const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_HEAVYHASH_H__ */
