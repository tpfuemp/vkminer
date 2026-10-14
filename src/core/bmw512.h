/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_BMW512_H__
#define VKMINER_BMW512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar BMW-512, the tweaked (round 2) specification. Digest is 64 bytes.  */
void bmw512_full( void *hash, const void *data, size_t len );

/* For an 80-byte message, whose nonce is bytes 76..79: every part of the
 * first compression that does not read the nonce, which the bmw512 kernel
 * takes as its uniform block. The nonce bytes of header are ignored.
 *   out[0..15]   Q[i] where it does not read the nonce, else W[i] of f0 with
 *                x[9] taken as zero
 *   out[16..31]  Q[i] of f1 less every term that reads the nonce
 *   out[32..34]  AddElement(6), (9) and (15) before the xor, M[9] as zero   */
void bmw512_80_precompute( uint64_t out[35], const void *header );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_BMW512_H__ */
