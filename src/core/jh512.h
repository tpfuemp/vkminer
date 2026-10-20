/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_JH512_H__
#define VKMINER_JH512_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scalar JH-512, the round 3 (final) SHA-3 submission: 42 rounds of E8.
 * Digest is 64 bytes.  */
void jh512_full( void *hash, const void *data, size_t len );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_JH512_H__ */
