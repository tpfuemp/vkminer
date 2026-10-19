/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VKMINER_AES_ROUND_H__
#define VKMINER_AES_ROUND_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One AES encryption round on four columns, each a little-endian word (byte
 * r is row r), in place. A null key is the all-zero round key.  */
void aes_round_le( uint32_t x[4], const uint32_t key[4] );

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_AES_ROUND_H__ */
