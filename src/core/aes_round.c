/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * One AES encryption round (FIPS 197: SubBytes, ShiftRows, MixColumns, then
 * the round key), for the SHA-3 candidates built on it: SHAvite-3 and ECHO.
 * Plain on purpose, as the oracle for their kernels.
 */

#include "core/aes_round.h"

#include "core/groestl512.h"

static uint8_t xtime( uint8_t a )
{
    return (uint8_t)( ( a << 1 ) ^ ( ( a & 0x80 ) ? 0x1b : 0 ) );
}

void aes_round_le( uint32_t x[4], const uint32_t key[4] )
{
    uint8_t a[4][4];  /* [column][row] after SubBytes and ShiftRows */
    int c, r;

    /* Row r of column c comes from column c + r. Groestl's S-box is AES's. */
    for ( c = 0; c < 4; c++ )
        for ( r = 0; r < 4; r++ )
            a[c][r] = groestl512_sbox(
                (uint8_t)( x[( c + r ) & 3] >> ( 8 * r ) ) );

    for ( c = 0; c < 4; c++ ) {
        uint8_t all = (uint8_t)( a[c][0] ^ a[c][1] ^ a[c][2] ^ a[c][3] );
        uint32_t w = 0;

        for ( r = 0; r < 4; r++ ) {
            /* 2a_r + 3a_{r+1} + a_{r+2} + a_{r+3} */
            uint8_t b = (uint8_t)( a[c][r] ^ all
                                 ^ xtime( (uint8_t)( a[c][r] ^ a[c][( r + 1 ) & 3] ) ) );
            w |= (uint32_t)b << ( 8 * r );
        }
        x[c] = w ^ ( key ? key[c] : 0 );
    }
}
