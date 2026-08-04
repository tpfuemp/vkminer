/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Scalar SHA-256, written from FIPS 180-4 rather than carried over from
 * cpuminer-opt, whose implementations are all SIMD and all discarded here.
 *
 * Two callers, and they pull in opposite directions:
 *   - address_to_script(), where it checksums a base58 payload once per
 *     startup and speed is irrelevant;
 *   - the differential test harness, where it is the oracle the compute
 *     shader is checked against, and where being obviously correct by
 *     inspection is the entire point.
 * The second caller wins. Do not vectorize this file.
 */

#include "core/sha256.h"

#include <string.h>

static const uint32_t K[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t IV[8] = {
   0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static inline uint32_t ror( uint32_t x, int n )
{
   return ( x >> n ) | ( x << ( 32 - n ) );
}

static void sha256_transform( uint32_t state[8], const uint8_t block[64] )
{
   uint32_t w[64];
   uint32_t a, b, c, d, e, f, g, h;
   int i;

   for ( i = 0; i < 16; i++ )
      w[i] =   ( (uint32_t)block[ i*4     ] << 24 )
             | ( (uint32_t)block[ i*4 + 1 ] << 16 )
             | ( (uint32_t)block[ i*4 + 2 ] <<  8 )
             | ( (uint32_t)block[ i*4 + 3 ]       );

   for ( i = 16; i < 64; i++ )
   {
      uint32_t s0 = ror( w[i-15],  7 ) ^ ror( w[i-15], 18 ) ^ ( w[i-15] >>  3 );
      uint32_t s1 = ror( w[i-2],  17 ) ^ ror( w[i-2],  19 ) ^ ( w[i-2]  >> 10 );
      w[i] = w[i-16] + s0 + w[i-7] + s1;
   }

   a = state[0]; b = state[1]; c = state[2]; d = state[3];
   e = state[4]; f = state[5]; g = state[6]; h = state[7];

   for ( i = 0; i < 64; i++ )
   {
      uint32_t S1  = ror( e, 6 ) ^ ror( e, 11 ) ^ ror( e, 25 );
      uint32_t ch  = ( e & f ) ^ ( (~e) & g );
      uint32_t t1  = h + S1 + ch + K[i] + w[i];
      uint32_t S0  = ror( a, 2 ) ^ ror( a, 13 ) ^ ror( a, 22 );
      uint32_t maj = ( a & b ) ^ ( a & c ) ^ ( b & c );
      uint32_t t2  = S0 + maj;

      h = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
   }

   state[0] += a; state[1] += b; state[2] += c; state[3] += d;
   state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_full( void *hash, const void *data, size_t len )
{
   const uint8_t *p = (const uint8_t*)data;
   uint8_t *out = (uint8_t*)hash;
   uint32_t state[8];
   uint8_t tail[128];
   size_t rem = len, tail_len;
   uint64_t bits = (uint64_t)len * 8;
   int i;

   memcpy( state, IV, sizeof state );

   while ( rem >= 64 )
   {
      sha256_transform( state, p );
      p   += 64;
      rem -= 64;
   }

   memcpy( tail, p, rem );
   tail[ rem ] = 0x80;
   /* The length must land in the last 8 bytes of a block; if the 0x80 and
    * the length do not both fit, pad out to a second block.  */
   tail_len = ( rem < 56 ) ? 64 : 128;
   memset( tail + rem + 1, 0, tail_len - rem - 1 );

   for ( i = 0; i < 8; i++ )
      tail[ tail_len - 1 - i ] = (uint8_t)( bits >> ( i * 8 ) );

   sha256_transform( state, tail );
   if ( tail_len == 128 )
      sha256_transform( state, tail + 64 );

   for ( i = 0; i < 8; i++ )
   {
      out[ i*4     ] = (uint8_t)( state[i] >> 24 );
      out[ i*4 + 1 ] = (uint8_t)( state[i] >> 16 );
      out[ i*4 + 2 ] = (uint8_t)( state[i] >>  8 );
      out[ i*4 + 3 ] = (uint8_t)( state[i]       );
   }
}

void sha256d( void *hash, const void *data, size_t len )
{
   uint8_t first[32];

   sha256_full( first, data, len );
   sha256_full( hash, first, 32 );
}
