/* vkminer -- a Vulkan compute cryptocurrency miner.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Known-answer test for the scalar SHA-256 reference.
 *
 * The single-hash vectors are FIPS 180-4's own, including the one-million-'a'
 * case, which is the only one here that exercises the block loop and the
 * length counter past 2^19 bits. The double-hash vectors matter because
 * sha256d, not sha256, is what a block header goes through, and the last of
 * them is the Bitcoin genesis header: if the digest below is right, then
 * byte order, padding and the 80-byte length are all right at once, which is
 * exactly the set of mistakes that produces a miner that runs and never has a
 * share accepted.
 *
 * This is the oracle the GPU kernel will be differentially tested against, so
 * it is checked before anything is built on top of it.
 */

#include "core/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int from_hex( unsigned char *out, const char *hex, size_t len )
{
   for ( size_t i = 0; i < len; i++ )
   {
      unsigned int byte;
      if ( sscanf( hex + 2 * i, "%2x", &byte ) != 1 )
         return 0;
      out[i] = (unsigned char)byte;
   }
   return 1;
}

static void to_hex( char *out, const unsigned char *bin, size_t len )
{
   for ( size_t i = 0; i < len; i++ )
      sprintf( out + 2 * i, "%02x", bin[i] );
}

static int failures = 0;

static void check( const char *what, const void *data, size_t len,
                   const char *expect, int twice )
{
   unsigned char digest[32];
   char got[65];

   if ( twice )
      sha256d( digest, data, len );
   else
      sha256_full( digest, data, len );

   to_hex( got, digest, 32 );
   if ( strcmp( got, expect ) )
   {
      printf( "FAIL %s\n  expected %s\n  got      %s\n", what, expect, got );
      failures++;
   }
   else
      printf( "ok   %s\n", what );
}

struct vector {
   const char *name;
   const char *message;
   const char *sha256;
   const char *sha256d;
};

/* FIPS 180-4 B.1-B.3 for the single hash; the double-hash column is the same
 * message run through SHA-256 twice.  */
static const struct vector vectors[] = {
   { "empty string", "",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456" },
   { "\"abc\"", "abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358" },
   { "56 bytes (one block, padding spills)",
     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
     "0cffe17f68954dac3a84fb1458bd5ec99209449749b2b308b7cb55812f9563af" },
   { "112 bytes (two blocks)",
     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
     "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
     "accd7bd1cb0fcbd85cf0ba5ba96945127776373a7d47891eb43ed6b1e2ee60fe" },
};

/* The Bitcoin genesis block header, 80 bytes, exactly as it goes on the wire.
 * sha256d of it is the block hash in internal byte order -- reverse it and it
 * reads 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.  */
static const char genesis_header[] =
   "01000000"
   "0000000000000000000000000000000000000000000000000000000000000000"
   "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
   "29ab5f49"
   "ffff001d"
   "1dac2b7c";
static const char genesis_hash[] =
   "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";

int main( void )
{
   for ( size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++ )
   {
      const struct vector *v = &vectors[i];
      const size_t len = strlen( v->message );
      char name[128];

      snprintf( name, sizeof name, "sha256  %s", v->name );
      check( name, v->message, len, v->sha256, 0 );

      snprintf( name, sizeof name, "sha256d %s", v->name );
      check( name, v->message, len, v->sha256d, 1 );
   }

   unsigned char header[80];
   if ( !from_hex( header, genesis_header, sizeof header ) )
   {
      printf( "FAIL genesis header is not valid hex\n" );
      failures++;
   }
   else
      check( "sha256d Bitcoin genesis header", header, sizeof header,
             genesis_hash, 1 );

   char *million = malloc( 1000000 );
   if ( !million )
   {
      printf( "FAIL out of memory\n" );
      return 1;
   }
   memset( million, 'a', 1000000 );
   check( "sha256  one million 'a'", million, 1000000,
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 0 );
   free( million );

   if ( failures )
      printf( "\n%d test(s) failed\n", failures );
   return failures ? 1 : 0;
}
