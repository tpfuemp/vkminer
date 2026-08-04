/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2014 pooler
 * Copyright 2016-2025 Jay D Dee
 * Copyright 2026 vkminer contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * Derived from cpuminer-opt's util.c: logging, hex, base58 and
 * bech32, difficulty and target arithmetic, and the thread queue.
 */


#include "core/miner.h"

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <math.h>

#if defined(WIN32)
#include <winsock2.h>
#include "winansi.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifndef _MSC_VER
/* dirname() linux/mingw, else in compat.h */
#include <libgen.h>
#endif

#include "core/elist.h"
#include "core/sha256.h"

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

bool is_power_of_2( int n ) 
{ 
  while ( n > 1 ) 
  { 
      if ( n % 2 != 0 ) return false; 
      n = n / 2; 
  } 
  return true; 
} 

// Dsiplay prefix only with no colour & no nl, add more message and nl later
// with printf.
// No atomicity between prefix and message.
void applog_nl( const char *fmt, ... )
{
   va_list ap;
   va_start( ap, fmt );

   int len = 64 + (int) strlen( fmt ) + 2;
   struct tm tm;
   char *f = (char*)malloc( len );
   time_t now = time(NULL);
   localtime_r( &now, &tm );

   sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d] %s",
      tm.tm_year + 1900,
      tm.tm_mon + 1,
      tm.tm_mday,
      tm.tm_hour,
      tm.tm_min,
      tm.tm_sec,
      fmt
   );
   pthread_mutex_lock( &applog_lock );
   vfprintf( stdout, f, ap );   /* atomic write to stdout */
   fflush( stdout );
   free( f );
   pthread_mutex_unlock( &applog_lock );
   va_end( ap );
}

void applog2( int prio, const char *fmt, ... )
{
   va_list ap;

   va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
   if (use_syslog) {
      va_list ap2;
      char *buf;
      int len;

      /* custom colors to syslog prio */
      if (prio > LOG_DEBUG) {
         switch (prio) {
            case LOG_BLUE: prio = LOG_NOTICE; break;
         }
      }

      va_copy(ap2, ap);
      len = vsnprintf(NULL, 0, fmt, ap2) + 1;
      va_end(ap2);
      buf = alloca(len);
      if (vsnprintf(buf, len, fmt, ap) >= 0)
         syslog(prio, "%s", buf);
   }
#else
   if (0) {}
#endif
   else {
      const char* color = "";
      char *f;
      int len;
//    struct tm tm;
//    time_t now = time(NULL);
//    localtime_r(&now, &tm);

      switch ( prio )
      {
         case LOG_CRIT:    color = CL_LRD; break;
         case LOG_ERR:     color = CL_RED; break;
         case LOG_WARNING: color = CL_YL2; break;
         case LOG_MAJR:    color = CL_YL2; break;
         case LOG_NOTICE:  color = CL_WHT; break;
         case LOG_INFO:    color = ""; break;
         case LOG_DEBUG:   color = CL_GRY; break;
         case LOG_MINR:    color = CL_YLW; break;
         case LOG_GREEN:   color = CL_GRN; prio = LOG_INFO; break;
         case LOG_BLUE:    color = CL_CYN; prio = LOG_NOTICE; break;
         case LOG_PINK:    color = CL_LMA; prio = LOG_NOTICE; break;
      }
      if (!use_colors)
         color = "";
      
      len = 64 + (int) strlen(fmt) + 2;
      f = (char*) malloc(len);
      sprintf(f, "                     %s %s%s\n",
//      sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
//         tm.tm_year + 1900,
//         tm.tm_mon + 1,
//         tm.tm_mday,
//         tm.tm_hour,
//         tm.tm_min,
//         tm.tm_sec,
         color,
         fmt,
         use_colors ? CL_N : ""
      );
      pthread_mutex_lock(&applog_lock);
      vfprintf(stdout, f, ap);   /* atomic write to stdout */
      fflush(stdout);
      free(f);
      pthread_mutex_unlock(&applog_lock);
   }
   va_end(ap);
}


void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;

		/* custom colors to syslog prio */
		if (prio > LOG_DEBUG) {
			switch (prio) {
				case LOG_BLUE: prio = LOG_NOTICE; break;
			}
		}

		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		const char* color = "";
		char *f;
		int len;
		struct tm tm;
		time_t now = time(NULL);
      char *bell = "";

		localtime_r(&now, &tm);

		switch ( prio )
      {
         case LOG_CRIT:    color = CL_LRD; break;
         case LOG_ERR:     color = CL_RED; break;
         case LOG_WARNING: color = CL_YL2; break;
         case LOG_MAJR:    color = CL_YL2; break;
			case LOG_NOTICE:  color = CL_WHT; break;
			case LOG_INFO:    color = "";     break;
			case LOG_DEBUG:   color = CL_GRY; break;
         case LOG_MINR:    color = CL_YLW; break;
         case LOG_GREEN:   color = CL_GRN; prio = LOG_INFO;   break;
			case LOG_BLUE:    color = CL_CYN; prio = LOG_NOTICE; break;
         case LOG_PINK:    color = CL_LMA; prio = LOG_NOTICE; break;
		}
		if (!use_colors)
			color = "";

      if ( opt_bell && ( prio == LOG_WARNING || prio == LOG_ERR ) )
            *bell = ASCII_BELL;

		len = 64 + (int) strlen(fmt) + 2;
		f = (char*) malloc(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			color,
			fmt,
			use_colors ? CL_N : ""
		);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stdout, f, ap);	/* atomic write to stdout */
		fflush(stdout);
		free(f);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

void log_sw_err( char* filename, int line_number, char* msg )
{
  applog( LOG_ERR, "SW_ERR: %s:%d, %s", filename, line_number, msg );
}

/* Get default config.json path (will be system specific) */
void get_defconfig_path(char *out, size_t bufsize, char *argv0)
{
	char *cmd = strdup(argv0);
	char *dir = dirname(cmd);
	const char *sep = strstr(dir, "\\") ? "\\" : "/";
	struct stat info = { 0 };
#ifdef WIN32
	snprintf(out, bufsize, "%s\\cpuminer\\cpuminer-conf.json", getenv("APPDATA"));
#else
	snprintf(out, bufsize, "%s\\.cpuminer\\cpuminer-conf.json", getenv("HOME"));
#endif
	if (dir && stat(out, &info) != 0) {
		snprintf(out, bufsize, "%s%scpuminer-conf.json", dir, sep);
	}
	if (stat(out, &info) != 0) {
		out[0] = '\0';
		return;
	}
	out[bufsize - 1] = '\0';
	free(cmd);
}

// Decimal SI, factors 0f 1000
void scale_hash_for_display ( double* hashrate, char* prefix )
{
       if ( *hashrate < 1e4  )    *prefix =  0;
  else if ( *hashrate < 1e7  )  { *prefix = 'k';  *hashrate /= 1e3;  }
  else if ( *hashrate < 1e10 )  { *prefix = 'M';  *hashrate /= 1e6;  }
  else if ( *hashrate < 1e13 )  { *prefix = 'G';  *hashrate /= 1e9;  }
  else if ( *hashrate < 1e16 )  { *prefix = 'T';  *hashrate /= 1e12; }
  else if ( *hashrate < 1e19 )  { *prefix = 'P';  *hashrate /= 1e15; }
  else if ( *hashrate < 1e22 )  { *prefix = 'E';  *hashrate /= 1e18; }
  else if ( *hashrate < 1e25 )  { *prefix = 'Z';  *hashrate /= 1e21; }
  else                          { *prefix = 'Y';  *hashrate /= 1e24; }
}

void format_hashrate( double hashrate, char *output )
{
	char prefix = '\0';
   scale_hash_for_display( &hashrate, &prefix );
	sprintf( output, prefix ? "%.2f %cH/s" : "%.2f H/s%c", hashrate, prefix	);
}

// Binary SI, factors of 1024
void format_number_si( double* n, char* si_units )
{
  if ( *n < 1024*10 )  {  *si_units = 0;   return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'k'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'M'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'G'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'T'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'P'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'E'; return;  }
  *n /= 1024;
  if ( *n < 1024*10 )  {  *si_units = 'Z'; return;  }
  *n /= 1024;
  *si_units = 'Y';
}
/* cpuminer-opt special-cases len == 32 with a pair of SIMD byte swaps. That
 * path came from simd-utils, which is not inherited, and it is not on any
 * hot loop here -- this runs once per share, not once per hash. */
void memrev(unsigned char *p, size_t len)
{
   unsigned char c, *q;
   for (q = p + len - 1; p < q; p++, q--)
   {
      c = *p;
      *p = *q;
      *q = c;
   }
}

void cbin2hex(char *out, const char *in, size_t len)
{
   if (out) {
      unsigned int i;
      for (i = 0; i < len; i++)
         sprintf(out + (i * 2), "%02x", (uint8_t)in[i]);
   }
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s = (char*) malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

char *bebin2hex(const unsigned char *p, size_t len)
{
   char *s = (char*) malloc((len * 2) + 1);
   if (!s)  return NULL;
   for ( size_t i = 0, j = len - 1; i < len; i++, j-- )
      sprintf( s + ( i*2 ), "%02x", (unsigned int) p[ j ] );
   return s;
}

bool hex2bin( unsigned char *p, const char *hexstr, const size_t len )
{
	if( hexstr == NULL )	return false;

	size_t hexstr_len = strlen( hexstr );
	if( ( hexstr_len % 2 ) != 0 )
   {
		applog( LOG_ERR, "hex2bin string truncated" );
		return false;
	}
	size_t bin_len = hexstr_len / 2;
	if ( bin_len > len )
   {
		applog( LOG_ERR, "hex2bin buffer too small" );
		return false;
	}

	memset( p, 0, len );
	size_t i = 0;
	while ( i < hexstr_len )
   {
		char c = hexstr[i];
		unsigned char nibble;
		if      ( c >= '0' && c <= '9' )	 nibble = (c - '0');
		else if ( c >= 'A' && c <= 'F' )	 nibble = ( 10 + (c - 'A') );
		else if ( c >= 'a' && c <= 'f' )	 nibble = ( 10 + (c - 'a') );
		else
      {
			applog( LOG_ERR, "hex2bin invalid hex" );
			return false;
		}
		p[(i / 2)] |= (nibble << ( (1 - (i % 2) ) * 4) );
		i++;
	}

	return true;
}

int varint_encode(unsigned char *p, uint64_t n)
{
	int i;
	if (n < 0xfd) {
		p[0] = (uchar) n;
		return 1;
	}
	if (n <= 0xffff) {
		p[0] = 0xfd;
		p[1] = n & 0xff;
		p[2] = (uchar) (n >> 8);
		return 3;
	}
	if (n <= 0xffffffff) {
		p[0] = 0xfe;
		for (i = 1; i < 5; i++) {
			p[i] = n & 0xff;
			n >>= 8;
		}
		return 5;
	}
	p[0] = 0xff;
	for (i = 1; i < 9; i++) {
		p[i] = n & 0xff;
		n >>= 8;
	}
	return 9;
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = (uint32_t *) calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--; ) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
		case 3:
			*(bin++) = (outi[0] >> 16) & 0xff;
		case 2:
			*(bin++) = (outi[0] >> 8) & 0xff;
		case 1:
			*(bin++) = outi[0] & 0xff;
			++j;
		default:
			break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, (int) (binsz - 4));
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	 * (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin((uchar*) buf, hexstr, buflen))
		return false;

	return true;
}

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const int8_t bech32_charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static bool bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (input_len < 8 || input_len > 90) {
        return false;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    hrp_len = input_len - (1 + *data_len);
    if (1 + *data_len >= input_len || *data_len < 6) {
        return false;
    }
    *(data_len) -= 6;
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            return false;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : bech32_charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return false;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return false;
    }
    return chk == 1;
}

static bool convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return false;
    }
    return true;
}

static bool segwit_addr_decode(int *witver, uint8_t *witdata, size_t *witdata_len, const char *addr) {
    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len;
    if (!bech32_decode(hrp_actual, data, &data_len, addr)) return false;
    if (data_len == 0 || data_len > 65) return false;
    if (data[0] > 16) return false;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) return false;
    if (*witdata_len < 2 || *witdata_len > 40) return false;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return false;
    *witver = data[0];
    return true;
}

static size_t bech32_to_script(uint8_t *out, size_t outsz, const char *addr) {
    uint8_t witprog[40];
    size_t witprog_len;
    int witver;

    if (!segwit_addr_decode(&witver, witprog, &witprog_len, addr))
        return 0;
    if (outsz < witprog_len + 2)
        return 0;
    out[0] = witver ? (0x50 + witver) : 0;
    out[1] = witprog_len;
    memcpy(out + 2, witprog, witprog_len);

   if ( opt_debug )
      applog( LOG_INFO, "Coinbase address uses Bech32 coding");

    return witprog_len + 2;
}

size_t address_to_script( unsigned char *out, size_t outsz, const char *addr )
{
	unsigned char addrbin[ pk_buffer_size_max ];
	int addrver;
	size_t rv;

	if ( !b58dec( addrbin, outsz, addr ) )
		return bech32_to_script( out, outsz, addr );

   addrver = b58check( addrbin, outsz, addr );
   if ( addrver < 0 )
		return 0;

   if ( opt_debug )
      applog( LOG_INFO, "Coinbase address uses B58 coding");

   switch ( addrver )
   {
		case 5:    /* Bitcoin script hash */
		case 196:  /* Testnet script hash */
			if ( outsz < ( rv = 23 ) )
				return rv;
			out[ 0] = 0xa9;  /* OP_HASH160 */
			out[ 1] = 0x14;  /* push 20 bytes */
			memcpy( &out[2], &addrbin[1], 20 );
			out[22] = 0x87;  /* OP_EQUAL */
			return rv;
		default:
			if (outsz < (rv = 25))
				return rv;
			out[ 0] = 0x76;  /* OP_DUP */
			out[ 1] = 0xa9;  /* OP_HASH160 */
			out[ 2] = 0x14;  /* push 20 bytes */
			memcpy( &out[3], &addrbin[1], 20 );
			out[23] = 0x88;  /* OP_EQUALVERIFY */
			out[24] = 0xac;  /* OP_CHECKSIG */
			return rv;
	}
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

// Deprecated
bool fulltest( const uint32_t *hash, const uint32_t *target )
{
	int i;
	bool rc = true;
	
	for ( i = 7; i >= 0; i-- )
   {
		if ( hash[i] > target[i] )
      {
			rc = false;
			break;
		}
		if ( hash[i] < target[i] )
      {
			rc = true;
			break;
		}
	}

	if ( opt_debug )
   {
		uint32_t hash_be[8], target_be[8];
		char hash_str[65], target_str[65];
		
		for ( i = 0; i < 8; i++ )
      {
			be32enc( hash_be + i, hash[7 - i] );
			be32enc( target_be + i, target[7 - i] );
		}
		bin2hex( hash_str, (unsigned char *)hash_be, 32 );
		bin2hex( target_str, (unsigned char *)target_be, 32 );

		applog( LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
                         rc ? "hash <= target"
			                   : "hash > target (false positive)",
	                      hash_str, target_str );
	}
	return rc;
}

// Mathmatically the difficulty is simply the reciprocal of the hash: d = 1/h.
// Both are real numbers but the hash (target) is represented as a 256 bit
// fixed point number with the upper 32 bits representing the whole integer
// part and the lower 224 bits representing the fractional part:
//   target[ 255:224 ] = trunc( 1/diff )
//   target[ 223:  0 ] = frac( 1/diff )
//
// The 256 bit hash is exact but any floating point representation is not.
// Stratum provides the target difficulty as double precision, inexcact,
// which must be converted to a hash target. The converted hash target will
// likely be less precise due to inexact input and conversion error.
// On the other hand getwork provides a 256 bit hash target which is exact.
//
// How much precision is needed?
//
// 128 bit types are implemented in software by the compiler on 64 bit
// hardware resulting in lower performance and more error than would be
// expected with a hardware 128 bit implementaion.
// Float80 exploits the internals of the FP unit which provide a 64 bit
// mantissa in an 80 bit register with hardware rounding. When the destination
// is double the data is rounded to float64 format. Long double returns all
// 80 bits without rounding and including any accumulated computation error.
// Float80 does not fit efficiently in memory.
//
// Significant digits:
// 256 bit hash: 76     
// float:         7     (float32, 80 bits with rounding to 32 bits)
// double:       15     (float64, 80 bits with rounding to 64 bits)
// long double:  19     (float80, 80 bits with no rounding)
// __float128:   33     (128 bits with no rounding)
// uint32_t:      9
// uint64_t:     19
// uint128_t     38
//
// The concept of significant digits doesn't apply to the 256 bit hash
// representation. It's fixed point making leading zeros significant,
// limiting its range and precision due to fewer zon-zero significant digits.
//
// Doing calculations with float128 and uint128 increases precision for
// target_to_diff, but doesn't help with stratum diff being limited to
// double precision. Is the extra precision really worth the extra cost?
// With float128 the error rate is 1/1e33 compared with 1/1e15 for double.
// For double that's 1 error in every petahash with a very low difficulty,
// not a likely situation. With higher difficulty effective precision
// increases.
//
// Unfortunately I can't get float128 to work so long double (float80) is
// as precise as it gets.
// All calculations will be done using long double then converted to double.
// This prevents introducing significant new error while taking advantage
// of HW rounding.

#if defined(GCC_INT128)

void diff_to_hash( uint32_t *target, const double diff )
{
  uint128_t *targ = (uint128_t*)target;
  register long double m = 1. / diff;
//  targ[0] = 0;
  targ[0] = -1;
  targ[1] = (uint128_t)( m * exp96 );
}

double hash_to_diff( const void *target )
{
   const uint128_t *targ = (const uint128_t*)target;
   register long double m = ( (long double)targ[1] / exp96 );
//                        + ( (long double)targ[0] / exp160 );
   return (double)( 1. / m );
}

inline bool valid_hash( const void *hash, const void *target )
{
   const uint128_t *h = (const uint128_t*)hash;
   const uint128_t *t = (const uint128_t*)target;
   if ( h[1] > t[1] ) return false;
   if ( h[1] < t[1] ) return true;
   if ( h[0] > t[0] ) return false;
   return true;
}

#else

void diff_to_hash( uint32_t *target, const double diff )
{
  uint64_t *targ = (uint64_t*)target;
  register long double m = ( 1. / diff ) * exp32;
//  targ[1] = targ[0] = 0;
  targ[1] = targ[0] = -1;
  targ[3] = (uint64_t)m;
  targ[2] = (uint64_t)( ( m - (long double)targ[3] ) * exp64 );
}

double hash_to_diff( const void *target )
{
   const uint64_t *targ = (const uint64_t*)target;
   register long double m = ( (long double)targ[3] / exp32 )
                          + ( (long double)targ[2] / exp96 );
   return (double)( 1. / m );
}

inline bool valid_hash( const void *hash, const void *target )
{
   const uint64_t *h = (const uint64_t*)hash;
   const uint64_t *t = (const uint64_t*)target;
   if ( h[3] > t[3] ) return false;
   if ( h[3] < t[3] ) return true;
   if ( h[2] > t[2] ) return false;
   if ( h[2] < t[2] ) return true;
   if ( h[1] > t[1] ) return false;
   if ( h[1] < t[1] ) return true;
   if ( h[0] > t[0] ) return false;
   return true;
}

#endif 

inline double nbits_to_diff( uint32_t nbits )
{
   long double diff;
   uint32_t shift = nbits & 0xff;
   uint32_t bits = bswap_32( nbits ) & 0x00ffffff;
   int shift_off = (int)shift - 29;

   // diff = ( (2**16 -1) / ( 256**shift_off * bits )
   // With uint128 byte shift is good for 16 <= shift <= 41. As unlikely
   // as this may seem necessary, check just in case.

   if ( shift_off >= -13 && shift_off <= 12 ) 
   {  // fast
      if ( shift_off == 0 )
         diff = (long double)0xffff / (long double)bits;
      else if ( shift_off < 0 )   // shift < 29
         diff = (long double)( (uint128_t)0xffff << ( (-shift_off) *8 ) ) 
              / (long double)bits;
      else // ( shift_off > 0 )   // shift > 29
         diff =   (long double)0xffff
                / (long double)( (uint128_t)bits << ( shift_off*8 ) );  
   }
   else
   {  // slow
      int m;
      diff = 0.;
      for ( m = shift; m < 29; m++ )    diff *= 256.0;
      for ( m = 29; m < shift; m++ )    diff /= 256.0;
   }

   if ( opt_debug )
      applog( LOG_INFO, "nbits %08x: shift %u(%d), bits %06x, diff %8g",
                         nbits, shift, shift_off, bits, (double)diff );

   return (double)diff;
}
struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = (struct thread_q*) calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = (struct tq_ent*) calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
 	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}

/* sprintf can be used in applog */
static char* format_hash(char* buf, uint8_t *hash)
{
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void applog_compare_hash(void *hash, void *hash_ref)
{
        char s[256] = "";
        int len = 0;
        uchar* hash1 = (uchar*)hash;
        uchar* hash2 = (uchar*)hash_ref;
        for (int i=0; i < 32; i += 4) {
                const char *color = memcmp(hash1+i, hash2+i, 4) ? CL_WHT : CL_GRY;
                len += sprintf(s+len, "%s%02x%02x%02x%02x " CL_GRY, color,
                        hash1[i], hash1[i+1], hash1[i+2], hash1[i+3]);
                s[len] = '\0';
        }
        applog(LOG_DEBUG, "%s", s);
}

void applog_hash(void *hash)
{
	char s[128] = {'\0'};
	applog(LOG_DEBUG, "%s", format_hash(s, (uchar*) hash));
}

void applog_hex(void *data, int len)
{
        char* hex = abin2hex((uchar*)data, len);
        applog(LOG_DEBUG, "%s", hex);
        free(hex);
}

void applog_hash64(void *hash)
{
        char s[128] = {'\0'};
        char t[128] = {'\0'};
        applog(LOG_DEBUG, "%s %s", format_hash(s, (uchar*)hash), format_hash(t, &((uchar*)hash)[32]));
}
