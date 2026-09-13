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
 * Derived from cpuminer-opt's util.c: the Stratum v1 client.
 * Ported as-is. It is worth what it is because it is debugged.
 */


#include "core/miner.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

static bool send_line( struct stratum_ctx *sctx, char *s )
{
	size_t sent = 0;
	int len;

	len = (int) strlen(s);
	s[len++] = '\n';

	while ( len > 0 )
   {
		struct timeval timeout = {0, 0};
		int n;
		fd_set wd;

// Something nasty going on With Windows on aarch64. This hack prevents
// corrupting the sctx pointer. This only works if placed inside the while loop.
#if defined(__aarch64__) && defined(WIN32) && defined(ARM_WIN_HACK)
      printf("");
#endif

		FD_ZERO( &wd );
		FD_SET( sctx->sock, &wd );
		if ( select( (int) ( sctx->sock + 1 ), NULL, &wd, NULL, &timeout ) < 1 )
			return false;

#if LIBCURL_VERSION_NUM >= 0x071802

     CURLcode rc = curl_easy_send(sctx->curl, s + sent, len, (size_t *)&n);
     if ( rc != CURLE_OK )
     {
        if ( rc != CURLE_AGAIN )
#else                      
     n = send( sctx->sock, s + sent, len, 0);
     if ( n < 0 )
     {
     if ( !socket_blocks() )
#endif
        return false;
	     n = 0;
	  }
     sent += n;
     len -= n;
   }

	return true;
}

bool stratum_send_line(struct stratum_ctx *sctx, char *s)
{
	bool ret = false;

	if (opt_protocol)
		applog(LOG_DEBUG, "> %s", s);

	pthread_mutex_lock(&sctx->sock_lock);
	ret = send_line( sctx, s );
	pthread_mutex_unlock(&sctx->sock_lock);

	return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	struct timeval tv;
	fd_set rd;

	FD_ZERO(&rd);
	FD_SET(sock, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select((int)(sock + 1), &rd, NULL, NULL, &tv) > 0)
		return true;
	return false;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
	size_t old, n;

	old = strlen(sctx->sockbuf);
	n = old + strlen(s) + 1;
	if (n >= sctx->sockbuf_size) {
		sctx->sockbuf_size = n + (RBUFSIZE - (n % RBUFSIZE));
		sctx->sockbuf = (char*) realloc(sctx->sockbuf, sctx->sockbuf_size);
	}
	strcpy(sctx->sockbuf + old, s);
}

char *stratum_recv_line(struct stratum_ctx *sctx)
{
	ssize_t len, buflen;
	char *tok, *sret = NULL;

	if (!strstr(sctx->sockbuf, "\n")) {
		bool ret = true;
		time_t rstart;

		time(&rstart);
		if (!socket_full(sctx->sock, 60)) {
			applog(LOG_WARNING, "stratum_recv_line timed out");
			goto out;
		}
		do {
			char s[RBUFSIZE];
			ssize_t n;

			memset(s, 0, RBUFSIZE);

#if LIBCURL_VERSION_NUM >= 0x071802

			/* One curl handle, two threads. This reads the connection while
			   the workio thread writes shares down it through send_line, and
			   an easy handle may not be in two calls at once. sock_lock is
			   what connect, disconnect and send already take; this reader was
			   the one path that did not, and a share flood is what makes the
			   overlap frequent enough to lose the connection. Held across the
			   call alone: curl_easy_recv answers CURLE_AGAIN instead of
			   blocking, and every wait below is socket_full, outside it. */
			CURLcode rc;
			pthread_mutex_lock(&sctx->sock_lock);
			rc = curl_easy_recv(sctx->curl, s, RECVSIZE, (size_t *)&n);
			pthread_mutex_unlock(&sctx->sock_lock);
			if (rc == CURLE_OK && !n) {
				ret = false;
				break;
			}
			if (rc != CURLE_OK) {
				/* A quiet second is not a broken connection. The tail of a
				   line split across TCP segments can pause for longer than
				   that, and the budget for a whole line is the 60 s this
				   loop counts -- so wait a slice and go round again, and
				   give up only when that budget is spent. socket_full is
				   the wait as well as the test, so this cannot spin. */
				if (rc != CURLE_AGAIN
				    || (!socket_full(sctx->sock, 1)
				        && time(NULL) - rstart >= 60)) {
#else

         n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				ret = false;
				break;
			}
			if (n < 0) {
				if (!socket_blocks()
				    || (!socket_full(sctx->sock, 1)
				        && time(NULL) - rstart >= 60)) {
#endif
               ret = false;
					break;
				}
			} else
				stratum_buffer_append(sctx, s);
		} while (time(NULL) - rstart < 60 && !strstr(sctx->sockbuf, "\n"));

		if (!ret) {
			applog(LOG_WARNING, "stratum_recv_line failed");
			goto out;
		}
	}

	/* A whole line or nothing. The read above can run out of its budget
	   still holding part of one, and strtok below splits on newlines: with
	   none in the buffer it would hand that fragment up as though it were a
	   complete message and drop the remainder with it. */
	if (!strstr(sctx->sockbuf, "\n")) {
		applog(LOG_WARNING,
		       "stratum_recv_line timed out holding a partial message");
		goto out;
	}

	buflen = (ssize_t) strlen(sctx->sockbuf);
	tok = strtok(sctx->sockbuf, "\n");
	if (!tok) {
		applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
		goto out;
	}
	sret = strdup(tok);
	len = (ssize_t) strlen(sret);

	if (buflen > len + 1)
		memmove(sctx->sockbuf, sctx->sockbuf + len + 1, buflen - len + 1);
	else
		sctx->sockbuf[0] = '\0';

out:
	if (sret && opt_protocol)
		applog(LOG_DEBUG, "< %s", sret);
	return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101 && LIBCURL_VERSION_NUM < 0x072d00
//#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = (curl_socket_t*) clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl;
	int rc;

	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl)
		curl_easy_cleanup(sctx->curl);
	sctx->curl = curl_easy_init();
	if (!sctx->curl) {
		applog(LOG_ERR, "CURL initialization failed");
		pthread_mutex_unlock(&sctx->sock_lock);
		return false;
	}
	curl = sctx->curl;
	if (!sctx->sockbuf) {
		sctx->sockbuf = (char*) calloc(RBUFSIZE, 1);
		sctx->sockbuf_size = RBUFSIZE;
	}
	sctx->sockbuf[0] = '\0';
	pthread_mutex_unlock(&sctx->sock_lock);
	if (url != sctx->url) {
		free(sctx->url);
		sctx->url = strdup(url);
	}

   free(sctx->curl_url);
	sctx->curl_url = (char*) malloc(strlen(url));

   // replace the stratum protocol prefix with http, https for ssl
   sprintf( sctx->curl_url, "%s%s",
            ( strstr( url, "s://" ) || strstr( url, "ssl://" ) )
               ? "https" : "http", strstr( url, "://" ) );



//   sprintf( sctx->curl_url, "http%s", strstr( url, "s://" ) 
//                              ? strstr( url, "s://" )
//                              : strstr (url, "://"  ) );

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
   if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
#if LIBCURL_VERSION_NUM >= 0x070f06
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101 && LIBCURL_VERSION_NUM < 0x072d00
//#if LIBCURL_VERSION_NUM >= 0x071101
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		curl_easy_cleanup(curl);
		sctx->curl = NULL;
		return false;
	}

#if LIBCURL_VERSION_NUM >= 0x072d00
	curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sctx->sock);
#elif LIBCURL_VERSION_NUM < 0x071101   
//#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
#endif

	return true;
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl) {
		curl_easy_cleanup(sctx->curl);
		sctx->curl = NULL;
		sctx->sockbuf[0] = '\0';
	}
	pthread_mutex_unlock(&sctx->sock_lock);
}

static const char *get_stratum_session_id(json_t *val)
{
	json_t *arr_val;
	int i, n;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;
	n = (int) json_array_size(arr_val);
	for (i = 0; i < n; i++) {
		const char *notify;
		json_t *arr = json_array_get(arr_val, i);

		if (!arr || !json_is_array(arr))
			break;
		notify = json_string_value(json_array_get(arr, 0));
		if (!notify)
			continue;
		if (!strcasecmp(notify, "mining.notify"))
			return json_string_value(json_array_get(arr, 1));
	}
	return NULL;
}

/* The ProgPoW subscribe reply: [null, "<extranonce1_hex>"], and that is all of
 * it. There is no extranonce2 field and there is nothing for one to do -- the
 * pool has already hashed the header, so there is no coinbase for the miner to
 * change. What the hex string is, is the top of the 64-bit nonce: the pool's
 * way of making sure two miners on the same job never test the same nonce.
 *
 * The width is checked rather than accepted. The algorithm has already said
 * how many low bits it will walk, and every worker's range was going to be cut
 * from that number; a pool that keeps some other number of bytes would have the
 * miner submitting nonces outside its own prefix, which is a session's worth of
 * rejects and no other symptom.                                              */
static bool stratum_parse_nonce_prefix( struct stratum_ctx *sctx,
                                        json_t *params, int pndx )
{
   const char *prefix = json_string_value( json_array_get( params, pndx ) );
   size_t want = ( 64 - opt_nonce_bits ) / 8;

   if ( !prefix )
   {
      applog( LOG_ERR, "Stratum subscribe: no nonce prefix in the reply" );
      return false;
   }
   if ( strlen( prefix ) != want * 2 )
   {
      applog( LOG_ERR, "Stratum subscribe: pool assigned a %zu-byte nonce "
                       "prefix, this algorithm leaves room for %zu",
                       strlen( prefix ) / 2, want );
      return false;
   }

   pthread_mutex_lock( &sctx->work_lock );
   free( sctx->xnonce1 );
   sctx->xnonce1_size = want;
   sctx->xnonce1 = (uchar*) calloc( 1, want ? want : 1 );
   if ( unlikely( !sctx->xnonce1 ) )
   {
      pthread_mutex_unlock( &sctx->work_lock );
      applog( LOG_ERR, "Failed to alloc nonce prefix" );
      return false;
   }
   hex2bin( sctx->xnonce1, prefix, want );
   /* No coinbase, so no extranonce2. Zero here is what every other part of the
      miner reads as "this pool gives the miner nothing to roll", which for this
      dialect is the truth and not a problem.  */
   sctx->xnonce2_size = 0;
   pthread_mutex_unlock( &sctx->work_lock );

   if ( !opt_quiet )
      applog( LOG_INFO, "Stratum nonce prefix 0x%s, %u bits to mine in",
                        prefix, opt_nonce_bits );
   return true;
}

static bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
	const char* xnonce1;
	int xn2_size;

	xnonce1 = json_string_value(json_array_get(params, pndx));
	if (!xnonce1) {
		applog(LOG_ERR, "Failed to get extranonce1");
		goto out;
	}
	xn2_size = (int) json_integer_value(json_array_get(params, pndx+1));
	if (!xn2_size) {
		applog(LOG_ERR, "Failed to get extranonce2_size");
		goto out;
	}
	if (xn2_size < 2 || xn2_size > 16) {
		applog(LOG_INFO, "Failed to get valid n2size in parse_extranonce");
		goto out;
	}

	pthread_mutex_lock(&sctx->work_lock);
	if (sctx->xnonce1)
		free(sctx->xnonce1);
	sctx->xnonce1_size = strlen(xnonce1) / 2;
	sctx->xnonce1 = (uchar*) calloc(1, sctx->xnonce1_size);
	if (unlikely(!sctx->xnonce1)) {
		applog(LOG_ERR, "Failed to alloc xnonce1");
		pthread_mutex_unlock(&sctx->work_lock);
		goto out;
	}
	hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
	sctx->xnonce2_size = xn2_size;
	pthread_mutex_unlock(&sctx->work_lock);

   if ( !opt_quiet ) /* pool dynamic change */
      applog( LOG_INFO, "Stratum extranonce1 0x%s, extranonce2 size %d",
         xnonce1, xn2_size);

	return true;
out:
	return false;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
	char *s, *sret = NULL;
	const char *sid;
	json_t *val = NULL, *res_val, *err_val;
	json_error_t err;
	bool ret = false, retry = false;

start:
	s = (char*) malloc(128 + (sctx->session_id ? strlen(sctx->session_id) : 0));
	if (retry)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}");
	else if (sctx->session_id)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\", \"%s\"]}", sctx->session_id);
	else
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\"]}");

	if (!stratum_send_line(sctx, s)) {
		applog(LOG_ERR, "stratum_subscribe send failed");
		goto out;
	}

	if (!socket_full(sctx->sock, 30)) {
		applog(LOG_ERR, "stratum_subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (!sret)
		goto out;

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		if (opt_debug || retry) {
			free(s);
			if (err_val)
				s = json_dumps(err_val, JSON_INDENT(3));
			else
				s = strdup("(unknown reason)");
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);
		}
		goto out;
	}

	sid = get_stratum_session_id(res_val);
	if (opt_debug && sid)
		applog(LOG_DEBUG, "Stratum session id: %s", sid);

	pthread_mutex_lock(&sctx->work_lock);
	if (sctx->session_id)
		free(sctx->session_id);
	sctx->session_id = sid ? strdup(sid) : NULL;
	sctx->next_diff = 1.0;
	pthread_mutex_unlock(&sctx->work_lock);

	/* Standard Stratum subscribe result (3 elements):
	 *  [ [[subs...]], "xnonce1", xn2_size ]
	 * sid at index 0, extranonce params at indices 1 and 2.
	 *
	 * ProgPoW's is two: [ null, "nonce_prefix" ]. Same index, different
	 * meaning, and which one it is comes from the algorithm rather than from
	 * counting the elements -- a pool that sends three of them is not thereby
	 * speaking Bitcoin's.                                                 */
	if (opt_stratum_dialect == STRATUM_PROGPOW) {
		if (!stratum_parse_nonce_prefix(sctx, res_val, 1))
			goto out;
	} else if (!stratum_parse_extranonce(sctx, res_val, 1)) {
		goto out;
	}

	ret = true;

out:
	free(s);
	if (val)
		json_decref(val);

	if (!ret) {
		if (sret && !retry) {
			retry = true;
			goto start;
		}
	}

	return ret;
}

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
	json_t *val = NULL, *res_val, *err_val;
	char *s, *sret;
	json_error_t err;
	bool ret = false;

	s = (char*) malloc(80 + strlen(user) + strlen(pass));
	sprintf(s, "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}",
			user, pass);

	if (!stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_false(res_val) ||
	    (err_val && !json_is_null(err_val)))  {
		applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

	ret = true;

	if ( !opt_extranonce )
		goto out;

	// subscribe to extranonce (optional)
	sprintf(s, "{\"id\": 3, \"method\": \"mining.extranonce.subscribe\", \"params\": []}");

	if ( !stratum_send_line( sctx, s ) )
		goto out;

	if ( !socket_full( sctx->sock, 3 ) )
   {
      applog( LOG_WARNING, "Extranonce disabled, subscribe timed out" );
		opt_extranonce = false;
      goto out;
	}

	sret = stratum_recv_line( sctx );
	if ( sret )
   {
		json_t *extra = JSON_LOADS( sret, &err );
		if ( !extra )
      {
			applog(LOG_WARNING, "JSON decode failed(%d): %s", err.line, err.text);
		}
      else
      {
			if ( json_integer_value(json_object_get( extra, "id" ) ) != 3 )
         {
				// we receive a standard method if extranonce is ignored
				if ( !stratum_handle_method( sctx, sret ) )
					applog( LOG_WARNING, "Stratum answer id is not correct!" );
			}
         else
         {
            res_val = json_object_get( extra, "result" );
			   if ( opt_debug && ( !res_val || json_is_false( res_val ) ) )
				   applog( LOG_DEBUG,
                       "Method extranonce.subscribe is not supported" );
         }
         json_decref( extra );
		}
		free(sret);
	}

out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

bool stratum_suggest_difficulty( struct stratum_ctx *sctx, double diff )
{
   char *s;
   s = (char*) malloc( 80 );
   bool rc = true;

   // response is handled seperately, what ID?
   sprintf( s, "{\"id\": 1, \"method\": \"mining.suggest_difficulty\", \"params\": [\"%f\"]}", diff );
   if ( !stratum_send_line( sctx, s ) )
   {
      applog(LOG_WARNING,"stratum.suggest_difficulty send failed");
      rc = false;
   } 
   free ( s );
   return rc;
}



/**
 * Extract bloc height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t getblocheight(struct stratum_ctx *sctx)
{
	uint32_t height = 0;
	uint8_t hlen = 0, *p, *m;

	// find 0xffff tag
	p = (uint8_t*) sctx->job.coinbase + 32;
   m = p + sctx->job.coinbase_size - 32 - 2;
//   m = p + 128;
	while (*p != 0xff && p < m) p++;
	while (*p == 0xff && p < m) p++;
	if (*(p-1) == 0xff && *(p-2) == 0xff) {
		p++; hlen = *p;
		p++; height = le16dec(p);
		p += 2;
		switch (hlen) {
			case 4:
				height += 0x10000UL * le16dec(p);
				break;
			case 3:
				height += 0x10000UL * (*p);
				break;
		}
	}
	return height;
}

/* A 64-character big-endian hex string into work->target's layout: most
 * significant word last, each word's own bytes in host order. False if it is
 * not one, which is the whole of the validation -- a target is either 256 bits
 * of hex or it is not a target.                                              */
static bool parse_target_hex( const char *hex, uint32_t out[8] )
{
   uchar raw[32];

   if ( !hex || strlen( hex ) != 64 || !hex2bin( raw, hex, 32 ) )
      return false;

   for ( int i = 0; i < 8; i++ )
      out[7-i] = be32dec( raw + i * 4 );
   return true;
}

/* A field that pools spell either way: 12345 or "00003039". Integers stay
 * integers; a string is read as hex, because that is what every ProgPoW pool
 * that sends one means by it.                                               */
static bool parse_uint_field( json_t *val, uint64_t *out )
{
   if ( json_is_integer( val ) )
   {
      json_int_t n = json_integer_value( val );
      if ( n < 0 )
         return false;
      *out = (uint64_t) n;
      return true;
   }
   if ( json_is_string( val ) )
   {
      const char *s = json_string_value( val );
      char *end = NULL;
      unsigned long long n;

      if ( !s || !*s )
         return false;
      if ( s[0] == '0' && ( s[1] == 'x' || s[1] == 'X' ) )
         s += 2;
      n = strtoull( s, &end, 16 );
      if ( !end || *end )
         return false;
      *out = (uint64_t) n;
      return true;
   }
   return false;
}

/* mining.notify, ProgPoW dialect. Seven parameters and not one of them is a
 * coinbase:
 *
 *  [ job_id, header_hash, seed_hash, share_target, clean, height, nbits ]
 *
 * The pool has already done everything a merkle branch and an extranonce2 are
 * for, and hands over the 32-byte result. What is left for the miner is the
 * nonce -- which is why this dialect gives it 48 bits of one and nothing to
 * roll.
 *
 * The height is not decoration. It is the only channel through which the
 * epoch (the dataset) and the period (the program) reach the algorithm, so a
 * job without one is refused rather than mined at epoch zero.               */
static bool stratum_progpow_notify( struct stratum_ctx *sctx, json_t *params )
{
   /* The last seed hash complained about below, so that a pool this miner
      disagrees with costs one line an epoch and not one a job.

      The flag is not redundant, and leaving it out silenced the complaint
      exactly where it was most needed. An all-zero buffer is not an empty
      one: all zeros is epoch 0's real seed hash -- what a pool sends when it
      has not filled the field in -- so a zero-initialised buffer read as "no
      complaint yet" matches that seed and suppresses the first one.  */
   static unsigned char complained_about[32];
   static bool have_complained = false;

   const char *job_id, *header_hash, *seed_hash, *target_hex;
   uint64_t height = 0, nbits = 0;
   uint32_t target[8];
   bool clean, have_target;
   int p = 0;

   job_id      = json_string_value( json_array_get( params, p++ ) );
   header_hash = json_string_value( json_array_get( params, p++ ) );
   seed_hash   = json_string_value( json_array_get( params, p++ ) );
   target_hex  = json_string_value( json_array_get( params, p++ ) );
   /* json_is_true is a macro that names its argument twice, so the index is
      advanced separately here. Written the way the four lines above are, this
      one reads parameter 4 and leaves p at 6, and every field after it is off
      by one -- which costs the height, and with it the epoch.  */
   clean       = json_is_true( json_array_get( params, p ) ); p++;

   if ( !job_id || !header_hash || strlen( header_hash ) != 64
        || !seed_hash || strlen( seed_hash ) != 64 )
   {
      applog( LOG_ERR, "Stratum notify: invalid ProgPoW parameters" );
      return false;
   }

   if ( !parse_uint_field( json_array_get( params, p++ ), &height ) )
   {
      applog( LOG_ERR, "Stratum notify: no block height, so no epoch and no "
                       "program to mine with" );
      return false;
   }
   /* nbits is the network difficulty, which is reporting and not mining. A
      pool that leaves it out costs a log line, not a job.  */
   if ( !parse_uint_field( json_array_get( params, p++ ), &nbits ) )
      nbits = 0;

   /* The job's own target, when it states one. A pool that leaves this empty
      is relying on the last mining.set_target, which is a legitimate way to
      run and is why that is kept whole rather than converted.  */
   have_target = parse_target_hex( target_hex, target );

   pthread_mutex_lock( &sctx->work_lock );

   free( sctx->job.job_id );
   sctx->job.job_id = strdup( job_id );
   hex2bin( sctx->job.header_hash, header_hash, 32 );
   hex2bin( sctx->job.seed_hash, seed_hash, 32 );
   be32enc( sctx->job.nbits, (uint32_t) nbits );
   sctx->block_height = (int) height;
   sctx->job.clean = clean;
   sctx->job.diff = sctx->next_diff;

   if ( have_target )
      memcpy( sctx->job.target, target, sizeof target );
   else if ( sctx->have_next_target )
      memcpy( sctx->job.target, sctx->next_target, sizeof sctx->next_target );
   sctx->job.have_target = have_target || sctx->have_next_target;

   pthread_mutex_unlock( &sctx->work_lock );

   if ( !sctx->job.have_target )
   {
      applog( LOG_ERR, "Stratum notify: job %s states no target and none has "
                       "been set", job_id );
      return false;
   }

   /* The pool's opinion of which epoch this is, against ours. Complained about
      rather than refused: a disagreement means every share will be rejected,
      but a miner that stopped on it would look exactly like one that cannot
      reach the pool, and this is the first thing anybody would need to see.

      Once per seed rather than once per job -- which is once per epoch without
      having to know how long an epoch is here.  */
   if ( progpow_seed_hash_agrees
        && !progpow_seed_hash_agrees( height, sctx->job.seed_hash )
        && ( !have_complained
             || memcmp( complained_about, sctx->job.seed_hash,
                        sizeof complained_about ) ) )
   {
      char seen[65];
      have_complained = true;
      memcpy( complained_about, sctx->job.seed_hash,
              sizeof complained_about );
      bin2hex( seen, (char*) sctx->job.seed_hash, 32 );
      applog( LOG_ERR, "Stratum notify: the pool's seed hash at block %u is "
                       "%s, which is not the epoch '%s' would build -- one of "
                       "us has the wrong dataset, and every share from here "
                       "will be rejected", (uint32_t) height, seen, opt_algo );
   }

   return true;
}

static bool stratum_bitcoin_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *stime;
	size_t coinb1_size, coinb2_size;
	bool clean, ret = false;
	int merkle_count, i, p = 0;
	json_t *merkle_arr;
	uchar **merkle = NULL;

   job_id = json_string_value(json_array_get(params, p++));
	prevhash = json_string_value(json_array_get(params, p++));
	coinb1 = json_string_value(json_array_get(params, p++));
	coinb2 = json_string_value(json_array_get(params, p++));
	merkle_arr = json_array_get(params, p++);
	if (!merkle_arr || !json_is_array(merkle_arr))
		goto out;
	merkle_count = (int) json_array_size(merkle_arr);
	version = json_string_value(json_array_get(params, p++));
	nbits = json_string_value(json_array_get(params, p++));
	stime = json_string_value(json_array_get(params, p++));
	clean = json_is_true(json_array_get(params, p)); p++;
   
	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime ||
	    strlen(prevhash) != 64 || strlen(version) != 8 ||
	    strlen(nbits) != 8 || strlen(stime) != 8) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}

   hex2bin( sctx->job.version, version, 4 );

   pthread_mutex_lock( &sctx->work_lock );

   if ( merkle_count )
   {
      if ( merkle_count > sctx->job.merkle_buf_size )
      {
         for ( i = 0; i < sctx->job.merkle_count; i++ )
            free( sctx->job.merkle[i] );
         free( sctx->job.merkle );

         merkle = (uchar**) malloc( merkle_count * sizeof(char *) );
         for ( i = 0; i < merkle_count; i++ )
            merkle[i] = (uchar*) malloc( 32 );
         sctx->job.merkle_buf_size = merkle_count;
         sctx->job.merkle = merkle;
      }

      for ( i = 0; i < merkle_count; i++ )
      {
         const char *s = json_string_value( json_array_get( merkle_arr, i ) );
         if ( !s || strlen(s) != 64 )
         {
            sctx->job.merkle_count = 0;
            pthread_mutex_unlock( &sctx->work_lock );
            applog( LOG_ERR, "Stratum notify: invalid Merkle branch" );
            goto out;
         }
         hex2bin( sctx->job.merkle[i], s, 32 );
      }   
   }
   sctx->job.merkle_count = merkle_count;         

	coinb1_size = strlen( coinb1 ) / 2;
	coinb2_size = strlen( coinb2 ) / 2;
	sctx->job.coinbase_size = coinb1_size + sctx->xnonce1_size +
	                          sctx->xnonce2_size + coinb2_size;
	sctx->job.coinbase = (uchar*) realloc( sctx->job.coinbase,
                                          sctx->job.coinbase_size );
	sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + sctx->xnonce1_size;
	hex2bin( sctx->job.coinbase, coinb1, coinb1_size );
	memcpy( sctx->job.coinbase + coinb1_size,
           sctx->xnonce1, sctx->xnonce1_size );
	if ( !sctx->job.job_id || strcmp( sctx->job.job_id, job_id ) )
		memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
	hex2bin( sctx->job.xnonce2 + sctx->xnonce2_size, coinb2, coinb2_size );
	free( sctx->job.job_id );
	sctx->job.job_id = strdup( job_id );
	hex2bin( sctx->job.prevhash, prevhash, 32 );

	sctx->block_height = getblocheight( sctx );
	hex2bin( sctx->job.nbits, nbits, 4 );
	hex2bin( sctx->job.ntime, stime, 4 );
	sctx->job.clean = clean;
	sctx->job.diff = sctx->next_diff;

	pthread_mutex_unlock( &sctx->work_lock );

	ret = true;

out:
	return ret;
}

/* Which of the two a mining.notify is. The answer comes from the algorithm and
 * was fixed before the socket opened; nothing about the packet in hand is
 * consulted, and no other method can reach this decision.
 *
 * That is the whole point of the indirection. The sibling CUDA port took the
 * arrival of a mining.set_target as evidence about which dialect the pool spoke
 * and rewired this parser from inside the set_target handler -- a bug that
 * needs a live pool, a rare method and the one dialect nobody tests with to
 * show itself.                                                              */
static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	if (opt_stratum_dialect == STRATUM_PROGPOW)
		return stratum_progpow_notify(sctx, params);
	return stratum_bitcoin_notify(sctx, params);
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
	double diff;

	diff = json_number_value(json_array_get(params, 0));
	if (diff == 0)
		return false;

	pthread_mutex_lock(&sctx->work_lock);
	sctx->next_diff = diff;
	pthread_mutex_unlock(&sctx->work_lock);
	return true;
}

/* mining.set_target -- Equihash pools send a 256-bit target as a 64-char hex
 * string instead of a floating-point difficulty.
 *
 * Pool encoding (server-side):
 *   diff_to_target_equi: m = 0xFFFF0000/diff_reduced; target[k+1] = m>>8; target[k+2] = m>>40
 *  hexlify(target, 32) -> LE memory order
 *  string_be(hex)      -> byte-reversed -> big-endian (MSB first) on wire
 *
 * Our decode:
 *  hex2bin(raw)        -> MSB first in raw[]
 *  be32dec into tgt[]  -> tgt[7] = MSW (same layout as work->target)
 *  hash_to_diff(tgt)   -> diff_internal = 1/tgt[7]  (exact round-trip via diff_to_hash)
 *   next_diff           = diff_internal  (for correct target reconstruction)
 *  display             = diff_internal x EQH_DIFF_SCALE  (matches pool's number)
 */
static bool stratum_set_target(struct stratum_ctx *sctx, json_t *params)
{
	const char *target_hex = json_string_value(json_array_get(params, 0));
	if (!target_hex || strlen(target_hex) != 64) {
		applog(LOG_ERR, "mining.set_target: invalid target");
		return false;
	}

	uint32_t tgt[8];
	if (!parse_target_hex(target_hex, tgt)) {
		applog(LOG_ERR, "mining.set_target: hex decode failed");
		return false;
	}

	/* This handler sets a target and nothing else. It does not decide which
	 * dialect the pool speaks, it does not touch how a notify is read, and the
	 * miner will parse the next job exactly as it parsed the last one. See
	 * stratum_notify.
	 *
	 * For ProgPoW the 32 bytes are kept as they arrived. Every job of that
	 * dialect carries a target of its own, so this is the standing answer for
	 * one that does not -- and keeping it whole is what stops the round trip
	 * below from loosening it.                                             */
	if (opt_stratum_dialect == STRATUM_PROGPOW) {
		pthread_mutex_lock(&sctx->work_lock);
		memcpy(sctx->next_target, tgt, sizeof tgt);
		sctx->have_next_target = true;
		pthread_mutex_unlock(&sctx->work_lock);

		if (!opt_quiet)
			applog(LOG_BLUE, "Pool set target %s", target_hex);
		return true;
	}

	/* Convert to diff_pool -- the difficulty value the pool operator sees.
	 * diff_pool is stored in next_diff, exactly as set_difficulty does, and
	 * stratum_gen_work divides by opt_target_factor to recover the internal
	 * difficulty diff_to_hash wants.
	 *
	 * The round trip is lossy: diff_to_hash reproduces only the top 128
	 * bits of the target, so the reconstructed target can end up looser than
	 * the one the pool sent, and a share that we think passes can be
	 * rejected. cpuminer-opt keeps the raw 32 bytes alongside for the one
	 * algorithm that needs the precision. Carry the raw target here too if a
	 * pool ever shows up where this matters -- but that belongs to whatever
	 * owns the target semantics, not to the protocol client.               */
	double diff_internal = hash_to_diff(tgt);
	if (diff_internal <= 0) {
		applog(LOG_ERR, "mining.set_target: target yields zero difficulty");
		return false;
	}
	const double tgt_scale = ( opt_target_factor > 0.0 ) ? opt_target_factor
	                                                     : 1.0;
	double diff_pool = diff_internal * tgt_scale;

	pthread_mutex_lock(&sctx->work_lock);
	sctx->next_diff = diff_pool;   /* pool scale -- same unit as set_difficulty */
	pthread_mutex_unlock(&sctx->work_lock);

	if (!opt_quiet)
		applog(LOG_BLUE, "Pool set target %s (diff %.5g)", target_hex, diff_pool);

	return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	char *url;
	const char *host;
	int port;

	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (json_is_string(port_val))
		port = atoi(json_string_value(port_val));
	else
		port = (int) json_integer_value(port_val);
	if (!host || !port)
		return false;

	url = (char*) malloc(32 + strlen(host));

	strncpy( url, sctx->url, 15 );
	sprintf( strstr( url, "://" ) + 3, "%s:%d", host, port );

	if (!opt_redirect) {
		applog(LOG_INFO, "Ignoring request to reconnect to %s", url);
		free(url);
		return true;
	}

	applog(LOG_NOTICE, "Server requested reconnection to %s", url);

	free(sctx->url);
	sctx->url = url;
	stratum_disconnect(sctx);

	return true;
}

static bool json_object_set_error(json_t *result, int code, const char *msg)
{
	json_t *val = json_object();
	json_object_set_new(val, "code", json_integer(code));
	json_object_set_new(val, "message", json_string(msg));
	return json_object_set_new(result, "error", val) != -1;
}

static bool stratum_unknown_method(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "result", json_false());
	json_object_set_error(val, 38, "unknown method"); // ENOSYS

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_pong(struct stratum_ctx *sctx, json_t *id)
{
	char buf[64];
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	sprintf(buf, "{\"id\":%d,\"result\":\"pong\",\"error\":null}",
		(int) json_integer_value(id));
	ret = stratum_send_line(sctx, buf);

	return ret;
}

static bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char algo[64] = { 0 };
	char *s;
	json_t *val;
	bool ret = true;

	if (!id || json_is_null(id))
		return false;

	get_currentalgo(algo, sizeof(algo));

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(algo));

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}


static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret;
	
	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(USER_AGENT));
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	val = json_array_get(params, 0);
	if (val)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
	json_t *val, *id, *params;
	json_error_t err;
	const char *method;
	bool ret = false;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	method = json_string_value(json_object_get(val, "method"));
	if (!method)
		goto out;

	params = json_object_get(val, "params");

	id = json_object_get(val, "id");

	if (!strcasecmp(method, "mining.notify")) {
		ret = stratum_notify(sctx, params);
      sctx->new_job = true;
      goto out;
	}
	if (!strcasecmp(method, "mining.ping")) { // cgminer 4.7.1+
		if (opt_debug) applog(LOG_DEBUG, "Pool ping");
		ret = stratum_pong(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_difficulty")) {
		ret = stratum_set_difficulty(sctx, params);
		goto out;
	}
	/* Some pools send a 256-bit target instead of a difficulty. */
	if (!strcasecmp(method, "mining.set_target")) {
		ret = stratum_set_target(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_extranonce")) {
		ret = opt_stratum_dialect == STRATUM_PROGPOW
		    ? stratum_parse_nonce_prefix(sctx, params, 0)
		    : stratum_parse_extranonce(sctx, params, 0);
		goto out;
	}
	if (!strcasecmp(method, "client.reconnect")) {
		ret = stratum_reconnect(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_algo")) {
		// will prevent wrong algo parameters on a pool, will be used as test on rejects
		if (!opt_quiet) applog(LOG_NOTICE, "Pool asked your algo parameter");
		ret = stratum_get_algo(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_version")) {
		ret = stratum_get_version(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "client.show_message")) {
		ret = stratum_show_message(sctx, id, params);
		goto out;
	}

	if (!ret) {
		// don't fail = disconnect stratum on unknown (and optional?) methods
		if (opt_debug) applog(LOG_WARNING, "unknown stratum method %s!", method);
		ret = stratum_unknown_method(sctx, id);
	}
out:
	if (val)
		json_decref(val);

	return ret;
}
