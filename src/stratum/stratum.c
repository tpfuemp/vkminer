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

			CURLcode rc = curl_easy_recv(sctx->curl, s, RECVSIZE, (size_t *)&n);
			if (rc == CURLE_OK && !n) {
				ret = false;
				break;
			}
			if (rc != CURLE_OK) {
				if (rc != CURLE_AGAIN || !socket_full(sctx->sock, 1)) {
#else

         n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				ret = false;
				break;
			}
			if (n < 0) {
				if (!socket_blocks() || !socket_full(sctx->sock, 1)) {
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
	 *   [ [[subs...]], "xnonce1", xn2_size ]
	 * sid at index 0, extranonce params at indices 1 and 2.               */
	if (!stratum_parse_extranonce(sctx, res_val, 1))
		goto out;

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

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
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

/* mining.set_target — Equihash pools send a 256-bit target as a 64-char hex
 * string instead of a floating-point difficulty.
 *
 * Pool encoding (server-side):
 *   diff_to_target_equi: m = 0xFFFF0000/diff_reduced; target[k+1] = m>>8; target[k+2] = m>>40
 *   hexlify(target, 32) → LE memory order
 *   string_be(hex)      → byte-reversed → big-endian (MSB first) on wire
 *
 * Our decode:
 *   hex2bin(raw)        → MSB first in raw[]
 *   be32dec into tgt[]  → tgt[7] = MSW (same layout as work->target)
 *   hash_to_diff(tgt)   → diff_internal = 1/tgt[7]  (exact round-trip via diff_to_hash)
 *   next_diff           = diff_internal  (for correct target reconstruction)
 *   display             = diff_internal × EQH_DIFF_SCALE  (matches pool's number)
 */
static bool stratum_set_target(struct stratum_ctx *sctx, json_t *params)
{
	const char *target_hex = json_string_value(json_array_get(params, 0));
	if (!target_hex || strlen(target_hex) != 64) {
		applog(LOG_ERR, "mining.set_target: invalid target");
		return false;
	}

	/* Decode big-endian hex to raw bytes */
	uchar raw[32];
	if (!hex2bin(raw, target_hex, 32)) {
		applog(LOG_ERR, "mining.set_target: hex decode failed");
		return false;
	}

	/* Convert to uint32_t[8] with MSW at index 7 (work->target layout).
	 * raw[0] is the most significant byte → goes to tgt[7]'s MSB.          */
	uint32_t tgt[8];
	for (int i = 0; i < 8; i++) {
		int b = i * 4;
		tgt[7 - i] = ((uint32_t)raw[b+0] << 24) | ((uint32_t)raw[b+1] << 16)
		           | ((uint32_t)raw[b+2] <<  8) |  (uint32_t)raw[b+3];
	}

	/* Convert to diff_pool — the difficulty value the pool operator sees.
	 * diff_pool is stored in next_diff, exactly as set_difficulty does, and
	 * stratum_gen_work divides by opt_target_factor to recover the internal
	 * difficulty diff_to_hash wants.
	 *
	 * ⚠ The round trip is lossy: diff_to_hash reproduces only the top 128
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
	sctx->next_diff = diff_pool;   /* pool scale — same unit as set_difficulty */
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
		ret = stratum_parse_extranonce(sctx, params, 0);
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
