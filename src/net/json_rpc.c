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
 * Derived from cpuminer-opt's util.c: the curl transport and the
 * JSON-RPC call it carries.
 */


#include "core/miner.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
   size_t	content_length;
};

struct data_buffer {
	void			*buf;
	size_t			len;
	size_t			allocated;
	struct header_info	*headers;
};

/* Modify the representation of integer numbers which would cause an overflow
 * so that they are treated as floating-point numbers.
 * This is a hack to overcome the limitations of some versions of Jansson. */
static char *hack_json_numbers(const char *in)
{
	char *out;
	int i, off, intoff;
	bool in_str, in_int;

	out = (char*) calloc(2 * strlen(in) + 1, 1);
	if (!out)
		return NULL;
	off = intoff = 0;
	in_str = in_int = false;
	for (i = 0; in[i]; i++) {
		char c = in[i];
		if (c == '"') {
			in_str = !in_str;
		} else if (c == '\\') {
			out[off++] = c;
			if (!in[++i])
				break;
		} else if (!in_str && !in_int && isdigit(c)) {
			intoff = off;
			in_int = true;
		} else if (in_int && !isdigit(c)) {
			if (c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-') {
				in_int = false;
				if (off - intoff > 4) {
					char *end;
#if JSON_INTEGER_IS_LONG_LONG
					errno = 0;
					strtoll(out + intoff, &end, 10);
					if (!*end && errno == ERANGE) {
#else
					long l;
					errno = 0;
					l = strtol(out + intoff, &end, 10);
					if (!*end && (errno == ERANGE || l > INT_MAX)) {
#endif
						out[off++] = '.';
						out[off++] = '0';
					}
				}
			}
		}
		out[off++] = in[i];
	}
	return out;
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = user_data;
	size_t len = size * nmemb;
	size_t newalloc, reqalloc;
	void *newmem;
	static const unsigned char zero = 0;
	static const size_t max_realloc_increase = 8 * 1024 * 1024;
	static const size_t initial_alloc = 16 * 1024;

	/* minimum required allocation size */
	reqalloc = db->len + len + 1;

	if (reqalloc > db->allocated) {
		if (db->len > 0) {
			newalloc = db->allocated * 2;
		} else {
			if (db->headers->content_length > 0)
				newalloc = db->headers->content_length + 1;
			else
				newalloc = initial_alloc;
		}

		if (db->headers->content_length == 0) {
			/* limit the maximum buffer increase */
			if (newalloc - db->allocated > max_realloc_increase)
				newalloc = db->allocated + max_realloc_increase;
		}

		/* ensure we have a big enough allocation */
		if (reqalloc > newalloc)
			newalloc = reqalloc;

		newmem = realloc(db->buf, newalloc);
		if (!newmem)
			return 0;

		db->buf = newmem;
		db->allocated = newalloc;
	}

	memcpy(db->buf + db->len, ptr, len); /* append new data */
	memcpy(db->buf + db->len + len, &zero, 1); /* null terminate */

	db->len += len;

	return len;
}

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = (struct header_info *) user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = (char*) calloc(1, ptrlen);
	key = (char*) calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = (char*)tmp - (char*)ptr;
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = (char*)ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("Content-Length", key))
		hi->content_length = strtoul(val, NULL, 10);

out:
	free(key);
	free(val);
	return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
/* Static upstream, where the JSON-RPC transport and the Stratum client shared
 * one file. They no longer do, and the Stratum client wants the same callback.  */
int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,
	curlsocktype purpose)
{
#ifdef __linux
	int tcp_keepcnt = 3;
#endif
	int tcp_keepintvl = 50;
	int tcp_keepidle = 50;
#ifndef WIN32
	int keepalive = 1;
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;
	DWORD outputBytes;
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* WIN32 */

	return 0;
}
#endif

json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req,
		      int *curl_err, int flags)
{
	json_t *val, *err_val, *res_val;
	int rc;
	long http_rc;
	struct data_buffer all_data = {0};
	char *json_buf;
	json_error_t err;
	struct curl_slist *headers = NULL;
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	long timeout = (flags & JSON_RPC_LONGPOLL) ? opt_timeout : 30;
	struct header_info hi = {0};

   all_data.headers = &hi;
	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	if (opt_protocol)  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (opt_cert)      curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
   curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	if (opt_redirect)  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
	if (opt_proxy)
   {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	if (userpass)
   {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	if (flags & JSON_RPC_LONGPOLL)
		curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
   curl_easy_setopt(curl, CURLOPT_POSTFIELDS, rpc_req);

	if (opt_protocol)
		applog(LOG_DEBUG, "JSON protocol request:\n%s\n", rpc_req);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll reject-reason");
	//headers = curl_slist_append(headers, "Accept:"); // disable Accept hdr
	//headers = curl_slist_append(headers, "Expect:"); // disable Expect hdr

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (curl_err != NULL)
		*curl_err = rc;
	if (rc) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
		if (!((flags & JSON_RPC_LONGPOLL) && rc == CURLE_OPERATION_TIMEDOUT) &&
		    !((flags & JSON_RPC_QUIET_404) && http_rc == 404))
			applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
		if (curl_err && (flags & JSON_RPC_QUIET_404) && http_rc == 404)
			*curl_err = CURLE_OK;
		goto err_out;
	}

// want_stratum is useless, and so is this code it seems. Nothing in
// hi appears to be set.   
	/* If X-Stratum was found, activate Stratum */
	if (want_stratum && hi.stratum_url &&
	    !strncasecmp(hi.stratum_url, "stratum+tcp://", 14)) {
		have_stratum = true;
		tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
		hi.stratum_url = NULL;
	}

	/* If X-Long-Polling was found, activate long polling */
	if (!have_longpoll && want_longpoll && hi.lp_path && !have_gbt &&
	    allow_getwork && !have_stratum) {
		have_longpoll = true;
		tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
		hi.lp_path = NULL;
	}

	if (!all_data.buf) {
		applog(LOG_ERR, "Empty data received in json_rpc_call.");
		goto err_out;
	}

	json_buf = hack_json_numbers((char*) all_data.buf);
	errno = 0; /* needed for Jansson < 2.1 */
	val = JSON_LOADS(json_buf, &err);
	free(json_buf);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}

	if (opt_protocol) {
		char *s = json_dumps(val, JSON_INDENT(3));
		applog(LOG_DEBUG, "JSON protocol response:\n%s", s);
		free(s);
	}

	/* JSON-RPC valid response returns a 'result' and a null 'error'. */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || (err_val && !json_is_null(err_val)
		&& !(flags & JSON_RPC_IGNOREERR))) {

		char *s = NULL;

		if (err_val) {
			s = json_dumps(err_val, 0);
			json_t *msg = json_object_get(err_val, "message");
			json_t *err_code = json_object_get(err_val, "code");
			if (curl_err && json_integer_value(err_code))
				*curl_err = (int)json_integer_value(err_code);

			if (msg && json_is_string(msg)) {
				free(s);
				s = strdup(json_string_value(msg));
				if (have_longpoll && s && !strcmp(s, "method not getwork")) {
					json_decref(err_val);
					free(s);
					goto err_out;
				}
			}
			json_decref(err_val);
		}
		else
			s = strdup("(unknown reason)");

		if (!curl_err || opt_debug)
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);

		free(s);

		goto err_out;
	}

	if (hi.reason)
		json_object_set_new(val, "reject-reason", json_string(hi.reason));

	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	free(hi.lp_path);
	free(hi.reason);
	free(hi.stratum_url);
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

/* used to load a remote config */
json_t* json_load_url(char* cfg_url, json_error_t *err)
{
	char err_str[CURL_ERROR_SIZE] = { 0 };
	struct data_buffer all_data = { 0 };
	int rc = 0; json_t *cfg = NULL;
	CURL *curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "Remote config init failed!");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, cfg_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	} else if (getenv("http_proxy")) {
		if (getenv("all_proxy"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
		else if (getenv("ALL_PROXY"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
		else
			curl_easy_setopt(curl, CURLOPT_PROXY, "");
	}
	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Remote config read failed: %s", err_str);
		goto err_out;
	}
	if (!all_data.buf || !all_data.len) {
		applog(LOG_ERR, "Empty data received for config");
		goto err_out;
	}

	cfg = JSON_LOADS((char*)all_data.buf, err);
err_out:
	curl_easy_cleanup(curl);
	return cfg;
}
