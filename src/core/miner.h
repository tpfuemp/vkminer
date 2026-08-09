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
 * Derived from cpuminer-opt's miner.h. The per-algorithm fields are gone --
 * what a header means belongs to an Algorithm here, not to this struct -- and
 * so is everything that assumed the hash was computed by a CPU thread.
 */

#ifndef VKMINER_MINER_H__
#define VKMINER_MINER_H__

#include "core/config.h"

#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>

#if !defined(WIN32)
#include <unistd.h>
#endif

#include "compat.h"

/* Everything below is C, and main.cpp calls into it. */
#ifdef __cplusplus
extern "C" {
#endif

/* CPU architecture, for the user agent string the pool sees. */
#if defined(__x86_64__)
   #define USER_AGENT_ARCH "x64"
#elif defined(__aarch64__)
   #define USER_AGENT_ARCH "arm"
#elif defined(__riscv)
   #define USER_AGENT_ARCH "rv"
#else
   #define USER_AGENT_ARCH ""
#endif

#if defined(__linux)
   #define USER_AGENT_OS   "L"
#elif defined(WIN32)
   #define USER_AGENT_OS   "W"
#elif defined(__APPLE__)
   #define USER_AGENT_OS   "M"
#else
   #define USER_AGENT_OS   ""
#endif

#define USER_AGENT PACKAGE_NAME "-" PACKAGE_VERSION "-" USER_AGENT_ARCH USER_AGENT_OS

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_BLUE  0x10 /* unique value */
#define LOG_MAJR  0x11 /* unique value */
#define LOG_MINR  0x12 /* unique value */
#define LOG_GREEN 0x13 /* unique value */
#define LOG_PINK  0x14 /* unique value */
#else
enum {
   LOG_CRIT,
   LOG_ERR,
   LOG_WARNING,
   LOG_NOTICE,
   LOG_INFO,
   LOG_DEBUG,
   /* custom notices */
   LOG_BLUE  = 0x10,
   LOG_MAJR  = 0x11,
   LOG_MINR  = 0x12,
   LOG_GREEN = 0x13,
   LOG_PINK  = 0x14 };
#endif

#define WORK_ALIGNMENT 64

/* Bitcoin-style 80-byte header, as 32-bit words, plus the SHA-256 padding
 * cpuminer-opt carries in the same buffer. cpuminer-opt reaches these through
 * algo_gate; that table is not inherited, because it mixes protocol concerns
 * with execution concerns and this project keeps those apart. Until an
 * Algorithm owns the header layout, these are the layout.  */
#define STD_WORK_DATA_SIZE  128
#define STD_WORK_CMP_SIZE    76
#define STD_NTIME_INDEX      17
#define STD_NBITS_INDEX      18
#define STD_NONCE_INDEX      19

extern bool is_power_of_2( int n );

static inline bool is_windows(void)
{
#ifdef WIN32
   return true;
#else
   return false;
#endif
}

static inline bool is_root(void)
{
#if defined(WIN32)
   return false;
#else
   return !getuid();
#endif
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* Swap any two variables of the same type without using a temp */
#define swap_vars(a,b) a^=b; b^=a; a^=b;

typedef unsigned char uchar;

/* cpuminer-opt gets these from simd-utils, which is not inherited. The
 * difficulty and target arithmetic in util.c takes a materially different
 * path depending on whether a 128-bit integer type exists, so the name has
 * to survive even though the SIMD around it does not. */
#if defined(__SIZEOF_INT128__)
#define GCC_INT128 1
typedef __uint128_t uint128_t;
typedef __int128_t  int128_t;
#endif

static inline uint32_t be32dec(const void *pp)
{
   const uint8_t *p = (uint8_t const *)pp;
   return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
       ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline uint32_t le32dec(const void *pp)
{
   const uint8_t *p = (uint8_t const *)pp;
   return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
       ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
   uint8_t *p = (uint8_t *)pp;
   p[3] = x & 0xff;
   p[2] = (x >> 8) & 0xff;
   p[1] = (x >> 16) & 0xff;
   p[0] = (x >> 24) & 0xff;
}

static inline void le32enc(void *pp, uint32_t x)
{
   uint8_t *p = (uint8_t *)pp;
   p[0] = x & 0xff;
   p[1] = (x >> 8) & 0xff;
   p[2] = (x >> 16) & 0xff;
   p[3] = (x >> 24) & 0xff;
}

static inline uint16_t le16dec(const void *pp)
{
   const uint8_t *p = (uint8_t const *)pp;
   return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}

static inline void le16enc(void *pp, uint16_t x)
{
   uint8_t *p = (uint8_t *)pp;
   p[0] = x & 0xff;
   p[1] = (x >> 8) & 0xff;
}

static inline uint32_t bswap_32( uint32_t x )
{
   return ( ( (x) << 24 ) & 0xff000000u ) | ( ( (x) <<  8 ) & 0x00ff0000u )
        | ( ( (x) >>  8 ) & 0x0000ff00u ) | ( ( (x) >> 24 ) & 0x000000ffu );
}

/* From simd-utils, which is not inherited; the share and hash-rate reporting
 * divides by counters that are legitimately zero for the first few seconds of
 * a session. For floating point it is only as safe as 0 being precisely zero. */
#define safe_div( dividend, divisor, safe_result ) \
   ( (divisor) == 0 ? safe_result : ( (dividend) / (divisor) )  )

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads(str, 0, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, 0, err_ptr)
#else
#define JSON_LOADS(str, err_ptr) json_loads(str, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, err_ptr)
#endif

/* ------------------------------------------------------------------ work */

struct work
{
   uint32_t target[8] __attribute__ ((aligned (64)));
   uint32_t data[32]  __attribute__ ((aligned (64)));
   double targetdiff;
   double sharediff;
   double stratum_diff;
   int height;
   char *txs;
   int tx_count;
   char *workid;
   char *job_id;
   size_t xnonce2_len;
   unsigned char *xnonce2;
   bool stale;
   /* Bumped on every new job. A dispatch cannot be cancelled once submitted,
    * so results carry the epoch they were launched under and stale ones are
    * dropped on completion rather than prevented. */
   uint32_t job_epoch;
   /* The JSON-RPC id this share is submitted under, and the only thing that
    * ties the pool's reply back to it. Assigned before the share is queued,
    * so the request builder and the pending-stats entry agree on it. */
   uint32_t submit_id;
} __attribute__ ((aligned (WORK_ALIGNMENT)));

struct stratum_job
{
   unsigned char prevhash[32];
   char *job_id;
   size_t coinbase_size;
   unsigned char *coinbase;
   unsigned char *xnonce2;
   int merkle_count;
   int merkle_buf_size;
   unsigned char **merkle;
   unsigned char version[4];
   unsigned char nbits[4];
   unsigned char ntime[4];
   double diff;
   bool clean;
} __attribute__ ((aligned (64)));

struct stratum_ctx {
   char *url;

   CURL *curl;
   char *curl_url;
   char curl_err_str[CURL_ERROR_SIZE];
   curl_socket_t sock;
   size_t sockbuf_size;
   char *sockbuf;
   pthread_mutex_t sock_lock;

   double next_diff;
   double sharediff;

   char *session_id;
   size_t xnonce1_size;
   unsigned char *xnonce1;
   size_t xnonce2_size;
   struct stratum_job job;
   struct work work __attribute__ ((aligned (64)));
   pthread_mutex_t work_lock;

   int block_height;
   bool new_job;
} __attribute__ ((aligned (64)));

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool stratum_suggest_difficulty( struct stratum_ctx *sctx, double diff );

void work_free(struct work *w);
void work_copy(struct work *dest, const struct work *src);

/* --------------------------------------------------------------- threads */

struct thread_q;

struct thread_q *tq_new(void);
void tq_free(struct thread_q *tq);
bool tq_push(struct thread_q *tq, void *data);
void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void tq_freeze(struct thread_q *tq);
void tq_thaw(struct thread_q *tq);

struct thr_info {
        int id;
        pthread_t pth;
        pthread_attr_t attr;
        struct thread_q *q;
};

struct work_restart {
        volatile uint8_t restart;
        char padding[128 - sizeof(uint8_t)];
};

enum workio_commands {
        WC_GET_WORK,
        WC_SUBMIT_WORK,
};

struct workio_cmd {
        enum workio_commands cmd;
        struct thr_info *thr;
        union {
                struct work *work;
        } u;
};

/* --------------------------------------------------------------- globals */

/* A name, not cpuminer-opt's `enum algos`. That enum was the index into
 * algo_gate's tables; those are not inherited, so nothing here dispatches on
 * the algorithm and there is nothing for an enum to number. What is left is
 * the string the user typed and the pool is told.  */
extern char *opt_algo;
void get_currentalgo( char *buf, int sz );

extern bool opt_debug;
extern bool opt_debug_diff;
extern bool opt_benchmark;
extern int64_t opt_benchmark_target;
extern bool opt_protocol;
extern bool opt_extranonce;
extern bool opt_quiet;
extern bool opt_redirect;
extern int opt_timeout;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool have_gbt;
extern char *lp_id;
extern char *rpc_user;
extern char *rpc_userpass;
extern char *short_url;
extern const char *gbt_lp_req;
extern const char *getwork_req;
extern bool allow_getwork;
extern bool want_stratum;
extern bool have_stratum;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern bool use_colors;
extern pthread_mutex_t applog_lock;
extern pthread_mutex_t stats_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern int api_thr_id;
extern struct work_restart *work_restart;
extern double *thr_hashrates;
extern double global_hashrate;
extern double stratum_diff;
extern double net_diff;
extern double net_hashrate;
extern double opt_diff_factor;
extern double opt_target_factor;
extern bool allow_mininginfo;
extern pthread_rwlock_t g_work_lock;
extern time_t g_work_time;
extern bool opt_stratum_stats;
extern uint32_t accepted_share_count;
extern uint32_t rejected_share_count;
extern uint32_t solved_block_count;
extern const int pk_buffer_size_max;
extern int pk_buffer_size;
extern bool opt_bell;    /* keyboard beep */
extern char *rpc_url;
extern char *rpc_pass;
extern int  opt_retries;
extern int  opt_fail_pause;
extern int  opt_scantime;
extern bool opt_background;
extern bool opt_stratum_keepalive;
extern int  stratum_keepalive_timeout;
extern bool opt_hash_meter;
extern int  opt_time_limit;
extern bool opt_api_enabled;
extern char *opt_api_allow;
extern int  opt_api_listen;
extern int  opt_api_remote;

/* Device selection. Nothing here interprets these; the backend does, once it
 * has enumerated what is actually present. */
extern char *opt_devices;      /* comma separated indices, empty means all */
extern bool opt_device_list;   /* enumerate and exit */
extern bool opt_vk_validate;   /* Vulkan validation layers */
extern bool opt_vk_pipeline_stats; /* report what the driver compiled a shader into */
extern bool opt_vk_probe_best; /* have the shader track the best digest it sees */
extern char *opt_replay;       /* capture file to re-run, NULL to mine */
extern bool opt_self_test;     /* run the known-answer vectors and exit */
extern char *opt_backend;      /* backend name, NULL means the default */
extern char *opt_algo_dir;     /* where to load shaders from */
extern int  opt_queue_depth;   /* dispatches in flight per device, 0 = backend's */
extern bool opt_retune;        /* sweep even where a tuning is already known */
extern bool opt_no_tune;       /* do not sweep, and do not read one either */
extern uint32_t submitted_share_count;
extern uint32_t stale_share_count;
extern int  work_thr_id;

/* Upstream this is the CPU thread count, and everything derived from it --
 * nonce range per thread, aggregate hash rate -- assumed a CPU thread. Here it
 * is the number of device workers, which is a backend question; until the
 * scheduler owns it, one worker.  */
extern int  opt_n_threads;
extern bool opt_n_threads_set;

/* The job every worker is currently mining, and the lock that orders a new
 * job against the workers reading it. */
extern struct work g_work;

/* The one pool connection. There is no failover yet, so there is one. */
extern struct stratum_ctx stratum;
extern bool     stratum_down;
extern bool     stratum_need_reset;
extern uint32_t stratum_errors;

/* Session-wide hash counters, fed by the backends. */
extern double  total_hashes;
extern struct timeval total_hashes_time;
extern struct timeval session_start;

/* keyboard beep */
static const char ASCII_BELL = '\a';

/* ------------------------------------------------------------------ misc */

#define JSON_RPC_LONGPOLL	(1 << 0)
#define JSON_RPC_QUIET_404	(1 << 1)
#define JSON_RPC_IGNOREERR  (1 << 2)

#define JSON_BUF_LEN     512

#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m"
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"  /* dark yellow */
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"  /* purple */
#define CL_CYN  "\x1B[36m"

#define CL_BLK  "\x1B[22;30m" /* black */
#define CL_RD2  "\x1B[22;31m" /* red */
#define CL_GR2  "\x1B[22;32m" /* green */
#define CL_BRW  "\x1B[22;33m" /* brown */
#define CL_BL2  "\x1B[22;34m" /* blue */
#define CL_MA2  "\x1B[22;35m" /* purple */
#define CL_CY2  "\x1B[22;36m" /* cyan */
#define CL_SIL  "\x1B[22;37m" /* gray */

#ifdef WIN32
#define CL_GRY  "\x1B[01;30m" /* dark gray */
#else
#define CL_GRY  "\x1B[90m"    /* dark gray selectable in putty */
#endif
#define CL_LRD  "\x1B[01;31m" /* bright red */
#define CL_LGR  "\x1B[01;32m" /* bright green */
#define CL_YL2  "\x1B[01;33m" /* bright yellow */
#define CL_LBL  "\x1B[01;34m" /* light blue */
#define CL_LMA  "\x1B[01;35m" /* light magenta */
#define CL_LCY  "\x1B[01;36m" /* light cyan */

#define CL_WHT  "\x1B[01;37m" /* white */

void   applog(int prio, const char *fmt, ...);
void   applog2(int prio, const char *fmt, ...);
void   applog_nl( const char *fmt, ... );
void   applog_hash(void *hash);
void   applog_hex(void *data, int len);
void   restart_threads(void);
void   proper_exit(int reason);

/* Installs a function to run at the top of proper_exit, before exit() starts
   running destructors on the calling thread. The miner uses it to stop the
   device workers and give their devices back, in that order. */
void   set_exit_hook(void (*hook)(void));

json_t *json_load_url(char* cfg_url, json_error_t *err);
json_t *json_rpc_call( CURL *curl, const char *url, const char *userpass,
                       const char *rpc_req, int *curl_err, int flags );
#if LIBCURL_VERSION_NUM >= 0x070f06
int     sockopt_keepalive_cb( void *userdata, curl_socket_t fd,
                              curlsocktype purpose );
#endif

void   cbin2hex(char *out, const char *in, size_t len);
void   bin2hex( char *s, const unsigned char *p, size_t len );
char  *abin2hex( const unsigned char *p, size_t len );
char  *bebin2hex( const unsigned char *p, size_t len );
bool   hex2bin( unsigned char *p, const char *hexstr, const size_t len );
void   memrev(unsigned char *p, size_t len);
bool   jobj_binary( const json_t *obj, const char *key, void *buf,
                    size_t buflen );
int    varint_encode( unsigned char *p, uint64_t n );
size_t address_to_script( unsigned char *out, size_t outsz, const char *addr );
int    timeval_subtract( struct timeval *result, struct timeval *x,
                         struct timeval *y);

void   get_defconfig_path(char *out, size_t bufsize, char *argv0);
void   log_sw_err( char* filename, int line_number, char* msg );

/* Factors of 1000 used for hashes, ie kH/s, Mh/s. */
void   scale_hash_for_display ( double* hashrate, char* units );
/* Factors of 1024 used for bytes, ie kiB, MiB. */
void   format_number_si( double* hashrate, char* si_units );
void   format_hashrate( double hashrate, char *output );
void   report_summary_log( bool force );

/* One line per device in the periodic report, printed by whoever knows what a
 * device is. A hook rather than a call because this file sits below the
 * scheduler: it is linked into programs that have no workers at all, and those
 * leave it null. */
extern void ( *report_devices_hook )( void );

/* Bitcoin formula for converting difficulty to an equivalent
 * number of hashes.
 *
 *     https://en.bitcoin.it/wiki/Difficulty
 *     hash = diff * 2**32
 */

#define EXP16 65536.
#define EXP32 4294967296.
extern const long double exp32;  /* 2**32  */
extern const long double exp48;  /* 2**48  */
extern const long double exp64;  /* 2**64  */
extern const long double exp96;  /* 2**96  */
extern const long double exp128; /* 2**128 */
extern const long double exp160; /* 2**160 */

bool   fulltest( const uint32_t *hash, const uint32_t *target );
bool   valid_hash( const void*, const void* );
double hash_to_diff( const void* );
void   diff_to_hash( uint32_t*, const double );
double nbits_to_diff( uint32_t );

double hash_target_ratio( uint32_t* hash, uint32_t* target );
void   work_set_target_ratio( struct work* work, const void *hash );

bool   submit_solution( struct work *work, const void *hash,
                        struct thr_info *thr );

/* Share accounting. Static in cpu-miner.c, where the Stratum thread and the
 * share bookkeeping lived in one file; they no longer do.  */
const char *format_diff( char *buf, size_t bufsz, double d );
void   sprintf_et( char *str, unsigned long seconds );
void   share_stats_init( void );
void   share_stats_reset( void );
void   share_last_submit_time( struct timeval *tv );
/* `id` is the JSON-RPC id the pool echoed, which is what says *which* share
 * this reply is about. Several may be in flight at once. */
int    share_result( int result, uint32_t id, struct work *work,
                     const char *reason );

extern uint64_t session_first_block;
extern uint32_t last_block_height;
extern double   last_targetdiff;
extern double   lowest_share;

/* Header assembly, shared by the Stratum and (later) GBT paths. */
void   sha256d_gen_merkle_root( char *merkle_root, struct stratum_ctx *sctx );
void   std_build_block_header( struct work *g_work, uint32_t version,
                               uint32_t *prevhash, uint32_t *merkle_tree,
                               uint32_t ntime, uint32_t nbits );
void   std_build_extraheader( struct work *g_work, struct stratum_ctx *sctx );

/* Rebuild `work` on the same job with a different extranonce2, which is a
 * different coinbase and so a fresh nonce range. False means the job has
 * changed and the caller should take the new one. See the definition for what
 * callers owe each other about the counter.  */
bool   stratum_set_extranonce2( struct work *work, struct stratum_ctx *sctx,
                                uint64_t counter );
void   std_le_build_stratum_request( char *req, struct work *work );

void  *workio_thread( void *userdata );
void  *stratum_thread( void *userdata );

void   parse_arg(int key, char *arg);
void   parse_config(json_t *config, char *ref);
void   parse_cmdline(int argc, char *argv[]);
void   show_usage_and_exit(int status);

#ifdef __cplusplus
}
#endif

#endif /* VKMINER_MINER_H__ */
