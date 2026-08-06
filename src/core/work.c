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
 * Derived from cpuminer-opt's cpu-miner.c: the lifetime of a struct work,
 * the workio thread that owns the pool socket for submissions, and the share
 * accounting behind the per-share and periodic report lines.
 */


#include "core/miner.h"

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

#if defined(WIN32)
#include <windows.h>
#endif

/* ------------------------------------------------------------- the work */

struct work g_work __attribute__ ((aligned (64))) = {{ 0 }};

/* One writer -- whichever thread received the new job -- and one reader per
 * worker, so the workers never queue behind each other to find out what they
 * are mining. g_work_time is zero while there is no job to mine. */
pthread_rwlock_t g_work_lock;
time_t g_work_time = 0;

/* Difficulty as the pool states it, and as the network states it. They are
 * different numbers about different things: the first sets how often we are
 * expected to submit, the second what it would take to find a block. */
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;

/* The rate the whole miner is achieving, summed over the workers by
 * report_summary_log. */
double global_hashrate = 0.;

const long double exp32  = EXP32;                                 /* 2**32  */
const long double exp48  = EXP32 * EXP16;                         /* 2**48  */
const long double exp64  = EXP32 * EXP32;                         /* 2**64  */
const long double exp96  = EXP32 * EXP32 * EXP32;                 /* 2**96  */
const long double exp128 = EXP32 * EXP32 * EXP32 * EXP32;         /* 2**128 */
const long double exp160 = EXP32 * EXP32 * EXP32 * EXP32 * EXP16; /* 2**160 */

void work_free( struct work *w )
{
   if (w->txs)     free(w->txs);
   if (w->workid)  free(w->workid);
   if (w->job_id)  free(w->job_id);
   if (w->xnonce2) free(w->xnonce2);
}

void work_copy( struct work *dest, const struct work *src )
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {
		dest->xnonce2 = (uchar*) malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

void restart_threads(void)
{
	for ( int i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
   if ( opt_debug )
      applog( LOG_INFO, "Threads restarted for new work.");
}

/* Run just before the process ends, if anything installed one.

   This file is inherited code that knows nothing about devices, and the tests
   link it without linking main, so the teardown it needs cannot be called by
   name from here. The miner installs a hook; a test installs nothing and gets
   the behaviour this code always had. */
static void (*exit_hook)(void) = NULL;

void set_exit_hook(void (*hook)(void))
{
   exit_hook = hook;
}

void proper_exit(int reason)
{
   if (opt_debug) applog(LOG_INFO,"Program exit");

   /* Before exit(), which runs destructors on this thread while the other
      threads are still running. The workers are the ones holding devices. */
   if (exit_hook) exit_hook();

#ifdef WIN32
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// unhide parent command line windows
			ShowWindow(hcon, SW_SHOWMINNOACTIVE);
		}
	}
#endif
	exit(reason);
}

/* --------------------------------------------------------- share stats */

// Format a difficulty as a human-readable string with a k/M/G/T/P suffix
// instead of exponential notation (e.g. 170100 -> "170.10k", 2.26e6 -> "2.26M").
const char *format_diff( char *buf, size_t bufsz, double d )
{
   if ( d == 0.0 )      snprintf( buf, bufsz, "0" );
   // %.4g switches to exponential (e.g. 3.78e-06) once d < 1e-4; use fixed
   // notation for sub-unity diffs so small shares read as 0.00000378.
   else if ( d < 1.0 )  snprintf( buf, bufsz, "%.8f", d );
   else if ( d < 1e3 )  snprintf( buf, bufsz, "%.4g",  d );
   else if ( d < 1e6 )  snprintf( buf, bufsz, "%.2fk", d / 1e3  );
   else if ( d < 1e9 )  snprintf( buf, bufsz, "%.2fM", d / 1e6  );
   else if ( d < 1e12 ) snprintf( buf, bufsz, "%.2fG", d / 1e9  );
   else if ( d < 1e15 ) snprintf( buf, bufsz, "%.2fT", d / 1e12 );
   else                 snprintf( buf, bufsz, "%.2fP", d / 1e15 );
   return buf;
}

// Does not account for leap years.
void sprintf_et( char *str, unsigned long seconds )
{
   long unsigned int minutes = seconds / 60;
   if ( minutes )
   {
      long unsigned int hours = minutes / 60;
      if ( hours )
      {
         long unsigned int days = hours / 24;
         if ( days )
         {
            long unsigned int years = days / 365;
            if ( years )
               sprintf( str, "%luy%03lud", years, days % 365 ); // 0y000d
            else
               sprintf( str, "%lud%02luh", days, hours % 24 );  // 0d00h
         }
         else
            sprintf( str, "%luh%02lum", hours, minutes % 60 );  // 0h00m
      }
      else
         sprintf( str, "%lum%02lus", minutes, seconds % 60 );   // 0m00s
   }
   else
      sprintf( str, "%lus", seconds );   // 0s
}

struct share_stats_t
{
   int share_count;
   struct timeval submit_time;
   double net_diff;
   double share_diff;
   double stratum_diff;
   double target_diff;
   uint32_t height;
   char   job_id[32];
};

#define s_stats_size 8
static struct share_stats_t share_stats[ s_stats_size ] = {{0}};
static int s_get_ptr = 0, s_put_ptr = 0;
static struct timeval last_submit_time = {0};

void ( *report_devices_hook )( void ) = NULL;

static struct timeval five_min_start = {0};
struct timeval session_start = {0};
struct timeval total_hashes_time = {0};
double   total_hashes = 0.;

uint32_t accepted_share_count = 0;
uint32_t rejected_share_count = 0;
uint32_t stale_share_count    = 0;
uint32_t solved_block_count   = 0;
uint32_t submitted_share_count = 0;

static uint64_t submit_sum  = 0;
static uint64_t accept_sum  = 0;
static uint64_t stale_sum   = 0;
static uint64_t reject_sum  = 0;
static uint64_t solved_sum  = 0;
static double   norm_diff_sum = 0.;
static double   highest_share = 0;   // highest accepted share diff

/* File-scope in cpu-miner.c, where stratum_gen_work sat in the same file.
 * It is the Stratum thread that observes a new block or difficulty, so it is
 * the Stratum thread that moves these. */
uint64_t session_first_block = 0;
uint32_t last_block_height = 0;
double   last_targetdiff = 0.;
double   lowest_share = 9e99;        // lowest accepted share diff

static inline int stats_ptr_incr( int p )
{
   return ++p % s_stats_size;
}

/* Every elapsed time the report lines print is measured from here, so they all
 * have to start at the same instant, and that instant has to be the one the
 * workers start at -- not process start, which includes device enumeration. */
void share_stats_init( void )
{
   memset( share_stats, 0, sizeof share_stats );
   gettimeofday( &last_submit_time, NULL );
   five_min_start    = last_submit_time;
   session_start     = last_submit_time;
   total_hashes_time = last_submit_time;
}

/* Dropped on reconnect: the pending entries describe shares whose replies can
 * no longer arrive, and leaving them queued desynchronises the ring. */
void share_stats_reset( void )
{
   if ( s_get_ptr != s_put_ptr ) s_get_ptr = s_put_ptr = 0;
}

void share_last_submit_time( struct timeval *tv )
{
   memcpy( tv, &last_submit_time, sizeof *tv );
}

void report_summary_log( bool force )
{
   struct timeval now, et, uptime, start_time;

  if ( rejected_share_count > 10 )
  {
     if ( rejected_share_count > ( submitted_share_count / 2 ) )
     {
        applog(LOG_ERR,"Excessive rejected share rate, exiting...");
        exit(1);
     }
     else if ( rejected_share_count > ( submitted_share_count / 10 ) )
       applog(LOG_WARNING,"High rejected share rate, check settings.");
   }

   gettimeofday( &now, NULL );
   timeval_subtract( &et, &now, &five_min_start );

   /* cpuminer-opt reports CPU temperature and clock here. The equivalent for
    * this miner is per-device telemetry, which is a backend question and does
    * not exist yet. */

   if ( !( force && ( submit_sum || ( et.tv_sec > 5 ) ) ) )
   {
      if ( et.tv_sec < 300 )
         return;
      if ( ( s_get_ptr != s_put_ptr ) && ( et.tv_sec < 360 ) )
         return;
   }

   // collect and reset periodic counters
   pthread_mutex_lock( &stats_lock );

   uint64_t submits = submit_sum;  submit_sum = 0;
   uint64_t accepts = accept_sum;  accept_sum = 0;
   uint64_t rejects = reject_sum;  reject_sum = 0;
   uint64_t stales  = stale_sum;   stale_sum  = 0;
   uint64_t solved  = solved_sum;  solved_sum = 0;
   memcpy( &start_time, &five_min_start, sizeof start_time );
   memcpy( &five_min_start, &now, sizeof now );

   pthread_mutex_unlock( &stats_lock );

   timeval_subtract( &et, &now, &start_time );
   timeval_subtract( &uptime, &total_hashes_time, &session_start );

   double share_time = (double)et.tv_sec + (double)et.tv_usec * 1e-6;
   double ghrate = safe_div( total_hashes, (double)uptime.tv_sec, 0. );
   double target_diff = exp32 * last_targetdiff;
   double shrate = safe_div( target_diff * (double)(accepts),
                             share_time, 0. );
   double sess_hrate = safe_div( exp32 * norm_diff_sum,
                                 (double)uptime.tv_sec, 0. );
   double submit_rate = safe_div( (double)submits * 60., share_time, 0. );
   char shr_units[4] = {0};
   char ghr_units[4] = {0};
   char sess_hr_units[4] = {0};
   char et_str[24];
   char upt_str[24];

   scale_hash_for_display( &shrate, shr_units );
   scale_hash_for_display( &ghrate, ghr_units );
   scale_hash_for_display( &sess_hrate, sess_hr_units );

   sprintf_et( et_str, et.tv_sec );
   sprintf_et( upt_str, uptime.tv_sec );

   applog( LOG_BLUE, "%s: %s", opt_algo, rpc_url );
   applog2( LOG_NOTICE, "Periodic Report     %s        %s", et_str, upt_str );
   applog2( LOG_INFO, "Share rate        %.2f/min     %.2f/min",
            submit_rate, safe_div( (double)submitted_share_count*60.,
              ( (double)uptime.tv_sec + (double)uptime.tv_usec * 1e-6 ), 0. ) );
   applog2( LOG_INFO, "Hash rate       %7.2f%sh/s   %7.2f%sh/s   (%.2f%sh/s)",
            shrate, shr_units, sess_hrate, sess_hr_units, ghrate, ghr_units );

   if ( report_devices_hook ) report_devices_hook();

   if ( accepted_share_count < submitted_share_count )
   {
      double lost_ghrate = safe_div( target_diff
                    * (double)(submitted_share_count - accepted_share_count ),
                    (double)uptime.tv_sec, 0. );
      double lost_shrate = safe_div( target_diff * (double)(submits - accepts ),                                     share_time, 0. );
      char lshr_units[4] = {0};
      char lghr_units[4] = {0};
      scale_hash_for_display( &lost_shrate, lshr_units );
      scale_hash_for_display( &lost_ghrate, lghr_units );
      applog2( LOG_INFO, "Lost hash rate  %7.2f%sh/s    %7.2f%sh/s",
               lost_shrate, lshr_units, lost_ghrate, lghr_units );
   }

   /* The counters are 64- and 32-bit; cpuminer-opt prints them all with %d,
    * which is a varargs type mismatch rather than a formatting preference. */
   applog2( LOG_INFO,"Submitted       %7d      %7d",
               (int)submits, (int)submitted_share_count );
   applog2( LOG_INFO, "Accepted        %7d      %7d      %5.1f%%",
                      (int)accepts, (int)accepted_share_count,
                      100. * safe_div( (double)accepted_share_count,
                                       (double)submitted_share_count, 0. ) );
   if ( stale_share_count )
   {
      int prio = stales ? LOG_MINR : LOG_INFO;
      applog2( prio, "Stale           %7d      %7d      %5.1f%%",
                      (int)stales, (int)stale_share_count,
                      100. * safe_div( (double)stale_share_count,
                                       (double)submitted_share_count, 0. ) );
   }
   if ( rejected_share_count )
   {
      int prio = rejects ? LOG_ERR : LOG_INFO;
      applog2( prio, "Rejected        %7d      %7d      %5.1f%%",
                      (int)rejects, (int)rejected_share_count,
                      100. * safe_div( (double)rejected_share_count,
                                       (double)submitted_share_count, 0. ) );
   }
   if ( solved_block_count )
   {
      int prio = solved ? LOG_PINK : LOG_INFO;
      applog2( prio, "Blocks Solved   %7d      %7d",
               (int)solved, (int)solved_block_count );
   }
   if ( stratum_errors )
      applog2( LOG_INFO, "Stratum resets               %7d",
               (int)stratum_errors );

   applog2( LOG_INFO, "Hi/Lo Share Diff  %.5g /  %.5g",
            highest_share, lowest_share );

   int mismatch = submitted_share_count
         - ( accepted_share_count + stale_share_count + rejected_share_count );

   if ( mismatch )
   {
      if ( stratum_errors )
         applog2( LOG_MINR, "Count mismatch: %d, stats may be inaccurate",
                            mismatch );
      else if ( !opt_quiet )
         applog2( LOG_INFO, CL_LBL
                  "Count mismatch, submitted share may still be pending" CL_N );
   }
}

int share_result( int result, struct work *work, const char *reason )
{
   double share_time = 0.;
   double hashrate = 0.;
   int latency = 0;
   struct share_stats_t my_stats = {0};
   struct timeval ack_time, latency_tv, et;
   char ares[48];
   char sres[48];
   char rres[48];
   char bres[48];
   bool solved = false;
   bool stale = false;
   char *acol, *bcol, *scol, *rcol;
   acol = bcol = scol = rcol = "\0";

   pthread_mutex_lock( &stats_lock );

   if ( likely( share_stats[ s_get_ptr ].submit_time.tv_sec ) )
   {
      memcpy( &my_stats, &share_stats[ s_get_ptr], sizeof my_stats );
      memset( &share_stats[ s_get_ptr ], 0, sizeof my_stats );
      s_get_ptr = stats_ptr_incr( s_get_ptr );
      pthread_mutex_unlock( &stats_lock );
   }
   else
   {
      // empty queue, it must have overflowed and stats were lost for a share.
      pthread_mutex_unlock( &stats_lock );
      applog(LOG_WARNING,"Share stats not available.");
   }

   // calculate latency and share time.
   if likely( my_stats.submit_time.tv_sec )
   {
      gettimeofday( &ack_time, NULL );
      timeval_subtract( &latency_tv, &ack_time, &my_stats.submit_time );
      latency = ( latency_tv.tv_sec * 1e3  + latency_tv.tv_usec / 1e3 );
      timeval_subtract( &et, &my_stats.submit_time, &last_submit_time );
      share_time = (double)et.tv_sec + ( (double)et.tv_usec / 1e6 );
      memcpy( &last_submit_time, &my_stats.submit_time,
              sizeof last_submit_time );
   }

   // check result
   if ( likely( result ) )
   {
      accepted_share_count++;
      if ( ( my_stats.share_diff > 0. )
        && ( my_stats.share_diff < lowest_share ) )
         lowest_share = my_stats.share_diff;
      if ( my_stats.share_diff > highest_share )
         highest_share = my_stats.share_diff;
      sprintf( sres, "S%d", stale_share_count );
      sprintf( rres, "R%d", rejected_share_count );
      if unlikely( ( my_stats.net_diff > 0. )
                && ( my_stats.share_diff >= my_stats.net_diff ) )
      {
         solved = true;
         solved_block_count++;
         sprintf( bres, "BLOCK SOLVED %d", solved_block_count );
         sprintf( ares, "A%d", accepted_share_count );
      }
      else
      {
         sprintf( bres, "B%d", solved_block_count );
         sprintf( ares, "Accepted %d", accepted_share_count );
      }
   }
   else
   {
     sprintf( ares, "A%d", accepted_share_count );
     sprintf( bres, "B%d", solved_block_count );
     if ( reason )
        stale = strstr( reason, "job" ) || strstr( reason, "Job" );
     else if ( work )
        stale =  work->data[ STD_NTIME_INDEX ]
             != g_work.data[ STD_NTIME_INDEX ];
     if ( stale )
     {
        stale_share_count++;
        sprintf( sres, "Stale %d", stale_share_count );
        sprintf( rres, "R%d", rejected_share_count );
     }
     else
     {
        rejected_share_count++;
        sprintf( sres, "S%d", stale_share_count );
        sprintf( rres, "Rejected %d" , rejected_share_count );
     }
   }

   // update global counters for summary report
   pthread_mutex_lock( &stats_lock );

   for ( int i = 0; i < opt_n_threads; i++ )
       hashrate += thr_hashrates[i];
   global_hashrate = hashrate;

   if ( likely( result ) )
   {
      accept_sum++;
      norm_diff_sum += my_stats.target_diff;
      if ( solved ) solved_sum++;
   }
   else
   {
      if ( stale )  stale_sum++;
      else          reject_sum++;
   }
   submit_sum++;

   pthread_mutex_unlock( &stats_lock );

   if ( use_colors )
   {
     bcol = acol = scol = rcol = CL_N;
     if ( likely( result ) )
     {
       acol = CL_LGR;
       if ( unlikely( solved ) ) bcol = CL_LMA;
     }
     else if ( stale ) scol = CL_YL2;
     else              rcol = CL_LRD;
   }

   const char *bell = !result && opt_bell ? &ASCII_BELL : "";
   // One-liner: fold the former separate "Submitted Diff/Block/Job" line into
   // the result line so each share is a single compact entry.
   char sdiff[32];
   format_diff( sdiff, sizeof sdiff, my_stats.share_diff );
   applog( LOG_INFO,
           "%s%d %s%s %s%s %s%s %s%s%s, Diff %s, Block %u, Job %s, %.3f sec (%dms)",
           bell, my_stats.share_count, acol, ares, scol, sres, rcol, rres,
           bcol, bres, use_colors ? CL_N : "", sdiff, my_stats.height,
           my_stats.job_id, share_time, latency );
   if ( unlikely( !( opt_quiet || result || stale ) ) )
   {
      applog2( LOG_INFO, "%sReject reason: %s", bell, reason ? reason : "" );
      applog2( LOG_INFO, "Share diff: %.5g, Target: %.5g",
                        my_stats.share_diff, my_stats.target_diff );
   }
   return 1;
}

/* ---------------------------------------------------------- submission */

static const char *json_submit_req =
   "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}";

void std_le_build_stratum_request( char *req, struct work *work )
{
   unsigned char *xnonce2str;
   uint32_t ntime,       nonce;
   char     ntimestr[9], noncestr[9];
   le32enc( &ntime, work->data[ STD_NTIME_INDEX ] );
   le32enc( &nonce, work->data[ STD_NONCE_INDEX ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex( work->xnonce2, work->xnonce2_len );
   snprintf( req, JSON_BUF_LEN, json_submit_req, rpc_user, work->job_id,
             xnonce2str, ntimestr, noncestr );
   free( xnonce2str );
}

/* cpuminer-opt also handles the solo paths here -- a getblocktemplate submit
 * with the full transaction set, and a bare getwork submit. Neither exists
 * yet; only Stratum does. */
static bool submit_upstream_work( CURL *curl, struct work *work )
{
   char req[JSON_BUF_LEN];

   (void)curl;

   if ( !have_stratum )
   {
      applog( LOG_ERR, "Solo mining is not implemented" );
      return false;
   }

   stratum.sharediff = work->sharediff;
   std_le_build_stratum_request( req, work );
   if ( unlikely( !stratum_send_line( &stratum, req ) ) )
   {
      applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
      return false;
   }
   return true;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		work_free(wc->u.work);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc)); /* poison */
	free(wc);
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
   int failures = 0;

   /* submit solution to bitcoin via JSON-RPC */
   while (!submit_upstream_work(curl, wc->u.work))
   {
	if (unlikely((opt_retries >= 0) && (++failures > opt_retries)))
        {
	   applog(LOG_ERR, "...terminating workio thread");
	   return false;
	}
        /* pause, then restart work-request loop */
        if (!opt_benchmark)
	    applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
   }
   return true;
}

void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely( !curl ) )
   {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

   while ( likely(ok) )
   {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
		if (!wc)
      {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd)
      {
		   case WC_GET_WORK:
            /* Solo mining. Nothing pushes this yet. */
            applog(LOG_ERR, "getwork is not implemented");
            ok = false;
			   break;
		   case WC_SUBMIT_WORK:
			   ok = workio_submit_work(wc, curl);
			   break;

		   default:		/* should never happen */
			   ok = false;
			   break;
		}
		workio_cmd_free(wc);
	}

   tq_freeze(mythr->q);
	curl_easy_cleanup(curl);
	return NULL;
}

static bool submit_work( struct thr_info *thr, const struct work *work_in )
{
	struct workio_cmd *wc;

   /* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;
	wc->u.work = (struct work*) malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;
	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	work_copy(wc->u.work, work_in);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;
	return true;
err_out:
	workio_cmd_free(wc);
	return false;
}

static void update_submit_stats( struct work *work, const void *hash )
{
   (void)hash;

   pthread_mutex_lock( &stats_lock );

   submitted_share_count++;
   share_stats[ s_put_ptr ].share_count = submitted_share_count;
   gettimeofday( &share_stats[ s_put_ptr ].submit_time, NULL );
   share_stats[ s_put_ptr ].share_diff = work->sharediff;
   share_stats[ s_put_ptr ].net_diff = net_diff;
   share_stats[ s_put_ptr ].stratum_diff = stratum_diff;
   share_stats[ s_put_ptr ].target_diff = work->targetdiff * opt_target_factor;
   share_stats[ s_put_ptr ].height = work->height;
   if ( have_stratum )
      strncpy( share_stats[ s_put_ptr ].job_id, work->job_id, 30 );
   s_put_ptr = stats_ptr_incr( s_put_ptr );

   pthread_mutex_unlock( &stats_lock );
}

bool submit_solution( struct work *work, const void *hash,
                      struct thr_info *thr )
{
   work->sharediff = hash_to_diff( hash ) * opt_target_factor;
   if ( likely( submit_work( thr, work ) ) )
   {
     update_submit_stats( work, hash );

     if ( !opt_quiet )
     {
        // Submit details are folded into the single result line in
        // share_result(); keep the standalone line for debug only.
        if ( opt_debug )
           applog( LOG_INFO, "%d Submitted Diff %.5g, Block %d, Job %s",
                   submitted_share_count, work->sharediff, work->height,
                   work->job_id );
        if ( opt_debug && opt_extranonce )
        {
           unsigned char *xnonce2str = abin2hex( work->xnonce2,
                                                 work->xnonce2_len );
           applog( LOG_INFO, "Xnonce2 %s", xnonce2str );
           free( xnonce2str );
        }

        if ( opt_debug )
        {
           uint32_t* h = (uint32_t*)hash;
           uint32_t* t = (uint32_t*)work->target;
           uint32_t* d = (uint32_t*)work->data;

           applog( LOG_INFO, "Data[ 0: 9]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                                                 d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9] );
           applog( LOG_INFO, "Data[10:19]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                                        d[10],d[11],d[12],d[13],d[14],d[15],d[16],d[17],d[18],d[19] );
           applog( LOG_INFO, "Hash[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                                            h[7],h[6],h[5],h[4],h[3],h[2],h[1],h[0] );
           applog( LOG_INFO, "Targ[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                                            t[7],t[6],t[5],t[4],t[3],t[2],t[1],t[0] );
        }
     }
     return true;
   }
   else
     applog( LOG_WARNING, "%d failed to submit share", submitted_share_count );
   return false;
}
