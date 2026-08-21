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
 * Derived from cpuminer-opt's cpu-miner.c: the Stratum thread's connect and
 * reconnect loop, and the assembly of a block header from a mining.notify.
 *
 * The algo_gate indirection around header layout and merkle root is gone --
 * it mixed protocol concerns with execution concerns, which this project
 * keeps apart -- so the calls it dispatched are made directly. That is a
 * placeholder: what a header means will belong to an Algorithm, and the
 * sha256d merkle root below is one algorithm's answer.
 */


#include "core/miner.h"
#include "core/sha256.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

struct stratum_ctx stratum;
bool     stratum_down       = true;
bool     stratum_need_reset = false;
uint32_t stratum_errors     = 0;

static struct timeval stratum_reset_time = {0};
static struct timeval stratum_keepalive_timer = {0};

/* -------------------------------------------------------- header build */

void sha256d_gen_merkle_root( char *merkle_root, struct stratum_ctx *sctx )
{
  sha256d( merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size );
  for ( int i = 0; i < sctx->job.merkle_count; i++ )
  {
     memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
     sha256d( merkle_root, merkle_root, 64 );
  }
}

void std_build_block_header( struct work* g_work, uint32_t version,
       uint32_t *prevhash, uint32_t *merkle_tree, uint32_t ntime,
       uint32_t nbits )
{
   int i;

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = version;

   if ( have_stratum ) for ( i = 0; i < 8; i++ )
         g_work->data[ 1+i ] = le32dec( prevhash + i );
   else for (i = 0; i < 8; i++)
         g_work->data[ 8-i ] = le32dec( prevhash + i );
   for ( i = 0; i < 8; i++ )
      g_work->data[ 9+i ] = be32dec( merkle_tree + i );
   g_work->data[ STD_NTIME_INDEX ] = ntime;
   g_work->data[ STD_NBITS_INDEX ] = nbits;

   g_work->data[20] = 0x80000000;
   g_work->data[31] = 0x00000280;
}

void std_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_tree[64] = { 0 };

   sha256d_gen_merkle_root( (char*)merkle_tree, sctx );
   std_build_block_header( g_work, le32dec( sctx->job.version ),
          (uint32_t*) sctx->job.prevhash, (uint32_t*) merkle_tree,
          le32dec( sctx->job.ntime ), le32dec(sctx->job.nbits) );
}

/* Rebuild `work` on the job it already holds, with `counter` as its
   extranonce2. Returns false if that job is no longer the current one, which
   means the caller should take the new one instead.

   Extranonce2 is the miner's half of the coinbase, so a different value there
   is a different merkle root and an entirely fresh 32-bit nonce range on the
   same job. Upstream only moved it when a new job arrived, because a CPU takes
   hours to exhaust one range; a device takes seconds.

   The counter is written little-endian -- the order the field is counted and
   submitted in -- truncated to the width the pool asked for. Callers must not
   hand two workers the same value: stride the sequence by the worker count and
   no two of them ever build the same coinbase.  */

bool stratum_set_extranonce2( struct work *work, struct stratum_ctx *sctx,
                              uint64_t counter )
{
   bool ok = false;

   pthread_mutex_lock( &sctx->work_lock );

   /* Same job, or nothing to rebuild against. Comparing the id rather than
      trusting the caller, because the job can change between the copy the
      worker holds and this call.  */
   if ( sctx->xnonce2_size && sctx->job.job_id && work->job_id
        && !strcmp( sctx->job.job_id, work->job_id ) )
   {
      /* Written into the shared coinbase because that is what the merkle root
         is computed over; the lock makes that safe, and every other reader of
         this field takes it too. Trampling the sequence stratum_gen_work would
         have used costs nothing: any value is valid, and a new job resets the
         field anyway.  */
      for ( size_t i = 0; i < sctx->xnonce2_size; i++ )
         sctx->job.xnonce2[i] = i < sizeof counter
                              ? (uchar)( counter >> ( i * 8 ) ) : 0;

      work->xnonce2_len = sctx->xnonce2_size;
      work->xnonce2 = (uchar*) realloc( work->xnonce2, sctx->xnonce2_size );
      memcpy( work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size );

      /* Rebuilds data[] from the new coinbase. The target and the difficulty
         belong to the job, not to the coinbase, so they stay as they are.  */
      std_build_extraheader( work, sctx );
      ok = true;
   }

   pthread_mutex_unlock( &sctx->work_lock );
   return ok;
}

/* A ProgPoW job, which is a header the pool already hashed. Nothing is built:
 * the 32 bytes are the header, the height is glued on after them because it is
 * the only place the epoch and the period can come from, and the target arrives
 * whole rather than as a difficulty to reconstruct one from.
 *
 * The words are the wire's bytes big-endian-decoded, which is how struct
 * work carries every other algorithm's header too. The algorithm swaps them
 * back before absorbing them; what is checkable against a pool or an explorer
 * is the byte string in the middle, and that is the point of the round trip.  */
void progpow_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   memset( g_work->data, 0, sizeof g_work->data );
   for ( int i = 0; i < 8; i++ )
      g_work->data[i] = be32dec( sctx->job.header_hash + i * 4 );
   g_work->data[8] = (uint32_t) sctx->block_height;

   /* Copied, not derived. See struct stratum_job: a target that came back from
      a difficulty is a target with its low 128 bits invented.  */
   memcpy( g_work->target, sctx->job.target, sizeof g_work->target );
   g_work->targetdiff = hash_to_diff( g_work->target );

   /* The pool's prefix, sitting where it belongs: at the top of the 64-bit
      nonce, with the rest of it for the workers to divide.  */
   g_work->nonce_base = 0;
   for ( size_t i = 0; i < sctx->xnonce1_size && i < 8; i++ )
      g_work->nonce_base |= (uint64_t)sctx->xnonce1[i] << ( 56 - i * 8 );

   /* There is no coinbase, so there is nothing to roll and nothing to send
      back up. Every reader of this pair treats zero as "the pool gave the
      miner none", which here is a fact about the dialect.  */
   g_work->xnonce2_len = 0;

   net_diff = nbits_to_diff( le32dec( sctx->job.nbits ) ) * opt_target_factor;
}

/* ------------------------------------------------------------ new work */

static void stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   bool new_job;

   pthread_mutex_lock( &sctx->work_lock );

   new_job =  sctx->new_job;  // otherwise just increment extranonce2
   sctx->new_job = false;

   pthread_rwlock_wrlock( &g_work_lock );

   free( g_work->job_id );
   g_work->job_id = strdup( sctx->job.job_id );
   g_work->height = sctx->block_height;

   if ( opt_stratum_dialect == STRATUM_PROGPOW )
      progpow_gen_work( sctx, g_work );
   else
   {
      g_work->targetdiff = sctx->job.diff
                              / ( opt_target_factor * opt_diff_factor );

      g_work->xnonce2_len = sctx->xnonce2_size;
      g_work->xnonce2 = (uchar*) realloc( g_work->xnonce2, sctx->xnonce2_size );
      memcpy( g_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size );
      std_build_extraheader( g_work, sctx );
      /* nbits_to_diff uses the Bitcoin difficulty-1 base; opt_target_factor
       * then converts to the pool's scale. It wants the exponent in the compact
       * word's low byte, which is where the standard header carries it. */
      net_diff = nbits_to_diff( g_work->data[ STD_NBITS_INDEX ] )
               * opt_target_factor;

      diff_to_hash( g_work->target, g_work->targetdiff );
   }

   /* A dispatch already in flight cannot be recalled, so results are matched
    * against the epoch they were launched under rather than prevented. */
   g_work->job_epoch++;

   g_work_time = time(NULL);
   restart_threads();
   pthread_rwlock_unlock( &g_work_lock );

   // Pre increment extranonce2 in case of being called again before receiving
   // a new job.
   for ( size_t t = 0;
         t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] );
         t++ );

   pthread_mutex_unlock( &sctx->work_lock );

   pthread_mutex_lock( &stats_lock );

   double hr = 0.;
   for ( int i = 0; i < opt_n_threads; i++ )
      hr += thr_hashrates[i];
   global_hashrate = hr;

   pthread_mutex_unlock( &stats_lock );

   char db[24];
   if ( stratum_diff != sctx->job.diff )
      applog( LOG_BLUE, "New Stratum Diff %s, Block %d, Tx %d, Job %s",
                        format_diff( db, sizeof db, sctx->job.diff ),
                        sctx->block_height,
                        sctx->job.merkle_count, g_work->job_id );
   else if ( last_block_height != (uint32_t)sctx->block_height )
      applog( LOG_BLUE, "New Block %d, Tx %d, Netdiff %s, Job %s",
                        sctx->block_height, sctx->job.merkle_count,
                        format_diff( db, sizeof db, net_diff ), g_work->job_id );
   else if ( g_work->job_id && new_job )
      applog( LOG_BLUE, "New Work: Block %d, Tx %d, Netdiff %s, Job %s",
                         sctx->block_height, sctx->job.merkle_count,
                         format_diff( db, sizeof db, net_diff ), g_work->job_id );
   else if ( opt_debug )
   {
      unsigned char *xnonce2str = bebin2hex( g_work->xnonce2,
                                             g_work->xnonce2_len );
      applog( LOG_INFO, "Extranonce2 0x%s, Block %d, Job %s",
                        xnonce2str, sctx->block_height, g_work->job_id );
      free( xnonce2str );
   }

   // Update data and calculate new estimates.
   if ( ( stratum_diff != sctx->job.diff )
     || ( last_block_height != (uint32_t)sctx->block_height ) )
   {
      if ( unlikely( !session_first_block ) )
         session_first_block = stratum.block_height;
      last_block_height = stratum.block_height;
      stratum_diff      = sctx->job.diff;
      last_targetdiff   = g_work->targetdiff;
      if ( lowest_share < last_targetdiff )
         lowest_share = 9e99;
    }

    if ( new_job && !opt_quiet )
    {
       /* targetdiff is stored in internal scale (for diff_to_hash).
        * Multiply by opt_target_factor to display in pool scale.
        * net_diff is already scaled above. stratum_diff is pool scale. */
       char dn[24], ds[24], dt[24];
       applog2( LOG_INFO, "Diff: Net %s, Stratum %s, Target %s",
                          format_diff( dn, sizeof dn, net_diff ),
                          format_diff( ds, sizeof ds, stratum_diff ),
                          format_diff( dt, sizeof dt,
                                       g_work->targetdiff * opt_target_factor ) );

       if ( likely( hr > 0. ) )
       {
          double nd = net_diff * exp32;
          char hr_units[4] = {0};
          char block_ttf[32];
          char share_ttf[32];
          static bool multipool = false;

          if ( (uint32_t)stratum.block_height < last_block_height )
             multipool = true;

          sprintf_et( block_ttf, nd / hr );
          sprintf_et( share_ttf, ( g_work->targetdiff * exp32 ) / hr );
          scale_hash_for_display ( &hr, hr_units );
          applog2( LOG_INFO, "TTF @ %.2f %sh/s: Block %s, Share %s",
                             hr, hr_units, block_ttf, share_ttf );

          if ( !multipool && last_block_height > session_first_block )
          {
             struct timeval now, et;
             gettimeofday( &now, NULL );
             timeval_subtract( &et, &now, &session_start );
             uint64_t net_ttf = safe_div( et.tv_sec,
                                 last_block_height - session_first_block, 0 );
             if ( net_diff > 0. && net_ttf )
             {
                double net_hr = safe_div( nd, net_ttf, 0. );
                char net_hr_units[4] = {0};
                scale_hash_for_display ( &net_hr, net_hr_units );
                applog2( LOG_INFO, "Net hash rate (est) %.2f %sh/s",
                                   net_hr, net_hr_units );
             }
          }
       }  // hr > 0
    } // !quiet
}

/* ------------------------------------------------------------- the loop */

static bool stratum_handle_response( char *buf )
{
	json_t *val, *id_val, *res_val, *err_val;
	json_error_t err;
	bool ret = false;
   bool share_accepted = false;

	val = JSON_LOADS( buf, &err );
	if (!val)
   {
      applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
	   goto out;
	}
   res_val = json_object_get( val, "result" );
   if ( !res_val ) { /* now what? */ }

   id_val = json_object_get( val, "id" );
	if ( !id_val || json_is_null(id_val) )
		goto out;

   err_val = json_object_get( val, "error" );

   /* 1..3 are subscribe, authorize and extranonce.subscribe; every id from 4
    * up belongs to one share, and is what says *which* share this answers. */
   json_int_t id = json_integer_value( id_val );
   if ( !res_val || id < 4 )
      goto out;
   share_accepted = json_is_true( res_val );
   share_result( share_accepted, (uint32_t)id, NULL, err_val ?
                 json_string_value( json_array_get(err_val, 1) ) : NULL );

	ret = true;
out:
	if (val)
		json_decref(val);
	return ret;
}

// Loop is out of order:
//
//   connect/reconnect
//   handle message
//   get new message
//
// change to
//   connect/reconnect
//   get new message
//   handle message

void *stratum_thread(void *userdata )
{
   struct thr_info *mythr = (struct thr_info *) userdata;
   char *s = NULL;

   stratum.url = (char*) tq_pop(mythr->q, NULL);
   if (!stratum.url)
      goto out;
   applog( LOG_BLUE, "Stratum connect %s", stratum.url );

   /* main() seeded these in cpu-miner.c, where they were file scope beside it.
    * Nothing outside this thread reads them, so this thread can seed them. */
   gettimeofday( &stratum_keepalive_timer, NULL );
   stratum_reset_time = stratum_keepalive_timer;

   while (1)
   {
      int failures = 0;

      if ( unlikely( stratum_need_reset ) )
      {
          stratum_need_reset = false;
          gettimeofday( &stratum_reset_time, NULL );
          stratum_down = true;
          stratum_errors++;
          stratum_disconnect( &stratum );
          if ( strcmp( stratum.url, rpc_url ) )
          {
	          free( stratum.url );
	          stratum.url = strdup( rpc_url );
	          applog(LOG_BLUE, "Connection changed to %s", short_url);
          }
          else
	          applog(LOG_BLUE, "Stratum connection reset");
          // reset stats queue as well
          restart_threads();
          share_stats_reset();
      }

      while ( !stratum.curl )
      {
         stratum_down = true;
         restart_threads();
         pthread_rwlock_wrlock( &g_work_lock );
         g_work_time = 0;
         pthread_rwlock_unlock( &g_work_lock );
         if ( !stratum_connect( &stratum, stratum.url )
              || !stratum_subscribe( &stratum )
              || !stratum_authorize( &stratum, rpc_user, rpc_pass ) )
         {
            stratum_disconnect( &stratum );
            if (opt_retries >= 0 && ++failures > opt_retries)
            {
               applog(LOG_ERR, "...terminating workio thread");
               tq_push(thr_info[work_thr_id].q, NULL);
               goto out;
            }
            if (!opt_benchmark)
                applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
            sleep(opt_fail_pause);
         }
         else
         {
// sometimes stratum connects but doesn't immediately send a job, wait for one.
            applog(LOG_BLUE,"Stratum connection established" );
            if ( stratum.new_job )   // prime first job
            {
               stratum_down = false;
               stratum_gen_work( &stratum, &g_work );
            }
         }
      }

      // Wait for new message from server
      if ( likely( stratum_socket_full( &stratum, opt_timeout ) ) )
      {
         if ( likely( s = stratum_recv_line( &stratum ) ) )
         {
            stratum_down = false;
            if ( likely( !stratum_handle_method( &stratum, s ) ) )
               stratum_handle_response( s );
            free( s );
         }
         else
            stratum_need_reset = true;
      }
      else
      {
         applog(LOG_ERR, "Stratum connection timeout");
         stratum_need_reset = true;
      }

      report_summary_log( ( stratum_diff != stratum.job.diff )
                       && ( stratum_diff != 0. ) );

      if ( !stratum_need_reset )
      {
         // Is keepalive needed? Mutex would normally be required but that
         // would block any attempt to submit a share. A share is more
         // important even if it messes up the keepalive.

         if ( opt_stratum_keepalive )
         {
            struct timeval now, et, last_submit;
            gettimeofday( &now, NULL );
            share_last_submit_time( &last_submit );
            // any shares submitted since last keepalive?
            if ( last_submit.tv_sec > stratum_keepalive_timer.tv_sec )
               memcpy( &stratum_keepalive_timer, &last_submit,
                       sizeof (struct timeval) );

            timeval_subtract( &et, &now, &stratum_keepalive_timer );

            if ( et.tv_sec > stratum_keepalive_timeout )
            {
                double diff = stratum.job.diff * 0.5;
                stratum_keepalive_timer = now;
                if ( !opt_quiet )
                   applog( LOG_BLUE,
                           "Stratum keepalive requesting lower difficulty" );
                stratum_suggest_difficulty( &stratum, diff );
            }

            if ( last_submit.tv_sec > stratum_reset_time.tv_sec )
              timeval_subtract( &et, &now, &last_submit );
            else
              timeval_subtract( &et, &now, &stratum_reset_time );

            if ( et.tv_sec > stratum_keepalive_timeout + 90 )
            {
               applog( LOG_NOTICE, "No shares submitted, resetting stratum connection" );
               stratum_need_reset = true;
               stratum_keepalive_timer = now;
            }
         } // stratum_keepalive

         if ( stratum.new_job && !stratum_need_reset )
            stratum_gen_work( &stratum, &g_work );

      } // stratum_need_reset
   }  // loop
out:
  return NULL;
}
