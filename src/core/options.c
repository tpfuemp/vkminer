/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2016-2025 Jay D Dee
 * Copyright 2026 vkminer contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 *
 * Derived from cpuminer-opt's cpu-miner.c and miner.h: the option table, the
 * argument parser, and the JSON configuration file that shares it. The options
 * that described a CPU -- affinity, priority, the self-test -- are gone, and
 * the ones that describe a GPU are new. Everything in between is upstream's,
 * because pools and users already know it.
 */

#include "core/miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option
{
   const char *name;
   int has_arg;
   int *flag;
   int val;
};
#endif

/* ------------------------------------------------------- option settings */

/* The algorithm is a name here, not an index into a dispatch table. Nothing
 * in this file knows which names are valid; that is the algorithm registry's
 * question, and it is asked after the configuration is complete.  */
char *opt_algo = NULL;

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_benchmark = false;
bool opt_protocol = false;
bool opt_extranonce = true;
bool opt_quiet = false;
bool opt_redirect = true;
bool opt_background = false;
bool opt_bell = false;
bool opt_stratum_stats = false;
bool opt_stratum_keepalive = false;
bool opt_hash_meter = false;
bool use_syslog = false;
bool use_colors = true;

bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool allow_mininginfo = true;
bool want_stratum = true;
bool have_stratum = false;

int opt_timeout = 300;
int opt_retries = -1;
int opt_fail_pause = 10;
int opt_scantime = 5;
int opt_time_limit = 0;
int stratum_keepalive_timeout = 60;

/* The most significant word of --benchmark's synthetic target, or -1 for the
 * realistic one benchmark_work() picks by itself. Held wider than the 32 bits
 * it carries so that "not given" is a value the type can hold and not a
 * reserved target. */
int64_t opt_benchmark_target = -1;

double opt_diff_factor = 1.0;

/* Every difficulty this miner prints is in the scale the pool quotes; every
 * target it compares against is in the scale the algorithm defines. For the
 * Bitcoin-descended algorithms those are the same scale, so the factor is 1.
 * It exists for the algorithms where they are not, and belongs to whichever
 * Algorithm that is -- there is nowhere yet for it to be set from. */
double opt_target_factor = 1.0;

/* The two other things the protocol client has to know before it can read a
 * packet, and both are the algorithm's answers. main() sets them beside
 * opt_target_factor, from the same object, before any thread starts; the
 * defaults here are Bitcoin's, which is what every algorithm but one wants. */
int      opt_stratum_dialect = STRATUM_BITCOIN;
uint32_t opt_nonce_bits      = 32;

/* Installed beside those two when the algorithm has epoch arithmetic to check
 * a pool's seed hash against, and null otherwise. */
bool ( *progpow_seed_hash_agrees )( uint64_t height,
                                    const unsigned char seed[32] ) = NULL;

char *rpc_url = NULL;
char *rpc_userpass = NULL;
char *rpc_user = NULL;
char *rpc_pass = NULL;
char *short_url = NULL;
char *lp_id = NULL;
char *opt_cert = NULL;
char *opt_proxy = NULL;
long opt_proxy_type = 0;

/* The number of miner workers. Upstream this was a count of CPU threads and
 * defaulted to the core count; here it is a count of device workers, and the
 * device enumeration that would set it has not run yet when options are
 * parsed. Zero means "decide once the devices are known". */
int opt_n_threads = 0;
bool opt_n_threads_set = false;

/* Devices to mine on, as a comma separated list of indices into the order
 * --device-list prints. Empty means every device found. */
char *opt_devices = NULL;
bool opt_device_list = false;
bool opt_vk_validate = false;
bool opt_vk_pipeline_stats = false;

/* Whether the shader keeps a running minimum of the digests it computes. It
 * answers the one question a share count cannot -- whether the kernel is
 * missing valid nonces -- and it costs an atomic per invocation to ask, so it
 * is off, and a hash rate measured with it on is not a hash rate. */
bool opt_vk_probe_best = false;

/* Report every device as lacking shaderInt64. The feature is optional, so an
 * algorithm with a 64-bit state ships two kernels, and this is how the one
 * written for hardware without it gets run on hardware with it. The device is
 * created without the feature too, so a 64-bit module chosen by mistake is a
 * validation error here rather than a fault on someone else's phone. */
bool opt_no_int64 = false;

/* A capture file to re-run instead of mining. NULL is the ordinary case. */
char *opt_replay = NULL;

/* Dispatches a worker may leave outstanding on its device. Zero lets the
 * backend pick, which is the setting to mine with; an explicit value exists so
 * one binary can be run at two depths and the difference measured. */
int opt_queue_depth = 0;
int opt_progpow_max_epoch = 0;

/* Invocations per workgroup, for the same reason: the tuner's other axis, and
 * two runs at two widths are the only way to check that tuning it is worth
 * anything. Zero lets the backend pick. */
int opt_workgroup = 0;

/* Which of an algorithm's kernels to run, by the name kernels() gives it. NULL
 * lets the tuner choose, which is the setting to mine with.
 *
 * The third axis, and the one --no-tune leaves nowhere to go without this: with
 * the tuner off there is no measurement to read, so the algorithm's own opening
 * guess runs -- and for an algorithm offering several that guess is the control
 * rather than the fast one. Two runs a change is being measured across have to
 * be the same kernel as well as the same width and depth, and this is how they
 * are said to be. */
char *opt_kernel = NULL;

/* What to do about the tuning file. By default it is read and a sweep runs only
 * where this device, driver, algorithm and shader are not in it; --retune
 * sweeps regardless, for when a measurement is in doubt; --no-tune neither
 * reads nor writes it, which is what makes two runs comparable. */
bool opt_retune = false;
bool opt_no_tune = false;

/* Run the known-answer vectors and exit. The same check the miner makes at
 * startup regardless; the option exists so that a machine can be checked
 * without a pool, a wallet or a network. */
bool opt_self_test = false;

/* Which compute backend to use. NULL means the default, which is Vulkan; the
 * others exist so that everything around the device -- the pool, the
 * scheduler, the share path -- can be exercised on a machine with no GPU. */
char *opt_backend = NULL;
char *opt_algo_dir = NULL;

/* The API server binds loopback by default: it is a status feed, not an
 * authenticated control channel. */
static const char *default_api_allow = "127.0.0.1";
static const int   default_api_listen = 4048;

bool  opt_api_enabled = false;
char *opt_api_allow = NULL;
int   opt_api_listen = 0;
int   opt_api_remote = 0;

/* The token is checked before a request is routed, so an unauthenticated
 * client cannot learn which paths exist. NULL means no token, which is the
 * default because the default bind address is loopback. */
char *opt_api_token = NULL;

/* One origin, verbatim, or NULL. Setting it also enables the OPTIONS
 * preflight: a browser that is not told an origin cannot read a response it
 * fetched successfully, which reads as a broken server. */
char *opt_api_cors = NULL;

/* Whether the run state -- pause, resume, stop -- may be changed from outside
 * the process, and how long a change waits for the workers to stop dispatching
 * before it gives up and leaves the miner mining. A dispatch cannot be
 * cancelled, so the wait is never shorter than one of them plus a drain; the
 * default is long enough for a slow device under other load, because a timeout
 * that is too short refuses requests a device was going to answer. */
bool  opt_api_control = false;
int   opt_api_control_park_timeout = 30000;

/* The shortest gap between two accepted pool changes. Not a rate limit on the
 * API -- pause, resume and stop are never refused for being early -- but on
 * how often the miner may be moved: a session takes a subscribe, an authorize
 * and a first job to become worth anything, and a manager that can re-target
 * faster than that mines nowhere. 0 turns it off. */
int   opt_api_control_min_interval = 15;

/* P2PKH is 25 bytes, P2SH 23, P2WPKH 22; the buffer is sized for the largest
 * and address_to_script writes however many it needs. */
const int pk_buffer_size_max = 26;
int pk_buffer_size = 25;

void get_currentalgo( char *buf, int sz )
{
   snprintf( buf, sz, "%s", opt_algo ? opt_algo : "" );
}

/* ----------------------------------------------------------------- usage */

static const char *usage_text = "\
Usage: vkminer [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       hashing algorithm to mine\n\
  -o, --url=URL         URL of the mining server\n\
  -u, --user=USERNAME   username for the mining server\n\
  -p, --pass=PASSWORD   password for the mining server\n\
  -O, --userpass=U:P    username:password pair for the mining server\n\
  -c, --config=FILE     load a JSON configuration file (see\n\
                        config-template.json); options given on the command\n\
                        line override it, whatever their order\n\
\n\
      --devices=LIST    comma separated indices of the GPUs to mine on, as\n\
                        numbered by --device-list (default: all of them)\n\
      --device-list     list the Vulkan devices found and exit\n\
      --backend=NAME    compute backend: vulkan (default), cpu, which runs\n\
                        each algorithm's reference implementation and is the\n\
                        control the GPU is checked against, or null, which\n\
                        finds no solutions and is only for testing\n\
      --vk-validate     enable the Vulkan validation layers (slow; for\n\
                        debugging a backend, not for mining)\n\
      --vk-pipeline-stats\n\
                        report what the driver compiled each shader into --\n\
                        registers, spills, occupancy -- and exit. Needs a\n\
                        driver offering VK_KHR_pipeline_executable_properties,\n\
                        and asking for the numbers can itself change what is\n\
                        compiled, so it is not for mining either\n\
      --vk-probe-best   have the shader report the best digest it saw, which\n\
                        is the only way to see nonces it should have found and\n\
                        did not. Costs an atomic per hash, so a rate measured\n\
                        with this on is not a rate\n\
      --no-int64        report every device as having no shaderInt64, so an\n\
                        algorithm carrying both a 64-bit and a 32-bit kernel\n\
                        takes the 32-bit one. That feature is optional, and\n\
                        this runs the path written for devices without it\n\
      --replay=FILE     re-run the candidates a previous run failed to verify,\n\
                        from the file it wrote, and exit\n\
      --algo-dir=DIR    load algorithm shaders from DIR instead of the\n\
                        installed location\n\
      --queue-depth=N   dispatches to keep queued on each device at once\n\
                        (vulkan only; default: let the backend choose). 1 is\n\
                        submit-and-wait. Higher keeps the device fed but costs\n\
                        N dispatches of latency on every job change. For\n\
                        measuring the difference, not for mining\n\
      --progpow-max-epoch=N\n\
                        the largest epoch a ProgPoW coin is assumed ever to\n\
                        reach, overriding the figure built into this miner.\n\
                        Only the check that decides whether a device has the\n\
                        memory to be offered a coin reads it; it does not\n\
                        change what is mined, and a wrong one shows up as a\n\
                        coin refused or as a rebuild that runs out of memory\n\
      --workgroup=N     invocations per workgroup (vulkan only; default: let\n\
                        the backend choose). The tuner's other axis, named so\n\
                        that two runs can be compared at two widths\n\
      --kernel=NAME     which of the algorithm's kernels to run, where it\n\
                        offers more than one (default: let the tuner choose).\n\
                        --no-tune otherwise falls back to the algorithm's\n\
                        opening guess, which need not be the fast one\n\
      --retune          measure the workgroup size and queue depth this GPU\n\
                        runs fastest at, even though they are already known.\n\
                        The sweep takes a few seconds, runs against the\n\
                        algorithm's own test vector rather than pool work, and\n\
                        is repeated by itself after a driver update anyway\n\
      --no-tune         do not measure, and do not use a measurement: run at\n\
                        the built-in defaults. Two runs of one binary are then\n\
                        comparable, which a run that tuned itself is not\n\
      --self-test       check that this build reproduces published block\n\
                        hashes on every selected device, then exit. The same\n\
                        check runs before every mining session anyway; this\n\
                        runs it without needing a pool\n\
  -t, --threads=N       number of miner workers (default: one per device, or\n\
                        one per core on the cpu backend)\n\
\n\
      --time-limit=N    exit cleanly after N seconds of mining. Counted from\n\
                        the first job, so a slow pool does not eat into it;\n\
                        under --benchmark, from startup. Prints the benchmark\n\
                        rate for the whole run on the way out\n\
  -T, --timeout=N       network timeout in seconds (default: 300)\n\
  -r, --retries=N       number of times to retry a failed request\n\
                        (default: -1, retry indefinitely)\n\
      --retry-pause=N   seconds to wait between retries (default: 10)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                        long polling is unavailable, in seconds (default: 5)\n\
      --stratum-keepalive\n\
                        prevent a pool from disconnecting an idle connection\n\
      --no-extranonce   disable Stratum extranonce subscription\n\
      --no-longpoll     disable long polling support\n\
      --no-getwork      disable getwork support\n\
      --no-gbt          disable getblocktemplate support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]\n\
                        connect through a proxy\n\
      --cert=FILE       certificate for the mining server using SSL\n\
\n\
  -f, --diff-factor=N   divide the difficulty given by the pool by N\n\
  -m, --diff-multiplier=N\n\
                        multiply the difficulty given by the pool by N\n\
\n\
  -b, --api-bind=ADDR   IP:port to bind the monitoring API to\n\
                        (default: 127.0.0.1:4048, 0 disables it)\n\
      --api-remote      allow remote control through the API\n\
      --api-mode=MODE   API protocol on the port; only 'http' works here\n\
      --api-token=TOKEN require Authorization: Bearer TOKEN on every\n\
                        route\n\
      --api-cors=ORIGIN send Access-Control-Allow-Origin: ORIGIN, and\n\
                        answer the OPTIONS preflight\n\
      --api-control     allow the run state to be changed through the API\n\
      --api-control-min-interval=S\n\
                        shortest gap between two pool changes, in seconds\n\
                        (default: 15, 0 for none)\n\
      --api-control-park-timeout=MS\n\
                        how long a change waits for the workers to stop\n\
                        dispatching (default: 30000)\n\
\n\
  -B, --background      run in the background as a daemon\n\
  -q, --quiet           reduce the log to errors and accepted shares\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of the pool protocol\n\
      --hash-meter      log the hash rate of each worker, not just the total\n\
      --no-color        disable colored output\n\
      --bell            beep on an accepted share\n\
      --benchmark       run without connecting to a pool\n\
      --benchmark-target=HEX\n\
                        loosen --benchmark's synthetic target to HEX as its\n\
                        most significant word, the rest all ones, so that\n\
                        candidates are actually found: one nonce in\n\
                        2^32/(HEX+1) passes. Nothing is ever submitted. Use it\n\
                        to prove the emit and re-verification path runs at a\n\
                        rate arithmetic predicts -- a silent benchmark is no\n\
                        evidence that it works at all\n"
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n"
#endif
"\
  -V, --version         print the version and exit\n\
  -h, --help            print this message and exit\n\
";

/* Short options that would collide with something upstream already spent are
 * avoided even where upstream's use is gone, so that a command line written
 * for cpuminer-opt either works or fails loudly, never silently differs. */
static char const short_options[] =
#ifdef HAVE_SYSLOG_H
   "S"
#endif
   "a:b:Bc:Df:hm:p:Pqr:s:t:T:o:u:O:x:V";

static struct option const options[] = {
   { "algo",              1, NULL, 'a' },
   { "algo-dir",          1, NULL, 1043 },
   { "api-bind",          1, NULL, 'b' },
   { "api-control",       0, NULL, 1056 },
   { "api-control-min-interval", 1, NULL, 1058 },
   { "api-control-park-timeout", 1, NULL, 1057 },
   { "api-cors",          1, NULL, 1060 },
   { "api-mode",          1, NULL, 1061 },
   { "api-remote",        0, NULL, 1030 },
   { "api-token",         1, NULL, 1059 },
   { "backend",           1, NULL, 1044 },
   { "background",        0, NULL, 'B' },
   { "bell",              0, NULL, 1031 },
   { "benchmark",         0, NULL, 1005 },
   { "benchmark-target",  1, NULL, 1052 },
   { "cert",              1, NULL, 1001 },
   { "config",            1, NULL, 'c' },
   { "debug",             0, NULL, 'D' },
   { "device-list",       0, NULL, 1041 },
   { "devices",           1, NULL, 1040 },
   { "diff-factor",       1, NULL, 'f' },
   { "diff-multiplier",   1, NULL, 'm' },
   { "hash-meter",        0, NULL, 1014 },
   { "help",              0, NULL, 'h' },
   { "kernel",            1, NULL, 1055 },
   { "no-color",          0, NULL, 1002 },
   { "no-extranonce",     0, NULL, 1012 },
   { "no-gbt",            0, NULL, 1011 },
   { "no-getwork",        0, NULL, 1010 },
   { "no-int64",          0, NULL, 1053 },
   { "no-longpoll",       0, NULL, 1003 },
   { "no-redirect",       0, NULL, 1009 },
   { "no-stratum",        0, NULL, 1007 },
   { "no-tune",           0, NULL, 1048 },
   { "pass",              1, NULL, 'p' },
   { "progpow-max-epoch", 1, NULL, 1062 },
   { "protocol",          0, NULL, 'P' },
   { "protocol-dump",     0, NULL, 'P' },
   { "proxy",             1, NULL, 'x' },
   { "queue-depth",       1, NULL, 1046 },
   { "quiet",             0, NULL, 'q' },
   { "replay",            1, NULL, 1051 },
   { "retries",           1, NULL, 'r' },
   { "retry-pause",       1, NULL, 1025 },
   { "retune",            0, NULL, 1047 },
   { "scantime",          1, NULL, 's' },
   { "self-test",         0, NULL, 1045 },
   { "stratum-keepalive", 0, NULL, 1029 },
#ifdef HAVE_SYSLOG_H
   { "syslog",            0, NULL, 'S' },
#endif
   { "threads",           1, NULL, 't' },
   { "time-limit",        1, NULL, 1008 },
   { "timeout",           1, NULL, 'T' },
   { "url",               1, NULL, 'o' },
   { "user",              1, NULL, 'u' },
   { "userpass",          1, NULL, 'O' },
   { "version",           0, NULL, 'V' },
   { "vk-pipeline-stats", 0, NULL, 1049 },
   { "vk-probe-best",     0, NULL, 1050 },
   { "vk-validate",       0, NULL, 1042 },
   { "workgroup",         1, NULL, 1054 },
   { 0, 0, 0, 0 }
};

void show_usage_and_exit( int status )
{
   if ( status )
      fprintf( stderr, "Try `--help' for more information.\n" );
   else
      printf( "%s", usage_text );
   exit( status );
}

/* A password that reached us through argv is visible in ps output for as long
 * as the process lives, so it is overwritten in place the moment it is
 * copied. The first character becomes 'x' rather than NUL so the argument
 * still occupies a slot. */
static void strhide( char *s )
{
   if ( *s ) *s++ = 'x';
   while ( *s ) *s++ = '\0';
}

void parse_arg( int key, char *arg )
{
   char *p;
   int v;
   double d;

   switch( key )
   {
      case 'a':  // algo
         free( opt_algo );
         opt_algo = strdup( arg );
         for ( p = opt_algo; *p; p++ ) *p = tolower( (unsigned char)*p );
         break;

      case 1043: // algo-dir
         free( opt_algo_dir );
         opt_algo_dir = strdup( arg );
         break;

      case 'b':  // api-bind
         opt_api_enabled = true;
         p = strstr( arg, ":" );
         if ( p )
         {
            /* ip:port */
            if ( p - arg > 0 )
            {
               free( opt_api_allow );
               opt_api_allow = strdup( arg );
               opt_api_allow[ p - arg ] = '\0';
            }
            opt_api_listen = atoi( p + 1 );
         }
         else if ( strstr( arg, "." ) )
         {
            /* ip only */
            free( opt_api_allow );
            opt_api_allow = strdup( arg );
            opt_api_listen = default_api_listen;
         }
         else
         {
            /* port, or 0 to disable */
            free( opt_api_allow );
            opt_api_allow = strdup( default_api_allow );
            opt_api_listen = atoi( arg );
         }
         break;

      case 1030: // api-remote
         opt_api_remote = 1;
         break;

      case 1059: // api-token
         free( opt_api_token );
         opt_api_token = strdup( arg );
         /* Hidden for the same reason the pool password is: an argv string
          * shows in ps output for the life of the process, and this one is
          * the whole of the API's authentication. */
         strhide( arg );
         break;

      case 1060: // api-cors
         free( opt_api_cors );
         opt_api_cors = strdup( arg );
         break;

      case 1061: // api-mode
         /* Accepted so that a command line written for the sibling miners is
          * understood rather than rejected as an unknown option, and refused
          * loudly for the other two values rather than silently serving REST
          * to something expecting a line protocol. Nothing is stored: one
          * mode is legal and it is already the default. */
         if ( strcmp( arg, "http" ) )
         {
            fprintf( stderr, "--api-mode=%s: this miner serves REST only; "
                             "the line protocol is not implemented here\n", arg );
            show_usage_and_exit( 1 );
         }
         break;

      case 1056: // api-control
         opt_api_control = true;
         break;

      case 1057: // api-control-park-timeout
         v = atoi( arg );
         /* The floor is a dispatch and a drain: under it every change would be
          * rolled back before a worker could reach the top of its loop, which
          * is a control API that never works rather than one that works
          * slowly. The ceiling stops a typo hanging a request handler for an
          * hour. */
         if ( v < 250 || v > 600000 )
            show_usage_and_exit( 1 );
         opt_api_control_park_timeout = v;
         break;

      case 1058: // api-control-min-interval
         v = atoi( arg );
         /* Zero is a choice and not a mistake -- a test harness re-targets as
          * fast as it can on purpose. The ceiling is an hour, past which the
          * number is likelier to be milliseconds typed into a seconds option
          * than an interval anyone wants. */
         if ( v < 0 || v > 3600 )
            show_usage_and_exit( 1 );
         opt_api_control_min_interval = v;
         break;

      case 'B':  // background
         opt_background = true;
         use_colors = false;
         break;

      case 1031: // bell
         opt_bell = true;
         break;

      case 1005: // benchmark
         opt_benchmark = true;
         want_longpoll = false;
         want_stratum = false;
         have_stratum = false;
         break;

      case 1001: // cert
         free( opt_cert );
         opt_cert = strdup( arg );
         break;

      case 'c':  // config
      {
         json_error_t err;
         json_t *config;

         if ( strstr( arg, "://" ) )
            config = json_load_url( arg, &err );
         else
            config = JSON_LOADF( arg, &err );
         if ( !json_is_object( config ) )
         {
            if ( err.line < 0 )
               fprintf( stderr, "%s\n", err.text );
            else
               fprintf( stderr, "%s:%d: %s\n", arg, err.line, err.text );
            show_usage_and_exit( 1 );
         }
         parse_config( config, arg );
         json_decref( config );
         break;
      }

      case 'D':  // debug
         opt_debug = true;
         opt_quiet = false;
         break;

      case 1041: // device-list
         opt_device_list = true;
         break;

      case 1040: // devices
         free( opt_devices );
         opt_devices = strdup( arg );
         break;

      case 'f':  // diff-factor
         d = atof( arg );
         if ( d == 0. )
            show_usage_and_exit( 1 );
         opt_diff_factor = d;
         break;

      case 'm':  // diff-multiplier
         d = atof( arg );
         if ( d == 0. )
            show_usage_and_exit( 1 );
         opt_diff_factor = 1.0 / d;
         break;

      case 1014: // hash-meter
         opt_hash_meter = true;
         break;

      case 1002: // no-color
         use_colors = false;
         break;

      case 1012: // no-extranonce
         opt_extranonce = false;
         break;

      case 1011: // no-gbt
         have_gbt = false;
         break;

      case 1010: // no-getwork
         allow_getwork = false;
         break;

      case 1003: // no-longpoll
         want_longpoll = false;
         break;

      case 1009: // no-redirect
         opt_redirect = false;
         break;

      case 1007: // no-stratum
         want_stratum = false;
         opt_extranonce = false;
         break;

      case 'p':  // pass
         free( rpc_pass );
         rpc_pass = strdup( arg );
         strhide( arg );
         break;

      case 'P':  // protocol-dump
         opt_protocol = true;
         opt_quiet = false;
         break;

      case 'x':  // proxy
         if ( !strncasecmp( arg, "socks4://", 9 ) )
            opt_proxy_type = CURLPROXY_SOCKS4;
         else if ( !strncasecmp( arg, "socks5://", 9 ) )
            opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
         else if ( !strncasecmp( arg, "socks4a://", 10 ) )
            opt_proxy_type = CURLPROXY_SOCKS4A;
         else if ( !strncasecmp( arg, "socks5h://", 10 ) )
            opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
         else
            opt_proxy_type = CURLPROXY_HTTP;
         free( opt_proxy );
         opt_proxy = strdup( arg );
         break;

      case 1046: // queue-depth
         v = atoi( arg );
         /* The ceiling is not a hardware limit -- a depth costs about a
          * kilobyte -- but a bound on how much finished work a job change
          * throws away, and a guard against a typo asking for a thousand. */
         if ( v < 1 || v > 16 )
            show_usage_and_exit( 1 );
         opt_queue_depth = v;
         break;

      case 1062: // progpow-max-epoch
         v = atoi( arg );
         /* An epoch is a few days of a chain, so the ceiling is centuries and
          * is there to catch a block height pasted in where an epoch belongs --
          * which would size every device against a dataset of petabytes and
          * refuse the coin on all of them. */
         if ( v < 1 || v > 100000 )
            show_usage_and_exit( 1 );
         opt_progpow_max_epoch = v;
         break;

      case 1054: // workgroup
         v = atoi( arg );
         /* The upper bound Vulkan guarantees; what this device actually allows
          * is checked where the pipeline is built, which is the only place that
          * knows it. */
         if ( v < 1 || v > 1024 )
            show_usage_and_exit( 1 );
         opt_workgroup = v;
         break;

      case 1055: // kernel
         free( opt_kernel );
         opt_kernel = strdup( arg );
         break;

      case 1047: // retune
         opt_retune = true;
         break;

      case 1048: // no-tune
         opt_no_tune = true;
         break;

      /* --debug and --protocol-dump outrank --quiet whichever order they
       * arrive in, so that asking for more output never asks for less. */
      case 'q':  // quiet
         opt_quiet = !( opt_debug || opt_protocol );
         break;

      case 'r':  // retries
         v = atoi( arg );
         if ( v < -1 || v > 9999 )   /* sanity check */
            show_usage_and_exit( 1 );
         opt_retries = v;
         break;

      case 1025: // retry-pause
         v = atoi( arg );
         if ( v < 1 || v > 9999 )    /* sanity check */
            show_usage_and_exit( 1 );
         opt_fail_pause = v;
         break;

      case 's':  // scantime
         v = atoi( arg );
         if ( v < 1 || v > 9999 )    /* sanity check */
            show_usage_and_exit( 1 );
         opt_scantime = v;
         break;

      case 1029: // stratum-keepalive
         opt_stratum_keepalive = true;
         break;

#ifdef HAVE_SYSLOG_H
      case 'S':  // syslog
         use_syslog = true;
         use_colors = false;
         break;
#endif

      case 't':  // threads
         v = atoi( arg );
         if ( v < 0 || v > 9999 )    /* sanity check */
            show_usage_and_exit( 1 );
         opt_n_threads = v;
         opt_n_threads_set = true;
         break;

      case 1052: // benchmark-target
      {
         /* Hex, because a target is read as hex everywhere else in mining and
          * because the useful values are powers of two minus one. strtoull
          * rather than atoi: this is unsigned and the top bit is legal. */
         char *end = NULL;
         unsigned long long t = strtoull( arg, &end, 16 );
         if ( !*arg || !end || *end || t > 0xffffffffULL )
            show_usage_and_exit( 1 );
         opt_benchmark_target = (int64_t) t;
         break;
      }

      case 1008: // time-limit
         v = atoi( arg );
         /* A negative limit would read as already expired and exit the miner
          * before it hashed anything, which is a confusing way to spell zero. */
         if ( v < 1 )
            show_usage_and_exit( 1 );
         opt_time_limit = v;
         break;

      case 'T':  // timeout
         v = atoi( arg );
         if ( v < 1 || v > 99999 )   /* sanity check */
            show_usage_and_exit( 1 );
         opt_timeout = v;
         break;

      case 'o':  // url
      {
         char *ap, *hp;
         ap = strstr( arg, "://" );
         ap = ap ? ap + 3 : arg;
         hp = strrchr( arg, '@' );
         if ( hp )
         {
            *hp = '\0';
            p = strchr( ap, ':' );
            if ( p )
            {
               free( rpc_userpass );
               rpc_userpass = strdup( ap );
               free( rpc_user );
               rpc_user = (char*)calloc( p - ap + 1, 1 );
               strncpy( rpc_user, ap, p - ap );
               free( rpc_pass );
               rpc_pass = strdup( ++p );
               if ( *p ) *p++ = 'x';
               v = (int)strlen( hp + 1 ) + 1;
               memmove( p + 1, hp + 1, v );
               memset( p + v, 0, hp - p );
               hp = p;
            }
            else
            {
               free( rpc_user );
               rpc_user = strdup( ap );
            }
            *hp++ = '@';
         }
         else
            hp = ap;
         if ( ap != arg )
         {
            if ( strncasecmp( arg, "http://", 7 )
              && strncasecmp( arg, "https://", 8 )
              && strncasecmp( arg, "stratum+tcp://", 14 )
              && strncasecmp( arg, "stratum+ssl://", 14 )
              && strncasecmp( arg, "stratum+tcps://", 15 ) )
            {
               fprintf( stderr, "unknown protocol -- '%s'\n", arg );
               show_usage_and_exit( 1 );
            }
            free( rpc_url );
            rpc_url = strdup( arg );
            strcpy( rpc_url + (ap - arg), hp );
            short_url = &rpc_url[ ap - arg ];
         }
         else
         {
            if ( *hp == '\0' || *hp == '/' )
            {
               fprintf( stderr, "invalid URL -- '%s'\n", arg );
               show_usage_and_exit( 1 );
            }
            free( rpc_url );
            rpc_url = (char*)malloc( strlen(hp) + 15 );
            sprintf( rpc_url, "stratum+tcp://%s", hp );
            short_url = &rpc_url[ sizeof("stratum+tcp://") - 1 ];
         }
         have_stratum = !opt_benchmark && !strncasecmp( rpc_url, "stratum", 7 );
         break;
      }

      case 'u':  // user
         free( rpc_user );
         rpc_user = strdup( arg );
         break;

      case 'O':  // userpass
         p = strchr( arg, ':' );
         if ( !p )
         {
            fprintf( stderr, "invalid username:password pair -- '%s'\n", arg );
            show_usage_and_exit( 1 );
         }
         free( rpc_userpass );
         rpc_userpass = strdup( arg );
         free( rpc_user );
         rpc_user = (char*)calloc( p - arg + 1, 1 );
         strncpy( rpc_user, arg, p - arg );
         free( rpc_pass );
         rpc_pass = strdup( ++p );
         strhide( p );
         break;

      case 1042: // vk-validate
         opt_vk_validate = true;
         break;

      case 1049: // vk-pipeline-stats
         opt_vk_pipeline_stats = true;
         break;

      case 1050: // vk-probe-best
         opt_vk_probe_best = true;
         break;

      case 1053: // no-int64
         opt_no_int64 = true;
         break;

      case 1051: // replay
         free( opt_replay );
         opt_replay = strdup( arg );
         break;

      case 1045: // self-test
         opt_self_test = true;
         break;

      case 1044: // backend
         free( opt_backend );
         opt_backend = strdup( arg );
         break;

      case 'V':  // version
         printf( "%s\n", USER_AGENT );
         exit( 0 );

      case 'h':  // help
         show_usage_and_exit( 0 );

      default:
         show_usage_and_exit( 1 );
   }
}

/* --------------------------------------------------- configuration file */

static const struct option *find_option( const char *name )
{
   for ( size_t i = 0; i < ARRAY_SIZE(options); i++ )
   {
      if ( !options[i].name ) break;
      if ( !strcmp( options[i].name, name ) ) return &options[i];
   }
   return NULL;
}

void parse_config( json_t *config, char *ref )
{
   const char *key;
   json_t *val;

   json_object_foreach( config, key, val )
   {
      /* A documented comment convention: keys beginning with an underscore
       * are ignored, so a configuration file can explain itself. */
      if ( key[0] == '_' ) continue;

      const struct option *opt = find_option( key );
      if ( !opt )
      {
         /* Upstream silently ignores anything it does not recognise, which
          * turns a typo into a setting that quietly never took effect. */
         applog( LOG_WARNING, "%s: unknown option '%s', ignored", ref, key );
         continue;
      }

      if ( opt->has_arg && json_is_string( val ) )
      {
         char *s = strdup( json_string_value( val ) );
         if ( !s ) break;
         parse_arg( opt->val, s );
         free( s );
      }
      else if ( opt->has_arg && json_is_integer( val ) )
      {
         char buf[16];
         sprintf( buf, "%d", (int)json_integer_value( val ) );
         parse_arg( opt->val, buf );
      }
      else if ( opt->has_arg && json_is_real( val ) )
      {
         char buf[16];
         sprintf( buf, "%f", json_real_value( val ) );
         parse_arg( opt->val, buf );
      }
      else if ( !opt->has_arg )
      {
         if ( json_is_true( val ) ) parse_arg( opt->val, (char*)"" );
      }
      else
         applog( LOG_ERR, "%s: option '%s' has the wrong type", ref, key );
   }
}

/* ------------------------------------------------------------ command line */

/* config-template.json promises that options given on the command line
 * override the file. Upstream parses in argv order, so whether they do
 * depends on where -c happens to sit. Rather than run getopt twice -- there
 * is no portable way to reset it across glibc, the BSDs and mingw -- the
 * command line is scanned once into this list and then replayed, config
 * files first. optarg points into argv, which outlives the scan, so the
 * arguments a replayed option mutates are still the ones the user typed. */
struct parsed_opt
{
   int   key;
   char *arg;
};

void parse_cmdline( int argc, char *argv[] )
{
   struct parsed_opt *parsed = NULL;
   size_t count = 0, capacity = 0;
   int key;

   while ( 1 )
   {
#ifdef HAVE_GETOPT_LONG
      key = getopt_long( argc, argv, short_options, options, NULL );
#else
      key = getopt( argc, argv, short_options );
#endif
      if ( key < 0 ) break;

      if ( count == capacity )
      {
         capacity = capacity ? capacity * 2 : 32;
         parsed = (struct parsed_opt*)realloc( parsed,
                                       capacity * sizeof(struct parsed_opt) );
         if ( !parsed )
         {
            fprintf( stderr, "out of memory parsing the command line\n" );
            exit( 1 );
         }
      }
      parsed[count].key = key;
      parsed[count].arg = optarg;
      count++;
   }

   if ( optind < argc )
   {
      fprintf( stderr, "%s: unsupported non-option argument -- '%s'\n",
               argv[0], argv[optind] );
      show_usage_and_exit( 1 );
   }

   for ( size_t i = 0; i < count; i++ )
      if ( parsed[i].key == 'c' ) parse_arg( parsed[i].key, parsed[i].arg );

   for ( size_t i = 0; i < count; i++ )
      if ( parsed[i].key != 'c' ) parse_arg( parsed[i].key, parsed[i].arg );

   free( parsed );
}
