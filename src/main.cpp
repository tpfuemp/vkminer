// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Derived from cpuminer-opt's cpu-miner.c main(): the order things are brought
// up in, and the fact that the process lives exactly as long as the work I/O
// thread does. What it starts is different -- device workers rather than CPU
// threads, and no CPU affinity or priority to arrange -- but the sequence of
// checks before the first thread starts is upstream's, because each of them
// exists for a failure someone has already had.

extern "C" {
#include "core/miner.h"
}

#include "backends/backend.h"
#include "scheduler/worker.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef WIN32
#include <windows.h>
#endif

// Thread bookkeeping. These are declared in miner.h, which the inherited C
// reads; main owns them because main is what creates the threads they
// describe. C linkage, so the C side sees the names it expects.
extern "C" {
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
struct thr_info *thr_info = nullptr;
double *thr_hashrates = nullptr;
struct work_restart *work_restart = nullptr;
int work_thr_id = 0;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
}

namespace {

std::unique_ptr<vkminer::ComputeBackend> g_backend;
std::vector<int> g_device_map;

void show_credits()
{
    std::printf("\n         **********  %s %s  **********\n",
                PACKAGE_NAME, PACKAGE_VERSION);
    std::printf("     A GPU miner on Vulkan compute, portable across vendors.\n");
    std::printf("     Descended from cpuminer-opt by JayDDee, and from pooler's\n");
    std::printf("     cpuminer before it.\n\n");
}

// Set by the signal handler, read by main. Upstream logged and exited from
// inside the handler; a handler runs on whichever thread the signal lands on,
// so that deadlocks outright whenever that thread is already inside applog or
// inside stdio -- which, in a miner that logs every job, is often. Setting a
// flag is the only thing the handler is allowed to do.
volatile sig_atomic_t g_shutdown = 0;

#ifndef WIN32
void signal_handler(int sig)
{
    if (sig == SIGHUP)  // upstream logged it and carried on; carry on
        return;
    g_shutdown = sig;
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
    switch (dwType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        g_shutdown = 1;
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

int thread_create(struct thr_info *thr, void *(*func)(void *))
{
    pthread_attr_init(&thr->attr);
    const int err = pthread_create(&thr->pth, &thr->attr, func, thr);
    pthread_attr_destroy(&thr->attr);
    return err;
}

void print_device_list(const std::vector<vkminer::DeviceInfo> &devices)
{
    std::printf("%zu device(s) found by the %s backend:\n\n",
                devices.size(), g_backend->name());
    for (const vkminer::DeviceInfo &d : devices) {
        std::printf("  %2d  %s\n", d.index, d.name.c_str());
        if (!d.driver.empty())
            std::printf("      driver %s\n", d.driver.c_str());
        if (d.memory)
            std::printf("      memory %.1f GiB\n", d.memory / 1073741824.0);
    }
    std::printf("\nSelect with --devices, e.g. --devices 0,1\n");
}

// "0,2,3" -> {0, 2, 3}. An empty or absent list means every device.
bool select_devices(const std::vector<vkminer::DeviceInfo> &devices,
                    std::vector<int> &selected)
{
    if (!opt_devices || !*opt_devices) {
        for (const vkminer::DeviceInfo &d : devices)
            selected.push_back(d.index);
        return true;
    }

    const char *p = opt_devices;
    while (*p) {
        char *end = nullptr;
        const long index = std::strtol(p, &end, 10);
        if (end == p) {
            applog(LOG_ERR, "--devices: '%s' is not a list of device indices",
                   opt_devices);
            return false;
        }
        if (index < 0 || index >= static_cast<long>(devices.size())) {
            applog(LOG_ERR, "--devices: no device %ld (--device-list shows %zu)",
                   index, devices.size());
            return false;
        }
        selected.push_back(static_cast<int>(index));
        p = end;
        while (*p == ',' || *p == ' ') p++;
    }
    return !selected.empty();
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    show_credits();

    rpc_user = strdup("");
    rpc_pass = strdup("");

    parse_cmdline(argc, argv);

    // The backend comes up before the option checks that depend on it, so
    // that --device-list works without a pool, an algorithm or a wallet.
    g_backend = vkminer::make_null_backend();
    if (!g_backend->init()) {
        applog(LOG_ERR, "No usable compute device found");
        return 1;
    }

    if (opt_device_list) {
        print_device_list(g_backend->devices());
        return 0;
    }

    if (!opt_algo) {
        std::fprintf(stderr, "%s: no algorithm specified\n", argv[0]);
        show_usage_and_exit(1);
    }

    if (!opt_benchmark && !short_url) {
        std::fprintf(stderr, "%s: no URL supplied\n", argv[0]);
        show_usage_and_exit(1);
    }

    if (!select_devices(g_backend->devices(), g_device_map))
        return 1;

    // One worker per selected device unless the user said otherwise. More
    // workers than devices is legal -- they round-robin -- because a device
    // that stalls between dispatches can be kept busier by a second queue.
    if (!opt_n_threads_set)
        opt_n_threads = static_cast<int>(g_device_map.size());
    if (opt_n_threads < 1)
        opt_n_threads = 1;

    std::vector<int> worker_device(opt_n_threads);
    for (int i = 0; i < opt_n_threads; i++)
        worker_device[i] = g_device_map[i % g_device_map.size()];
    worker_set_backend(g_backend.get(), worker_device.data());

    if (!rpc_userpass) {
        rpc_userpass = static_cast<char *>(
            malloc(strlen(rpc_user) + strlen(rpc_pass) + 2));
        if (!rpc_userpass)
            return 1;
        sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
    }

    pthread_mutex_init(&stats_lock, nullptr);
    pthread_rwlock_init(&g_work_lock, nullptr);
    pthread_mutex_init(&stratum.sock_lock, nullptr);
    pthread_mutex_init(&stratum.work_lock, nullptr);

    // Initialising curl's SSL layer pulls in a lot for a plain stratum+tcp
    // connection that will never use it, so it is only asked for when the URL
    // says it is needed.
    long flags = CURL_GLOBAL_ALL;
    if (!opt_benchmark)
        if (strncasecmp(rpc_url, "https:", 6)
            && strncasecmp(rpc_url, "stratum+ssl://", 14)
            && strncasecmp(rpc_url, "stratum+tcps://", 15))
            flags &= ~CURL_GLOBAL_SSL;

    if (curl_global_init(flags)) {
        applog(LOG_ERR, "CURL initialization failed");
        return 1;
    }

    if (is_root())
        applog(LOG_NOTICE, "Running vkminer as Superuser is discouraged.");

#ifndef WIN32
    if (opt_background) {
        int i = fork();
        if (i < 0) exit(1);
        if (i > 0) exit(0);
        i = setsid();
        if (i < 0)
            applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
        i = chdir("/");
        if (i < 0)
            applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
        signal(SIGHUP, signal_handler);
        signal(SIGTERM, signal_handler);
    }
    /* Always catch Ctrl+C */
    signal(SIGINT, signal_handler);
#else
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
    if (opt_background) {
        HWND hcon = GetConsoleWindow();
        if (hcon) {
            // this method also hides the parent command line window
            ShowWindow(hcon, SW_HIDE);
        } else {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            CloseHandle(h);
            FreeConsole();
        }
    }
#endif

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
        openlog(PACKAGE_NAME, LOG_PID, LOG_USER);
#endif

    work_restart = static_cast<struct work_restart *>(
        calloc(opt_n_threads, sizeof(*work_restart)));
    if (!work_restart)
        return 1;
    // Four beyond the workers: work I/O, long poll, stratum, API.
    thr_info = static_cast<struct thr_info *>(
        calloc(opt_n_threads + 4, sizeof(*thr_info)));
    if (!thr_info)
        return 1;
    thr_hashrates = static_cast<double *>(calloc(opt_n_threads, sizeof(double)));
    if (!thr_hashrates)
        return 1;

    /* init workio thread info */
    work_thr_id = opt_n_threads;
    struct thr_info *thr = &thr_info[work_thr_id];
    thr->id = work_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        return 1;

    if (rpc_pass && rpc_user)
        opt_stratum_stats = (strstr(rpc_pass, "stats") != nullptr)
                         || (strcmp(rpc_user, "benchmark") == 0);

    /* start work I/O thread */
    if (thread_create(thr, workio_thread)) {
        applog(LOG_ERR, "work thread create failed");
        return 1;
    }

    if (have_stratum) {
        if (opt_debug)
            applog(LOG_INFO, "Creating stratum thread");

        stratum.new_job = false;  // just to make sure

        stratum_thr_id = opt_n_threads + 2;
        thr = &thr_info[stratum_thr_id];
        thr->id = stratum_thr_id;
        thr->q = tq_new();
        if (!thr->q)
            return 1;
        if (thread_create(thr, stratum_thread)) {
            applog(LOG_ERR, "Stratum thread create failed");
            return 1;
        }
        tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
    }

    if (want_longpoll && !have_stratum)
        applog(LOG_WARNING, "Long polling is not implemented yet; "
                            "use a stratum+tcp:// URL");

    if (opt_api_enabled)
        applog(LOG_WARNING, "The monitoring API is not implemented yet");

    // Hold the stats lock while starting the workers, so that none of them
    // reports a rate before the clocks those rates are measured against exist.
    pthread_mutex_lock(&stats_lock);

    for (int i = 0; i < opt_n_threads; i++) {
        thr = &thr_info[i];
        thr->id = i;
        thr->q = tq_new();
        if (!thr->q)
            return 1;
        if (thread_create(thr, miner_thread)) {
            applog(LOG_ERR, "Miner thread %d create failed", i);
            return 1;
        }
    }

    share_stats_init();
    pthread_mutex_unlock(&stats_lock);

    applog(LOG_INFO, "%d worker(s) started on %zu device(s), algorithm '%s', "
                     "backend '%s'",
           opt_n_threads, g_device_map.size(), opt_algo, g_backend->name());

    // Upstream simply joined the work I/O thread and let the process end when
    // it did. This waits for the same thing, but has to poll rather than join
    // so that it also notices the flag a signal handler sets.
    while (!g_shutdown) {
        if (pthread_kill(thr_info[work_thr_id].pth, 0) != 0) {
            applog(LOG_WARNING, "workio thread dead, exiting.");
            return 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    applog(LOG_INFO, "Signal %d received, exiting", static_cast<int>(g_shutdown));
    proper_exit(0);
    return 0;
}
