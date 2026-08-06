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

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "scheduler/worker.h"
#include "self_test.h"

#include <sys/stat.h>

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

// How long release_devices waits for the workers to let go of their devices.
constexpr auto kStopGrace = std::chrono::seconds(5);

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

    bool any_cpu = false;

    for (const vkminer::DeviceInfo &d : devices) {
        // The device type goes on the first line, next to the name, because a
        // software rasterizer is often named after the CPU it runs on and
        // reads like hardware otherwise.
        std::printf("  %2d  %s [%s]\n", d.index, d.name.c_str(),
                    vkminer::device_kind_name(d.kind));
        // Every line below is omitted when the backend did not fill it in,
        // rather than printed as a zero: a device reporting no subgroup size
        // and a backend that does not know the subgroup size are different
        // things, and only one of them is a reason to file a bug.
        if (!d.driver.empty())
            std::printf("      driver     %s\n", d.driver.c_str());
        if (d.api_version)
            std::printf("      vulkan     %s\n",
                        vkminer::version_string(d.api_version).c_str());
        if (d.vendor_id)
            std::printf("      ids        vendor 0x%04x, device 0x%04x\n",
                        d.vendor_id, d.device_id);
        if (d.memory)
            std::printf("      memory     %.1f GiB device-local\n",
                        d.memory / 1073741824.0);
        if (d.subgroup_size)
            std::printf("      subgroup   %u invocations%s\n", d.subgroup_size,
                        d.subgroup_ballot ? ", ballot" : "");
        if (d.max_invocations)
            std::printf("      workgroup  %u invocations, %u wide, %u groups\n",
                        d.max_invocations, d.max_workgroup_size,
                        d.max_workgroup_count);
        if (d.api_version)
            std::printf("      integers   %s\n",
                        (!d.int64 && !d.int16 && !d.int8) ? "32-bit only"
                        : d.int64 && d.int16 && d.int8    ? "64, 32, 16, 8-bit"
                        : d.int64                         ? "64 and 32-bit"
                                                          : "32-bit and narrower");

        any_cpu = any_cpu || d.kind == vkminer::DeviceKind::Cpu;
    }

    // What is worth saying about a CPU device depends on which backend found
    // it, so the backend says it rather than this function guessing.
    const char *caveat = g_backend->device_caveat();
    if (any_cpu && caveat)
        std::printf("\n%s\n", caveat);

    std::printf("\nSelect with --devices, e.g. --devices 0,1\n");
}

std::unique_ptr<vkminer::ComputeBackend> make_backend(const char *name)
{
    if (!name || !*name || !std::strcmp(name, "vulkan"))
        return vkminer::make_vulkan_backend();
    if (!std::strcmp(name, "cpu"))
        return vkminer::make_cpu_backend();
    if (!std::strcmp(name, "null"))
        return vkminer::make_null_backend();

    applog(LOG_ERR, "--backend: no backend called '%s'; "
                    "it is 'vulkan', 'cpu' or 'null'", name);
    return nullptr;
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

// Give the devices back before the process ends.
//
// exit() runs destructors on the thread that called it while every other
// thread is still running. The workers are mid-dispatch on those devices, and
// a Vulkan dispatch cannot be recalled -- so destroying the backend underneath
// them is a use-after-free inside the driver, which on Ctrl-C is a segfault
// instead of an exit. The order that works is the reverse of the order things
// were brought up in: stop the workers, wait until they have handed their
// kernels back, and only then destroy the backend.
//
// Called from proper_exit, so it covers every way out of the process rather
// than only the signal. Outside the anonymous namespace because the inherited
// C has to be able to link against it.
extern "C" void release_devices(void)
{
    if (!g_backend)
        return;

    worker_request_stop();

    // One batch is the whole wait, and batches are sized in tens of
    // milliseconds. The bound is for a device that has already stopped
    // answering: a miner that will not quit when asked is worse than one that
    // leaves a device object behind, which is what process exit does to it
    // anyway.
    const auto deadline = std::chrono::steady_clock::now() + kStopGrace;
    while (worker_count() > 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    const int stuck = worker_count();
    if (stuck > 0) {
        applog(LOG_WARNING, "%d worker(s) still on a device after %ds; "
                            "exiting without closing it",
               stuck, static_cast<int>(kStopGrace.count()));
        // Deliberately leaked. The driver is still being called from another
        // thread, and freeing it out from under that thread is precisely the
        // crash this function exists to prevent.
        (void)g_backend.release();
        return;
    }

    g_backend.reset();
}

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    show_credits();

    rpc_user = strdup("");
    rpc_pass = strdup("");

    parse_cmdline(argc, argv);

    // The backend comes up before the option checks that depend on it, so
    // that --device-list works without a pool, an algorithm or a wallet.
    g_backend = make_backend(opt_backend);
    if (!g_backend)
        return 1;
    if (!g_backend->init()) {
        applog(LOG_ERR, "No usable compute device found");
        return 1;
    }

    // From here on there is a device to give back, and several of the ways out
    // of this process go through proper_exit rather than through main.
    set_exit_hook(release_devices);

    if (opt_device_list) {
        print_device_list(g_backend->devices());
        return 0;
    }

    if (!opt_algo) {
        std::fprintf(stderr, "%s: no algorithm specified\n", argv[0]);
        show_usage_and_exit(1);
    }

    // Checked here rather than in the option parser: the parser accepts what
    // the inherited code has always accepted, and what this miner can actually
    // run is a shorter list. Finding out now costs a message; finding out from
    // the worker costs a pool connection and a job first.
    if (!vkminer::algorithm_exists(opt_algo)) {
        applog(LOG_ERR, "--algo: no algorithm called '%s'; this build has %s",
               opt_algo, vkminer::algorithm_names().c_str());
        return 1;
    }

    // A typo here would otherwise mean "use the built-in shaders after all",
    // reported once per worker and easy to read past. --algo-dir is only ever
    // set deliberately, so it not existing is a mistake worth stopping for.
    if (opt_algo_dir && *opt_algo_dir) {
        struct stat st;
        if (stat(opt_algo_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            applog(LOG_ERR, "--algo-dir: '%s' is not a directory", opt_algo_dir);
            return 1;
        }
        applog(LOG_WARNING, "Loading shaders from %s. Kernels outside the "
                            "binary are for development, not for mining.",
               opt_algo_dir);
    }

    // Only the Vulkan backend queues anything. Worth saying out loud: this
    // option exists to compare two runs, and one that silently did nothing
    // would make the two identical and the comparison a measurement of noise.
    if (opt_queue_depth > 0 && std::strcmp(g_backend->name(), "vulkan") != 0)
        applog(LOG_WARNING, "--queue-depth has no effect on the %s backend, "
                            "which runs one dispatch at a time",
               g_backend->name());

    if (!opt_benchmark && !opt_self_test && !short_url) {
        std::fprintf(stderr, "%s: no URL supplied\n", argv[0]);
        show_usage_and_exit(1);
    }

    if (!select_devices(g_backend->devices(), g_device_map))
        return 1;

    // Before curl, before the stratum thread, before anything leaves this
    // machine. A miner that hashes wrongly should find that out by itself
    // rather than by having a pool reject a thousand shares, and the check
    // costs a few hundred nonces per device.
    //
    // The null backend is exempt because it finds nothing by design; there is
    // no result of its to be right or wrong about.
    if (std::strcmp(g_backend->name(), "null") != 0) {
        if (!vkminer::self_test(*g_backend, g_device_map, opt_algo)) {
            applog(LOG_ERR, "Self-test failed. Not connecting to a pool: "
                            "shares from this build would be rejected.");
            return 1;
        }
    } else if (opt_self_test) {
        applog(LOG_WARNING, "The null backend computes nothing, so there is "
                            "nothing to self-test");
    }

    if (opt_self_test)
        return 0;

    // The backend decides the default, because what a worker is differs
    // between them: on a GPU it is a queue to keep fed, one per device, and
    // more than one is legal because a device that stalls between dispatches
    // can be kept busier by a second; on the CPU backend the worker is the
    // thing that hashes, so the default is one per core.
    if (!opt_n_threads_set)
        opt_n_threads =
            g_backend->preferred_workers(static_cast<int>(g_device_map.size()));
    if (opt_n_threads < 1)
        opt_n_threads = 1;

    // Round robin, so that workers beyond the first per device spread over the
    // devices rather than piling onto device 0.
    std::vector<int> worker_device(opt_n_threads);
    for (int i = 0; i < opt_n_threads; i++)
        worker_device[i] = g_device_map[i % g_device_map.size()];
    worker_set_backend(g_backend.get(), worker_device.data());

    // Fewer workers than devices leaves a selected device unmined. Legal --
    // --threads is explicit -- but indistinguishable from a machine that is
    // quietly half as fast as it looks, so it is said out loud, by name.
    if (static_cast<size_t>(opt_n_threads) < g_device_map.size())
        for (size_t i = static_cast<size_t>(opt_n_threads);
             i < g_device_map.size(); i++)
            applog(LOG_WARNING, "Device %d (%s) has no worker: --threads %d is "
                                "fewer than the %zu devices selected",
                   g_device_map[i],
                   g_backend->devices()[static_cast<size_t>(g_device_map[i])]
                       .name.c_str(),
                   opt_n_threads, g_device_map.size());

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

    // With one device the line above says everything. With several, which
    // worker sits on which device is what every later per-device number has to
    // be read against, and it is only worth printing once.
    if (g_device_map.size() > 1)
        for (const int dev : g_device_map) {
            std::string workers;
            for (int i = 0; i < opt_n_threads; i++)
                if (worker_device[i] == dev)
                    workers += (workers.empty() ? "" : ",") + std::to_string(i);
            applog2(LOG_INFO, "device %-2d worker %-8s %s", dev,
                    workers.empty() ? "none" : workers.c_str(),
                    g_backend->devices()[static_cast<size_t>(dev)].name.c_str());
        }

    // When --time-limit started counting, or zero while it has not. The clock
    // starts at the first job, so that a pool taking seconds to answer is not
    // measured as this machine's hashrate. A benchmark publishes no job, so
    // there it starts now -- which is when its first dispatch goes out anyway.
    auto limit_start = std::chrono::steady_clock::time_point{};
    double limit_hashes = 0.;
    if (opt_time_limit && opt_benchmark)
        limit_start = std::chrono::steady_clock::now();

    // Upstream simply joined the work I/O thread and let the process end when
    // it did. This waits for the same thing, but has to poll rather than join
    // so that it also notices the flag a signal handler sets.
    while (!g_shutdown) {
        if (pthread_kill(thr_info[work_thr_id].pth, 0) != 0) {
            applog(LOG_WARNING, "workio thread dead, exiting.");
            proper_exit(0);
        }
        // A worker that cannot go on gives up its device and says so here,
        // rather than ending the process from a thread the teardown is about
        // to wait for. It has already logged what went wrong.
        const int failed = worker_exit_code();
        if (failed >= 0)
            proper_exit(failed);

        // Enforced here for the same reason as the line above: this thread
        // holds no device, so teardown can wait for every worker to drain and
        // hand its device back. A worker ending the process from inside its
        // own loop would be waiting for itself.
        if (opt_time_limit) {
            const auto now = std::chrono::steady_clock::now();
            if (limit_start == std::chrono::steady_clock::time_point{}) {
                if (g_work_time) {
                    limit_start = now;
                    pthread_mutex_lock(&stats_lock);
                    limit_hashes = total_hashes;
                    pthread_mutex_unlock(&stats_lock);
                }
            } else if (now - limit_start >=
                       std::chrono::seconds(opt_time_limit)) {
                // The rate is the reason to limit a benchmark at all: it is
                // what a script wrapping this in a timeout had to parse back
                // out of the log. Averaged over the limit rather than read off
                // global_hashrate, a two-second window that would make this a
                // copy of the last periodic report -- and on a limit that is a
                // multiple of the report interval, literally the same line
                // twice. The counter is snapshotted when the clock starts, so
                // startup is in neither.
                if (opt_benchmark) {
                    pthread_mutex_lock(&stats_lock);
                    const double hashes = total_hashes - limit_hashes;
                    pthread_mutex_unlock(&stats_lock);

                    const double elapsed =
                        std::chrono::duration<double>(now - limit_start).count();
                    char scaled[32];
                    format_hashrate(safe_div(hashes, elapsed, 0.), scaled);
                    applog(LOG_NOTICE, "Time limit of %ds reached, exiting. "
                                       "Benchmark: %s averaged over the run",
                           opt_time_limit, scaled);
                } else {
                    applog(LOG_NOTICE, "Time limit of %ds reached, exiting",
                           opt_time_limit);
                }
                proper_exit(0);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    applog(LOG_INFO, "Signal %d received, exiting", static_cast<int>(g_shutdown));
    proper_exit(0);
    return 0;
}
