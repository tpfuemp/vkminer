// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "api/api_model.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>

#include "api/api_control.h"
#include "core/miner.h"
#include "core/sensors.h"
#include "scheduler/candidate_log.h"
#include "scheduler/worker.h"
#include "tune.h"

namespace vkminer {
namespace {

const std::vector<DeviceInfo> *g_devices = nullptr;
const char *g_backend_name = "";

const char *host_os()
{
// _WIN32, for the reason api_server.cpp spells out: WIN32 is not defined in a
// C++ translation unit here, and asking for it would report every Windows
// build's host os as the fallback string.
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux)
    return "linux";
#else
    return "unknown";
#endif
}

std::string text(const char *s)
{
    return s ? s : "";
}

double seconds_since(const struct timeval &then)
{
    if (!then.tv_sec)
        return 0.;

    struct timeval now;
    gettimeofday(&now, nullptr);
    const double elapsed = static_cast<double>(now.tv_sec - then.tv_sec) +
                           1e-6 * static_cast<double>(now.tv_usec - then.tv_usec);
    return elapsed > 0. ? elapsed : 0.;
}

// One read of every worker's rate, under the lock the workers publish through.
// Taken once per collector and shared out from there: a per-device loop that
// took the lock per device would let a worker publish between two devices of
// one response.
std::vector<double> worker_rates()
{
    const int workers = opt_n_threads > 0 ? opt_n_threads : 0;
    std::vector<double> rates(static_cast<size_t>(workers), 0.);
    if (!workers || !thr_hashrates)
        return rates;

    const bool hashing = model_is_mining();
    pthread_mutex_lock(&stats_lock);
    for (int i = 0; i < workers; i++)
        rates[static_cast<size_t>(i)] = hashing ? thr_hashrates[i] : 0.;
    pthread_mutex_unlock(&stats_lock);
    return rates;
}

// The pool's difficulty as a number to report, or nothing. Zero is what the
// field holds before a pool has set one, and a dashboard plotting that reads a
// pool that asked for the easiest possible share.
std::optional<double> positive(double value)
{
    if (value > 0.)
        return value;
    return std::nullopt;
}

}  // namespace

void model_set_devices(const std::vector<DeviceInfo> *devices,
                       const char *backend_name)
{
    g_devices = devices;
    g_backend_name = backend_name ? backend_name : "";
}

std::string mask_url(const char *url)
{
    std::string out = text(url);

    // Only the userinfo between the scheme and the host: an `@` later in the
    // string is part of a path or a query and is nobody's password.
    const size_t scheme = out.find("://");
    const size_t start = scheme == std::string::npos ? 0 : scheme + 3;
    const size_t slash = out.find('/', start);
    const size_t at = out.find('@', start);
    if (at == std::string::npos || (slash != std::string::npos && at > slash))
        return out;

    out.erase(start, at + 1 - start);
    return out;
}

bool model_is_mining()
{
    if (opt_n_threads <= 0)
        return false;

    // The park is the case this exists for. A parked worker is blocked inside
    // control_park() and publishes nothing at all, so its last rate would
    // otherwise stand for the length of the pause.
    return !control_wants_park();
}

// Every collector clears its snapshot first. Half the fields here are set only
// when the miner has something to say, so a struct filled twice would otherwise
// carry the first answer into the second -- a session age surviving the outage
// that ended it, which is the shape of the defect this convention exists for.
void collect_miner(MinerSnapshot *out)
{
    *out = MinerSnapshot();
    out->name = PACKAGE_NAME;
    out->version = PACKAGE_VERSION;
    out->api_version = "1.0";
    out->kind = "gpu";
}

void collect_summary(SummarySnapshot *out)
{
    *out = SummarySnapshot();
    const std::vector<double> rates = worker_rates();

    out->algo = text(opt_algo);
    out->uptime_s = static_cast<uint64_t>(seconds_since(session_start));
    out->timestamp = static_cast<uint64_t>(time(nullptr));

    out->hashrate_hs = 0.;
    for (size_t i = 0; i < rates.size(); i++)
        out->hashrate_hs += rates[i];

    out->devices = g_devices ? static_cast<int>(g_devices->size()) : 0;
    out->threads = opt_n_threads > 0 ? opt_n_threads : 0;

    out->shares.accepted = accepted_share_count;
    out->shares.rejected = rejected_share_count;
    out->shares.solved = solved_block_count;
    out->shares.stale = stale_share_count;

    const double minutes = static_cast<double>(out->uptime_s) / 60.;
    out->accepted_per_min =
        minutes > 0. ? static_cast<double>(out->shares.accepted) / minutes : 0.;

    out->pool_difficulty = positive(stratum_diff);
    out->network_difficulty = positive(net_diff);
    out->network_hashrate_hs = positive(net_hashrate);

    out->pool_count = 1;
    out->active_pool = 0;

    out->disagree_below_target = candidates_below_target();
    out->disagree_wrong_digest = candidates_wrong_digest();
}

void collect_threads(std::vector<ThreadSnapshot> *out)
{
    const std::vector<double> rates = worker_rates();

    out->clear();
    out->reserve(rates.size());
    for (size_t i = 0; i < rates.size(); i++) {
        ThreadSnapshot one;
        one.id = static_cast<int>(i);
        one.device_id = worker_device_index(static_cast<int>(i));
        one.hashrate_hs = rates[i];
        out->push_back(one);
    }
}

void collect_devices(std::vector<DeviceSnapshot> *out)
{
    out->clear();
    if (!g_devices)
        return;

    const std::vector<double> rates = worker_rates();
    const int workers = static_cast<int>(rates.size());

    out->reserve(g_devices->size());
    for (size_t i = 0; i < g_devices->size(); i++) {
        const DeviceInfo &info = (*g_devices)[i];

        DeviceSnapshot one;
        one.id = info.index;
        one.type = "gpu";
        one.name = info.name;
        one.memory_bytes = info.memory;
        one.vendor_id = info.vendor_id;
        one.device_id = info.device_id;

        one.vulkan.driver = info.driver;
        one.vulkan.api_version = version_string(info.api_version);
        one.vulkan.backend = g_backend_name;
        one.vulkan.int64 = info.int64;

        // Every worker on this device folded together, the way the periodic
        // report already does it: what a worker is on a GPU is a queue to keep
        // fed, so the per-device line is the sum and not one of the workers.
        for (int j = 0; j < workers; j++) {
            if (worker_device_index(j) != info.index)
                continue;

            uint64_t total = 0, stale = 0;
            worker_batch_counts(j, &total, &stale);
            one.hashrate_hs += rates[static_cast<size_t>(j)];
            one.vulkan.batches_total += total;
            one.vulkan.batches_late += stale;
            one.workers++;
        }

        // Zero is a device holding no table, which the contract spells `null`
        // and not a table of no size.
        const uint64_t shared = worker_shared_table_bytes(info.index);
        if (shared)
            one.vulkan.shared_table_bytes = shared;

        Tuning tuning;
        if (device_tuning(info.index, &tuning)) {
            one.vulkan.tuned = true;
            if (tuning.local_size_x)
                one.vulkan.workgroup = tuning.local_size_x;
            if (tuning.queue_depth)
                one.vulkan.queue_depth = tuning.queue_depth;
            if (!tuning.variant.empty())
                one.vulkan.kernel = tuning.variant;
        }

        // What the card is doing physically, from outside Vulkan entirely and
        // joined to this device by its bus address -- which is why a device
        // that would not report one, a software rasterizer included, keeps the
        // empty fields it had before.
        if (info.pci)
            one.bus_id = static_cast<int>(info.pci_bus);

        const DeviceSensors sensors = device_sensors(pci_address(info));
        one.temp_c = sensors.temp_c;
        one.fan_pct = sensors.fan_pct;
        one.fan_rpm = sensors.fan_rpm;
        one.clock_mhz = sensors.clock_mhz;
        one.mem_clock_mhz = sensors.mem_clock_mhz;
        one.power_mw = sensors.power_mw;
        one.power_limit_mw = sensors.power_limit_mw;

        // Any one reading is enough: a source that answered about this card is
        // monitoring it, whichever attributes that particular driver publishes.
        one.monitoring = sensors.temp_c || sensors.fan_pct || sensors.fan_rpm
                      || sensors.clock_mhz || sensors.mem_clock_mhz
                      || sensors.power_mw || sensors.power_limit_mw;

        // kH/s per watt is hashes per millijoule, so the two thousands cancel
        // and this is the plain ratio. Derived here rather than by whoever
        // renders it, so that /status and /metrics cannot disagree about it --
        // and only where both halves are real: a card reporting 0 mW is a
        // driver declining to answer, not a card drawing nothing.
        if (one.power_mw && *one.power_mw > 0 && one.hashrate_hs > 0.)
            one.hashrate_per_watt_khs =
                one.hashrate_hs / static_cast<double>(*one.power_mw);

        out->push_back(one);
    }
}

void collect_system(SystemSnapshot *out)
{
    *out = SystemSnapshot();
    out->os = host_os();
    if (g_devices && !g_devices->empty())
        out->driver = (*g_devices)[0].driver;

    out->cpus = static_cast<int>(std::thread::hardware_concurrency());

    // Rounded, because the field is an integer and the sensor's third decimal
    // is not a fact about the processor.
    if (const std::optional<double> temp = cpu_temperature_c())
        out->cpu_temp_c = static_cast<int>(*temp + 0.5);
}

void collect_pool(int index, PoolSnapshot *out)
{
    *out = PoolSnapshot();
    out->index = index;
    out->active = index == 0;
    out->name = text(short_url);
    out->url = mask_url(rpc_url);
    out->user = text(rpc_user);
    out->algo = text(opt_algo);
    out->type = have_stratum ? "stratum" : "getwork";
    out->status = stratum_down ? "disconnected" : "connected";

    out->shares.accepted = accepted_share_count;
    out->shares.rejected = rejected_share_count;
    out->shares.solved = solved_block_count;
    out->shares.stale = stale_share_count;

    out->difficulty = positive(stratum_diff);
    out->disconnects = stratum_errors;

    if (!stratum_down && stratum_up_time)
        out->session_s =
            static_cast<uint64_t>(time(nullptr) - stratum_up_time);

    if (!have_stratum)
        return;

    // The job fields are read under the lock the stratum thread replaces them
    // through: `job_id` is freed and reallocated on every mining.notify, so a
    // reader that copied the pointer would be holding freed memory a moment
    // later.
    pthread_mutex_lock(&stratum.work_lock);
    if (stratum.job.job_id)
        out->job.id = stratum.job.job_id;
    if (stratum.block_height > 0)
        out->job.height = static_cast<uint64_t>(stratum.block_height);
    if (stratum.xnonce2_size)
        out->job.extranonce2_size = static_cast<int>(stratum.xnonce2_size);
    pthread_mutex_unlock(&stratum.work_lock);
}

void collect_health(HealthSnapshot *out)
{
    *out = HealthSnapshot();
    out->mining = model_is_mining();
    out->pool_connected = !stratum_down;
    out->devices_ok = g_devices ? static_cast<int>(g_devices->size()) : 0;

    out->reasons.clear();
    if (!out->pool_connected && !control_holds_connection())
        out->reasons.push_back("pool_disconnected");
    if (!out->devices_ok)
        out->reasons.push_back("no_devices");

    // A miner somebody deliberately stopped is healthy and not mining. Only a
    // fault degrades it, which is why the park state is not a reason above.
    out->status = out->reasons.empty() ? "ok" : "degraded";
}

void collect_control(ControlSnapshot *out)
{
    *out = ControlSnapshot();
    const ControlStatus status = control_status();

    out->state = control_state_name(status.state);
    out->epoch = status.epoch;
    out->since_s = static_cast<uint64_t>(status.state_age_s);

    out->algo = text(opt_algo);
    out->pool_index = 0;
    out->pool_url = mask_url(rpc_url);
    out->pool_user = text(rpc_user);
    if (have_stratum)
        out->pool_connected = !stratum_down;

    out->threads_total = status.workers;
    out->threads_parked = status.parked;

    out->switch_count = status.switch_count;
    if (status.last_switch_age_s >= 0)
        out->last_switch_age_s = static_cast<uint64_t>(status.last_switch_age_s);
    out->min_interval_s = status.min_interval_s;
    out->ready_for_switch = status.ready_for_switch;
    if (!status.last_error.empty())
        out->last_error = status.last_error;
}

void collect_config(ConfigSnapshot *out)
{
    *out = ConfigSnapshot();
    out->algo = text(opt_algo);
    out->url = mask_url(rpc_url);
    out->user = text(rpc_user).empty() ? "" : "***";
    out->backend = text(g_backend_name);
    out->devices = text(opt_devices);
    out->threads = opt_n_threads > 0 ? opt_n_threads : 0;
    out->timeout = opt_timeout;
    out->scantime = opt_scantime;
    out->retries = opt_retries;
    out->time_limit = opt_time_limit;
    out->benchmark = opt_benchmark;
    out->quiet = opt_quiet;
    out->debug = opt_debug;
    out->protocol = opt_protocol;

    if (opt_workgroup > 0)
        out->workgroup = static_cast<uint32_t>(opt_workgroup);
    if (opt_queue_depth > 0)
        out->queue_depth = static_cast<uint32_t>(opt_queue_depth);
    if (opt_kernel)
        out->kernel = opt_kernel;
    if (opt_algo_dir)
        out->algo_dir = opt_algo_dir;
    out->no_tune = opt_no_tune;
    out->retune = opt_retune;
    out->no_int64 = opt_no_int64;
    out->vk_validate = opt_vk_validate;

    out->api_enabled = opt_api_enabled;
    out->api_allow = text(opt_api_allow);
    out->api_port = opt_api_listen;
    out->api_remote = opt_api_remote != 0;
    out->api_control = opt_api_control;
    out->api_control_min_interval = opt_api_control_min_interval;
    out->api_control_park_timeout = opt_api_control_park_timeout;
}

}  // namespace vkminer
