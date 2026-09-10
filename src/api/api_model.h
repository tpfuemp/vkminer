// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Neutral snapshots of everything the API reports, and the collectors that fill
// them from the miner's live state.
//
// Snapshots hold copies, never pointers into miner state. The API thread runs
// alongside the workers and the stratum thread, so every field is read once
// here and formatted later; a renderer that went back to a global would be able
// to put two different reads of one number into one response.
//
// Nothing in this file knows about HTTP or JSON. The route handlers call a
// collector and format what comes back, which is also what makes the collectors
// testable without a socket.
//
// `std::optional` is the "unavailable" of the contract's `null`: an empty
// optional is a field this build cannot answer, and is not the same statement
// as a zero. A temperature Vulkan will not report is empty; a hashrate of a
// miner that is not hashing is zero, because that one is a measurement.

#ifndef VKMINER_API_API_MODEL_H__
#define VKMINER_API_API_MODEL_H__

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "backends/backend.h"

namespace vkminer {

// ------------------------------------------------------------------- wiring

// The devices the backend enumerated, and what the backend calls itself.
// Called from main once the backend is up and before the API thread starts;
// the vector is the backend's own and has to outlive that thread.
//
// A pointer rather than a copy because the device list is built once and never
// rebuilt, and because taking it here rather than a ComputeBackend keeps the
// collectors out of the backend interface -- a test supplies a vector, not a
// dozen stubbed virtuals.
void model_set_devices(const std::vector<DeviceInfo> *devices,
                       const char *backend_name);

// ----------------------------------------------------------------- snapshots

// Present on every response, errors included.
struct MinerSnapshot {
    std::string name;
    std::string version;
    std::string api_version;
    std::string kind;  // "gpu"
};

struct SharesSnapshot {
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    uint64_t solved = 0;
    uint64_t stale = 0;
};

struct SummarySnapshot {
    std::string algo;
    uint64_t uptime_s = 0;
    uint64_t timestamp = 0;

    double hashrate_hs = 0.;

    // Empty: nothing keeps a rolling average. The session mean is a different
    // number and reporting it under this name would be a lie a dashboard cannot
    // see through.
    std::optional<double> hashrate_avg_hs;

    int devices = 0;  // GPUs enumerated
    int threads = 0;  // workers, which is a larger number under --threads

    SharesSnapshot shares;
    double accepted_per_min = 0.;

    std::optional<double> pool_difficulty;
    std::optional<double> network_difficulty;
    std::optional<double> best_share;      // empty: nothing tracks it yet
    std::optional<double> network_hashrate_hs;

    int pool_count = 1;   // there is one pool and no failover
    int active_pool = 0;
    std::optional<uint64_t> wait_time_s;   // empty: nothing tracks it yet

    // Times the device handed back a candidate the host disagreed with, split
    // the way the run summary splits them. Process-wide, not per device:
    // nothing attributes one of these to the card that produced it, so there is
    // no per-device form of this number to serve.
    uint64_t disagree_below_target = 0;
    uint64_t disagree_wrong_digest = 0;
};

struct ThreadSnapshot {
    int id = -1;
    int device_id = -1;   // indexes the device list, not the worker list
    double hashrate_hs = 0.;

    // Empty, all five. Shares are counted process-wide, not per worker; the
    // device-vs-host disagreement counters are process-wide totals too, so a
    // per-worker `hw_errors` would be a new counter rather than a read of an
    // old one. Intensity and throughput are ccminer's dispatch knobs and have
    // no vkminer spelling.
    std::optional<uint64_t> accepted;
    std::optional<uint64_t> rejected;
    std::optional<uint64_t> hw_errors;
    std::optional<double> intensity;
    std::optional<uint64_t> throughput;
};

// What is interesting about a Vulkan device, which is not what NVML reports.
struct VulkanSnapshot {
    std::string driver;        // driver name and version
    std::string api_version;   // "1.4.329"
    std::string backend;       // the backend that enumerated it
    bool int64 = false;

    // What the tuner settled, empty on a device it never reached: --no-tune, a
    // backend with nothing to tune, or a run that has not got there yet. That
    // is a different statement from a device measured and found to like the
    // defaults, which is why `tuned` is not just "workgroup is set".
    bool tuned = false;
    std::optional<uint32_t> workgroup;
    std::optional<uint32_t> queue_depth;
    std::optional<std::string> kernel;

    // H-5's evidence, summed over every worker on this device.
    uint64_t batches_total = 0;
    uint64_t batches_late = 0;
};

struct DeviceSnapshot {
    int id = -1;
    std::string type;  // "gpu"
    std::string name;

    uint64_t memory_bytes = 0;
    uint32_t vendor_id = 0;
    uint32_t device_id = 0;

    // Vulkan exposes no telemetry, so these stay empty rather than becoming
    // zeroes a dashboard would plot as a cold, idle, unpowered card.
    std::optional<double> temp_c;
    std::optional<int> fan_pct;
    std::optional<int> fan_rpm;
    std::optional<uint32_t> clock_mhz;
    std::optional<uint32_t> mem_clock_mhz;
    std::optional<uint64_t> power_mw;
    std::optional<uint64_t> power_limit_mw;
    std::optional<double> hashrate_per_watt_khs;

    // Every worker on this device folded together: one entry per GPU, not per
    // worker, so two workers keeping one queue busy read as one device at their
    // combined rate.
    double hashrate_hs = 0.;
    int workers = 0;

    VulkanSnapshot vulkan;
};

struct SystemSnapshot {
    std::string os;
    std::optional<std::string> driver;  // the first device's, empty with none
    int cpus = 0;
    std::optional<int> cpu_temp_c;
    std::optional<uint32_t> cpu_clock_mhz;
    std::optional<int> cpu_fan_pct;
};

struct PoolJobSnapshot {
    std::optional<std::string> id;
    std::optional<uint64_t> height;
    std::optional<int> extranonce2_size;
    std::optional<std::string> extranonce2;
};

struct PoolSnapshot {
    int index = 0;
    bool active = true;
    std::string name;   // the short url; nothing names a pool here
    std::string url;    // credentials stripped
    std::string user;   // never the password, on any route
    std::string algo;
    std::string type;   // "stratum" or "getwork"
    std::string status; // "connected" or "disconnected"

    SharesSnapshot shares;
    std::optional<double> difficulty;
    std::optional<double> best_share;
    PoolJobSnapshot job;

    std::optional<uint32_t> ping_ms;
    uint64_t disconnects = 0;
    std::optional<uint64_t> wait_time_s;

    // Empty while the connection is down rather than a number that keeps
    // climbing across an outage: it is the age of this session, and an outage
    // ends one.
    std::optional<uint64_t> session_s;
    std::optional<uint64_t> last_share_age_s;
};

struct HealthSnapshot {
    std::string status;  // "ok" or "degraded"
    bool mining = false;
    bool pool_connected = false;
    int devices_ok = 0;
    std::vector<std::string> reasons;
};

struct ControlSnapshot {
    std::string state;
    uint64_t epoch = 0;
    uint64_t since_s = 0;

    std::string algo;
    int pool_index = 0;
    std::string pool_url;
    std::string pool_user;
    std::optional<bool> pool_connected;  // empty for getwork/GBT

    int threads_total = 0;
    int threads_parked = 0;

    uint64_t switch_count = 0;
    std::optional<uint64_t> last_switch_age_s;
    int min_interval_s = 0;
    bool ready_for_switch = true;
    std::optional<std::string> last_error;
};

// The effective options, which is a per-miner key set by the contract's own
// admission. Credentials are masked here and not at the renderer, so no route
// can serve an unmasked one by forgetting to ask.
struct ConfigSnapshot {
    std::string algo;
    std::string url;          // userinfo stripped
    std::string user;         // masked
    std::string backend;
    std::string devices;      // as given, empty means all
    int threads = 0;
    int timeout = 0;
    int scantime = 0;
    int retries = 0;
    int time_limit = 0;
    bool benchmark = false;
    bool quiet = false;
    bool debug = false;
    bool protocol = false;

    std::optional<uint32_t> workgroup;    // empty means the backend chooses
    std::optional<uint32_t> queue_depth;
    std::optional<std::string> kernel;    // empty means the tuner's pick
    std::optional<std::string> algo_dir;
    bool no_tune = false;
    bool retune = false;
    bool no_int64 = false;
    bool vk_validate = false;

    bool api_enabled = false;
    std::string api_allow;
    int api_port = 0;
    bool api_remote = false;
    bool api_control = false;
    int api_control_min_interval = 0;
    int api_control_park_timeout = 0;
};

// ---------------------------------------------------------------- collectors

// Whether this miner is hashing right now. Defined once because five surfaces
// report it and they must not disagree. False while the control API holds the
// workers parked, and while there are no workers at all.
//
// Not gated on the pool: a dropped connection stops the work arriving and the
// rate falls to zero through the accounting that publishes it.
bool model_is_mining();

void collect_miner(MinerSnapshot *out);
void collect_summary(SummarySnapshot *out);

// One entry per worker, in worker order.
void collect_threads(std::vector<ThreadSnapshot> *out);

// One entry per device, in the order the backend enumerated them -- not one
// per worker. `--threads 4` on two cards is four threads and two devices.
void collect_devices(std::vector<DeviceSnapshot> *out);

void collect_system(SystemSnapshot *out);
void collect_pool(int index, PoolSnapshot *out);
void collect_health(HealthSnapshot *out);
void collect_control(ControlSnapshot *out);
void collect_config(ConfigSnapshot *out);

// A url with any `user:pass@` removed, for the two routes that echo one back.
// Exposed because /config and /pools both need it and neither may be the place
// it is implemented.
std::string mask_url(const char *url);

}  // namespace vkminer

#endif  // VKMINER_API_API_MODEL_H__
