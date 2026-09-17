// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The route table and the handlers behind it. The table type and the handler
// signature come from api_routes.h, which is shared with the sibling miners;
// what the handlers read is not, which is why this half is not shared.
//
// A route this miner does not answer is registered with `.available = false`
// rather than left out. The transport turns that into a 501, and the capability
// list in GET /api/v1/ is walked out of this table, so a client can tell a route
// that does not exist here from one that exists and is switched off -- and the
// list cannot claim something the router would not serve.
//
// Handlers never touch the socket: they return a status and, on success, a
// json_t the transport writes and frees.

#include "api_routes.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "algorithms/registry.h"
#include "api/api_control.h"
#include "api/api_metrics.h"
#include "api/api_model.h"

namespace {

// An empty optional is the contract's `null`, and it has to reach the wire as
// one: a field emitted as 0 says "measured, and it is zero", and a field left
// out says "this build does not serve it". Neither is what an empty optional
// means, so every nullable field goes through here.
template <typename T>
json_t *or_null(const std::optional<T> &v)
{
    if (!v)
        return json_null();
    if constexpr (std::is_floating_point<T>::value)
        return json_real(static_cast<double>(*v));
    else
        return json_integer(static_cast<json_int_t>(*v));
}

json_t *or_null(const std::optional<std::string> &v)
{
    return v ? json_string(v->c_str()) : json_null();
}

// Its own overload because the template above would take a bool through the
// integer branch and put 1 on the wire where the contract says true.
json_t *or_null(const std::optional<bool> &v)
{
    return v ? json_boolean(*v) : json_null();
}

json_t *u64(uint64_t v)
{
    return json_integer(static_cast<json_int_t>(v));
}

// ?id=N, ?index=N.
bool query_int(const char *query, const char *key, long *out)
{
    const size_t klen = strlen(key);
    for (const char *p = query; p && *p;) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            char *end = nullptr;
            const long v = strtol(p + klen + 1, &end, 10);
            if (end == p + klen + 1)
                return false;
            *out = v;
            return true;
        }
        p = strchr(p, '&');
        if (p)
            p++;
    }
    return false;
}

// The last segment of a prefix route's path. Anything after the digits is a
// rejection rather than a partial read, so /devices/0x is not device 0.
bool trailing_int(const char *path, long *out)
{
    const char *slash = strrchr(path, '/');
    if (!slash || !slash[1])
        return false;
    char *end = nullptr;
    const long v = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end)
        return false;
    *out = v;
    return true;
}

// One pool, no failover. /pools is an array of one rather than a route this
// miner does not serve, and /pools/{n} bounds-checks against this.
constexpr int kPoolCount = 1;

json_t *miner_json_object()
{
    vkminer::MinerSnapshot m;
    vkminer::collect_miner(&m);

    json_t *o = json_object();
    if (!o)
        return nullptr;
    json_object_set_new(o, "name", json_string(m.name.c_str()));
    json_object_set_new(o, "version", json_string(m.version.c_str()));
    json_object_set_new(o, "api_version", json_string(m.api_version.c_str()));
    json_object_set_new(o, "kind", json_string(m.kind.c_str()));
    return o;
}

// Every reply carries the miner envelope, errors included -- which is why the
// transport is handed a serialized copy of it as well.
json_t *envelope()
{
    json_t *root = json_object();
    if (!root)
        return nullptr;
    json_t *m = miner_json_object();
    if (!m) {
        json_decref(root);
        return nullptr;
    }
    json_object_set_new(root, "miner", m);
    return root;
}

int oom(char *errmsg, size_t errlen)
{
    snprintf(errmsg, errlen, "out of memory");
    return 500;
}

/* ------------------------------------------------------------- JSON builders
 *
 * The snapshots are flat because they mirror what the miner measures; the wire
 * shape groups. The nesting happens here and nowhere else, so a builder is the
 * only place a field name can drift from the contract.
 */

// `accepted_per_min` belongs to the shares object by the contract, but only the
// summary measures one. A pool's copy is null rather than the process-wide
// figure repeated under a name that would read as this pool's.
json_t *shares_json(const vkminer::SharesSnapshot &s,
                    const std::optional<double> &accepted_per_min)
{
    json_t *o = json_object();
    if (!o)
        return nullptr;
    json_object_set_new(o, "accepted", u64(s.accepted));
    json_object_set_new(o, "rejected", u64(s.rejected));
    json_object_set_new(o, "stale", u64(s.stale));
    json_object_set_new(o, "solved", u64(s.solved));
    json_object_set_new(o, "accepted_per_min", or_null(accepted_per_min));
    return o;
}

json_t *summary_json(const vkminer::SummarySnapshot &s)
{
    json_t *o = json_object();
    json_t *sh = shares_json(s.shares, s.accepted_per_min);
    json_t *diff = json_object();
    json_t *net = json_object();
    json_t *pools = json_object();
    if (!o || !sh || !diff || !net || !pools) {
        json_decref(o);
        json_decref(sh);
        json_decref(diff);
        json_decref(net);
        json_decref(pools);
        return nullptr;
    }

    json_object_set_new(o, "algo", json_string(s.algo.c_str()));
    json_object_set_new(o, "uptime_s", u64(s.uptime_s));
    json_object_set_new(o, "timestamp", u64(s.timestamp));
    json_object_set_new(o, "hashrate_hs", json_real(s.hashrate_hs));
    json_object_set_new(o, "hashrate_avg_hs", or_null(s.hashrate_avg_hs));
    json_object_set_new(o, "devices", json_integer(s.devices));
    json_object_set_new(o, "threads", json_integer(s.threads));
    json_object_set_new(o, "shares", sh);

    json_object_set_new(diff, "pool", or_null(s.pool_difficulty));
    json_object_set_new(diff, "network", or_null(s.network_difficulty));
    json_object_set_new(diff, "best_share", or_null(s.best_share));
    json_object_set_new(o, "difficulty", diff);

    json_object_set_new(net, "hashrate_hs", or_null(s.network_hashrate_hs));
    json_object_set_new(o, "network", net);

    json_object_set_new(pools, "count", json_integer(s.pool_count));
    json_object_set_new(pools, "active", json_integer(s.active_pool));
    json_object_set_new(pools, "wait_time_s", or_null(s.wait_time_s));
    json_object_set_new(o, "pools", pools);
    return o;
}

json_t *thread_json(const vkminer::ThreadSnapshot &t)
{
    json_t *o = json_object();
    if (!o)
        return nullptr;
    json_object_set_new(o, "id", json_integer(t.id));
    json_object_set_new(o, "device_id", json_integer(t.device_id));
    json_object_set_new(o, "hashrate_hs", json_real(t.hashrate_hs));
    json_object_set_new(o, "accepted", or_null(t.accepted));
    json_object_set_new(o, "rejected", or_null(t.rejected));
    json_object_set_new(o, "hw_errors", or_null(t.hw_errors));
    json_object_set_new(o, "intensity", or_null(t.intensity));
    json_object_set_new(o, "throughput", or_null(t.throughput));
    return o;
}

// The ids are strings in the contract and 32-bit numbers here, because the PCI
// values a user recognises are written as hex. Formatted, not stringified.
json_t *hex_id(uint32_t v)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%04x", static_cast<unsigned>(v));
    return json_string(buf);
}

json_t *device_json(const vkminer::DeviceSnapshot &d)
{
    json_t *o = json_object();
    json_t *gpu = json_object();
    json_t *vk = json_object();
    if (!o || !gpu || !vk) {
        json_decref(o);
        json_decref(gpu);
        json_decref(vk);
        return nullptr;
    }

    json_object_set_new(o, "id", json_integer(d.id));
    json_object_set_new(o, "type", json_string(d.type.c_str()));
    json_object_set_new(o, "name", json_string(d.name.c_str()));
    json_object_set_new(o, "temp_c", or_null(d.temp_c));
    json_object_set_new(o, "fan_pct", or_null(d.fan_pct));
    json_object_set_new(o, "fan_rpm", or_null(d.fan_rpm));
    json_object_set_new(o, "clock_mhz", or_null(d.clock_mhz));
    json_object_set_new(o, "mem_clock_mhz", or_null(d.mem_clock_mhz));
    json_object_set_new(o, "power_mw", or_null(d.power_mw));
    json_object_set_new(o, "power_limit_mw", or_null(d.power_limit_mw));
    json_object_set_new(o, "hashrate_hs", json_real(d.hashrate_hs));
    json_object_set_new(o, "hashrate_per_watt_khs",
                        or_null(d.hashrate_per_watt_khs));

    // The sub-object is shared with a CUDA miner, so most of it is a vendor
    // library's answers and stays null here. `monitoring` is the field that
    // says which: false means nothing above it will ever be populated on this
    // machine, which is a different statement from a card that is momentarily
    // not reporting one attribute.
    json_object_set_new(gpu, "bus_id", or_null(d.bus_id));
    json_object_set_new(gpu, "sm", json_null());
    json_object_set_new(gpu, "mem_bytes", u64(d.memory_bytes));
    json_object_set_new(gpu, "pstate", json_null());
    json_object_set_new(gpu, "base_clock_mhz", json_null());
    json_object_set_new(gpu, "base_mem_clock_mhz", json_null());
    json_object_set_new(gpu, "vendor_id", hex_id(d.vendor_id));
    json_object_set_new(gpu, "device_id", hex_id(d.device_id));
    json_object_set_new(gpu, "serial", json_null());
    json_object_set_new(gpu, "bios", json_null());
    json_object_set_new(gpu, "nvml_id", json_null());
    json_object_set_new(gpu, "nvapi_id", json_null());
    json_object_set_new(gpu, "monitoring", json_boolean(d.monitoring));
    json_object_set_new(o, "gpu", gpu);

    // No `cpu` sub-object beside it: a device carries exactly one typed
    // sub-object, and every device here is a GPU.
    const vkminer::VulkanSnapshot &v = d.vulkan;
    json_object_set_new(vk, "driver", json_string(v.driver.c_str()));
    json_object_set_new(vk, "api_version", json_string(v.api_version.c_str()));
    json_object_set_new(vk, "backend", json_string(v.backend.c_str()));
    json_object_set_new(vk, "int64", json_boolean(v.int64));
    json_object_set_new(vk, "tuned", json_boolean(v.tuned));
    json_object_set_new(vk, "workgroup", or_null(v.workgroup));
    json_object_set_new(vk, "queue_depth", or_null(v.queue_depth));
    json_object_set_new(vk, "kernel", or_null(v.kernel));
    json_object_set_new(vk, "batches_total", u64(v.batches_total));
    json_object_set_new(vk, "batches_late", u64(v.batches_late));
    json_object_set_new(vk, "shared_table_bytes", or_null(v.shared_table_bytes));
    json_object_set_new(o, "vulkan", vk);
    return o;
}

json_t *system_json(const vkminer::SystemSnapshot &s)
{
    json_t *o = json_object();
    if (!o)
        return nullptr;
    json_object_set_new(o, "os", json_string(s.os.c_str()));
    json_object_set_new(o, "driver", or_null(s.driver));
    json_object_set_new(o, "cpus", json_integer(s.cpus));
    json_object_set_new(o, "cpu_temp_c", or_null(s.cpu_temp_c));
    json_object_set_new(o, "cpu_clock_mhz", or_null(s.cpu_clock_mhz));
    json_object_set_new(o, "cpu_fan_pct", or_null(s.cpu_fan_pct));
    return o;
}

json_t *pool_json(const vkminer::PoolSnapshot &p)
{
    json_t *o = json_object();
    json_t *sh = shares_json(p.shares, std::optional<double>());
    json_t *job = json_object();
    if (!o || !sh || !job) {
        json_decref(o);
        json_decref(sh);
        json_decref(job);
        return nullptr;
    }

    json_object_set_new(o, "index", json_integer(p.index));
    json_object_set_new(o, "active", json_boolean(p.active));
    json_object_set_new(o, "name", json_string(p.name.c_str()));
    json_object_set_new(o, "url", json_string(p.url.c_str()));
    json_object_set_new(o, "user", json_string(p.user.c_str()));
    json_object_set_new(o, "algo", json_string(p.algo.c_str()));
    json_object_set_new(o, "shares", sh);
    json_object_set_new(o, "type", json_string(p.type.c_str()));
    json_object_set_new(o, "status", json_string(p.status.c_str()));
    // Also inside `shares`. Both are documented, and a client reading one is
    // not obliged to know about the other.
    json_object_set_new(o, "stale", u64(p.shares.stale));
    json_object_set_new(o, "difficulty", or_null(p.difficulty));
    json_object_set_new(o, "best_share", or_null(p.best_share));

    json_object_set_new(job, "id", or_null(p.job.id));
    json_object_set_new(job, "height", or_null(p.job.height));
    // The only field of the job object the contract does not make nullable, so
    // a pool that has not sent an extranonce yet reads 0 rather than null.
    json_object_set_new(job, "extranonce2_size",
                        json_integer(p.job.extranonce2_size
                                         ? *p.job.extranonce2_size
                                         : 0));
    json_object_set_new(job, "extranonce2", or_null(p.job.extranonce2));
    json_object_set_new(o, "job", job);

    json_object_set_new(o, "ping_ms", or_null(p.ping_ms));
    json_object_set_new(o, "disconnects", u64(p.disconnects));
    json_object_set_new(o, "wait_time_s", or_null(p.wait_time_s));
    json_object_set_new(o, "session_s", or_null(p.session_s));
    json_object_set_new(o, "last_share_age_s", or_null(p.last_share_age_s));
    return o;
}

json_t *health_json(const vkminer::HealthSnapshot &h)
{
    json_t *o = json_object();
    if (!o)
        return nullptr;
    json_object_set_new(o, "status", json_string(h.status.c_str()));
    json_object_set_new(o, "mining", json_boolean(h.mining));
    json_object_set_new(o, "pool_connected", json_boolean(h.pool_connected));
    json_object_set_new(o, "devices_ok", json_integer(h.devices_ok));

    // The one field a response may leave out rather than null: it accompanies a
    // degraded status, and an empty array beside "ok" would read as a fault
    // nobody could name.
    if (!h.reasons.empty()) {
        json_t *reasons = json_array();
        if (reasons) {
            for (const std::string &r : h.reasons)
                json_array_append_new(reasons, json_string(r.c_str()));
            json_object_set_new(o, "reasons", reasons);
        }
    }
    return o;
}

json_t *config_json(const vkminer::ConfigSnapshot &c)
{
    json_t *o = json_object();
    if (!o)
        return nullptr;

    // `user` arrives masked and `url` arrives with its userinfo stripped, both
    // done at collection so that no route can serve a credential by forgetting
    // to ask for the masked form. There is no password field on any route.
    json_object_set_new(o, "algo", json_string(c.algo.c_str()));
    json_object_set_new(o, "url", json_string(c.url.c_str()));
    json_object_set_new(o, "user", json_string(c.user.c_str()));
    json_object_set_new(o, "backend", json_string(c.backend.c_str()));
    json_object_set_new(o, "devices", json_string(c.devices.c_str()));
    json_object_set_new(o, "threads", json_integer(c.threads));
    json_object_set_new(o, "timeout", json_integer(c.timeout));
    json_object_set_new(o, "scantime", json_integer(c.scantime));
    json_object_set_new(o, "retries", json_integer(c.retries));
    json_object_set_new(o, "time_limit", json_integer(c.time_limit));
    json_object_set_new(o, "benchmark", json_boolean(c.benchmark));
    json_object_set_new(o, "quiet", json_boolean(c.quiet));
    json_object_set_new(o, "debug", json_boolean(c.debug));
    json_object_set_new(o, "protocol", json_boolean(c.protocol));

    json_object_set_new(o, "workgroup", or_null(c.workgroup));
    json_object_set_new(o, "queue_depth", or_null(c.queue_depth));
    json_object_set_new(o, "kernel", or_null(c.kernel));
    json_object_set_new(o, "algo_dir", or_null(c.algo_dir));
    json_object_set_new(o, "no_tune", json_boolean(c.no_tune));
    json_object_set_new(o, "retune", json_boolean(c.retune));
    json_object_set_new(o, "no_int64", json_boolean(c.no_int64));
    json_object_set_new(o, "vk_validate", json_boolean(c.vk_validate));

    json_object_set_new(o, "api_enabled", json_boolean(c.api_enabled));
    json_object_set_new(o, "api_allow", json_string(c.api_allow.c_str()));
    json_object_set_new(o, "api_port", json_integer(c.api_port));
    json_object_set_new(o, "api_remote", json_boolean(c.api_remote));
    json_object_set_new(o, "api_control", json_boolean(c.api_control));
    json_object_set_new(o, "api_control_min_interval",
                        json_integer(c.api_control_min_interval));
    json_object_set_new(o, "api_control_park_timeout",
                        json_integer(c.api_control_park_timeout));
    return o;
}

// `params` is an object this miner has nothing to put in, and that is a
// property of the tunables rather than an omission: a workgroup, a queue depth
// and a kernel name are per-device measurements, not properties of the
// algorithm the way scrypt's N is, so there is no parameter a manager could
// carry from one machine to another. Empty rather than null, because a client
// iterating an object should find nothing in it rather than fail to iterate.
json_t *control_json(const vkminer::ControlSnapshot &c)
{
    json_t *o = json_object();
    json_t *params = json_object();
    json_t *pool = json_object();
    if (!o || !params || !pool) {
        json_decref(o);
        json_decref(params);
        json_decref(pool);
        return nullptr;
    }

    json_object_set_new(o, "state", json_string(c.state.c_str()));
    json_object_set_new(o, "epoch", u64(c.epoch));
    json_object_set_new(o, "since_s", u64(c.since_s));
    json_object_set_new(o, "algo", json_string(c.algo.c_str()));
    json_object_set_new(o, "params", params);

    json_object_set_new(pool, "index", json_integer(c.pool_index));
    json_object_set_new(pool, "url", json_string(c.pool_url.c_str()));
    json_object_set_new(pool, "user", json_string(c.pool_user.c_str()));
    json_object_set_new(o, "pool", pool);

    json_object_set_new(o, "pool_connected", or_null(c.pool_connected));
    json_object_set_new(o, "threads_total", json_integer(c.threads_total));
    json_object_set_new(o, "threads_parked", json_integer(c.threads_parked));
    json_object_set_new(o, "switch_count", u64(c.switch_count));
    json_object_set_new(o, "last_switch_age_s", or_null(c.last_switch_age_s));
    json_object_set_new(o, "min_interval_s", json_integer(c.min_interval_s));
    json_object_set_new(o, "ready_for_switch", json_boolean(c.ready_for_switch));
    json_object_set_new(o, "last_error", or_null(c.last_error));
    return o;
}

// Attaches a payload to a fresh envelope, decref'ing both on the way out if
// either allocation failed. Every read handler ends in this.
int respond(json_t *payload, const char *key, json_t **out, char *e, size_t n)
{
    json_t *root = envelope();
    if (!root || !payload) {
        json_decref(root);
        json_decref(payload);
        return oom(e, n);
    }
    json_object_set_new(root, key, payload);
    *out = root;
    return 200;
}

// The body of a write request, as an object. No body at all is an empty one
// rather than an error, so a route whose fields are all optional needs no
// special case; anything else that is not a JSON object is a 400, because a
// handler reading fields off a number or an array is how a wrong body type
// becomes a crash. Returns NULL with *status set, and never both.
json_t *parse_body(const api_request *req, char *e, size_t n, int *status)
{
    *status = 200;

    if (!req->body_len) {
        json_t *empty = json_object();
        if (!empty)
            *status = oom(e, n);
        return empty;
    }

    json_error_t err;
    json_t *root = json_loads(req->body, 0, &err);
    if (!root) {
        snprintf(e, n, "invalid JSON: %s", err.text);
        *status = 400;
        return NULL;
    }
    if (!json_is_object(root)) {
        json_decref(root);
        snprintf(e, n, "body must be a JSON object");
        *status = 400;
        return NULL;
    }
    return root;
}

// A control result says what happened, not what to answer with; this is the
// whole of the translation. Both 200 and 202 are success, and kInvalid is a 400
// because a request that could not be carried out at all was malformed -- it is
// answered ahead of the throttle, so a bad url reads as bad whatever the clock
// says.
int control_http_status(vkminer::ControlResult rc)
{
    switch (rc) {
    case vkminer::ControlResult::kOk:        return 200;
    case vkminer::ControlResult::kAccepted:  return 202;
    case vkminer::ControlResult::kBusy:      return 409;
    case vkminer::ControlResult::kTimeout:   return 409;
    case vkminer::ControlResult::kThrottled: return 429;
    case vkminer::ControlResult::kDisabled:  return 403;
    case vkminer::ControlResult::kInvalid:   return 400;
    }
    return 500;
}

// The uniform error envelope has no slot for a number, and the contract puts
// the retry delay in a field because a client may not read it out of a message.
// So a 429, and only a 429, builds its own body here -- which works because the
// serve loop keeps any body a handler supplies at >= 400.
//
// Every other status falls through to the transport, and so does a 429 whose
// body will not allocate: a refusal missing the field beats no refusal at all.
int control_error(int http, const char *msg, json_t **out)
{
    if (http != 429)
        return http;

    const vkminer::ControlStatus st = vkminer::control_status();
    json_t *root = envelope();
    json_t *err = json_object();
    if (!root || !err) {
        json_decref(root);
        json_decref(err);
        return http;
    }

    // Read a moment after the refusal decided it, so the interval may have run
    // out in between and left this at zero. The contract promises at least one
    // second, and a caller told to come back in no time has been told nothing.
    const int wait = st.retry_after_s > 0 ? st.retry_after_s : 1;

    json_object_set_new(err, "code", json_string(api_http_error_code(http)));
    json_object_set_new(err, "message",
                        json_string(msg && *msg ? msg : "too many requests"));
    json_object_set_new(err, "status", json_integer(http));
    json_object_set_new(err, "retry_after_s", json_integer(wait));
    json_object_set_new(root, "error", err);
    *out = root;
    return http;
}

// The name of the offending key, or NULL if every one of them is known. An
// object this refuses is one a client believes was understood.
const char *unknown_key(json_t *o, const char *const *known, size_t count)
{
    const char *key = NULL;
    json_t *val = NULL;

    json_object_foreach(o, key, val) {
        (void)val;
        bool ok = false;
        for (size_t i = 0; i < count && !ok; i++)
            ok = strcmp(key, known[i]) == 0;
        if (!ok)
            return key;
    }
    return NULL;
}

// The wire's `wait_ms`, if the body carries one.
//
// Absent is not zero. The control layer reads 0 as "wait out
// --api-control-park-timeout"; the contract reads it as "do not wait, answer
// 202 and I will poll". So an absent field gets the layer's meaning and a
// literal 0 gets the shortest wait there is. The translation is here because
// the layer's other callers are inside the miner and mean what it says.
bool wait_ms_field(json_t *body, unsigned *out, char *e, size_t n, int *status)
{
    *out = 0;
    *status = 200;

    json_t *jw = json_object_get(body, "wait_ms");
    if (!jw)
        return true;
    if (!json_is_integer(jw) || json_integer_value(jw) < 0) {
        snprintf(e, n, "wait_ms must be a non-negative integer");
        *status = 400;
        return false;
    }

    // No upper guard: a wait longer than the park timeout is cut back to it
    // inside the request, so a client asking for an hour waits what everyone
    // else waits.
    const json_int_t v = json_integer_value(jw);
    *out = v > 0 ? static_cast<unsigned>(v > 3600000 ? 3600000 : v) : 1u;
    return true;
}

// The body of an accepted start/pause/stop: the state as it is now, not the
// one that was asked for.
//
// Reading it also settles a mutation that has landed since the request
// returned, so a 202 can carry the state the caller wanted. That is not a
// contradiction -- the 202 says the answer was written before the change was
// certain, and a manager that polls once finds the epoch already advanced.
int control_result_respond(int http, json_t **out, char *e, size_t n)
{
    const vkminer::ControlStatus st = vkminer::control_status();

    json_t *res = json_object();
    if (!res)
        return oom(e, n);
    json_object_set_new(res, "state",
                        json_string(vkminer::control_state_name(st.state)));
    json_object_set_new(res, "epoch", u64(st.epoch));
    json_object_set_new(res, "parked", json_integer(st.parked));

    // Only on the 202. On a 200 there is nothing left to poll for, and a path
    // that says otherwise is one a client will follow.
    if (http == 202)
        json_object_set_new(res, "poll", json_string("/api/v1/control/state"));

    const int status = respond(res, "result", out, e, n);
    return status == 200 ? http : status;
}

// start, pause and stop differ in one enumerator and nothing else, so they are
// one function: three copies would be three places for the body check or the
// status mapping to drift apart.
int control_verb(const api_request *req, vkminer::ControlState want,
                 json_t **out, char *e, size_t n)
{
    int status = 200;
    json_t *body = parse_body(req, e, n, &status);
    if (!body)
        return status;

    static const char *const known[] = { "wait_ms" };
    const char *bad = unknown_key(body, known, 1);
    if (bad) {
        snprintf(e, n, "unknown field '%s'", bad);
        json_decref(body);
        return 400;
    }

    unsigned wait_ms = 0;
    const bool ok = wait_ms_field(body, &wait_ms, e, n, &status);
    json_decref(body);
    if (!ok)
        return status;

    std::string why;
    const vkminer::ControlResult rc =
        vkminer::control_request(want, wait_ms, &why);
    const int http = control_http_status(rc);
    if (http >= 400) {
        snprintf(e, n, "%s",
                 why.empty() ? "the run state was not changed" : why.c_str());
        return control_error(http, e, out);
    }
    return control_result_respond(http, out, e, n);
}

// ------------------------------------------------------------------ /metrics

// The snapshots an exposition is rendered from, kept in one place because
// api_metrics_input stores `const char *` for the top-level labels: they point
// into these strings, so the sources have to outlive the render call.
struct MetricsSources {
    vkminer::MinerSnapshot miner;
    vkminer::SummarySnapshot summary;
    vkminer::ControlSnapshot control;
    std::vector<vkminer::DeviceSnapshot> devices;
    vkminer::PoolSnapshot pool;
    bool pool_present = false;
};

void metrics_fill(MetricsSources *src, api_metrics_input *in)
{
    vkminer::collect_miner(&src->miner);
    vkminer::collect_summary(&src->summary);
    vkminer::collect_control(&src->control);
    vkminer::collect_devices(&src->devices);
    vkminer::collect_pool(0, &src->pool);
    src->pool_present = !src->pool.url.empty();

    memset(in, 0, sizeof(*in));
    in->name = src->miner.name.c_str();
    in->version = src->miner.version.c_str();
    in->kind = src->miner.kind.c_str();
    in->algo = src->summary.algo.c_str();
    in->control_state = src->control.state.c_str();

    in->mining_active = vkminer::model_is_mining();
    in->uptime_s = static_cast<double>(src->summary.uptime_s);
    in->hashrate_hs = src->summary.hashrate_hs;

    // An absent difficulty is an absent series, not a zero: --benchmark has no
    // chain, and the seconds before the first job have no pool difficulty.
    in->has_net_difficulty = src->summary.network_difficulty.has_value();
    in->net_difficulty = src->summary.network_difficulty.value_or(0.);
    in->has_pool_difficulty = src->summary.pool_difficulty.has_value();
    in->pool_difficulty = src->summary.pool_difficulty.value_or(0.);

    in->shares_accepted = src->summary.shares.accepted;
    in->shares_rejected = src->summary.shares.rejected;
    in->shares_stale = src->summary.shares.stale;
    in->blocks_solved = src->summary.shares.solved;

    for (const vkminer::DeviceSnapshot &d : src->devices) {
        if (in->ndevices >= API_METRICS_MAX_DEVICES)
            break;
        api_metrics_device *md = &in->devices[in->ndevices++];
        md->valid = true;
        md->device = d.id;
        snprintf(md->type, sizeof(md->type), "%s", d.type.c_str());
        snprintf(md->algo, sizeof(md->algo), "%s", src->summary.algo.c_str());
        md->hashrate_hs = d.hashrate_hs;
        if (d.temp_c) {
            md->has_temp = true;
            md->temp_c = *d.temp_c;
        }
        if (d.power_mw) {
            md->has_power = true;
            md->power_w = static_cast<double>(*d.power_mw) / 1000.;
        }
        if (d.fan_pct) {
            md->has_fan = true;
            md->fan_pct = static_cast<double>(*d.fan_pct);
        }
        // has_hw_errors stays false. The counter that would fill it is
        // process-wide, and metrics_extra() publishes it unlabelled.
    }

    // No url means no pool to report on -- a benchmark run has none, and a
    // series labelled with an empty pool would be one a dashboard groups by.
    if (src->pool_present) {
        api_metrics_pool *mp = &in->pools[in->npools++];
        mp->index = src->pool.index;
        mp->active = src->pool.active;
        snprintf(mp->url, sizeof(mp->url), "%s", src->pool.url.c_str());
        mp->stratum = src->pool.type == "stratum";
        mp->connected = src->pool.status == "connected";
        mp->disconnects = src->pool.disconnects;
        if (src->pool.last_share_age_s) {
            mp->has_last_share = true;
            mp->last_share_age_s =
                static_cast<double>(*src->pool.last_share_age_s);
        }
    }
}

// A printf into a fixed buffer that stops at the first thing that does not
// fit, the shape the shared renderer uses for the families above these.
struct MetricsSink {
    char *buf;
    size_t cap;
    size_t len;
    bool overflow;
};

void metrics_emit(MetricsSink *s, const char *fmt, ...)
{
    if (s->overflow)
        return;

    va_list ap;
    va_start(ap, fmt);
    const int wrote = vsnprintf(s->buf + s->len, s->cap - s->len, fmt, ap);
    va_end(ap);

    if (wrote < 0 || static_cast<size_t>(wrote) >= s->cap - s->len) {
        s->overflow = true;
        return;
    }
    s->len += static_cast<size_t>(wrote);
}

// The families that are this miner's and not the shared set's, appended after
// the render because api_metrics.c is byte-shared with the sibling miners and
// its family list is fixed. Returns the bytes written, or 0 if they did not
// fit -- never a partial one, for the same reason the renderer will not.
size_t metrics_extra(const MetricsSources &src, char *buf, size_t cap)
{
    MetricsSink s = { buf, cap, 0, false };

    metrics_emit(&s, "# HELP miner_device_batches_total Batches dispatched to"
                     " the device since process start.\n"
                     "# TYPE miner_device_batches_total counter\n");
    for (const vkminer::DeviceSnapshot &d : src.devices)
        metrics_emit(&s, "miner_device_batches_total{device=\"%d\"} %llu\n",
                     d.id,
                     static_cast<unsigned long long>(d.vulkan.batches_total));

    metrics_emit(&s, "# HELP miner_device_batches_late_total Batches whose"
                     " result arrived after the job had moved on.\n"
                     "# TYPE miner_device_batches_late_total counter\n");
    for (const vkminer::DeviceSnapshot &d : src.devices)
        metrics_emit(&s,
                     "miner_device_batches_late_total{device=\"%d\"} %llu\n",
                     d.id,
                     static_cast<unsigned long long>(d.vulkan.batches_late));

    // Unlabelled, where the contract's own hw_errors family is per device:
    // nothing here attributes a disagreement to the card that produced it, and
    // a device="0" on a process-wide total would be a fabrication on any rig
    // with a second card. Zero is the reading a healthy run has, so these two
    // are published at zero rather than left absent.
    metrics_emit(&s,
                 "# HELP miner_host_disagreements_total Candidates the device"
                 " returned that the host did not confirm.\n"
                 "# TYPE miner_host_disagreements_total counter\n"
                 "miner_host_disagreements_total{reason=\"below_target\"} %llu\n"
                 "miner_host_disagreements_total{reason=\"wrong_digest\"} %llu\n",
                 static_cast<unsigned long long>(
                     src.summary.disagree_below_target),
                 static_cast<unsigned long long>(
                     src.summary.disagree_wrong_digest));

    return s.overflow ? 0 : s.len;
}

}  // namespace

// api_handler_fn was declared in a C header, so the functions the table stores
// in it need C language linkage too. `static` inside the specification still
// keeps them out of the link.
extern "C" {

// GET /api/v1/ -- what this build serves, derived from the table below so that
// it cannot claim a route the router would answer 501 for.
static int h_index(const api_request *req, void *ctx, json_t **out,
                   char *e, size_t n)
{
    (void)req;
    (void)ctx;

    json_t *root = envelope();
    if (!root)
        return oom(e, n);

    json_t *index = json_object();
    json_t *caps = json_array();
    json_t *links = json_object();
    if (!index || !caps || !links) {
        json_decref(root);
        if (index)
            json_decref(index);
        if (caps)
            json_decref(caps);
        if (links)
            json_decref(links);
        return oom(e, n);
    }

    size_t count = 0;
    const api_route *routes = api_routes_get(&count);
    for (size_t i = 0; i < count; i++) {
        if (!routes[i].available)
            continue;

        const char *p = routes[i].path;
        if (strcmp(p, "/metrics") == 0) {
            json_array_append_new(caps, json_string("metrics"));
            continue;
        }
        if (strncmp(p, "/api/v1/", 8) != 0)
            continue;
        const char *name = p + 8;
        if (!*name)
            continue;  // the index itself

        char buf[64];
        snprintf(buf, sizeof(buf), "%s", name);
        size_t l = strlen(buf);
        if (l && buf[l - 1] == '/')
            buf[l - 1] = '\0';  // a prefix route and its exact twin are one name
        for (char *s = buf; *s; s++)
            if (*s == '/')
                *s = '.';

        bool seen = false;
        const size_t have = json_array_size(caps);
        for (size_t k = 0; k < have; k++) {
            const char *ex = json_string_value(json_array_get(caps, k));
            if (ex && strcmp(ex, buf) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen)
            json_array_append_new(caps, json_string(buf));
    }

    json_object_set_new(links, "summary", json_string("/api/v1/summary"));
    json_object_set_new(links, "devices", json_string("/api/v1/devices"));
    json_object_set_new(index, "capabilities", caps);
    json_object_set_new(index, "links", links);
    json_object_set_new(root, "index", index);
    *out = root;
    return 200;
}

// GET /api/v1/summary
static int h_summary(const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n)
{
    (void)req;
    (void)ctx;

    vkminer::SummarySnapshot s;
    vkminer::collect_summary(&s);
    return respond(summary_json(s), "summary", out, e, n);
}

// GET /api/v1/threads, optionally ?id=N
static int h_threads(const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n)
{
    (void)ctx;

    long want = -1;
    const bool filtered = query_int(req->query, "id", &want);

    std::vector<vkminer::ThreadSnapshot> threads;
    vkminer::collect_threads(&threads);

    json_t *arr = json_array();
    if (!arr)
        return oom(e, n);

    bool matched = false;
    for (const vkminer::ThreadSnapshot &t : threads) {
        if (filtered && t.id != static_cast<int>(want))
            continue;
        matched = true;
        json_t *o = thread_json(t);
        if (o)
            json_array_append_new(arr, o);
    }

    // A filter that matched nothing is a 404, not an empty array: the client
    // named a thread, and an empty list would read as "it exists and is idle".
    if (filtered && !matched) {
        json_decref(arr);
        snprintf(e, n, "no such thread");
        return 404;
    }
    return respond(arr, "threads", out, e, n);
}

// GET /api/v1/devices
static int h_devices(const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n)
{
    (void)req;
    (void)ctx;

    std::vector<vkminer::DeviceSnapshot> devices;
    vkminer::collect_devices(&devices);

    json_t *arr = json_array();
    if (!arr)
        return oom(e, n);
    for (const vkminer::DeviceSnapshot &d : devices) {
        json_t *o = device_json(d);
        if (o)
            json_array_append_new(arr, o);
    }
    return respond(arr, "devices", out, e, n);
}

// GET /api/v1/devices/{id}
static int h_device(const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n)
{
    (void)ctx;

    std::vector<vkminer::DeviceSnapshot> devices;
    vkminer::collect_devices(&devices);

    long id = 0;
    if (!trailing_int(req->path, &id) || id < 0 ||
        static_cast<size_t>(id) >= devices.size()) {
        snprintf(e, n, "no such device");
        return 404;
    }
    return respond(device_json(devices[static_cast<size_t>(id)]), "device",
                   out, e, n);
}

// GET /api/v1/system
static int h_system(const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n)
{
    (void)req;
    (void)ctx;

    vkminer::SystemSnapshot s;
    vkminer::collect_system(&s);
    return respond(system_json(s), "system", out, e, n);
}

// GET /api/v1/pools, optionally ?index=N
static int h_pools(const api_request *req, void *ctx, json_t **out,
                   char *e, size_t n)
{
    (void)ctx;

    long want = -1;
    const bool filtered = query_int(req->query, "index", &want);

    json_t *arr = json_array();
    if (!arr)
        return oom(e, n);

    for (int i = 0; i < kPoolCount; i++) {
        if (filtered && i != static_cast<int>(want))
            continue;
        vkminer::PoolSnapshot p;
        vkminer::collect_pool(i, &p);
        json_t *o = pool_json(p);
        if (o)
            json_array_append_new(arr, o);
    }

    if (filtered && json_array_size(arr) == 0) {
        json_decref(arr);
        snprintf(e, n, "no such pool");
        return 404;
    }
    return respond(arr, "pools", out, e, n);
}

// GET /api/v1/pools/{n}
static int h_pool(const api_request *req, void *ctx, json_t **out,
                  char *e, size_t n)
{
    (void)ctx;

    long idx = 0;
    if (!trailing_int(req->path, &idx) || idx < 0 || idx >= kPoolCount) {
        snprintf(e, n, "no such pool");
        return 404;
    }
    vkminer::PoolSnapshot p;
    vkminer::collect_pool(static_cast<int>(idx), &p);
    return respond(pool_json(p), "pool", out, e, n);
}

// GET /api/v1/health
static int h_health(const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n)
{
    (void)req;
    (void)ctx;

    vkminer::HealthSnapshot h;
    vkminer::collect_health(&h);

    const int status = respond(health_json(h), "health", out, e, n);
    if (status != 200)
        return status;

    // A degraded miner answers 503 carrying the health body, not an error
    // envelope: the point of the route is the reasons, and a monitor that gets
    // an error object learns only that something is wrong. Nothing else in this
    // file returns a non-2xx with a payload, which is why it is spelled out
    // here rather than left to the transport.
    return h.status == "ok" ? 200 : 503;
}

// GET /api/v1/config -- the effective options, a per-miner key set by the
// contract's own admission.
static int h_config(const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n)
{
    (void)req;
    (void)ctx;

    vkminer::ConfigSnapshot c;
    vkminer::collect_config(&c);
    return respond(config_json(c), "config", out, e, n);
}

// GET /api/v1/algos -- what this build can be asked to mine, so that a manager
// needs no hardcoded table.
static int h_algos(const api_request *req, void *ctx, json_t **out,
                   char *e, size_t n)
{
    (void)req;
    (void)ctx;

    json_t *arr = json_array();
    if (!arr)
        return oom(e, n);

    // The registry publishes its names as one comma-separated string, because
    // its other caller is an error message. Split rather than add a second
    // accessor that could list a different set.
    const std::string names = vkminer::algorithm_names();
    for (size_t at = 0; at <= names.size();) {
        const size_t end = names.find(',', at);
        std::string one = names.substr(
            at, end == std::string::npos ? std::string::npos : end - at);
        at = end == std::string::npos ? names.size() + 1 : end + 1;

        const size_t first = one.find_first_not_of(" \t");
        if (first == std::string::npos)
            continue;
        one = one.substr(first, one.find_last_not_of(" \t") - first + 1);

        json_t *a = json_object();
        if (!a)
            continue;
        json_object_set_new(a, "name", json_string(one.c_str()));
        // Empty, and not a placeholder: an algorithm here takes no per-algorithm
        // parameters, so there is nothing a client could be allowed to send.
        json_object_set_new(a, "params", json_array());
        json_array_append_new(arr, a);
    }
    return respond(arr, "algos", out, e, n);
}

// POST /api/v1/pools/url -- mine for a different pool without a restart.
//
// The three fields stay separate and are never assembled into a packed url: a
// url carrying credentials reaches the log and the /pools body.
//
// Refused 403 while --api-control is off, even though this is a write and
// --api-remote is what admits a write: parking every worker and replacing the
// pool is the operation the control gate exists to withhold, so serving it
// here would be a way round that gate.
//
// The wait is unbounded because control_pool_request() bounds it at
// --api-control-park-timeout. The contract gives this route no wait_ms and no
// 202; a client wanting the polling shape asks /control/profile with a pool.
static int h_pools_url(const api_request *req, void *ctx, json_t **out,
                       char *e, size_t n)
{
    (void)ctx;

    int status = 200;
    json_t *body = parse_body(req, e, n, &status);
    if (!body)
        return status;

    json_t *jurl = json_object_get(body, "url");
    json_t *juser = json_object_get(body, "user");
    json_t *jpass = json_object_get(body, "pass");

    if (!json_is_string(jurl)) {
        json_decref(body);
        snprintf(e, n, "url is required and must be a string");
        return 400;
    }
    if ((juser && !json_is_string(juser)) ||
        (jpass && !json_is_string(jpass))) {
        json_decref(body);
        snprintf(e, n, "user and pass must be strings");
        return 400;
    }

    const std::string url = json_string_value(jurl);
    const std::string user = juser ? json_string_value(juser) : "";
    const std::string pass = jpass ? json_string_value(jpass) : "";
    json_decref(body);

    // The scheme guard lives with the re-target and not here: a url this miner
    // cannot mine against is kInvalid, refused with nothing parked and nothing
    // disconnected, and a second copy of the rule in this file would be a
    // second rule.
    std::string why;
    const vkminer::ControlResult rc =
        vkminer::control_pool_request(url, user, pass, 0, &why);

    if (rc != vkminer::ControlResult::kOk &&
        rc != vkminer::ControlResult::kAccepted) {
        if (rc == vkminer::ControlResult::kDisabled)
            snprintf(e, n, "re-targeting the pool needs --api-control");
        else
            snprintf(e, n, "%s",
                     why.empty() ? "the pool was not changed" : why.c_str());
        return control_error(control_http_status(rc), e, out);
    }

    json_t *res = json_object();
    if (!res)
        return oom(e, n);
    json_object_set_new(res, "ok", json_true());

    status = respond(res, "result", out, e, n);
    return status == 200 ? control_http_status(rc) : status;
}

// POST /api/v1/quit
static int h_quit(const api_request *req, void *ctx, json_t **out,
                  char *e, size_t n)
{
    (void)req;

    json_t *root = envelope();
    if (!root)
        return oom(e, n);
    json_t *res = json_object();
    if (!res) {
        json_decref(root);
        return oom(e, n);
    }
    json_object_set_new(res, "ok", json_true());
    json_object_set_new(root, "result", res);

    // Only the flag. The server acts on it after this response has been
    // written, so the client always sees its 200 rather than a closed socket.
    if (ctx)
        static_cast<api_ctx *>(ctx)->quit_requested = true;

    *out = root;
    return 200;
}

// GET /api/v1/control/state -- what a manager polls.
//
// A read by the privilege table and still refused without --api-control. The
// two gates are not the same one: --api-remote says who may write, the control
// flag says whether this miner may be driven at all, and contract section 2
// says the /control/ routes answer 403 without it. The transport enforces that
// for the four mutations because their privilege is CONTROL; this one is READ,
// so the check is here, and it answers with the transport's own wording so a
// client cannot tell which layer refused it.
static int h_control_state(const api_request *req, void *ctx, json_t **out,
                           char *e, size_t n)
{
    (void)req;
    (void)ctx;

    if (!vkminer::control_enabled()) {
        snprintf(e, n, "control API disabled (--api-control)");
        return 403;
    }

    vkminer::ControlSnapshot c;
    vkminer::collect_control(&c);
    return respond(control_json(c), "control", out, e, n);
}

// POST /api/v1/control/start
static int h_control_start(const api_request *req, void *ctx, json_t **out,
                           char *e, size_t n)
{
    (void)ctx;
    return control_verb(req, vkminer::ControlState::kRunning, out, e, n);
}

// POST /api/v1/control/pause
static int h_control_pause(const api_request *req, void *ctx, json_t **out,
                           char *e, size_t n)
{
    (void)ctx;
    return control_verb(req, vkminer::ControlState::kPaused, out, e, n);
}

// POST /api/v1/control/stop
static int h_control_stop(const api_request *req, void *ctx, json_t **out,
                          char *e, size_t n)
{
    (void)ctx;
    return control_verb(req, vkminer::ControlState::kStopped, out, e, n);
}

// POST /api/v1/control/profile -- a whole profile, applied or refused whole.
//
// Every legal body reaches here: algo+pool, pool alone, run alone, and those
// combined. One park and one epoch carry all of it, so a step that fails leaves
// none of the rest moved.
//
// `params` is a difference rather than a gap: this miner's tunables are
// per-device measurements taken by the sweep, not request fields. An empty
// object is a no-op; any key inside it is named and refused.
//
// An `algo` without a `pool` is 400: mining one algorithm against a pool
// selling another is 100% rejected shares with every other metric healthy.
// Unknown fields are refused for the same reason -- ignoring one lets a manager
// believe something it sent was applied.
static int h_control_profile(const api_request *req, void *ctx, json_t **out,
                             char *e, size_t n)
{
    (void)ctx;

    int status = 200;
    json_t *body = parse_body(req, e, n, &status);
    if (!body)
        return status;

    static const char *const known[] = { "algo", "params", "pool", "run",
                                         "wait_ms" };
    const char *bad = unknown_key(body, known, 5);
    if (bad) {
        snprintf(e, n, "unknown field '%s'", bad);
        json_decref(body);
        return 400;
    }

    json_t *jalgo = json_object_get(body, "algo");
    json_t *jparams = json_object_get(body, "params");
    json_t *jpool = json_object_get(body, "pool");
    json_t *jrun = json_object_get(body, "run");

    if ((jalgo && !json_is_string(jalgo)) ||
        (jparams && !json_is_object(jparams)) ||
        (jpool && !json_is_object(jpool)) ||
        (jrun && !json_is_boolean(jrun))) {
        json_decref(body);
        snprintf(e, n, "algo is a string, params and pool are objects, "
                       "run is a boolean");
        return 400;
    }
    if (!jalgo && !jparams && !jpool && !jrun) {
        json_decref(body);
        snprintf(e, n, "the body must carry at least one of algo, params, "
                       "pool, run");
        return 400;
    }

    // Ahead of everything this miner might have to say about the algorithm,
    // because the pairing is structural: mining X against a pool expecting Y
    // is 100% rejected shares with every other metric healthy, and a miner
    // that ever best-efforts it teaches a manager that the field is optional.
    if (jalgo && !jpool) {
        json_decref(body);
        snprintf(e, n, "algo requires pool: an algorithm without the pool that "
                       "sells it is not a profile");
        return 400;
    }

    // No parameters in v1, so any key at all is unknown and named as such.
    if (jparams) {
        const char *p = unknown_key(jparams, NULL, 0);
        if (p) {
            json_decref(body);
            snprintf(e, n, "unknown parameter '%s': this miner takes none, its "
                           "tunables are per-device measurements", p);
            return 400;
        }
    }

    std::string url, user, pass;
    if (jpool) {
        static const char *const pkeys[] = { "url", "user", "pass" };
        const char *p = unknown_key(jpool, pkeys, 3);
        if (p) {
            json_decref(body);
            snprintf(e, n, "unknown field 'pool.%s'", p);
            return 400;
        }

        json_t *jurl = json_object_get(jpool, "url");
        json_t *juser = json_object_get(jpool, "user");
        json_t *jpass = json_object_get(jpool, "pass");
        if (!json_is_string(jurl)) {
            json_decref(body);
            snprintf(e, n, "pool.url is required and must be a string");
            return 400;
        }
        if ((juser && !json_is_string(juser)) ||
            (jpass && !json_is_string(jpass))) {
            json_decref(body);
            snprintf(e, n, "pool.user and pool.pass must be strings");
            return 400;
        }
        url = json_string_value(jurl);
        user = juser ? json_string_value(juser) : "";
        pass = jpass ? json_string_value(jpass) : "";
    }

    unsigned wait_ms = 0;
    if (!wait_ms_field(body, &wait_ms, e, n, &status)) {
        json_decref(body);
        return status;
    }

    // Everything the body says, off the body, before it is freed.
    const bool has_algo = jalgo != NULL;
    const bool has_pool = jpool != NULL;
    const bool has_run = jrun != NULL;
    const bool run = jrun && json_is_true(jrun);
    const std::string algo = has_algo ? json_string_value(jalgo) : "";
    json_decref(body);

    vkminer::ControlSnapshot cur;
    vkminer::collect_control(&cur);

    // The state table's `switching` row is 409 for every verb. The barrier
    // would answer this one too, and in the same terms; asking here is what
    // keeps the message the state table's rather than the mutex's.
    if (cur.state == "switching") {
        snprintf(e, n, "another change is already in progress");
        return 409;
    }

    // One pass of the barrier for all of it: the workers park once, algorithm
    // and pool move on the far side of that park, and the run state is what
    // they are released into. A failure at any step rolls all three back.
    const vkminer::ControlState want = run ? vkminer::ControlState::kRunning
                                           : vkminer::ControlState::kPaused;
    const vkminer::ControlState *target = has_run ? &want : nullptr;

    std::string why;
    vkminer::ControlResult rc = vkminer::ControlResult::kOk;

    // An `algo` naming what is already running goes the pool's way instead.
    // Both are the same barrier; the algorithm path additionally drops every
    // device's shared table and rebuilds it, which on a ProgPoW fork is
    // gigabytes and seconds spent arriving where the miner already was.
    if (has_pool && has_algo && algo != cur.algo)
        rc = vkminer::control_algo_request(algo, url, user, pass, wait_ms, &why,
                                           target);
    else if (has_pool)
        rc = vkminer::control_pool_request(url, user, pass, wait_ms, &why,
                                           target);
    else if (has_run)
        rc = vkminer::control_request(want, wait_ms, &why);

    const int http = control_http_status(rc);
    if (http >= 400) {
        snprintf(e, n, "%s",
                 why.empty() ? "the profile was not applied" : why.c_str());
        return control_error(http, e, out);
    }

    // The resulting state rather than an ok flag, both times: the contract
    // makes this the one mutation whose answer is a /control/state body, so
    // that a manager reads the epoch it has to compare against without a
    // second call.
    vkminer::ControlSnapshot after;
    vkminer::collect_control(&after);
    status = respond(control_json(after), "control", out, e, n);
    return status == 200 ? http : status;
}

// GET /metrics -- Prometheus text exposition.
//
// A text handler, not a json one: the body is an exposition and the route names
// its own content type, so nothing here goes through the miner envelope. The
// transport frees the buffer this leaves in *out.
static int h_metrics(const api_request *req, void *ctx, char **out,
                     char *e, size_t n)
{
    (void)req;
    (void)ctx;

    MetricsSources src;
    api_metrics_input in;
    metrics_fill(&src, &in);

    // One allocation for the whole exposition. The renderer answers 0 rather
    // than truncating, and a truncated exposition is worse than none: a scraper
    // reads it as a family that has stopped existing.
    const size_t cap = 64 * 1024;
    char *buf = static_cast<char *>(malloc(cap));
    if (!buf)
        return oom(e, n);

    const size_t len = api_metrics_render(&in, buf, cap);
    if (!len || !metrics_extra(src, buf + len, cap - len)) {
        free(buf);
        snprintf(e, n, "metrics exposition did not fit");
        return 500;
    }

    *out = buf;
    return 200;
}

// Registered for the routes that answer 501. The transport returns before it
// reaches a handler, so this never runs; it is here so that flipping
// `.available` is the only edit a route needs.
static int h_unavailable(const api_request *req, void *ctx, json_t **out,
                         char *e, size_t n)
{
    (void)req;
    (void)ctx;
    (void)out;
    snprintf(e, n, "not implemented");
    return 501;
}

}  // extern "C"

static const api_route g_routes[] = {
    { API_M_GET,  "/api/v1",              API_PRIV_READ, true,  h_index, NULL, NULL },

    // Read routes.
    { API_M_GET,  "/api/v1/summary",      API_PRIV_READ, true,  h_summary, NULL, NULL },
    { API_M_GET,  "/api/v1/threads",      API_PRIV_READ, true,  h_threads, NULL, NULL },
    { API_M_GET,  "/api/v1/devices",      API_PRIV_READ, true,  h_devices, NULL, NULL },
    { API_M_GET,  "/api/v1/devices/",     API_PRIV_READ, true,  h_device,  NULL, NULL },
    { API_M_GET,  "/api/v1/system",       API_PRIV_READ, true,  h_system,  NULL, NULL },
    { API_M_GET,  "/api/v1/pools",        API_PRIV_READ, true,  h_pools,   NULL, NULL },
    { API_M_GET,  "/api/v1/pools/",       API_PRIV_READ, true,  h_pool,    NULL, NULL },
    { API_M_GET,  "/api/v1/health",       API_PRIV_READ, true,  h_health,  NULL, NULL },
    { API_M_GET,  "/api/v1/config",       API_PRIV_READ, true,  h_config,  NULL, NULL },
    { API_M_GET,  "/api/v1/algos",        API_PRIV_READ, true,  h_algos,   NULL, NULL },

    // Permanently 501, and the reason is the same for all three: they describe
    // a per-job record of scanned nonce ranges, for resume and for dedup. The
    // workers here take disjoint ranges by construction and roll the extranonce
    // per batch, so there is no such log and nothing that wants one.
    { API_M_GET,  "/api/v1/history",      API_PRIV_READ, false, h_unavailable, NULL, NULL },
    { API_M_GET,  "/api/v1/scanlog",      API_PRIV_READ, false, h_unavailable, NULL, NULL },
    { API_M_GET,  "/api/v1/meminfo",      API_PRIV_READ, false, h_unavailable, NULL, NULL },

    // Permanently 501 as well: one pool means no array to switch within.
    { API_M_POST, "/api/v1/pools/switch", API_PRIV_WRITE, false, h_unavailable, NULL, NULL },

    // Write routes. API_PRIV_WRITE is what makes the transport answer 403
    // without --api-remote, and 401 first when --api-token is set.
    { API_M_POST, "/api/v1/pools/url",    API_PRIV_WRITE, true,  h_pools_url,   NULL, NULL },
    { API_M_POST, "/api/v1/quit",         API_PRIV_WRITE, true,  h_quit,        NULL, NULL },

    // Run control. Reading the state is a read; the mutations are
    // API_PRIV_CONTROL, which the transport also gates on --api-control.
    { API_M_GET,  "/api/v1/control/state",   API_PRIV_READ,    true,  h_control_state,   NULL, NULL },
    { API_M_POST, "/api/v1/control/start",   API_PRIV_CONTROL, true,  h_control_start,   NULL, NULL },
    { API_M_POST, "/api/v1/control/pause",   API_PRIV_CONTROL, true,  h_control_pause,   NULL, NULL },
    { API_M_POST, "/api/v1/control/stop",    API_PRIV_CONTROL, true,  h_control_stop,    NULL, NULL },
    { API_M_POST, "/api/v1/control/profile", API_PRIV_CONTROL, true,  h_control_profile, NULL, NULL },

    // Outside /api/v1 on purpose: it is not versioned JSON, and it is the path
    // every scraper defaults to. A read, but --api-token still applies.
    { API_M_GET,  "/metrics", API_PRIV_READ, true, NULL, h_metrics,
      API_METRICS_CONTENT_TYPE },
};

const api_route *api_routes_get(size_t *count)
{
    *count = sizeof(g_routes) / sizeof(g_routes[0]);
    return g_routes;
}

char *api_routes_miner_json_str(void)
{
    json_t *m = miner_json_object();
    if (!m)
        return nullptr;
    char *s = json_dumps(m, JSON_COMPACT);
    json_decref(m);
    return s;
}
