// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The snapshot layer, on its own. No device, no pool and no HTTP: the miner's
// state is set here by hand, and what is under test is whether a collector
// reports it the way the API contract says to.
//
// Two things this is really for. One is the per-device fold: a worker is a
// queue to keep a GPU fed, so `--threads 4` on two cards is four threads and
// two devices, and a collector that reported four devices would put a card in
// a dashboard twice at half its rate. The other is the nullable fields, which
// are where a miner lies without meaning to -- a temperature Vulkan does not
// expose has to be absent, not zero, because zero is a temperature.

#include "api/api_control.h"
#include "api/api_model.h"
#include "tune.h"

extern "C" {
#include "core/miner.h"
}

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

// The miner state the collectors read. Defined here rather than linked from
// the inherited C, which would bring the option parser and the network stack
// in with it: what this test asserts is partly that this list is all there is.
extern "C" {
char *opt_algo = nullptr;
char *rpc_url = nullptr;
char *short_url = nullptr;
char *rpc_user = nullptr;
char *rpc_pass = nullptr;
char *opt_devices = nullptr;
char *opt_kernel = nullptr;
char *opt_algo_dir = nullptr;
char *opt_api_allow = nullptr;

bool opt_debug = false;
bool opt_benchmark = false;
bool opt_quiet = false;
bool opt_protocol = false;
bool opt_no_tune = false;
bool opt_retune = false;
bool opt_no_int64 = false;
bool opt_vk_validate = false;
bool opt_api_enabled = false;
bool opt_api_control = false;
bool have_stratum = true;
bool stratum_down = false;

int opt_n_threads = 0;
int opt_timeout = 300;
int opt_scantime = 5;
int opt_retries = -1;
int opt_time_limit = 0;
int opt_workgroup = 0;
int opt_queue_depth = 0;
int opt_api_listen = 4048;
int opt_api_remote = 0;
int opt_api_control_park_timeout = 30000;
int opt_api_control_min_interval = 0;

double *thr_hashrates = nullptr;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;

uint32_t accepted_share_count = 0;
uint32_t rejected_share_count = 0;
uint32_t solved_block_count = 0;
uint32_t stale_share_count = 0;
uint32_t stratum_errors = 0;

time_t stratum_up_time = 0;
struct timeval session_start;
struct stratum_ctx stratum;
pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

void applog(int prio, const char *fmt, ...)
{
    va_list ap;

    (void)prio;
    if (!opt_debug)
        return;
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
}
}

// The scheduler and the tuner, stubbed to the two questions the collectors ask
// them. Both are read-only accessors in the miner; here they are arrays, which
// is the point -- a collector that went looking for anything else would not
// link.
namespace {

std::vector<int> g_worker_device;
std::vector<uint64_t> g_worker_total;
std::vector<uint64_t> g_worker_stale;

bool g_have_tuning = false;
vkminer::Tuning g_tuning;

uint64_t g_below_target = 0;
uint64_t g_wrong_digest = 0;

}  // namespace

int worker_device_index(int thr_id)
{
    if (thr_id < 0 || thr_id >= static_cast<int>(g_worker_device.size()))
        return -1;
    return g_worker_device[static_cast<size_t>(thr_id)];
}

void worker_batch_counts(int thr_id, uint64_t *total, uint64_t *stale)
{
    *total = 0;
    *stale = 0;
    if (thr_id < 0 || thr_id >= static_cast<int>(g_worker_total.size()))
        return;
    *total = g_worker_total[static_cast<size_t>(thr_id)];
    *stale = g_worker_stale[static_cast<size_t>(thr_id)];
}

namespace vkminer {
bool device_tuning(int device_index, Tuning *out)
{
    if (!g_have_tuning || device_index != 0)
        return false;
    *out = g_tuning;
    return true;
}

// The candidate log's two run totals. Stubbed rather than linked because the
// real ones come with a file writer and a config path.
uint64_t candidates_below_target()
{
    return g_below_target;
}

uint64_t candidates_wrong_digest()
{
    return g_wrong_digest;
}
}  // namespace vkminer

namespace {

int failures = 0;

void fail(const char *fmt, ...)
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

void expect_int(const char *what, long long got, long long want)
{
    if (got != want)
        fail("%s: %lld, expected %lld", what, got, want);
}

void expect_double(const char *what, double got, double want)
{
    const double slack = want == 0. ? 1e-9 : 1e-9 * (want < 0. ? -want : want);
    const double diff = got - want;
    if (diff > slack || -diff > slack)
        fail("%s: %.6f, expected %.6f", what, got, want);
}

void expect_text(const char *what, const std::string &got, const char *want)
{
    if (got != want)
        fail("%s: \"%s\", expected \"%s\"", what, got.c_str(), want);
}

void expect_true(const char *what, bool got)
{
    if (!got)
        fail("%s: false, expected true", what);
}

void expect_false(const char *what, bool got)
{
    if (got)
        fail("%s: true, expected false", what);
}

template <typename T>
void expect_empty(const char *what, const std::optional<T> &got)
{
    if (got.has_value())
        fail("%s is set, and this build cannot know it", what);
}

// The two cards this miner is pretending to have, and the four workers on
// them: two on the first, two on the second. Not the same as one worker per
// device on purpose -- a fold that only ever sees one worker per device passes
// whether it folds or not.
constexpr int kWorkers = 4;

std::vector<vkminer::DeviceInfo> make_devices()
{
    std::vector<vkminer::DeviceInfo> devices(2);

    devices[0].index = 0;
    devices[0].name = "Test Discrete 3060";
    devices[0].driver = "test 1.2.3";
    devices[0].memory = 12ull * 1024 * 1024 * 1024;
    devices[0].vendor_id = 0x10de;
    devices[0].device_id = 0x2504;
    // 1.4.329, packed the way Vulkan packs it.
    devices[0].api_version = (1u << 22) | (4u << 12) | 329u;
    devices[0].int64 = true;

    devices[1].index = 1;
    devices[1].name = "Test lavapipe";
    devices[1].driver = "llvmpipe 25.2";
    devices[1].memory = 0;
    devices[1].api_version = (1u << 22) | (3u << 12) | 255u;
    devices[1].int64 = false;

    return devices;
}

// A worker as the barrier sees one: it asks whether to park, and parks. Enough
// to make a pause land, which is what the hashrate assertions need -- a rate
// clamped to zero because nobody was mining is not a clamp.
std::atomic<bool> g_stop{false};

void stub_worker(int thr_id)
{
    while (!g_stop.load()) {
        if (vkminer::control_wants_park())
            vkminer::control_park(thr_id);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void test_mask_url()
{
    expect_text("a url with credentials", vkminer::mask_url(
                    "stratum+tcp://wallet.worker:x@pool.example:3333"),
                "stratum+tcp://pool.example:3333");
    expect_text("a url without them",
                vkminer::mask_url("stratum+tcp://pool.example:3333"),
                "stratum+tcp://pool.example:3333");

    // An `@` past the first slash belongs to a path, and stripping back to it
    // would delete the host as well as the part that is nobody's password.
    expect_text("an at sign in the path",
                vkminer::mask_url("http://pool.example/a@b"),
                "http://pool.example/a@b");
    expect_text("no url at all", vkminer::mask_url(nullptr), "");
}

void test_miner()
{
    vkminer::MinerSnapshot miner;
    vkminer::collect_miner(&miner);

    // The two a manager negotiates on. The version is whatever this build is
    // and is not asserted; that it is not empty is.
    expect_text("miner.name", miner.name, "vkminer");
    expect_text("miner.kind", miner.kind, "gpu");
    expect_text("miner.api_version", miner.api_version, "1.0");
    if (miner.version.empty())
        fail("miner.version is empty");
}

void test_threads()
{
    std::vector<vkminer::ThreadSnapshot> threads;
    vkminer::collect_threads(&threads);

    expect_int("threads reported", static_cast<long long>(threads.size()),
               kWorkers);
    for (int i = 0; i < kWorkers; i++) {
        const vkminer::ThreadSnapshot &one = threads[static_cast<size_t>(i)];
        expect_int("thread id", one.id, i);
        expect_int("thread device_id", one.device_id, i / 2);

        // Every one of these would be a number this miner does not have. A
        // per-thread share count needs per-thread accounting; hw_errors needs
        // a per-device disagreement counter, and the ones that exist are
        // process-wide totals.
        expect_empty("threads[].accepted", one.accepted);
        expect_empty("threads[].rejected", one.rejected);
        expect_empty("threads[].hw_errors", one.hw_errors);
        expect_empty("threads[].intensity", one.intensity);
        expect_empty("threads[].throughput", one.throughput);
    }

    expect_double("thread 0 rate", threads[0].hashrate_hs, 1000.);
    expect_double("thread 3 rate", threads[3].hashrate_hs, 4000.);
}

void test_devices()
{
    std::vector<vkminer::DeviceSnapshot> devices;
    vkminer::collect_devices(&devices);

    // Two devices from four workers: the fold, which is the whole reason this
    // collector is not a loop over threads.
    expect_int("devices reported", static_cast<long long>(devices.size()), 2);
    expect_int("workers folded into device 0", devices[0].workers, 2);
    expect_int("workers folded into device 1", devices[1].workers, 2);

    expect_double("device 0 rate", devices[0].hashrate_hs, 3000.);
    expect_double("device 1 rate", devices[1].hashrate_hs, 7000.);
    expect_int("device 0 batches", (long long)devices[0].vulkan.batches_total,
               30);
    expect_int("device 0 late", (long long)devices[0].vulkan.batches_late, 3);
    expect_int("device 1 batches", (long long)devices[1].vulkan.batches_total,
               70);
    expect_int("device 1 late", (long long)devices[1].vulkan.batches_late, 7);

    expect_text("device 0 name", devices[0].name, "Test Discrete 3060");
    expect_text("device 0 type", devices[0].type, "gpu");
    expect_text("device 0 api version", devices[0].vulkan.api_version,
                "1.4.329");
    expect_text("device 0 backend", devices[0].vulkan.backend, "test");
    expect_true("device 0 int64", devices[0].vulkan.int64);
    expect_false("device 1 int64", devices[1].vulkan.int64);

    // Vulkan exposes none of these, so they are absent. A zero here is a card
    // a dashboard would draw as cold, still and unpowered.
    expect_empty("devices[].temp_c", devices[0].temp_c);
    expect_empty("devices[].fan_pct", devices[0].fan_pct);
    expect_empty("devices[].power_mw", devices[0].power_mw);
    expect_empty("devices[].hashrate_per_watt_khs",
                 devices[0].hashrate_per_watt_khs);

    // Tuned on one card and not the other, which is the ordinary case: --no-tune
    // and a device the sweep never reached both read as untuned, and neither is
    // the same claim as a device measured at the defaults.
    expect_true("device 0 tuned", devices[0].vulkan.tuned);
    expect_int("device 0 workgroup",
               (long long)devices[0].vulkan.workgroup.value_or(0), 256);
    expect_int("device 0 queue depth",
               (long long)devices[0].vulkan.queue_depth.value_or(0), 3);
    expect_text("device 0 kernel", devices[0].vulkan.kernel.value_or(""),
                "spec-sub");
    expect_false("device 1 tuned", devices[1].vulkan.tuned);
    expect_empty("device 1 workgroup", devices[1].vulkan.workgroup);
    expect_empty("device 1 kernel", devices[1].vulkan.kernel);
}

void test_summary()
{
    g_below_target = 3;
    g_wrong_digest = 1;

    vkminer::SummarySnapshot summary;
    vkminer::collect_summary(&summary);

    expect_text("summary.algo", summary.algo, "sha256d");

    // Both counts are real and they differ: four workers keeping two cards
    // busy. A dashboard showing one number for both would be showing the wrong
    // one half the time.
    expect_int("summary.devices", summary.devices, 2);
    expect_int("summary.threads", summary.threads, kWorkers);

    expect_double("summary.hashrate_hs", summary.hashrate_hs, 10000.);
    expect_int("summary.shares.accepted",
               (long long)summary.shares.accepted, 41);
    expect_int("summary.shares.rejected",
               (long long)summary.shares.rejected, 1);
    expect_int("summary.shares.stale", (long long)summary.shares.stale, 2);
    expect_int("summary.shares.solved", (long long)summary.shares.solved, 0);

    expect_int("summary.pool_count", summary.pool_count, 1);
    expect_double("summary.difficulty.pool",
                  summary.pool_difficulty.value_or(0.), 0.5);
    expect_double("summary.difficulty.network",
                  summary.network_difficulty.value_or(0.), 372.5);

    // Nothing keeps a rolling average, tracks a best share, or times how long
    // the miner waited for work. Three fields, three admissions.
    expect_empty("summary.hashrate_avg_hs", summary.hashrate_avg_hs);
    expect_empty("summary.best_share", summary.best_share);
    expect_empty("summary.wait_time_s", summary.wait_time_s);

    // The pool has set no network hashrate, and 0 H/s is a claim about the
    // chain rather than an absence of one.
    expect_empty("summary.network_hashrate_hs", summary.network_hashrate_hs);

    // Run totals, not per-device ones: the counters exist once for the process,
    // which is why /metrics publishes them without a device label.
    expect_int("summary.disagree_below_target",
               (long long)summary.disagree_below_target, 3);
    expect_int("summary.disagree_wrong_digest",
               (long long)summary.disagree_wrong_digest, 1);
}

void test_pool()
{
    vkminer::PoolSnapshot pool;
    vkminer::collect_pool(0, &pool);

    expect_int("pools[].index", pool.index, 0);
    expect_true("pools[0] is the active one", pool.active);
    expect_text("pools[].url", pool.url, "stratum+tcp://pool.example:3333");
    expect_text("pools[].user", pool.user, "wallet.worker");
    expect_text("pools[].type", pool.type, "stratum");
    expect_text("pools[].status", pool.status, "connected");
    expect_int("pools[].disconnects", (long long)pool.disconnects, 2);
    expect_double("pools[].difficulty", pool.difficulty.value_or(0.), 0.5);
    expect_text("pools[].job.id", pool.job.id.value_or(""), "6a1f");
    expect_int("pools[].job.height", (long long)pool.job.height.value_or(0),
               812345);
    expect_int("pools[].job.extranonce2_size",
               pool.job.extranonce2_size.value_or(0), 4);
    if (!pool.session_s.has_value())
        fail("pools[].session_s is unset on a connected pool");

    // Down. The session ends with the connection: a session age that kept
    // climbing across an outage would report a link that has been solid for
    // hours, which is contract changelog row 17's defect exactly.
    stratum_down = true;
    stratum_up_time = 0;
    vkminer::collect_pool(0, &pool);
    expect_text("pools[].status while down", pool.status, "disconnected");
    expect_empty("pools[].session_s while down", pool.session_s);
    stratum_down = false;
    stratum_up_time = time(nullptr) - 60;
}

void test_health()
{
    vkminer::HealthSnapshot health;
    vkminer::collect_health(&health);

    expect_text("health.status", health.status, "ok");
    expect_true("health.mining", health.mining);
    expect_true("health.pool_connected", health.pool_connected);
    expect_int("health.devices_ok", health.devices_ok, 2);

    stratum_down = true;
    vkminer::collect_health(&health);
    expect_text("health.status with the pool down", health.status, "degraded");
    expect_int("reasons given", (long long)health.reasons.size(), 1);
    expect_text("the reason given", health.reasons[0], "pool_disconnected");
    stratum_down = false;
}

void test_config()
{
    vkminer::ConfigSnapshot config;
    vkminer::collect_config(&config);

    // The two ways a credential leaves this process, and neither may.
    expect_text("config.url", config.url, "stratum+tcp://pool.example:3333");
    expect_text("config.user", config.user, "***");

    expect_text("config.algo", config.algo, "sha256d");
    expect_text("config.backend", config.backend, "test");
    expect_int("config.threads", config.threads, kWorkers);
    expect_int("config.api_control_min_interval",
               config.api_control_min_interval, 0);

    // Unset knobs are absent rather than zero: a workgroup of 0 is not a width
    // anyone asked for, it is the backend being left to choose.
    expect_empty("config.workgroup", config.workgroup);
    expect_empty("config.queue_depth", config.queue_depth);
    expect_empty("config.kernel", config.kernel);
}

// The park, which is the one state where a live rate is a lie: a parked worker
// is blocked and publishes nothing, so its last rate would otherwise stand for
// the length of the pause. The predicate lives in the model once and every
// surface reads it, which is what this asserts by checking all three at once.
void test_parked_reports_zero()
{
    opt_api_control = true;
    vkminer::control_init(kWorkers);

    std::vector<std::thread> workers;
    for (int i = 0; i < kWorkers; i++)
        workers.emplace_back(stub_worker, i);

    expect_true("mining before the pause", vkminer::model_is_mining());

    if (vkminer::control_request(vkminer::ControlState::kPaused, 5000,
                                 nullptr) != vkminer::ControlResult::kOk)
        fail("the pause did not land");

    expect_false("mining while paused", vkminer::model_is_mining());

    vkminer::SummarySnapshot summary;
    vkminer::collect_summary(&summary);
    expect_double("summary.hashrate_hs while paused", summary.hashrate_hs, 0.);

    std::vector<vkminer::ThreadSnapshot> threads;
    vkminer::collect_threads(&threads);
    for (size_t i = 0; i < threads.size(); i++)
        expect_double("a thread's rate while paused", threads[i].hashrate_hs,
                      0.);

    std::vector<vkminer::DeviceSnapshot> devices;
    vkminer::collect_devices(&devices);
    for (size_t i = 0; i < devices.size(); i++)
        expect_double("a device's rate while paused", devices[i].hashrate_hs,
                      0.);

    // The batch counters are not rates and do not go to zero with one: they
    // are what this device has done, and a pause is not an undoing.
    expect_int("device 0 batches while paused",
               (long long)devices[0].vulkan.batches_total, 30);

    vkminer::HealthSnapshot health;
    vkminer::collect_health(&health);
    expect_false("health.mining while paused", health.mining);

    // Paused on purpose is not a fault. A manager that stopped this miner
    // wants a `503` no more than it wants its own instruction called an error.
    expect_text("health.status while paused", health.status, "ok");

    vkminer::ControlSnapshot control;
    vkminer::collect_control(&control);
    expect_text("control.state", control.state, "paused");
    expect_int("control.threads_parked", control.threads_parked, kWorkers);
    expect_int("control.epoch", (long long)control.epoch, 1);
    expect_true("control.ready_for_switch with no interval set",
                control.ready_for_switch);

    if (vkminer::control_request(vkminer::ControlState::kRunning, 5000,
                                 nullptr) != vkminer::ControlResult::kOk)
        fail("the resume did not land");
    expect_true("mining after the resume", vkminer::model_is_mining());

    g_stop.store(true);
    vkminer::control_release_all();
    for (size_t i = 0; i < workers.size(); i++)
        workers[i].join();

    opt_api_control = false;
}

char *dup(const char *s)
{
    return strdup(s);
}

void seed_miner_state()
{
    opt_algo = dup("sha256d");
    rpc_url = dup("stratum+tcp://wallet.worker:secret@pool.example:3333");
    short_url = dup("pool.example:3333");
    rpc_user = dup("wallet.worker");
    rpc_pass = dup("x");

    opt_n_threads = kWorkers;
    static double rates[kWorkers] = {1000., 2000., 3000., 4000.};
    thr_hashrates = rates;

    g_worker_device.assign({0, 0, 1, 1});
    g_worker_total.assign({10, 20, 30, 40});
    g_worker_stale.assign({1, 2, 3, 4});

    g_have_tuning = true;
    g_tuning.local_size_x = 256;
    g_tuning.queue_depth = 3;
    g_tuning.variant = "spec-sub";

    accepted_share_count = 41;
    rejected_share_count = 1;
    stale_share_count = 2;
    stratum_diff = 0.5;
    net_diff = 372.5;

    stratum_errors = 2;
    stratum_up_time = time(nullptr) - 60;
    gettimeofday(&session_start, nullptr);

    pthread_mutex_init(&stratum.work_lock, nullptr);
    stratum.job.job_id = dup("6a1f");
    stratum.block_height = 812345;
    stratum.xnonce2_size = 4;
}

}  // namespace

int main(void)
{
    static const std::vector<vkminer::DeviceInfo> devices = make_devices();

    seed_miner_state();
    vkminer::model_set_devices(&devices, "test");

    test_mask_url();
    test_miner();
    test_threads();
    test_devices();
    test_summary();
    test_pool();
    test_health();
    test_config();
    test_parked_reports_zero();

    // The state the fixture was left in, re-asserted after the pause section
    // put the miner through two mutations: a collector that cached anything
    // would answer from before them.
    test_threads();
    test_devices();

    if (failures) {
        std::printf("api_model_test: %d failure%s\n", failures,
                    failures == 1 ? "" : "s");
        return 1;
    }
    std::printf("api_model_test: ok\n");
    return 0;
}
