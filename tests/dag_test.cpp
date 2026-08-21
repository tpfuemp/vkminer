// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The DAG generation kernel against the host reference, item by item.
//
// A DAG item is a hundred hashes and there are tens of millions of them, so
// the table the miner hashes against is built by the device that is about to
// read it. That makes it the first thing here whose *input* is computed on the
// GPU, and a wrong item is not a wrong share -- it is a miner that hashes
// fluently, finds nothing, and reports no error at all.
//
// So every word is compared. Two windows of the DAG are generated and checked
// against ethash's calculate_dataset_item: one at the start, and one at the
// far end where the item index no longer fits the arithmetic a careless kernel
// would use. Windows rather than the whole thing because a whole DAG is a
// gigabyte on the smallest epoch and this has to run on a software rasterizer.
//
// The kernel that reads the result back is the shared-state probe, which
// already reports eight words of the shared buffer as though they were a
// digest. Nothing in this test hashes anything: what is under test is what the
// buffer holds after the setup pass, and that is what the probe reports.

#include "algorithms/algorithm.h"
#include "algorithms/kawpow/kawpow_dag.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_common.h"
#include "backends/vulkan/vulkan_pipeline.h"   // read_spirv

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and the option parser reach for and no more.
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

using vkminer::kawpow::kItemWords;

// The epoch to generate. Zero, because its light cache is the smallest there
// is and this test is about the arithmetic rather than about the size: a
// kernel that is right for epoch 0 is right for epoch 400 over more items.
constexpr uint32_t kEpoch = 0;

// Items per window. Big enough that the backend slices the pass into several
// dispatches -- the slicing is the part that has to get the item index right
// -- and small enough that both windows and the host's reference for them are
// seconds rather than minutes on a software rasterizer.
constexpr uint32_t kWindowItems = 4608;

// Bytes per piece of the shared buffer: 1024 items, so the 4608-item window is
// four whole pieces and a short one. Both of those matter -- the pass has to
// stop a slice at a boundary rather than write past the piece it is pointed at,
// and the last piece of a real table is very unlikely to be a whole one.
constexpr uint64_t kPieceBytes = 64u << 10;

// Words the read-back kernel reports per dispatched nonce, which is half an
// item. Its unit is a digest because it was written for a table of digests.
constexpr uint32_t kGroupWords = 8;
constexpr uint32_t kGroupsPerItem = kItemWords / kGroupWords;

// Groups per read-back dispatch. Under kMaxCandidates, because every
// invocation emits: the probe reports what it read rather than what met a
// target, so a larger dispatch would be answers deliberately thrown away.
constexpr uint32_t kBatch = 16;

int failures = 0;

// An item index and a DAG size are 64-bit quantities and are printed as such,
// so the format string has to be checked against the printf that will read it
// rather than against the C library's default one. progpow_kat, which counts
// the same things, says the same thing at more length.
#if defined(__MINGW_PRINTF_FORMAT)
#define DAG_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#elif defined(__GNUC__)
#define DAG_PRINTF_FORMAT printf
#endif

void fail(const char *fmt, ...)
#if defined(DAG_PRINTF_FORMAT)
    __attribute__((format(DAG_PRINTF_FORMAT, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::printf("FAIL ");
    std::vprintf(fmt, args);
    std::printf("\n");
    va_end(args);
    failures++;
}

// What the read-back kernel's push block is; shaders/shared-state.comp.
struct CheckPush {
    uint32_t count;
    uint32_t capacity;
    uint32_t nonce;
};

// An algorithm whose shared state is a window of the KawPoW DAG, generated on
// the device. It hashes nothing: its hash() is the host's answer for what the
// window should hold, so that the probe's report can be compared to it.
class DagAlgorithm final : public vkminer::Algorithm {
public:
    DagAlgorithm(const uint32_t *check, size_t check_words,
                 const uint32_t *dag, size_t dag_words)
        : check_(check), check_words_(check_words),
          dag_(dag), dag_words_(dag_words) {}

    const char *name() const override { return "kawpow-dag-test"; }

    // Which window, as the one number that crosses to the backend: the epoch
    // in the top half and the DAG index the window starts at in the bottom.
    // Both windows of a run are the same size, so the buffer never changes.
    uint64_t state_key(const uint32_t *header) const override
    {
        return (static_cast<uint64_t>(header[0]) << 32) | header[1];
    }

    static uint32_t epoch_of(uint64_t key) { return uint32_t(key >> 32); }
    static uint64_t first_of(uint64_t key) { return key & 0xffffffffu; }

    // The light cache, which is what the pass generates from.
    bool setup_seed(uint64_t key, uint64_t offset, void *out,
                    size_t bytes) const override
    {
        if (!vkminer::kawpow::light_cache(epoch_of(key), offset, out, bytes)) {
            fail("the light cache for epoch %u has no %u bytes at %u",
                 epoch_of(key), static_cast<unsigned>(bytes),
                 static_cast<unsigned>(offset));
            return false;
        }
        seeded += bytes;
        return true;
    }

    // Where the slice the backend chose lands in the DAG and in the buffer.
    // The two differ by the window's start, which is the whole reason the
    // kernel is told both.
    size_t setup_push(uint64_t key, uint64_t first, uint64_t slot,
                      uint32_t count, void *out, size_t capacity) const override
    {
        if (capacity < sizeof(vkminer::kawpow::DagPush))
            return 0;

        vkminer::kawpow::DagPush push;
        push.count = count;
        push.first = static_cast<uint32_t>(first_of(key) + first);
        push.slot = static_cast<uint32_t>(slot);
        push.cache_items = vkminer::kawpow::light_cache_items(epoch_of(key));
        std::memcpy(out, &push, sizeof push);

        slices++;
        return sizeof push;
    }

    vkminer::KernelSpec kernel(const vkminer::DeviceInfo &device) const override
    {
        (void)device;
        vkminer::KernelSpec spec;
        spec.name = name();
        spec.spirv = check_;
        spec.spirv_words = check_words_;
        spec.storage_buffers = 1 + vkminer::kMaxSharedChunks;
        spec.push_constant_bytes = sizeof(CheckPush);
        spec.shared_bytes = window_bytes();
        spec.shared_chunks = vkminer::kMaxSharedChunks;

        // In pieces, on every device, whatever its own limits are. The window
        // is a quarter of a megabyte and no card in existence would split it;
        // the code that runs the pass over one piece at a time and tells the
        // shader where in that piece its slice lands is therefore code nothing
        // would ever execute, on the machines this test can run on, unless it
        // is asked for. A real DAG asks for it on a device the CI has none of.
        spec.shared_chunk_bytes = kPieceBytes;
        spec.setup.spirv = dag_;
        spec.setup.spirv_words = dag_words_;
        spec.setup.push_constant_bytes = sizeof(vkminer::kawpow::DagPush);
        spec.setup.seed_bytes = vkminer::kawpow::light_cache_bytes(kEpoch);
        spec.setup.items = kWindowItems;
        spec.algorithm = this;
        return spec;
    }

    size_t prepare(const vkminer::Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (capacity < sizeof(CheckPush))
            return 0;
        CheckPush push;
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;
        push.nonce = static_cast<uint32_t>(dispatch.nonce_start);
        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    // The host's answer, in the probe's units: `nonce` is a half-item of the
    // window, so it names an item of the DAG and which half of it to report.
    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        const uint64_t key = state_key(header);
        const uint64_t index = first_of(key) + nonce / kGroupsPerItem;
        const uint32_t half = static_cast<uint32_t>(nonce % kGroupsPerItem);

        uint32_t item[kItemWords];
        if (!vkminer::kawpow::dataset_item(epoch_of(key), index, item)) {
            fail("epoch %u has no DAG item %llu", epoch_of(key),
                 static_cast<unsigned long long>(index));
            std::memset(out, 0, kGroupWords * sizeof(uint32_t));
            return;
        }
        std::memcpy(out, item + half * kGroupWords,
                    kGroupWords * sizeof(uint32_t));
    }

    static constexpr uint64_t window_bytes()
    {
        return static_cast<uint64_t>(kWindowItems)
             * vkminer::kawpow::kItemBytes;
    }

    // What the backend has asked this algorithm for since the run began: one
    // light cache and one slice sequence per build, which is how a test tells
    // a window that was generated from one that was quietly reused.
    mutable uint64_t seeded = 0;
    mutable uint32_t slices = 0;

private:
    const uint32_t *check_ = nullptr;
    size_t check_words_ = 0;
    const uint32_t *dag_ = nullptr;
    size_t dag_words_ = 0;
};

// A header naming a window: the epoch, then the DAG index it starts at.
std::vector<uint32_t> header_for(uint32_t epoch, uint64_t first)
{
    std::vector<uint32_t> header(20, 0x5a5a5a5au);
    header[0] = epoch;
    header[1] = static_cast<uint32_t>(first);
    return header;
}

// Every item of the window the kernel is prepared for, against the host.
// `label` names the window in a failure.
bool window_matches(vkminer::Kernel &kernel, const DagAlgorithm &algo,
                    const std::vector<uint32_t> &header, const char *label)
{
    // Every candidate, whatever it read: the probe emits unconditionally.
    static const uint32_t open[8] = {
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };

    const uint32_t groups = kWindowItems * kGroupsPerItem;
    for (uint32_t base = 0; base < groups; base += kBatch) {
        if (!kernel.dispatch(header.data(), open, base, kBatch)) {
            fail("%s: the kernel refused a dispatch at group %u", label, base);
            return false;
        }

        vkminer::Solution got[vkminer::kMaxCandidates];
        const int n = kernel.collect(got, vkminer::kMaxCandidates);
        if (n < 0) {
            fail("%s: the device failed while reading group %u", label, base);
            return false;
        }
        if (n != static_cast<int>(kBatch)) {
            fail("%s: %d of %u groups came back at %u", label, n, kBatch, base);
            return false;
        }

        for (int i = 0; i < n; i++) {
            const uint64_t group = got[i].nonce;
            if (group < base || group >= base + kBatch) {
                fail("%s: group %s is outside the %u dispatched from %u", label,
                     vkminer::nonce_hex(group).c_str(), kBatch, base);
                return false;
            }

            uint32_t expect[8];
            algo.hash(header.data(), group, expect);
            for (uint32_t w = 0; w < kGroupWords; w++)
                if (got[i].hash[w] != expect[w]) {
                    // The item and the word inside it, because that is what a
                    // failure is about: a wrong parent index, a wrong keccak
                    // lane, a slice written at the wrong offset.
                    const uint64_t item = group / kGroupsPerItem;
                    const uint64_t word = (group % kGroupsPerItem) * kGroupWords
                                        + w;
                    fail("%s: item %llu word %llu read 0x%08x, and the host "
                         "says 0x%08x", label,
                         static_cast<unsigned long long>(item),
                         static_cast<unsigned long long>(word),
                         got[i].hash[w], expect[w]);
                    return false;
                }
        }
    }

    return true;
}

bool run_device(vkminer::VulkanBackend &backend,
                const vkminer::DeviceInfo &info, const uint32_t *check,
                size_t check_words, const uint32_t *dag, size_t dag_words)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    DagAlgorithm algo(check, check_words, dag, dag_words);
    const vkminer::KernelSpec spec = algo.kernel(info);

    std::unique_ptr<vkminer::Kernel> kernel =
        backend.create_kernel(info.index, spec);
    if (!kernel) {
        fail("could not create a kernel wanting %u KiB of DAG",
             static_cast<unsigned>(DagAlgorithm::window_bytes() >> 10));
        return false;
    }

    const uint64_t items = vkminer::kawpow::dag_items(kEpoch);
    const uint64_t cache = vkminer::kawpow::light_cache_bytes(kEpoch);
    std::printf("     epoch %u: %llu MiB of DAG in %llu items, from a %llu MiB "
                "cache\n", kEpoch,
                static_cast<unsigned long long>(
                    vkminer::kawpow::dag_bytes(kEpoch) >> 20),
                static_cast<unsigned long long>(items),
                static_cast<unsigned long long>(cache >> 20));

    if (items < kWindowItems) {
        fail("epoch %u has %llu items, and a window is %u", kEpoch,
             static_cast<unsigned long long>(items), kWindowItems);
        return false;
    }

    // ---- the low window
    //
    // Where every index is small and every off-by-one is still visible: an
    // item that read the wrong parent, a slice written at the wrong offset, a
    // keccak that dropped the top half of a lane.
    const std::vector<uint32_t> low = header_for(kEpoch, 0);
    if (!kernel->prepare_state(algo.state_key(low.data()))) {
        fail("could not generate the low window");
        return false;
    }
    if (algo.seeded != cache) {
        fail("generating one window uploaded %llu MiB of cache and it is %llu",
             static_cast<unsigned long long>(algo.seeded >> 20),
             static_cast<unsigned long long>(cache >> 20));
        return false;
    }
    if (algo.slices < 2) {
        fail("the pass ran in %u dispatch(es), so the slicing was never "
             "exercised", algo.slices);
        return false;
    }
    if (!window_matches(*kernel, algo, low, "low window"))
        return false;
    std::printf("ok   %u items from the start of the DAG, in %u slices\n",
                kWindowItems, algo.slices);

    // ---- and it stays generated
    if (algo.seeded != cache) {
        fail("the window was rebuilt across dispatches nothing asked to "
             "change");
        return false;
    }

    // ---- the high window
    //
    // The last items of the DAG, where an index no longer fits anything
    // narrower than the 32 bits the kernel carries and a host that computed
    // the parent in a different width would disagree.
    const uint64_t high_first = items - kWindowItems;
    const std::vector<uint32_t> high = header_for(kEpoch, high_first);
    const uint32_t before = algo.slices;
    if (!kernel->prepare_state(algo.state_key(high.data()))) {
        fail("could not generate the high window");
        return false;
    }
    if (algo.seeded != 2 * cache) {
        fail("a second window uploaded %llu MiB of cache in total, and two are "
             "%llu", static_cast<unsigned long long>(algo.seeded >> 20),
             static_cast<unsigned long long>((2 * cache) >> 20));
        return false;
    }
    if (algo.slices == before) {
        fail("a changed window generated nothing");
        return false;
    }
    if (!window_matches(*kernel, algo, high, "high window"))
        return false;
    std::printf("ok   %u items ending at %llu, the last of the DAG\n",
                kWindowItems, static_cast<unsigned long long>(items - 1));

    return true;
}

// Where a shader is. Beside the binary first, because a cross build bakes in a
// path that exists on the machine that compiled the test and not on the one
// running it -- which is every Windows and aarch64 run here.
std::string spirv_path(const char *argv0, const char *file, const char *built)
{
    std::string dir(argv0 ? argv0 : "");
    const size_t cut = dir.find_last_of("/\\");
    dir = cut == std::string::npos ? std::string(".") : dir.substr(0, cut);

    const std::string beside = dir + "/" + file;
    if (FILE *f = std::fopen(beside.c_str(), "rb")) {
        std::fclose(f);
        return beside;
    }
    return built;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);
    (void)argc;

    const std::string dag_file =
        spirv_path(argv[0], "dag.spv", DAG_SPV);
    const std::string check_file =
        spirv_path(argv[0], "shared-state.spv", SHARED_STATE_SPV);

    // The layers are worth their cost here for the same reason as in the
    // shared-state test, and one more: this is the first pass that writes the
    // shared buffer, so the barrier between generating it and reading it is
    // new code and exactly what they check.
    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    std::vector<uint32_t> dag, check;
    if (!vkminer::read_spirv(dag_file, &dag)
        || !vkminer::read_spirv(check_file, &check)) {
        std::printf("FAIL could not read the shaders\n");
        return 1;
    }

    for (const vkminer::DeviceInfo &info : backend.devices())
        run_device(backend, info, check.data(), check.size(), dag.data(),
                   dag.size());

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (vkminer::vk_validation_enabled) {
        std::printf("\nok   no validation errors\n");
    } else {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the numbers came back right\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
