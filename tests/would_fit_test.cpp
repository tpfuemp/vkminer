// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Asking a device whether it has room, before anything is built on it.
//
// The answer arrives too late otherwise: a miner told to change algorithm has
// already stopped mining the old one by the time the new one's allocation
// fails, and on a board whose display driver shares the memory the failure is
// the machine going down. So the arithmetic is asked twice -- by would_fit(),
// which allocates nothing, and by the build that follows.
//
// Which makes agreement the only interesting property: a pre-check that is
// merely conservative refuses work the device could do, and one that is merely
// optimistic is the crash it was written to prevent. Every case asks both
// routes about the same spec and requires the same verdict:
//
//   - a table the device can hold: accepted, and the build succeeds;
//   - a table needing more bindings than the shader declares: refused by both;
//   - a scratchpad no batch size can pay for: refused by both;
//   - a table another kernel is still reading: refused, and the same table with
//     nothing but a park's pin on it: accepted, because the next build drops
//     that pin -- the switch away from a large algorithm;
//   - and a ProgPoW spec sized at the epoch it is *declared* to reach rather
//     than the one it happens to be on, with the option that moves that
//     declaration named in the refusal.
//
// Nothing here dispatches: what is tested is the decision made before a
// dispatch could happen.

#include "algorithms/algorithm.h"
#include "algorithms/progpow/progpow_dag.h"
#include "algorithms/progpow/progpow_params.h"
#include "algorithms/registry.h"
#include "backends/vulkan/shared_state.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_common.h"
#include "backends/vulkan/vulkan_kernel.h"     // vulkan_table_budget
#include "backends/vulkan/vulkan_pipeline.h"   // read_spirv

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog reaches for and no more.
//
// The last one is borrowed rather than owned: it is the miner's own option,
// defined where the parser is, and this test writes it. That is the point --
// what the pre-check reads has to be the variable `--progpow-max-epoch` sets,
// and a test with a private copy of it would pass while the option did nothing.
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
extern int opt_progpow_max_epoch;
}

namespace {

// Two sizes, both small enough for a software rasterizer to hold and different
// enough that neither could be mistaken for the other in a message. What is
// being tested is which of them the device is holding, never how large it is.
constexpr uint64_t kTableBytes = 20u << 20;
constexpr uint64_t kOtherBytes =  8u << 20;

int failures = 0;

void fail(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
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

struct Push {
    uint32_t count;
    uint32_t capacity;
    uint32_t nonce;
};

// An algorithm whose entire content is its shared state, and which is never
// asked to hash: it exists so that a real KernelSpec with a real table on it
// can be handed to both routes.
class TableAlgorithm final : public vkminer::Algorithm {
public:
    TableAlgorithm(const uint32_t *spirv, size_t words)
        : spirv_(spirv), spirv_words_(words) {}

    const char *name() const override { return "would-fit-test"; }

    uint64_t state_key(const uint32_t *header) const override
    {
        return header[0];
    }

    bool shared_state(uint64_t key, uint64_t offset, void *out,
                      size_t bytes) const override
    {
        (void)key;
        (void)offset;
        std::memset(out, 0, bytes);
        return true;
    }

    vkminer::KernelSpec kernel(const vkminer::DeviceInfo &device) const override
    {
        (void)device;
        vkminer::KernelSpec spec;
        spec.name = name();
        spec.spirv = spirv_;
        spec.spirv_words = spirv_words_;
        spec.storage_buffers = 1 + vkminer::kMaxSharedChunks;
        spec.push_constant_bytes = sizeof(Push);
        spec.shared_bytes = table_bytes;
        spec.shared_chunks = vkminer::kMaxSharedChunks;
        spec.algorithm = this;
        return spec;
    }

    size_t prepare(const vkminer::Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (capacity < sizeof(Push))
            return 0;
        Push push;
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;
        push.nonce = static_cast<uint32_t>(dispatch.nonce_start);
        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        (void)header;
        (void)nonce;
        std::memset(out, 0, 8 * sizeof(uint32_t));
    }

    // How large a table the next spec asks for.
    uint64_t table_bytes = kTableBytes;

private:
    const uint32_t *spirv_ = nullptr;
    size_t spirv_words_ = 0;
};

// Both routes, one spec, and a demand that they agree. `expect` is what the
// device ought to say; `label` names the case in a failure.
//
// The build is attempted whichever way the pre-check went, because the failure
// this guards against is precisely the two of them disagreeing -- a spec that
// passed here and then would not build is the crash the check was added to
// prevent, and a spec refused here that would have built is work the miner
// turned down for nothing.
bool both_agree(vkminer::VulkanBackend &backend, int index,
                const vkminer::KernelSpec &spec, bool expect,
                const char *label)
{
    char why[256] = {0};
    const bool said = backend.would_fit(index, spec, why, sizeof why);
    if (said != expect) {
        fail("%s: the pre-check said %s%s%s", label, said ? "yes" : "no",
             said ? "" : " -- ", said ? "" : why);
        return false;
    }
    if (!said && !why[0]) {
        fail("%s: refused without saying why", label);
        return false;
    }

    if (!expect)
        std::printf("     (the next line is what this case is checking for)\n");
    std::unique_ptr<vkminer::Kernel> built = backend.create_kernel(index, spec);
    if (!!built != expect) {
        fail("%s: the pre-check said %s and the build said %s", label,
             expect ? "yes" : "no", built ? "yes" : "no");
        return false;
    }

    return true;
}

// What a fork's table would be at the largest epoch it is declared to reach,
// which is the number a refusal has to be about.
uint64_t worst_case_bytes(const vkminer::progpow::Params &params,
                          uint32_t declared)
{
    return vkminer::progpow::dag_bytes(
        vkminer::progpow::epochs_for(params, declared).full);
}

const vkminer::progpow::Params *const kForks[] = {
    &vkminer::progpow::kKawpow,   &vkminer::progpow::kMeowpow,
    &vkminer::progpow::kEvrprogpow, &vkminer::progpow::kFiropow,
    &vkminer::progpow::kMeraki,
};

// ---- the declaration itself, which needs no device
//
// A fork that declares nothing is sized at epoch 0, which is a gigabyte where
// the chain is at six -- the pre-check would pass every switch and mean
// nothing. The other direction is the one that costs: a declaration left to go
// stale under-sizes the check silently, and there is nothing here that can see
// a date, so what this asserts is that a number exists, that it is above the
// epoch the miner starts on, and that the arithmetic reaches a size from it.
bool check_declarations()
{
    for (const vkminer::progpow::Params *fork : kForks) {
        if (!fork->max_epoch) {
            fail("%s declares no worst-case epoch", fork->name);
            continue;
        }

        const uint64_t worst = worst_case_bytes(*fork, fork->max_epoch);
        const uint64_t start = worst_case_bytes(*fork, 0);
        if (worst <= start) {
            fail("%s: epoch %u is %u MiB and epoch 0 is %u", fork->name,
                 fork->max_epoch,
                 static_cast<unsigned>(worst >> 20),
                 static_cast<unsigned>(start >> 20));
            continue;
        }

        std::printf("ok   %-11s declares epoch %5u -- %u MiB\n", fork->name,
                    fork->max_epoch,
                    static_cast<unsigned>(worst >> 20));
    }

    return failures == 0;
}

// ---- and what a spec does with it
//
// The declared size has to reach the pre-check, and the pre-check has to answer
// about *that* rather than about the table the miner is holding today. Both
// halves matter: an algorithm that filled in only shared_bytes would be sized
// against epoch 0 and pass a switch it cannot survive, and a refusal quoting
// today's epoch would send an operator to look at a number that is not the one
// the decision was made on.
bool check_progpow(vkminer::VulkanBackend &backend,
                   const vkminer::DeviceInfo &info)
{
    const uint64_t budget = vulkan_table_budget(info);

    for (const vkminer::progpow::Params *fork : kForks) {
        std::unique_ptr<vkminer::Algorithm> algo =
            vkminer::create_algorithm(fork->name);
        if (!algo) {
            fail("no algorithm answers to '%s'", fork->name);
            return false;
        }

        const vkminer::KernelSpec spec = algo->kernel(info);
        const uint64_t worst = worst_case_bytes(*fork, fork->max_epoch);

        if (spec.shared_bytes_max != worst) {
            fail("%s: the spec is sized at %u MiB and the declaration is "
                 "%u", fork->name,
                 static_cast<unsigned>(spec.shared_bytes_max >> 20),
                 static_cast<unsigned>(worst >> 20));
            return false;
        }
        if (!spec.size_override) {
            fail("%s: nothing is named for an operator to change", fork->name);
            return false;
        }

        // What the chunking says about a table that size, asked separately so
        // that a device whose bindings are the obstacle is not read as a device
        // whose memory is.
        uint64_t chunk = 0;
        uint64_t count = 0;
        char shape[256] = {0};
        const bool chunkable = vkminer::SharedState::plan(
            info, spec, worst, &chunk, &count, shape, sizeof shape);

        char why[256] = {0};
        const bool said = backend.would_fit(info.index, spec, why, sizeof why);
        const bool expect = worst <= budget && chunkable;
        if (said != expect) {
            fail("%s: %u MiB against a %u MiB budget was %s -- %s",
                 fork->name, static_cast<unsigned>(worst >> 20),
                 static_cast<unsigned>(budget >> 20),
                 said ? "accepted" : "refused", said ? "" : why);
            return false;
        }

        if (!said && worst > budget) {
            // The refusal has to be about the declared size and has to say what
            // would change it. A message quoting spec.shared_bytes would be the
            // epoch the miner is on, which is not what was refused.
            char declared[32];
            std::snprintf(declared, sizeof declared, "%u MiB",
                          static_cast<unsigned>(worst >> 20));
            if (!std::strstr(why, declared)) {
                fail("%s: the refusal does not name the %s it refused -- %s",
                     fork->name, declared, why);
                return false;
            }
            if (!std::strstr(why, spec.size_override)) {
                fail("%s: the refusal does not name %s -- %s", fork->name,
                     spec.size_override, why);
                return false;
            }
        }

        std::printf("ok   %-11s %5u MiB declared, %s\n", fork->name,
                    static_cast<unsigned>(worst >> 20),
                    said ? "accepted"
                         : worst > budget ? "refused by the budget, and it says "
                                            "which option moves it"
                                          : "refused by the bindings");
    }

    // And the option that is named actually moves the number. Epoch 1, which
    // is a table any device here can hold, so a fork refused above is accepted
    // now -- that is what the message offers, and an option parsed but never
    // read would leave the answer where it was.
    opt_progpow_max_epoch = 1;
    for (const vkminer::progpow::Params *fork : kForks) {
        std::unique_ptr<vkminer::Algorithm> algo =
            vkminer::create_algorithm(fork->name);
        const vkminer::KernelSpec spec = algo->kernel(info);
        const uint64_t override_bytes = worst_case_bytes(*fork, 1);

        if (spec.shared_bytes_max != override_bytes) {
            fail("%s: --progpow-max-epoch=1 sized the spec at %u MiB and "
                 "epoch 1 is %u", fork->name,
                 static_cast<unsigned>(spec.shared_bytes_max >> 20),
                 static_cast<unsigned>(override_bytes >> 20));
            opt_progpow_max_epoch = 0;
            return false;
        }
    }
    opt_progpow_max_epoch = 0;
    std::printf("ok   --progpow-max-epoch re-sizes what is asked about\n");

    return true;
}

bool run_device(vkminer::VulkanBackend &backend,
                const vkminer::DeviceInfo &info, const uint32_t *spirv,
                size_t spirv_words)
{
    std::printf("\n-- device %d: %s [%s], %u MiB, table budget %u MiB\n",
                info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind),
                static_cast<unsigned>(info.memory >> 20),
                static_cast<unsigned>(
                    vulkan_table_budget(info) >> 20));

    TableAlgorithm algo(spirv, spirv_words);

    // ---- a table the device can hold
    {
        const vkminer::KernelSpec spec = algo.kernel(info);
        if (!both_agree(backend, info.index, spec, true, "a table that fits"))
            return false;
        if (backend.shared_state_bytes(info.index)) {
            fail("the table outlived the kernel that wanted it");
            return false;
        }
        std::printf("ok   a table the device can hold is accepted by both\n");
    }

    // ---- more pieces than the shader has bindings for
    //
    // Refused by arithmetic rather than by an allocation, so the answer is the
    // same on every device: the shader declares a fixed number of bindings and
    // no device changes how many a table of a given piece size needs.
    {
        vkminer::KernelSpec spec = algo.kernel(info);
        spec.shared_chunks = 4;
        spec.shared_chunk_bytes = 1u << 20;
        if (!both_agree(backend, info.index, spec, false,
                        "a table in more pieces than there are bindings"))
            return false;
        std::printf("ok   too many pieces is refused by both\n");
    }

    // ---- a scratchpad no batch can pay for
    //
    // The whole device to one invocation, so there is no width and no depth at
    // which a single workgroup fits. This is the arithmetic that used to live
    // inside the kernel's own setup, where nothing could ask it in advance.
    {
        vkminer::KernelSpec spec = algo.kernel(info);
        spec.scratch_bytes = info.memory ? info.memory : (1ull << 34);
        if (!both_agree(backend, info.index, spec, false,
                        "a scratchpad the size of the device"))
            return false;
        std::printf("ok   an unpayable scratchpad is refused by both\n");
    }

    // ---- a table another kernel is still reading
    {
        const vkminer::KernelSpec held = algo.kernel(info);
        std::unique_ptr<vkminer::Kernel> live =
            backend.create_kernel(info.index, held);
        if (!live) {
            fail("could not build the kernel that holds the table");
            return false;
        }

        algo.table_bytes = kOtherBytes;
        const vkminer::KernelSpec other = algo.kernel(info);
        char why[256] = {0};
        if (backend.would_fit(info.index, other, why, sizeof why)) {
            fail("a second size was accepted onto a device dispatching against "
                 "the first");
            return false;
        }
        if (!std::strstr(why, "already holding")) {
            fail("the refusal does not say what the device is holding -- %s",
                 why);
            return false;
        }
        std::printf("ok   a table a live kernel is reading is not displaced\n");

        // ---- and the same table with only a park's pin on it
        //
        // The paused case: the worker is gone, its kernel with it, and the pin
        // is all that keeps the table alive for a resume that has come back as
        // a different algorithm instead. Counting that pin would refuse every
        // switch away from a large table, which is the switch this exists to
        // allow -- so the pre-check has to see it for what it is, and the build
        // that follows has to actually drop it.
        backend.retain_shared_state(info.index, true);
        live.reset();
        if (backend.shared_state_bytes(info.index) != kTableBytes) {
            fail("the pin did not hold the table across the kernel going away");
            return false;
        }

        why[0] = '\0';
        if (!backend.would_fit(info.index, other, why, sizeof why)) {
            fail("a pinned table was counted against the one replacing it -- %s",
                 why);
            return false;
        }

        std::unique_ptr<vkminer::Kernel> replacement =
            backend.create_kernel(info.index, other);
        if (!replacement) {
            fail("the pre-check accepted the replacement and the build refused "
                 "it");
            return false;
        }
        if (backend.shared_state_bytes(info.index) != kOtherBytes) {
            fail("the device holds %u MiB and the replacement asked for %u",
                 static_cast<unsigned>(
                     backend.shared_state_bytes(info.index) >> 20),
                 static_cast<unsigned>(kOtherBytes >> 20));
            return false;
        }
        std::printf("ok   a pinned table is not counted against its "
                    "replacement\n");

        replacement.reset();
        backend.retain_shared_state(info.index, false);
        algo.table_bytes = kTableBytes;
    }

    // ---- and the algorithm whose table is sized by work that has not arrived
    return check_progpow(backend, info);
}

// Where the shader is. Beside the test binary first, because a cross build
// bakes in a path that exists on the machine that compiled the test and not on
// the one running it.
std::string spirv_path(const char *argv0)
{
    std::string dir(argv0 ? argv0 : "");
    const size_t cut = dir.find_last_of("/\\");
    dir = cut == std::string::npos ? std::string(".") : dir.substr(0, cut);

    const std::string beside = dir + "/shared-state.spv";
    if (FILE *f = std::fopen(beside.c_str(), "rb")) {
        std::fclose(f);
        return beside;
    }
    return SHARED_STATE_SPV;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    const std::string spirv_file =
        argc > 1 ? std::string(argv[1]) : spirv_path(argv[0]);

    // The declarations first: they are a property of the tree rather than of a
    // machine, so a box with no Vulkan still gets to fail on them rather than
    // skipping past.
    if (!check_declarations()) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    std::vector<uint32_t> spirv;
    if (!vkminer::read_spirv(spirv_file, &spirv)) {
        std::printf("FAIL could not read %s\n", spirv_file.c_str());
        return 1;
    }

    for (const vkminer::DeviceInfo &info : backend.devices())
        run_device(backend, info, spirv.data(), spirv.size());

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
