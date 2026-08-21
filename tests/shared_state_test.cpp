// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared device state, through the backend's own kernel path.
//
// The state is memory a kernel reads and never writes, built once outside any
// dispatch and shared by every kernel on the device. Four things have to be
// true of it and none of them can be seen from a hash rate:
//
//   - the bytes survive dispatch after dispatch, because that is the whole
//     point of not sending them with each one;
//   - a kernel told to hash against something else gets something else, so a
//     new epoch is a rebuild and not a stale table quietly mining nothing;
//   - the tuner racing four candidates allocates one table, not four -- for a
//     real algorithm the difference is gigabytes, which is the device;
//   - and a table the device will not address in one binding is held in several
//     and reads back the same, which is the only way a DAG fits on the parts
//     whose limit is the Vulkan minimum.
//
// The algorithm here hashes nothing. It fills the table with numbers it can
// recompute and its shader reports what it read back as though it were a
// digest, so a wrong table is a wrong digest and the host says which word.

#include "algorithms/algorithm.h"
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

// Big enough that the backend has to upload it in more than one chunk, small
// enough to allocate on a software rasterizer whose "device memory" is the
// host's. A real one is measured in gigabytes; what is being tested is not the
// size.
constexpr uint64_t kTableBytes = 20u << 20;
constexpr uint64_t kTableWords = kTableBytes / sizeof(uint32_t);

// And the size of a piece, for the run that forces the table to be several
// buffers rather than one. Two whole pieces and a short third, because a table
// large enough to need pieces is very unlikely to be a whole number of them.
//
// Forced, because no device in reach would split twenty megabytes on its own:
// the limit that makes this happen is 128 MiB on a software rasterizer and four
// gigabytes on the cards here, so without asking for it the whole path would
// first run on hardware nobody has, holding a table nobody could check.
constexpr uint64_t kPieceBytes = 8u << 20;

// Words the shader reads per nonce, which is a digest's worth.
constexpr uint32_t kGroupWords = 8;

// Nonces per dispatch. Under kMaxCandidates, because every one of them
// produces a candidate: this kernel reports what it read rather than what met
// a target, so a larger dispatch would be candidates deliberately thrown away.
constexpr uint32_t kBatch = 16;

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

// What the word at `index` of the table for `key` is. Any mixing function
// would do; this one is here because both halves of the answer -- what the
// host uploads and what the host expects to read back -- must come from one
// place, and because it must depend on the key in every word. A table that
// differed only in its first bytes would let a rebuild that copied nothing at
// all pass this test.
uint32_t table_word(uint64_t key, uint64_t index)
{
    uint64_t x = index * 0x9e3779b97f4a7c15ull + key * 0xd1b54a32d192ed03ull;
    x ^= x >> 29;
    x *= 0xbf58476d1ce4e5b9ull;
    x ^= x >> 32;
    return static_cast<uint32_t>(x);
}

struct Push {
    uint32_t count;
    uint32_t capacity;
    uint32_t nonce;
};

// An algorithm whose entire content is its shared state. It reports the eight
// words at the nonce's group as the digest for that nonce, on the host and on
// the device both, so the two can be compared word for word.
class TableAlgorithm final : public vkminer::Algorithm {
public:
    TableAlgorithm(const uint32_t *spirv, size_t words)
        : spirv_(spirv), spirv_words_(words) {}

    const char *name() const override { return "shared-state-test"; }

    // The first header word, which is what a test changes to ask for a
    // different table. A real one reads a block height and divides.
    uint64_t state_key(const uint32_t *header) const override
    {
        return header[0];
    }

    bool shared_state(uint64_t key, uint64_t offset, void *out,
                      size_t bytes) const override
    {
        if ((offset % sizeof(uint32_t)) || (bytes % sizeof(uint32_t))) {
            fail("the backend asked for %u bytes at offset %u, and the table "
                 "is words", static_cast<unsigned>(bytes),
                 static_cast<unsigned>(offset));
            return false;
        }

        uint32_t *word = static_cast<uint32_t *>(out);
        const uint64_t first = offset / sizeof(uint32_t);
        const size_t count = bytes / sizeof(uint32_t);
        for (size_t i = 0; i < count; i++)
            word[i] = table_word(key, first + i);

        filled += bytes;
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
        spec.shared_bytes = kTableBytes;
        spec.shared_chunks = vkminer::kMaxSharedChunks;
        spec.shared_chunk_bytes = piece_bytes;
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
        const uint64_t key = state_key(header);
        for (uint32_t i = 0; i < kGroupWords; i++)
            out[i] = table_word(key, nonce * kGroupWords + i);
    }

    // Bytes the backend has asked this algorithm to produce since the run
    // began. One table's worth per build, which is how a test tells one
    // allocation shared by four kernels from four tables that happen to hold
    // the same numbers.
    mutable uint64_t filled = 0;

    // How large a piece of the table the next kernel should ask for. Zero --
    // the only value a miner sets -- lets the backend take the largest the
    // device will address, which for a table this size is all of it.
    uint64_t piece_bytes = 0;

private:
    const uint32_t *spirv_ = nullptr;
    size_t spirv_words_ = 0;
};

// A header naming table `key`. The nonce word is left alone: this kernel takes
// its nonce from the dispatch, like every other one here.
std::vector<uint32_t> header_for(uint32_t key)
{
    std::vector<uint32_t> header(20, 0x5a5a5a5au);
    header[0] = key;
    return header;
}

// One dispatch, and every word of what came back checked against what the host
// says the table holds. `label` names the case in a failure.
bool dispatch_matches(vkminer::Kernel &kernel, const TableAlgorithm &algo,
                      const std::vector<uint32_t> &header, uint32_t nonce,
                      const char *label)
{
    // Every candidate, whatever it hashed to: the shader emits unconditionally
    // because what is being read back is the table, not a solution.
    static const uint32_t open[8] = {
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
        0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    };

    if (!kernel.dispatch(header.data(), open, nonce, kBatch)) {
        fail("%s: the kernel refused a dispatch of %u nonces", label, kBatch);
        return false;
    }

    vkminer::Solution got[vkminer::kMaxCandidates];
    const int n = kernel.collect(got, vkminer::kMaxCandidates);
    if (n < 0) {
        fail("%s: the device failed while reading the table", label);
        return false;
    }
    if (n != static_cast<int>(kBatch)) {
        fail("%s: %d nonces came back and %u were dispatched", label, n,
             kBatch);
        return false;
    }

    // By nonce rather than by position: the order candidates land in is the
    // order the invocations reached the counter, which is the device's
    // business and not a thing to assert about.
    bool seen[kBatch] = {false};
    for (int i = 0; i < n; i++) {
        const uint64_t reported = got[i].nonce;
        if (reported < nonce || reported >= nonce + kBatch) {
            fail("%s: nonce %s is outside the %u dispatched from %u", label,
                 vkminer::nonce_hex(reported).c_str(), kBatch, nonce);
            return false;
        }
        const size_t slot = static_cast<size_t>(reported - nonce);
        if (seen[slot]) {
            fail("%s: nonce %s came back twice", label,
                 vkminer::nonce_hex(reported).c_str());
            return false;
        }
        seen[slot] = true;

        uint32_t expect[8];
        algo.hash(header.data(), reported, expect);
        for (uint32_t w = 0; w < kGroupWords; w++)
            if (got[i].hash[w] != expect[w]) {
                fail("%s: word %u of nonce %s read 0x%08x, and the table holds "
                     "0x%08x", label, w,
                     vkminer::nonce_hex(reported).c_str(), got[i].hash[w],
                     expect[w]);
                return false;
            }
    }

    return true;
}

bool run_device(vkminer::VulkanBackend &backend,
                const vkminer::DeviceInfo &info, const uint32_t *spirv,
                size_t spirv_words)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    TableAlgorithm algo(spirv, spirv_words);
    const vkminer::KernelSpec spec = algo.kernel(info);

    std::unique_ptr<vkminer::Kernel> kernel =
        backend.create_kernel(info.index, spec);
    if (!kernel) {
        fail("could not create a kernel wanting %u MiB of shared state",
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }

    if (backend.shared_state_bytes(info.index) != kTableBytes) {
        fail("the device holds %u MiB of shared state and the kernel asked for "
             "%u",
             static_cast<unsigned>(backend.shared_state_bytes(info.index) >> 20),
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }

    // ---- nothing is dispatched against a table nobody built
    //
    // The error line this prints is the test passing. A kernel that accepted
    // this would hash against an allocation holding whatever was there before,
    // and report candidates that fail verification for no visible reason.
    {
        const std::vector<uint32_t> header = header_for(1u);
        static const uint32_t open[8] = {
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
            0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
        };
        std::printf("     (the next line is what this case is checking for)\n");
        if (kernel->dispatch(header.data(), open, 0, kBatch)) {
            fail("the kernel dispatched before its table was built");
            return false;
        }
        std::printf("ok   an unbuilt table is refused rather than hashed\n");
    }

    // ---- the state survives dispatch after dispatch
    const std::vector<uint32_t> first = header_for(0x00000011u);
    if (!kernel->prepare_state(algo.state_key(first.data()))) {
        fail("could not build the first table");
        return false;
    }
    if (algo.filled != kTableBytes) {
        fail("building one table asked for %u MiB and it is %u",
             static_cast<unsigned>(algo.filled >> 20),
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }

    // Different nonces each time, so the passes read different parts of the
    // table: three dispatches over the same eight words would not notice a
    // device that had only the first chunk.
    for (uint32_t pass = 0; pass < 4; pass++) {
        const uint32_t nonce = pass * 163840u;
        if (!dispatch_matches(*kernel, algo, first, nonce, "first table"))
            return false;
    }
    if (algo.filled != kTableBytes) {
        fail("the table was rebuilt across dispatches nothing asked to change");
        return false;
    }
    std::printf("ok   the table survives repeated dispatches\n");

    // ---- a changed key rebuilds it
    const std::vector<uint32_t> second = header_for(0x0000c0deu);
    if (!kernel->prepare_state(algo.state_key(second.data()))) {
        fail("could not rebuild for a second key");
        return false;
    }
    if (algo.filled != 2 * kTableBytes) {
        fail("a changed key asked for %u MiB in total, and two tables are %u",
             static_cast<unsigned>(algo.filled >> 20),
             static_cast<unsigned>((2 * kTableBytes) >> 20));
        return false;
    }
    if (backend.shared_state_bytes(info.index) != kTableBytes) {
        fail("the rebuild left %u MiB on the device rather than %u",
             static_cast<unsigned>(backend.shared_state_bytes(info.index) >> 20),
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }
    if (!dispatch_matches(*kernel, algo, second, 610000u, "second table"))
        return false;
    std::printf("ok   a changed key rebuilds it\n");

    // ---- four kernels, one table
    //
    // What the tuner does: several candidates alive at once, raced against
    // each other. Each is a separate pipeline over the same bytes.
    std::vector<std::unique_ptr<vkminer::Kernel>> racers;
    racers.push_back(std::move(kernel));
    for (int i = 1; i < 4; i++) {
        vkminer::KernelSpec candidate = spec;
        candidate.concurrent_kernels = 4;
        std::unique_ptr<vkminer::Kernel> other =
            backend.create_kernel(info.index, candidate);
        if (!other) {
            fail("could not create candidate %d of 4", i + 1);
            return false;
        }
        racers.push_back(std::move(other));
    }

    if (backend.shared_state_bytes(info.index) != kTableBytes) {
        fail("four kernels hold %u MiB of shared state between them, and one "
             "table is %u",
             static_cast<unsigned>(backend.shared_state_bytes(info.index) >> 20),
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }

    for (size_t i = 0; i < racers.size(); i++) {
        if (!racers[i]->prepare_state(algo.state_key(second.data()))) {
            fail("candidate %u could not prepare the state the others hold",
                 static_cast<unsigned>(i + 1));
            return false;
        }
        char label[64];
        std::snprintf(label, sizeof label, "candidate %u of 4",
                      static_cast<unsigned>(i + 1));
        if (!dispatch_matches(*racers[i], algo, second,
                              500000u + 17u * static_cast<uint32_t>(i), label))
            return false;
    }

    if (algo.filled != 2 * kTableBytes) {
        fail("four kernels sharing one table asked the algorithm for %u MiB, "
             "and two tables are %u",
             static_cast<unsigned>(algo.filled >> 20),
             static_cast<unsigned>((2 * kTableBytes) >> 20));
        return false;
    }
    std::printf("ok   four kernels allocate one table between them\n");

    // ---- and it goes when they do
    racers.clear();
    if (backend.shared_state_bytes(info.index) != 0) {
        fail("%u MiB of shared state outlived every kernel that wanted it",
             static_cast<unsigned>(backend.shared_state_bytes(info.index) >> 20));
        return false;
    }
    std::printf("ok   the last kernel to go takes it with it\n");

    // ---- the same table, in pieces
    //
    // What a device that will not address the whole table in one binding gets:
    // several buffers, and a shader that finds a word in whichever of them it
    // is in. Nothing above this line changes -- same table, same numbers, same
    // read-back -- so a difference here is the pieces and nothing else.
    algo.piece_bytes = kPieceBytes;
    const vkminer::KernelSpec split = algo.kernel(info);
    std::unique_ptr<vkminer::Kernel> pieced =
        backend.create_kernel(info.index, split);
    if (!pieced) {
        fail("could not create a kernel holding %u MiB of shared state in %u "
             "MiB pieces", static_cast<unsigned>(kTableBytes >> 20),
             static_cast<unsigned>(kPieceBytes >> 20));
        return false;
    }
    if (backend.shared_state_bytes(info.index) != kTableBytes) {
        fail("the pieces hold %u MiB between them and the table is %u",
             static_cast<unsigned>(backend.shared_state_bytes(info.index) >> 20),
             static_cast<unsigned>(kTableBytes >> 20));
        return false;
    }
    if (!pieced->prepare_state(algo.state_key(second.data()))) {
        fail("could not build the table in pieces");
        return false;
    }
    if (algo.filled != 3 * kTableBytes) {
        fail("building it in pieces asked for %u MiB in total, and three "
             "tables are %u",
             static_cast<unsigned>(algo.filled >> 20),
             static_cast<unsigned>((3 * kTableBytes) >> 20));
        return false;
    }

    // One nonce in each piece, the last of them in the short one at the end:
    // a shader that read every word out of the first buffer would pass any
    // check that stayed inside it, and so would a backend that uploaded the
    // whole table into it.
    static const uint32_t kInEachPiece[] = { 0u, 300000u, 600000u, 655000u };
    for (uint32_t nonce : kInEachPiece)
        if (!dispatch_matches(*pieced, algo, second, nonce, "table in pieces"))
            return false;

    pieced.reset();
    algo.piece_bytes = 0;
    std::printf("ok   a table in %u MiB pieces reads back word for word\n",
                static_cast<unsigned>(kPieceBytes >> 20));

    return true;
}

// Where the shader is. Beside the test binary first, because a cross build
// bakes in a path that exists on the machine that compiled the test and not on
// the one running it -- which is every Windows and aarch64 run here.
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

    // The layers are the point of this test as much as the numbers are: a
    // descriptor bound to a buffer nobody wrote, or a copy read without a
    // barrier, is exactly the shape of bug this code can have and exactly what
    // they report.
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
