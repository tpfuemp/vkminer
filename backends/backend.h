// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The compute axis. A backend knows how to enumerate devices, load a kernel
// onto one, and run it over a range of nonces. It does not know what the
// kernel computes, and it never sees a block header as anything but bytes.
// Everything an algorithm means -- the header layout, the endianness, what
// counts as a solution -- lives on the other axis.

#ifndef VKMINER_BACKENDS_BACKEND_H__
#define VKMINER_BACKENDS_BACKEND_H__

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace vkminer {

// What the device physically is. `Cpu` is the one that matters: a software
// rasterizer enumerates and runs like any other device, and a benchmark taken
// against one describes the CPU it was emulated on.
enum class DeviceKind { Other, IntegratedGpu, DiscreteGpu, VirtualGpu, Cpu };

const char *device_kind_name(DeviceKind kind);

// "1.3.255", from the packed form the version fields below use.
std::string version_string(uint32_t version);

struct DeviceInfo {
    int         index = -1;   // as listed by --device-list, and as --devices selects
    std::string name;         // what the driver calls it
    std::string driver;       // driver name and version, for a bug report
    uint64_t    memory = 0;   // device-local bytes, 0 if the backend cannot say
    DeviceKind  kind = DeviceKind::Other;

    // Enough to identify a device in a bug report without the reporter having
    // to run anything else. Versions are packed the way Vulkan packs them.
    uint32_t vendor_id      = 0;
    uint32_t device_id      = 0;
    uint32_t api_version    = 0;
    uint32_t driver_version = 0;

    // What a kernel has to be built against. The scheduler sizes dispatches
    // from the limits; an algorithm picks a variant from the features.
    uint32_t subgroup_size       = 0;   // 0 if the device will not say
    uint32_t max_invocations     = 0;   // per workgroup
    uint32_t max_workgroup_size  = 0;   // along x
    uint32_t max_workgroup_count = 0;   // along x

    // What a kernel with persistent state has to fit inside, and not the same
    // number as `memory`: a device with 12 GiB of it may still refuse a single
    // 5 GiB buffer, or refuse to let a shader address more than 4 GiB-1 of one
    // it accepted. A kernel whose state outgrows either splits it across
    // bindings, which is a shader decision and so has to be knowable before the
    // shader is chosen.
    uint64_t max_allocation      = 0;   // one allocation, bytes
    uint64_t max_binding_range   = 0;   // one storage buffer binding, bytes
    uint32_t max_storage_buffers = 0;   // storage bindings in one pipeline
    uint32_t max_shared_memory   = 0;   // workgroup-shared bytes

    bool int64 = false;           // 64-bit integers in a shader
    bool int16 = false;
    bool int8  = false;
    bool subgroup_ballot = false;
    bool subgroup_shuffle = false;   // lanes can read each other's registers
};

// A nonce that met the target, and the hash the device says it produced. The
// hash is advisory: the host re-computes it before submitting anything, so a
// device that disagrees is reporting a bug rather than a share.
//
// The nonce is 64 bits whatever the algorithm's own width is. Nothing on this
// axis reads the number, so the algorithms say how much of it they use.
struct Solution {
    uint64_t nonce;
    uint32_t hash[8];
};

// How a nonce is spelled in a log line or a test failure: eight hex digits
// while it fits in 32 bits, sixteen when it does not. So a 32-bit nonce reads
// as it always did, and a wider one is never printed with the top missing.
inline std::string nonce_hex(uint64_t nonce)
{
    char text[17];
    if (nonce > 0xffffffffull)
        std::snprintf(text, sizeof text, "%016llx",
                      static_cast<unsigned long long>(nonce));
    else
        std::snprintf(text, sizeof text, "%08llx",
                      static_cast<unsigned long long>(nonce));
    return text;
}

// Candidates a single dispatch can hand back. Here rather than inside a backend
// because a caller of collect() has to size its array by it: a smaller host
// array drops solutions the device stored and had room for, and nothing reports
// it. Far more than a dispatch should ever produce, so a batch that fills it is
// sized for a difficulty nobody is mining at and the host says so.
constexpr uint32_t kMaxCandidates = 32;

// Bindings a shader may split its shared table across. A shader-side limit --
// each chunk is a block declared in the GLSL and a compare in the chain that
// selects one -- so every kernel with chunks declares exactly this many,
// whatever a given device turns out to need. The unused compares fold away when
// the count is specialized in.
constexpr uint32_t kMaxSharedChunks = 16;

// Constants a kernel's module may declare for the program it runs. A limit
// rather than a size: nothing allocates this, it is what stops a mistake on the
// algorithm axis from asking the compiler for a million of them.
constexpr uint32_t kMaxProgramConstants = 256;

class Algorithm;

// The one thing that crosses between the two axes: what to run, in the terms
// each side already speaks. The backend reads the resource contract and the
// SPIR-V and never asks what any of it computes; the algorithm fills it in and
// never learns which backend consumed it.
struct KernelSpec {
    const char *name = "";  // the algorithm's name, for logs and errors

    // Which of the algorithm's kernels this is, where it has more than one --
    // "int64" against "2x32", say; empty where there is only one. The backend
    // never reads it, only logs it: it is how the tuner names what it raced and
    // how the cache remembers which one won.
    const char *variant = "";

    // The GPU half. Null SPIR-V is not an error -- it means this algorithm has
    // no shader for this device, which is the state an algorithm is in while
    // its CPU reference is being written.
    const uint32_t *spirv = nullptr;
    size_t   spirv_words         = 0;
    uint32_t storage_buffers     = 0;
    uint32_t push_constant_bytes = 0;
    uint32_t local_size_x        = 0;  // 0 lets the backend choose

    // Invocations that cooperate on one nonce. One -- and zero, which means the
    // same -- is every kernel where an invocation is a hash. More is a kernel
    // whose state is too wide for one invocation to hold, sixteen lanes each
    // keeping a slice of the mix and exchanging it every round.
    //
    // The backend launches `count * lanes` invocations for a dispatch of
    // `count` nonces and everything it counts stays in nonces. All it enforces
    // is that a workgroup holds a whole number of nonces, because a nonce split
    // across two of them could not exchange anything.
    uint32_t lanes = 0;

    // Whether the workgroup has to be a whole number of subgroups. Set by a
    // kernel that exchanges through subgroup operations rather than shared
    // memory: a workgroup ending in a half-full subgroup would leave such a
    // shader with lanes it cannot reach. The backend rounds down, and a device
    // that will not report a subgroup size has nothing to round to -- so a
    // kernel that sets this is one the algorithm already cleared for the device.
    bool full_subgroups = false;

    // Device-local bytes each invocation needs to itself, bound after the
    // result buffer. Zero for a kernel whose whole state fits in registers.
    // The algorithm states its appetite; how much memory is free, and how much
    // is spoken for by dispatches in flight, is the backend's to know, and it
    // caps the batch there.
    uint64_t scratch_bytes = 0;

    // Device-local bytes this kernel reads and never writes, the same for every
    // invocation and every dispatch: a table too large to recompute per hash
    // and too large to send with one. Bound after the scratchpad, or straight
    // after the result buffer where there is none.
    //
    // Neither multiplied by the batch nor divided by concurrent_kernels, which
    // is what makes it different from scratch: it is one allocation on the
    // device however many kernels read it, because the tuner races several at
    // once and a table measured in gigabytes cannot be raced any other way.
    // Filled by Algorithm::shared_state, keyed by a number the backend never
    // interprets -- see Kernel::prepare_state.
    uint64_t shared_bytes = 0;

    // Bindings the shader has for that table, where a device will not let it be
    // one: maxStorageBufferRange is 4 GiB-1 on a desktop GPU and 128 MiB on
    // lavapipe, so how many bindings a table needs is a property of the device
    // rather than of the algorithm. The shader declares the most it can address
    // and the backend uses as few as the device allows, telling it how big one
    // is; the shader selects with a chain of compares, because dynamically
    // indexing an array of storage buffers needs descriptor indexing and this
    // project builds against Vulkan 1.1.
    //
    // 0 and 1 both mean one binding. More than kMaxSharedChunks is refused.
    uint32_t shared_chunks = 0;

    // Bytes per chunk, where the device's own limit is not the number to use.
    // Zero -- the only value a miner should set -- takes the largest the device
    // will address. A test sets it small so the chunk path runs on hardware
    // whose limits would never reach for it. Rounded down to a power of two, so
    // the shader divides by a shift.
    uint64_t shared_chunk_bytes = 0;

    // How those bytes get made, where the host cannot make them fast enough: a
    // table whose every 64 bytes is a hundred hashes is a day's work for a CPU
    // and seconds for the device about to read it.
    //
    // A second SPIR-V module, run over the shared buffer before the first
    // mining dispatch, bound to the shared state it writes at 0 and a
    // host-filled seed at 1, dispatched in slices of `items` invocations, each
    // slice carrying push constants the algorithm writes. The backend chooses
    // the slice size, which is a question about this device's watchdog.
    //
    // Null SPIR-V means there is no such pass and the host fills the buffer.
    struct SetupPass {
        const uint32_t *spirv = nullptr;
        size_t   spirv_words         = 0;
        uint32_t push_constant_bytes = 0;
        uint32_t local_size_x        = 0;  // 0 lets the backend choose

        // Device-local bytes of input, filled by Algorithm::setup_seed and
        // bound at binding 1. Freed once the pass is over: nothing dispatched
        // afterwards reads it.
        uint64_t seed_bytes = 0;

        // Invocations to run, one per item of whatever the shared buffer holds.
        // The backend never learns what an item is; it hands out ranges of them
        // and the algorithm turns a range into push constants.
        uint64_t items = 0;
    } setup;

    // Specialization constants this module declares for the program it runs,
    // filled by Algorithm::program_values and handed to the compiler from a
    // fixed constant ID upwards. Zero is a module that computes the same thing
    // whatever the job, and is built once.
    //
    // More than zero makes the pipeline the compile: the module is a skeleton,
    // the program is the constants, and a new program means a new pipeline. The
    // backend keys them by Algorithm::program_key and builds the next one ahead
    // of being asked -- see Kernel::prepare_program.
    uint32_t program_constants = 0;

    // Specialization constants that do not change with the job: the same values
    // in every pipeline built from this spec, handed to the compiler from a
    // fixed constant ID above the program's.
    //
    // What this is for is one module serving a family of algorithms that differ
    // only in numbers -- the shape of a loop, the words a hash absorbs. Those
    // belong here rather than in the program, because a program is recompiled
    // whenever the job moves and these never move at all.
    //
    // Borrowed, like the SPIR-V, and read whenever a pipeline is built: it must
    // outlive the kernel.
    const uint32_t *constants = nullptr;
    size_t constant_count = 0;

    // Dispatches this kernel may hold at once; 0 lets the backend choose. Not
    // an algorithm's business -- it is here so a caller sweeping both axes can
    // ask for one combination without going through a process-wide global.
    uint32_t queue_depth = 0;

    // Kernels the caller will hold alive on this device at once, itself
    // included; the backend divides its scratch budget by this. Zero and one
    // both mean alone. Each gets an equal share rather than whatever is left
    // when it is built, so a tuner racing several compares them and not their
    // build order. Nothing but the batch size changes.
    uint32_t concurrent_kernels = 1;

    // The CPU half: the scalar reference every algorithm must supply. A backend
    // with no way to run SPIR-V runs this instead, and the differential test
    // measures the shader against it. Borrowed, not owned -- the kernel must
    // not outlive the Algorithm that produced the spec.
    const Algorithm *algorithm = nullptr;
};

// What one dispatch is, in the only terms a backend has: a job, a slice of the
// nonce space, and the room there is for answers. The backend fills this in and
// hands it to the algorithm, which turns it into the bytes its shader declared.
struct Dispatch {
    const uint32_t *header = nullptr;  // struct work's words, as the pool sent them
    const uint32_t *target = nullptr;  // 8 words, as fulltest() compares them
    uint64_t nonce_start = 0;
    uint32_t count = 0;             // nonces from there, and a dispatch is small
    uint32_t capacity = 0;             // candidates the result buffer holds
};

// One algorithm compiled for one device. Owns whatever the backend needed to
// allocate to run it, and releases it on destruction.
class Kernel {
public:
    virtual ~Kernel() = default;

    // Hash `count` nonces starting at `nonce_start` against `header` (an
    // 80-byte block header as 32-bit words, already in the byte order the
    // kernel expects) and `target` (8 words, little endian).
    //
    // The call is asynchronous: it returns once the work is submitted, not
    // once it is done. `collect` is what waits. Returns false, having logged,
    // if the kernel already has `queue_depth` dispatches outstanding.
    virtual bool dispatch(const uint32_t *header, const uint32_t *target,
                          uint64_t nonce_start, uint32_t count) = 0;

    // Make the kernel's shared device state be the state `key` names, building
    // it if it is not there already, and say whether it is. Called before the
    // first dispatch and again whenever the key changes, which for an algorithm
    // with an epoch is a few times a day and costs seconds each time.
    //
    // The backend never learns what a key means: only that two dispatches under
    // one key want the same bytes and that the algorithm can produce them.
    // True by default, whatever the key, so callers ask unconditionally.
    virtual bool prepare_state(uint64_t key) { (void)key; return true; }

    // Make the kernel run the program `key` names, and say whether it does. The
    // sibling of prepare_state, asked in the same place and once per dispatch:
    // almost always a comparison, and a pipeline build when it is not. Having
    // been told what the next key will be, the backend compiles that pipeline
    // on a background thread while this one is still mining.
    //
    // True by default and for a module that declares no program: there is one
    // pipeline, built when the kernel was, and every job runs it.
    virtual bool prepare_program(uint64_t key) { (void)key; return true; }

    // What that cost. `builds` counts pipelines compiled and `ahead` those
    // already being built when they were asked for -- the only observable
    // difference between a program prepared in advance and one compiled on the
    // boundary, since both produce the right digest.
    struct ProgramStats {
        uint64_t builds = 0;
        uint64_t ahead = 0;
    };
    virtual ProgramStats program_stats() const { return ProgramStats{}; }

    // Wait for the *oldest* outstanding dispatch and write any solutions it
    // found into `out`, at most `max` of them. Returns the count, 0 if nothing
    // is outstanding, or -1 if the device failed. That dispatch is retired
    // either way, so a caller emptying the pipeline after a failure still
    // gets there.
    virtual int collect(Solution *out, int max) = 0;

    // Nonces the caller should ask for per dispatch to keep the device busy
    // without holding it long enough to miss a new job.
    virtual uint32_t preferred_batch() const = 0;

    // The largest dispatch this kernel will accept at all: preferred_batch is
    // an answer about time, this one is about memory. A caller sizing a
    // dispatch from anything else, as the tests do, has to ask -- more than
    // this is refused. Unbounded by default, because a kernel holding its state
    // in registers has no such limit.
    virtual uint32_t max_batch() const { return 0xffffffffu; }

    // The width this kernel was built at, which need not be the one asked for:
    // a spec naming none leaves the backend to pick off the device's limits. A
    // tuner has to read that back, because what it writes down must be a number
    // a later run can ask for. Zero from a backend with no such concept.
    virtual uint32_t local_size() const { return 0; }

    // Dispatches the caller may leave outstanding at once. More than one lets
    // the device start the next the instant it finishes one, rather than
    // waiting for the host to notice that it did. Results come back oldest
    // first, and the caller has to remember what each was launched under.
    virtual uint32_t queue_depth() const { return 1; }

    // What the best-digest probe has seen: the one thing a caller can observe
    // about the nonces that did *not* come back. A kernel that misses valid
    // nonces reports nothing at all -- no rejects, no failed re-verify, just
    // worse luck than it should have had.
    //
    // `samples` counts the dispatches that reported a reading; `ratio_sum`
    // adds up, for each, the smallest most significant digest word it saw times
    // the nonces it covered, over 2^32. Digest words are uniform, so each term
    // has an expected value of one whatever the batch was: `ratio_sum /
    // samples` reads 1.00 for a kernel that searches every nonce handed to it
    // and 2.00 for one searching half.
    //
    // Not a running minimum, which saturates to zero within seconds on a fast
    // card and then reads like a probe that was never wired up. `samples` of
    // zero means no observation, not a measurement of zero.
    struct BestDigest {
        double ratio_sum = 0.;
        uint64_t samples = 0;
    };
    virtual BestDigest best_digest() const { return BestDigest{}; }
};

class ComputeBackend {
public:
    virtual ~ComputeBackend() = default;

    // Short name for the log line that says which backend is in use.
    virtual const char *name() const = 0;

    // Bring the backend up far enough to answer `devices`. Returns false and
    // logs if the platform cannot support it at all -- no loader, no driver,
    // no device -- which is a reason to try another backend, not to exit.
    virtual bool init() = 0;

    virtual const std::vector<DeviceInfo> &devices() const = 0;

    // Build `spec` for the device at `device_index`, an index into `devices`.
    // Returns null, having logged why, if this backend cannot run that spec --
    // no shader for a GPU, no scalar reference for the CPU.
    virtual std::unique_ptr<Kernel> create_kernel(int device_index,
                                                  const KernelSpec &spec) = 0;

    // Workers to start when the user did not say. One per device suits a GPU,
    // where a device is a queue to keep fed; a CPU backend wants one per core.
    virtual int preferred_workers(int device_count) const
    {
        return device_count;
    }

    // A line printed under --device-list when this backend's devices need one,
    // null when they do not. It lives here because what is worth warning about
    // is a property of the backend: a device of kind Cpu means a software
    // rasterizer under Vulkan and the actual processor under the CPU backend.
    virtual const char *device_caveat() const { return nullptr; }
};

// The backend that does nothing, for bringing up everything around it.
std::unique_ptr<ComputeBackend> make_null_backend();

// The host processor, running the algorithm's own scalar reference. Slow by
// construction and never optimized: it is the control every GPU result is
// compared against, and a reference that shares a bug with the shader it
// checks is worse than no reference at all.
std::unique_ptr<ComputeBackend> make_cpu_backend();

// The real one. Returns a backend whose init() fails, rather than null, when
// the machine has no Vulkan loader or no device -- the caller decides whether
// that is fatal.
std::unique_ptr<ComputeBackend> make_vulkan_backend();

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_BACKEND_H__
