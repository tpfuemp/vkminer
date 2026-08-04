// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The compute axis. A backend knows how to enumerate devices, load a kernel
// onto one, and run it over a range of nonces. It does not know what the
// kernel computes, and it never sees a block header as anything but bytes.
// Everything an algorithm means -- the header layout, the endianness, what
// counts as a solution -- lives on the other axis.
//
// This is the shape the null backend needs and no more. It will grow when the
// Vulkan backend has something to say about it; treat every signature here as
// provisional until a real device has run through it.

#ifndef VKMINER_BACKENDS_BACKEND_H__
#define VKMINER_BACKENDS_BACKEND_H__

#include <cstdint>
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

    bool int64 = false;           // 64-bit integers in a shader
    bool int16 = false;
    bool int8  = false;
    bool subgroup_ballot = false;
};

// A nonce that met the target, and the hash the device says it produced. The
// hash is advisory: the host re-computes it before submitting anything, so a
// device that disagrees is reporting a bug rather than a share.
struct Solution {
    uint32_t nonce;
    uint32_t hash[8];
};

class Algorithm;

// The one thing that crosses between the two axes: what to run, in the terms
// each side already speaks. The backend reads the resource contract and the
// SPIR-V and never asks what any of it computes; the algorithm fills it in and
// never learns which backend consumed it.
struct KernelSpec {
    const char *name = "";  // the algorithm's name, for logs and errors

    // The GPU half. Null SPIR-V is not an error -- it means this algorithm has
    // no shader for this device, which is exactly the state an algorithm is in
    // while its CPU reference is being written.
    const uint32_t *spirv = nullptr;
    size_t   spirv_words         = 0;
    uint32_t storage_buffers     = 0;
    uint32_t push_constant_bytes = 0;
    uint32_t local_size_x        = 0;  // 0 lets the backend choose

    // The CPU half: the scalar reference every algorithm must supply. A
    // backend with no way to run SPIR-V runs this instead, and the differential
    // test measures the shader against it. Borrowed, not owned -- the kernel
    // must not outlive the Algorithm that produced the spec.
    const Algorithm *algorithm = nullptr;
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
    // once it is done. `collect` is what waits.
    virtual bool dispatch(const uint32_t *header, const uint32_t *target,
                          uint32_t nonce_start, uint32_t count) = 0;

    // Wait for the outstanding dispatch and write any solutions it found into
    // `out`, at most `max` of them. Returns the count, or -1 if the device
    // failed.
    virtual int collect(Solution *out, int max) = 0;

    // Nonces the caller should ask for per dispatch to keep the device busy
    // without holding it long enough to miss a new job.
    virtual uint32_t preferred_batch() const = 0;
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
