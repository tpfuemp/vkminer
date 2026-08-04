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

struct DeviceInfo {
    int         index = -1;   // as listed by --device-list, and as --devices selects
    std::string name;         // what the driver calls it
    std::string driver;       // driver name and version, for a bug report
    uint64_t    memory = 0;   // device-local bytes, 0 if the backend cannot say
};

// A nonce that met the target, and the hash it produced. The hash comes back
// with the nonce because the caller needs it to work out the share difficulty,
// and recomputing it on the host would mean the host knowing the algorithm.
struct Solution {
    uint32_t nonce;
    uint32_t hash[8];
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

    // Build `algo` for the device at `device_index`, an index into `devices`.
    // Returns null if this backend has no kernel for that algorithm.
    virtual std::unique_ptr<Kernel> create_kernel(int device_index,
                                                  const char *algo) = 0;
};

// The backend that does nothing, for bringing up everything around it.
std::unique_ptr<ComputeBackend> make_null_backend();

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_BACKEND_H__
