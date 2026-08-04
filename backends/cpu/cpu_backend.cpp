// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The host processor as a compute backend. It runs the algorithm's own scalar
// reference over the nonce range, one nonce at a time, and finds exactly what
// a correct GPU kernel would find.
//
// It is not a fallback for machines without a GPU, and it is not meant to be
// competitive -- the reference it drives is written to be read, not to be
// fast, and cpuminer-opt already exists for anyone who wants a CPU miner. What
// it is: the control. Every part of this miner except the shader can be proven
// against a pool through this backend, so when a GPU result later disagrees
// with it, the disagreement is the shader's, and the search has one place to
// start instead of five.

#include "algorithms/algorithm.h"
#include "backends/backend.h"

extern "C" {
#include "core/miner.h"
}

#include <cstring>
#include <thread>
#include <vector>

namespace vkminer {
namespace {

// Nonces per dispatch. Sized so one batch is tens of milliseconds of scalar
// hashing rather than a fixed time: the same constraint a GPU dispatch is
// under, for the same reason -- a batch that outlives its job is wasted work,
// and the epoch check that discards it costs the whole batch.
constexpr uint32_t kBatch = 1u << 16;

class CpuKernel final : public Kernel {
public:
    explicit CpuKernel(const Algorithm *algorithm) : algorithm_(algorithm) {}

    bool dispatch(const uint32_t *header, const uint32_t *target,
                  uint32_t nonce_start, uint32_t count) override
    {
        // 32 words is what struct work carries; copying rather than borrowing
        // means the caller may reuse its buffer while this "runs", which is
        // what an asynchronous backend would allow.
        std::memcpy(header_, header, sizeof header_);
        std::memcpy(target_, target, sizeof target_);
        nonce_start_ = nonce_start;
        count_ = count;
        return true;
    }

    // The work happens here rather than in dispatch(). On a device the caller
    // waits for a fence; here it waits for the loop, and the shape of the
    // caller's loop is identical either way.
    int collect(Solution *out, int max) override
    {
        int found = 0;
        uint32_t hash[8];

        for (uint32_t i = 0; i < count_ && found < max; i++) {
            const uint32_t nonce = nonce_start_ + i;
            if (!algorithm_->verify(header_, nonce, target_, hash))
                continue;

            out[found].nonce = nonce;
            std::memcpy(out[found].hash, hash, sizeof hash);
            found++;
        }

        return found;
    }

    uint32_t preferred_batch() const override { return kBatch; }

private:
    const Algorithm *algorithm_;
    uint32_t header_[32] = {0};
    uint32_t target_[8]  = {0};
    uint32_t nonce_start_ = 0;
    uint32_t count_ = 0;
};

class CpuBackend final : public ComputeBackend {
public:
    const char *name() const override { return "cpu"; }

    bool init() override
    {
        DeviceInfo info;
        info.index = 0;
        info.name = "host CPU";
        info.kind = DeviceKind::Cpu;
        devices_.push_back(info);
        return true;
    }

    const std::vector<DeviceInfo> &devices() const override { return devices_; }

    std::unique_ptr<Kernel> create_kernel(int device_index,
                                          const KernelSpec &spec) override
    {
        (void)device_index;

        // The one thing this backend cannot do without. An algorithm with no
        // scalar reference should not exist -- the interface makes hash() pure
        // virtual -- so this is a check against a hand-built spec, not against
        // a plausible algorithm.
        if (!spec.algorithm) {
            applog(LOG_ERR, "cpu: '%s' supplied no scalar reference to run",
                   spec.name);
            return nullptr;
        }

        return std::unique_ptr<Kernel>(new CpuKernel(spec.algorithm));
    }

    // One per hardware thread. Unlike a GPU, where a second worker on one
    // device just interleaves submissions, here a worker is the thing that
    // hashes, so the count is the parallelism.
    int preferred_workers(int device_count) const override
    {
        (void)device_count;
        const unsigned cores = std::thread::hardware_concurrency();
        return cores ? static_cast<int>(cores) : 1;
    }

    const char *device_caveat() const override
    {
        return "The CPU backend runs each algorithm's reference implementation,\n"
               "which is written to be verified rather than to be fast. It is\n"
               "the control the GPU is checked against, not a way to mine.";
    }

private:
    std::vector<DeviceInfo> devices_;
};

}  // namespace

std::unique_ptr<ComputeBackend> make_cpu_backend()
{
    return std::unique_ptr<ComputeBackend>(new CpuBackend());
}

}  // namespace vkminer
