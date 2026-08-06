// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A backend that hashes nothing. It reports imaginary devices, accepts any
// algorithm, and returns no solutions -- but it does so at a steady, plausible
// rate, which is enough to exercise the pool connection, the job pipeline, the
// share accounting and the shutdown path without a GPU in the machine.
//
// It never finds a share. That is deliberate: a fake share submitted to a real
// pool is a rejected share on someone's account.

#include "backends/backend.h"

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace vkminer {
namespace {

// Roughly a mid-range GPU on a simple algorithm, so the rate lines and the
// scheduler's batch sizing see numbers of a realistic order.
constexpr double kFakeHashesPerSecond = 500e6;
constexpr uint32_t kBatch = 1u << 22;

class NullKernel final : public Kernel {
public:
    bool dispatch(const uint32_t *header, const uint32_t *target,
                  uint32_t nonce_start, uint32_t count) override
    {
        (void)header;
        (void)target;
        (void)nonce_start;
        pending_ = count;
        return true;
    }

    int collect(Solution *out, int max) override
    {
        (void)out;
        (void)max;

        // Sleeping for as long as the work would have taken is what makes the
        // reported rate a rate rather than a busy loop pegging a core.
        const double seconds = pending_ / kFakeHashesPerSecond;
        std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
        pending_ = 0;
        return 0;
    }

    uint32_t preferred_batch() const override { return kBatch; }

private:
    uint32_t pending_ = 0;
};

class NullBackend final : public ComputeBackend {
public:
    const char *name() const override { return "null"; }

    bool init() override
    {
        // Two, so that the scheduler's multi-device half -- the worker-to-device
        // map, per-device accounting, one partition per worker -- is reachable
        // on a machine with one GPU. Neither computes anything, so the second
        // costs nothing.
        for (int i = 0; i < 2; i++) {
            DeviceInfo dev;
            dev.index = i;
            dev.name = "null device " + std::to_string(i);
            dev.driver = "none";
            dev.memory = 0;
            devices_.push_back(dev);
        }
        return true;
    }

    const std::vector<DeviceInfo> &devices() const override { return devices_; }

    std::unique_ptr<Kernel> create_kernel(int device_index,
                                          const KernelSpec &spec) override
    {
        // Any algorithm, because it implements none of them.
        (void)spec;
        if (device_index < 0 || device_index >= static_cast<int>(devices_.size()))
            return nullptr;
        return std::unique_ptr<Kernel>(new NullKernel());
    }

private:
    std::vector<DeviceInfo> devices_;
};

}  // namespace

std::unique_ptr<ComputeBackend> make_null_backend()
{
    return std::unique_ptr<ComputeBackend>(new NullBackend());
}

}  // namespace vkminer
