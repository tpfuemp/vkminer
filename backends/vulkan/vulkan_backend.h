// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The Vulkan backend, declared rather than hidden behind make_vulkan_backend()
// so that the tests can reach a VulkanDevice. Nothing in the miner itself
// should include this: it talks to ComputeBackend.

#ifndef VKMINER_BACKENDS_VULKAN_BACKEND_H__
#define VKMINER_BACKENDS_VULKAN_BACKEND_H__

#include "backends/backend.h"
#include "backends/vulkan/pipeline_cache.h"
#include "backends/vulkan/shared_state.h"
#include "backends/vulkan/vulkan_device.h"

#include <mutex>
#include <vector>

namespace vkminer {

class VulkanBackend final : public ComputeBackend {
public:
    ~VulkanBackend() override;

    const char *name() const override { return "vulkan"; }
    bool init() override;
    const std::vector<DeviceInfo> &devices() const override { return devices_; }
    std::unique_ptr<Kernel> create_kernel(int device_index,
                                          const KernelSpec &spec) override;

    // A Vulkan device of kind Cpu is a software rasterizer, which is a
    // different thing from the CPU backend's one device and needs saying so.
    const char *device_caveat() const override
    {
        return "A CPU device is a software implementation of Vulkan. It will "
               "run every\nkernel correctly and mine far slower than the same "
               "CPU would natively.";
    }

    // The logical device for `device_index`, created on first use. Null if it
    // could not be created; the reason is logged. Owned by the backend, and
    // valid until the backend is destroyed.
    VulkanDevice *device(int device_index);

    VkInstance instance() const { return instance_; }

    // How much shared state is alive on `device_index`, and zero when none is.
    // Here for the tests: that four kernels share one table rather than
    // allocating four is the whole of what the state is for, and there is
    // otherwise nothing to observe it by.
    uint64_t shared_state_bytes(int device_index);

    void retain_shared_state(int device_index, bool retain) override;

private:
    bool create_instance();
    void enumerate();
    void describe(VkPhysicalDevice handle, DeviceInfo *out, uint32_t *family);

    VkInstance instance_ = VK_NULL_HANDLE;
    VkDebugUtilsMessengerEXT messenger_ = VK_NULL_HANDLE;
    std::vector<VkPhysicalDevice> handles_;
    std::vector<DeviceInfo> devices_;
    std::vector<uint32_t> compute_family_;             // parallel to devices_
    std::vector<std::unique_ptr<VulkanDevice>> open_;  // parallel to devices_
    std::vector<std::unique_ptr<PipelineCache>> caches_;  // and so is this

    // And this: the shared state of whichever kernels are running on the
    // device, held weakly so that the kernels own it. A run that changes
    // algorithm frees the old table when the last kernel reading it goes,
    // rather than keeping gigabytes for a shader nobody will dispatch again.
    std::vector<std::weak_ptr<SharedState>> shared_;

    // Except while every kernel that was reading it has been released on
    // purpose. A parked worker asks for this so the table survives the park;
    // it is dropped by the next kernel built on the device, whichever way that
    // build goes.
    std::vector<std::shared_ptr<SharedState>> pinned_;  // parallel to shared_

    // Both of those are filled in on first use, and first use can be a worker
    // thread. Two workers sharing a device would otherwise each see an empty
    // slot and each create one, and the second assignment destroys the first's
    // while a kernel is being built on it.
    std::mutex lazy_lock_;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_BACKEND_H__
