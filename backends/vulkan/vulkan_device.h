// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One logical device, its compute queue, and the memory allocator that hangs
// off it. Everything a kernel needs to exist is owned here, so that a kernel
// can be created and destroyed while the device stays up -- which is what
// happens when a pool switches algorithm.
//
// Device-level entry points are resolved into a per-device table rather than
// into volk's globals. A miner is expected to drive several GPUs at once, and
// the globals hold one device's pointers: with two devices from two vendors,
// whichever was loaded last would answer for both.

#ifndef VKMINER_BACKENDS_VULKAN_DEVICE_H__
#define VKMINER_BACKENDS_VULKAN_DEVICE_H__

#include "backends/vulkan/vulkan_common.h"
#include "backends/vulkan/vma.h"

#include <memory>

namespace vkminer {

// What the buffer is for, which is what decides where it lives. Upload and
// Readback are host-visible and stay mapped for the lifetime of the buffer:
// mapping costs a driver call, the ranges are small, and a kernel dispatch
// would otherwise map and unmap them thousands of times a second.
enum class BufferKind {
    DeviceLocal,  // the device's own memory; the host cannot see it
    Upload,       // host writes, device reads: headers, targets
    Readback,     // device writes, host reads: solutions
};

struct Buffer {
    VkBuffer      handle     = VK_NULL_HANDLE;
    VmaAllocation allocation = nullptr;
    void         *mapped     = nullptr;  // null for DeviceLocal
    VkDeviceSize  size       = 0;
};

class VulkanDevice {
public:
    // Returns null and logs if the device cannot be created. `info` is the
    // enumeration result for this device: the features it says it has are the
    // features this asks for, so a device is never asked for what it lacks.
    static std::unique_ptr<VulkanDevice> create(VkInstance instance,
                                                VkPhysicalDevice physical,
                                                uint32_t queue_family,
                                                const DeviceInfo &info);

    ~VulkanDevice();

    VulkanDevice(const VulkanDevice &) = delete;
    VulkanDevice &operator=(const VulkanDevice &) = delete;

    VkDevice handle() const { return device_; }
    VkPhysicalDevice physical() const { return physical_; }
    VkQueue queue() const { return queue_; }
    uint32_t queue_family() const { return family_; }
    VmaAllocator allocator() const { return allocator_; }
    const VolkDeviceTable &fn() const { return fn_; }
    const DeviceInfo &info() const { return info_; }

    // Whether this device was created able to say what it compiled a shader
    // into -- --vk-pipeline-stats asked for it *and* the driver offers it.
    // False on most of the device set, so every caller needs the other path.
    bool pipeline_stats() const { return pipeline_stats_; }

    bool create_buffer(VkDeviceSize size, VkBufferUsageFlags usage,
                       BufferKind kind, Buffer *out);
    void destroy_buffer(Buffer *buffer);

    // Make host writes visible to the device, and device writes visible to the
    // host. No-ops on coherent memory, which is the usual case; they exist
    // because "usual" is not "always" and the platforms where it is not are
    // the ones nobody tests on.
    bool flush(const Buffer &buffer);
    bool invalidate(const Buffer &buffer);

    // Wait for everything submitted to the queue. Only for shutdown and for
    // error paths: a dispatch is waited on with a fence, not with this.
    void wait_idle();

private:
    VulkanDevice() = default;

    VkPhysicalDevice physical_ = VK_NULL_HANDLE;
    VkDevice         device_   = VK_NULL_HANDLE;
    VkQueue          queue_    = VK_NULL_HANDLE;
    uint32_t         family_   = 0;
    VmaAllocator     allocator_ = nullptr;
    VolkDeviceTable  fn_{};
    DeviceInfo       info_;
    bool             pipeline_stats_ = false;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_DEVICE_H__
