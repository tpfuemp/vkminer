// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_device.h"

#include <cstring>
#include <vector>

namespace vkminer {
namespace {

bool has_extension(const std::vector<VkExtensionProperties> &list,
                   const char *name)
{
    for (const VkExtensionProperties &e : list)
        if (!std::strcmp(e.extensionName, name))
            return true;
    return false;
}

// Hands VMA the entry points from this device's table, rather than letting it
// resolve its own. VMA can call volk for them, but only through volk's global
// pointers -- the ones deliberately not loaded here, so that two devices can
// be driven at once.
VmaVulkanFunctions vma_functions(const VolkDeviceTable &fn)
{
    VmaVulkanFunctions f{};

    // Instance level: one set for the whole process, and correct from any
    // device, because they dispatch on the physical device handle passed in.
    f.vkGetInstanceProcAddr = vkGetInstanceProcAddr;
    f.vkGetDeviceProcAddr = vkGetDeviceProcAddr;
    f.vkGetPhysicalDeviceProperties = vkGetPhysicalDeviceProperties;
    f.vkGetPhysicalDeviceMemoryProperties = vkGetPhysicalDeviceMemoryProperties;
    f.vkGetPhysicalDeviceMemoryProperties2KHR =
        vkGetPhysicalDeviceMemoryProperties2;
    f.vkGetPhysicalDeviceProperties2KHR = vkGetPhysicalDeviceProperties2;

    f.vkAllocateMemory = fn.vkAllocateMemory;
    f.vkFreeMemory = fn.vkFreeMemory;
    f.vkMapMemory = fn.vkMapMemory;
    f.vkUnmapMemory = fn.vkUnmapMemory;
    f.vkFlushMappedMemoryRanges = fn.vkFlushMappedMemoryRanges;
    f.vkInvalidateMappedMemoryRanges = fn.vkInvalidateMappedMemoryRanges;
    f.vkBindBufferMemory = fn.vkBindBufferMemory;
    f.vkBindImageMemory = fn.vkBindImageMemory;
    f.vkGetBufferMemoryRequirements = fn.vkGetBufferMemoryRequirements;
    f.vkGetImageMemoryRequirements = fn.vkGetImageMemoryRequirements;
    f.vkCreateBuffer = fn.vkCreateBuffer;
    f.vkDestroyBuffer = fn.vkDestroyBuffer;
    f.vkCreateImage = fn.vkCreateImage;
    f.vkDestroyImage = fn.vkDestroyImage;
    f.vkCmdCopyBuffer = fn.vkCmdCopyBuffer;
    f.vkGetBufferMemoryRequirements2KHR = fn.vkGetBufferMemoryRequirements2;
    f.vkGetImageMemoryRequirements2KHR = fn.vkGetImageMemoryRequirements2;
    f.vkBindBufferMemory2KHR = fn.vkBindBufferMemory2;
    f.vkBindImageMemory2KHR = fn.vkBindImageMemory2;

    return f;
}

}  // namespace

std::unique_ptr<VulkanDevice> VulkanDevice::create(VkInstance instance,
                                                   VkPhysicalDevice physical,
                                                   uint32_t queue_family,
                                                   const DeviceInfo &info)
{
    std::unique_ptr<VulkanDevice> dev(new VulkanDevice());
    dev->physical_ = physical;
    dev->family_ = queue_family;
    dev->info_ = info;

    uint32_t ext_count = 0;
    vkEnumerateDeviceExtensionProperties(physical, nullptr, &ext_count, nullptr);
    std::vector<VkExtensionProperties> available(ext_count);
    if (ext_count)
        vkEnumerateDeviceExtensionProperties(physical, nullptr, &ext_count,
                                             available.data());

    std::vector<const char *> extensions;

    // Lets VMA report how much of the device's memory is actually free rather
    // than how much exists, which on a card that is also driving a display is
    // a different number entirely.
    const bool memory_budget =
        has_extension(available, VK_EXT_MEMORY_BUDGET_EXTENSION_NAME);
    if (memory_budget)
        extensions.push_back(VK_EXT_MEMORY_BUDGET_EXTENSION_NAME);

    // Asks the driver to keep, and hand back, what it compiled the shader into.
    // Only under --vk-pipeline-stats: the pipelines then have to be created with
    // a capture bit set, and a driver is entitled to compile differently when
    // asked to preserve that information -- so a miner that always requested it
    // would be measuring a shader it does not ship.
    dev->pipeline_stats_ =
        opt_vk_pipeline_stats
        && has_extension(available,
                         VK_KHR_PIPELINE_EXECUTABLE_PROPERTIES_EXTENSION_NAME);
    if (dev->pipeline_stats_)
        extensions.push_back(
            VK_KHR_PIPELINE_EXECUTABLE_PROPERTIES_EXTENSION_NAME);
    else if (opt_vk_pipeline_stats)
        applog(LOG_WARNING, "Vulkan: %s does not offer %s, so there are no "
                            "pipeline statistics to report for it",
               info.name.c_str(),
               VK_KHR_PIPELINE_EXECUTABLE_PROPERTIES_EXTENSION_NAME);

    // 8-bit integers are core from 1.2 and an extension before it. Only asked
    // for when enumeration already found the feature present.
    const bool need_float16_int8_ext =
        info.int8 && info.api_version < VK_API_VERSION_1_2
        && has_extension(available, VK_KHR_SHADER_FLOAT16_INT8_EXTENSION_NAME);
    if (need_float16_int8_ext)
        extensions.push_back(VK_KHR_SHADER_FLOAT16_INT8_EXTENSION_NAME);

    // Only what enumeration found. Asking for a feature a device does not have
    // makes vkCreateDevice fail outright, so the enumeration result is the
    // request: this is the reason DeviceInfo carries these at all.
    VkPhysicalDeviceFeatures2 features{};
    features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    features.features.shaderInt64 = info.int64 ? VK_TRUE : VK_FALSE;
    features.features.shaderInt16 = info.int16 ? VK_TRUE : VK_FALSE;

    VkPhysicalDeviceShaderFloat16Int8Features f16i8{};
    f16i8.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT16_INT8_FEATURES;
    f16i8.shaderInt8 = VK_TRUE;
    if (info.int8
        && (need_float16_int8_ext || info.api_version >= VK_API_VERSION_1_2))
        features.pNext = &f16i8;

    // Enabling the extension is not enough on its own; the feature bit is what
    // makes the query legal, and the loader's validation says so loudly.
    // Chained ahead of whatever is already there rather than assigned over it.
    VkPhysicalDevicePipelineExecutablePropertiesFeaturesKHR executable{};
    executable.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_EXECUTABLE_PROPERTIES_FEATURES_KHR;
    executable.pipelineExecutableInfo = VK_TRUE;
    if (dev->pipeline_stats_) {
        executable.pNext = features.pNext;
        features.pNext = &executable;
    }

    // One queue. A second queue on the same family would not add throughput --
    // the device is already saturated by one queue's worth of dispatches -- and
    // the scheduler overlaps work with fences instead.
    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queue{};
    queue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue.queueFamilyIndex = queue_family;
    queue.queueCount = 1;
    queue.pQueuePriorities = &priority;

    VkDeviceCreateInfo create{};
    create.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    create.pNext = &features;
    create.queueCreateInfoCount = 1;
    create.pQueueCreateInfos = &queue;
    create.enabledExtensionCount = static_cast<uint32_t>(extensions.size());
    create.ppEnabledExtensionNames = extensions.data();

    if (!vk_ok(vkCreateDevice(physical, &create, nullptr, &dev->device_),
               "vkCreateDevice"))
        return nullptr;

    volkLoadDeviceTable(&dev->fn_, dev->device_);
    dev->fn_.vkGetDeviceQueue(dev->device_, queue_family, 0, &dev->queue_);

    VmaVulkanFunctions functions = vma_functions(dev->fn_);

    VmaAllocatorCreateInfo allocator{};
    allocator.physicalDevice = physical;
    allocator.device = dev->device_;
    allocator.instance = instance;
    // The version the instance was created with, not the one the device
    // supports: VMA must not use an entry point the instance did not enable.
    allocator.vulkanApiVersion = VK_API_VERSION_1_1;
    allocator.pVulkanFunctions = &functions;
    if (memory_budget)
        allocator.flags |= VMA_ALLOCATOR_CREATE_EXT_MEMORY_BUDGET_BIT;

    if (!vk_ok(vmaCreateAllocator(&allocator, &dev->allocator_),
               "vmaCreateAllocator")) {
        dev->fn_.vkDestroyDevice(dev->device_, nullptr);
        dev->device_ = VK_NULL_HANDLE;
        return nullptr;
    }

    return dev;
}

VulkanDevice::~VulkanDevice()
{
    // Nothing should still be in flight -- the kernels go first, and a command
    // ring waits for the device before giving anything back. This is for the
    // case where something did not: destroying a device with work outstanding
    // is undefined behaviour, not an error the driver reports.
    wait_idle();

    if (allocator_)
        vmaDestroyAllocator(allocator_);
    if (device_ != VK_NULL_HANDLE)
        fn_.vkDestroyDevice(device_, nullptr);
}

bool VulkanDevice::create_buffer(VkDeviceSize size, VkBufferUsageFlags usage,
                                 BufferKind kind, Buffer *out)
{
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = size;
    info.usage = usage;
    info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;  // one queue family

    VmaAllocationCreateInfo alloc{};
    alloc.usage = VMA_MEMORY_USAGE_AUTO;
    switch (kind) {
    case BufferKind::DeviceLocal:
        break;
    case BufferKind::Upload:
        // Sequential write: the host writes each byte once and never reads
        // back, which is what lets VMA put this in write-combined memory.
        alloc.flags = VMA_ALLOCATION_CREATE_HOST_ACCESS_SEQUENTIAL_WRITE_BIT
                    | VMA_ALLOCATION_CREATE_MAPPED_BIT;
        break;
    case BufferKind::Readback:
        alloc.flags = VMA_ALLOCATION_CREATE_HOST_ACCESS_RANDOM_BIT
                    | VMA_ALLOCATION_CREATE_MAPPED_BIT;
        break;
    }

    VmaAllocationInfo result{};
    if (!vk_ok(vmaCreateBuffer(allocator_, &info, &alloc, &out->handle,
                               &out->allocation, &result),
               "vmaCreateBuffer"))
        return false;

    out->mapped = result.pMappedData;
    out->size = size;
    return true;
}

void VulkanDevice::destroy_buffer(Buffer *buffer)
{
    if (buffer->handle != VK_NULL_HANDLE)
        vmaDestroyBuffer(allocator_, buffer->handle, buffer->allocation);
    *buffer = Buffer{};
}

bool VulkanDevice::flush(const Buffer &buffer)
{
    return vk_ok(vmaFlushAllocation(allocator_, buffer.allocation, 0,
                                    VK_WHOLE_SIZE),
                 "vmaFlushAllocation");
}

bool VulkanDevice::invalidate(const Buffer &buffer)
{
    return vk_ok(vmaInvalidateAllocation(allocator_, buffer.allocation, 0,
                                         VK_WHOLE_SIZE),
                 "vmaInvalidateAllocation");
}

bool VulkanDevice::submit(const VkSubmitInfo &info, VkFence fence)
{
    std::lock_guard<std::mutex> held(queue_lock_);
    return vk_ok(fn_.vkQueueSubmit(queue_, 1, &info, fence), "vkQueueSubmit");
}

void VulkanDevice::wait_idle()
{
    if (device_ == VK_NULL_HANDLE)
        return;

    // Under the same lock as a submission: vkDeviceWaitIdle is specified as
    // externally synchronised against every queue the device owns, so shutting
    // down while another worker is submitting is the same violation by a
    // different call.
    std::lock_guard<std::mutex> held(queue_lock_);
    fn_.vkDeviceWaitIdle(device_);
}

}  // namespace vkminer
