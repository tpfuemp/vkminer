// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Instance creation and device enumeration.
//
// Headless throughout: no surface, no swapchain, no WSI extension of any kind.
// A miner never presents an image, and asking for a surface extension is the
// usual reason a compute-only program fails to start on a headless machine.
//
// Enumeration stops at the physical device. It has to work on a machine where
// the miner will not run -- to report what is present and why it is not usable
// -- so a logical device is created later, and only for the devices selected.

#include "backends/vulkan/vulkan_backend.h"

#include "backends/vulkan/pipeline_cache.h"
#include "backends/vulkan/vulkan_common.h"
#include "backends/vulkan/vulkan_kernel.h"

#include <cstring>
#include <vector>

namespace vkminer {
namespace {

constexpr const char *kValidationLayer = "VK_LAYER_KHRONOS_validation";

bool has_extension(const std::vector<VkExtensionProperties> &list,
                   const char *name)
{
    for (const VkExtensionProperties &e : list)
        if (!std::strcmp(e.extensionName, name))
            return true;
    return false;
}

DeviceKind kind_of(VkPhysicalDeviceType type)
{
    switch (type) {
    case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU: return DeviceKind::IntegratedGpu;
    case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:   return DeviceKind::DiscreteGpu;
    case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU:    return DeviceKind::VirtualGpu;
    case VK_PHYSICAL_DEVICE_TYPE_CPU:            return DeviceKind::Cpu;
    default:                                     return DeviceKind::Other;
    }
}

VKAPI_ATTR VkBool32 VKAPI_CALL debug_callback(
    VkDebugUtilsMessageSeverityFlagBitsEXT severity,
    VkDebugUtilsMessageTypeFlagsEXT types,
    const VkDebugUtilsMessengerCallbackDataEXT *data, void *user)
{
    (void)types;
    (void)user;

    int level = LOG_DEBUG;
    if (severity & VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT) {
        level = LOG_ERR;
        vk_validation_errors++;
    } else if (severity & VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT) {
        level = LOG_WARNING;
        vk_validation_warnings++;
    } else if (severity & VK_DEBUG_UTILS_MESSAGE_SEVERITY_INFO_BIT_EXT) {
        level = LOG_INFO;
    }

    applog(level, "Vulkan validation: %s",
           data->pMessage ? data->pMessage : "(no message)");

    // Always VK_FALSE: returning true aborts the call that triggered the
    // message, which turns a diagnostic into a different bug.
    return VK_FALSE;
}

}  // namespace

VulkanBackend::~VulkanBackend()
{
    // Devices first: a VkDevice outliving its VkInstance is undefined, and the
    // order members are destroyed in would get this wrong. The caches go before
    // the devices they were created on, for the same reason.
    caches_.clear();
    open_.clear();

    if (messenger_ != VK_NULL_HANDLE)
        vkDestroyDebugUtilsMessengerEXT(instance_, messenger_, nullptr);
    if (instance_ != VK_NULL_HANDLE)
        vkDestroyInstance(instance_, nullptr);
}

bool VulkanBackend::init()
{
    if (!create_instance())
        return false;

    enumerate();
    if (devices_.empty()) {
        applog(LOG_ERR, "Vulkan: no physical device found. The loader is "
                        "present but no driver is installed for it.");
        return false;
    }

    open_.resize(devices_.size());
    caches_.resize(devices_.size());
    return true;
}

VulkanDevice *VulkanBackend::device(int device_index)
{
    if (device_index < 0 || device_index >= static_cast<int>(open_.size()))
        return nullptr;

    std::lock_guard<std::mutex> held(lazy_lock_);
    if (!open_[device_index])
        open_[device_index] = VulkanDevice::create(instance_,
                                                   handles_[device_index],
                                                   compute_family_[device_index],
                                                   devices_[device_index]);
    return open_[device_index].get();
}

std::unique_ptr<Kernel> VulkanBackend::create_kernel(int device_index,
                                                     const KernelSpec &spec)
{
    VulkanDevice *dev = device(device_index);
    if (!dev)
        return nullptr;

    // An algorithm with no SPIR-V for this device is not a broken algorithm --
    // it is one whose reference exists and whose shader does not yet. Say which
    // of the two it is, because the fix is different.
    if (!spec.spirv) {
        applog(LOG_ERR, "Vulkan: '%s' has no shader for this device; "
                        "try --backend=cpu", spec.name);
        return nullptr;
    }

    // One cache per device rather than per kernel: several workers on one
    // device compile the same pipeline, and they would otherwise each write
    // the same file over the top of the others.
    VkPipelineCache cache = VK_NULL_HANDLE;
    {
        std::lock_guard<std::mutex> held(lazy_lock_);
        if (!caches_[device_index])
            caches_[device_index] = PipelineCache::open(*dev);
        cache = caches_[device_index]->handle();
    }

    // Outside the lock: the driver synchronises the cache itself for
    // vkCreateComputePipelines, and building a pipeline is the slow part of
    // starting a worker.
    return make_vulkan_kernel(*dev, cache, spec);
}

bool VulkanBackend::create_instance()
{
    // volk opens the platform loader itself. This failing is the ordinary
    // case on a machine with no Vulkan installed, so it is not an error yet.
    if (volkInitialize() != VK_SUCCESS) {
        applog(LOG_ERR, "Vulkan: no loader found "
                        "(vulkan-1.dll or libvulkan.so.1)");
        return false;
    }

    const uint32_t loader_version = volkGetInstanceVersion();
    if (loader_version < VK_API_VERSION_1_1) {
        applog(LOG_ERR, "Vulkan: loader reports %s, this miner needs 1.1",
               version_string(loader_version).c_str());
        return false;
    }

    std::vector<const char *> layers;
    std::vector<const char *> extensions;

    if (opt_vk_validate) {
        uint32_t count = 0;
        vkEnumerateInstanceLayerProperties(&count, nullptr);
        std::vector<VkLayerProperties> available(count);
        if (count)
            vkEnumerateInstanceLayerProperties(&count, available.data());

        bool found = false;
        for (const VkLayerProperties &l : available)
            if (!std::strcmp(l.layerName, kValidationLayer))
                found = true;

        if (found) {
            layers.push_back(kValidationLayer);
            extensions.push_back(VK_EXT_DEBUG_UTILS_EXTENSION_NAME);
            vk_validation_enabled = true;
        } else {
            applog(LOG_WARNING, "Vulkan: --vk-validate asked for, but %s is "
                                "not installed; continuing without it",
                   kValidationLayer);
        }
    }

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = PACKAGE_NAME;
    app.applicationVersion = VK_MAKE_VERSION(0, 1, 0);
    app.pEngineName = PACKAGE_NAME;
    app.engineVersion = VK_MAKE_VERSION(0, 1, 0);
    // The baseline, deliberately, even where the loader offers more: a device
    // that only speaks 1.1 must still be usable. Later versions are opted into
    // per feature, once the device has said it has them.
    app.apiVersion = VK_API_VERSION_1_1;

    VkInstanceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    info.pApplicationInfo = &app;
    info.enabledLayerCount = static_cast<uint32_t>(layers.size());
    info.ppEnabledLayerNames = layers.data();
    info.enabledExtensionCount = static_cast<uint32_t>(extensions.size());
    info.ppEnabledExtensionNames = extensions.data();

    // The messenger is chained into instance creation as well as created
    // afterwards, so that anything wrong with the instance itself is reported
    // rather than lost -- there is no messenger yet at the moment it happens.
    VkDebugUtilsMessengerCreateInfoEXT debug{};
    debug.sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
    debug.messageSeverity = VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT
                          | VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT;
    debug.messageType = VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT
                      | VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT
                      | VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
    debug.pfnUserCallback = debug_callback;
    if (opt_debug)
        debug.messageSeverity |= VK_DEBUG_UTILS_MESSAGE_SEVERITY_INFO_BIT_EXT;
    if (!layers.empty())
        info.pNext = &debug;

    if (!vk_ok(vkCreateInstance(&info, nullptr, &instance_), "vkCreateInstance"))
        return false;

    volkLoadInstanceOnly(instance_);

    if (!layers.empty()
        && !vk_ok(vkCreateDebugUtilsMessengerEXT(instance_, &debug, nullptr,
                                                 &messenger_),
                  "vkCreateDebugUtilsMessengerEXT"))
        messenger_ = VK_NULL_HANDLE;  // diagnostics only; not fatal

    return true;
}

void VulkanBackend::describe(VkPhysicalDevice handle, DeviceInfo *out,
                             uint32_t *family)
{
    uint32_t ext_count = 0;
    vkEnumerateDeviceExtensionProperties(handle, nullptr, &ext_count, nullptr);
    std::vector<VkExtensionProperties> exts(ext_count);
    if (ext_count)
        vkEnumerateDeviceExtensionProperties(handle, nullptr, &ext_count,
                                             exts.data());

    VkPhysicalDeviceProperties base{};
    vkGetPhysicalDeviceProperties(handle, &base);

    VkPhysicalDeviceSubgroupProperties subgroup{};
    subgroup.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_PROPERTIES;

    VkPhysicalDeviceDriverProperties driver{};
    driver.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;

    VkPhysicalDeviceProperties2 props{};
    props.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    props.pNext = &subgroup;

    const bool have_driver_props =
        base.apiVersion >= VK_API_VERSION_1_2
        || has_extension(exts, VK_KHR_DRIVER_PROPERTIES_EXTENSION_NAME);
    if (have_driver_props)
        subgroup.pNext = &driver;

    vkGetPhysicalDeviceProperties2(handle, &props);

    VkPhysicalDeviceShaderFloat16Int8Features f16i8{};
    f16i8.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT16_INT8_FEATURES;

    VkPhysicalDeviceFeatures2 features{};
    features.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
    if (base.apiVersion >= VK_API_VERSION_1_2
        || has_extension(exts, VK_KHR_SHADER_FLOAT16_INT8_EXTENSION_NAME))
        features.pNext = &f16i8;

    vkGetPhysicalDeviceFeatures2(handle, &features);

    VkPhysicalDeviceMemoryBudgetPropertiesEXT budget{};
    budget.sType =
        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT;

    VkPhysicalDeviceMemoryProperties2 memory{};
    memory.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2;
    if (has_extension(exts, VK_EXT_MEMORY_BUDGET_EXTENSION_NAME))
        memory.pNext = &budget;

    vkGetPhysicalDeviceMemoryProperties2(handle, &memory);

    uint64_t local_bytes = 0;
    for (uint32_t i = 0; i < memory.memoryProperties.memoryHeapCount; i++) {
        const VkMemoryHeap &heap = memory.memoryProperties.memoryHeaps[i];
        if (heap.flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
            local_bytes += heap.size;
    }

    // A queue that can compute and nothing else, where the device has one:
    // it is the family least likely to be preempted by the desktop, and on
    // AMD and NVIDIA it is a physically separate engine.
    *family = UINT32_MAX;
    uint32_t queue_count = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(handle, &queue_count, nullptr);
    std::vector<VkQueueFamilyProperties> families(queue_count);
    if (queue_count)
        vkGetPhysicalDeviceQueueFamilyProperties(handle, &queue_count,
                                                 families.data());
    for (uint32_t i = 0; i < queue_count; i++) {
        if (!(families[i].queueFlags & VK_QUEUE_COMPUTE_BIT))
            continue;
        if (!(families[i].queueFlags & VK_QUEUE_GRAPHICS_BIT)) {
            *family = i;
            break;
        }
        if (*family == UINT32_MAX)
            *family = i;
    }

    out->name = base.deviceName;
    out->kind = kind_of(base.deviceType);
    out->vendor_id = base.vendorID;
    out->device_id = base.deviceID;
    out->api_version = base.apiVersion;
    out->driver_version = base.driverVersion;
    out->memory = local_bytes;

    if (have_driver_props && driver.driverName[0]) {
        out->driver = driver.driverName;
        if (driver.driverInfo[0]) {
            out->driver += " ";
            out->driver += driver.driverInfo;
        }
    } else {
        out->driver = vk_driver_version_string(base.vendorID,
                                               base.driverVersion);
    }

    // subgroupSize is meaningless for this program unless compute shaders are
    // among the stages it applies to.
    if (subgroup.supportedStages & VK_SHADER_STAGE_COMPUTE_BIT) {
        out->subgroup_size = subgroup.subgroupSize;
        out->subgroup_ballot =
            (subgroup.supportedOperations & VK_SUBGROUP_FEATURE_BALLOT_BIT) != 0;
    }

    out->max_invocations = base.limits.maxComputeWorkGroupInvocations;
    out->max_workgroup_size = base.limits.maxComputeWorkGroupSize[0];
    out->max_workgroup_count = base.limits.maxComputeWorkGroupCount[0];

    // --no-int64 lies here rather than where the answer is read, because the
    // device is created from this struct too: a 64-bit module chosen anyway
    // then fails validation instead of quietly working.
    out->int64 = !opt_no_int64 && features.features.shaderInt64 == VK_TRUE;
    out->int16 = features.features.shaderInt16 == VK_TRUE;
    out->int8 = f16i8.shaderInt8 == VK_TRUE;
}

void VulkanBackend::enumerate()
{
    uint32_t count = 0;
    if (!vk_ok(vkEnumeratePhysicalDevices(instance_, &count, nullptr),
               "vkEnumeratePhysicalDevices"))
        return;

    handles_.resize(count);
    if (count
        && !vk_ok(vkEnumeratePhysicalDevices(instance_, &count, handles_.data()),
                  "vkEnumeratePhysicalDevices"))
        return;

    // Indices follow the loader's order and are never sorted. A "best device
    // first" ordering would mean --devices 0 selecting different hardware on
    // two machines, or on one machine after a driver update.
    for (uint32_t i = 0; i < count; i++) {
        DeviceInfo info;
        uint32_t family = UINT32_MAX;
        describe(handles_[i], &info, &family);

        if (family == UINT32_MAX) {
            applog(LOG_WARNING, "Vulkan: %s has no compute queue, skipping",
                   info.name.c_str());
            continue;
        }

        info.index = static_cast<int>(devices_.size());
        devices_.push_back(info);
        compute_family_.push_back(family);
    }
}

std::unique_ptr<ComputeBackend> make_vulkan_backend()
{
    return std::unique_ptr<ComputeBackend>(new VulkanBackend());
}

}  // namespace vkminer
