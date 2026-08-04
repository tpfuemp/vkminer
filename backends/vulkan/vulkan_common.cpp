// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_common.h"

#include <cstdio>

namespace vkminer {

bool vk_validation_enabled = false;
unsigned vk_validation_errors = 0;
unsigned vk_validation_warnings = 0;

const char *vk_result_name(VkResult result)
{
    switch (result) {
    case VK_SUCCESS:                        return "VK_SUCCESS";
    case VK_NOT_READY:                      return "VK_NOT_READY";
    case VK_TIMEOUT:                        return "VK_TIMEOUT";
    case VK_INCOMPLETE:                     return "VK_INCOMPLETE";
    case VK_ERROR_OUT_OF_HOST_MEMORY:       return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:     return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_INITIALIZATION_FAILED:    return "VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_DEVICE_LOST:              return "VK_ERROR_DEVICE_LOST";
    case VK_ERROR_MEMORY_MAP_FAILED:        return "VK_ERROR_MEMORY_MAP_FAILED";
    case VK_ERROR_LAYER_NOT_PRESENT:        return "VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_EXTENSION_NOT_PRESENT:    return "VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_FEATURE_NOT_PRESENT:      return "VK_ERROR_FEATURE_NOT_PRESENT";
    case VK_ERROR_INCOMPATIBLE_DRIVER:      return "VK_ERROR_INCOMPATIBLE_DRIVER";
    case VK_ERROR_TOO_MANY_OBJECTS:         return "VK_ERROR_TOO_MANY_OBJECTS";
    case VK_ERROR_FORMAT_NOT_SUPPORTED:     return "VK_ERROR_FORMAT_NOT_SUPPORTED";
    case VK_ERROR_FRAGMENTED_POOL:          return "VK_ERROR_FRAGMENTED_POOL";
    case VK_ERROR_UNKNOWN:                  return "VK_ERROR_UNKNOWN";
    case VK_ERROR_OUT_OF_POOL_MEMORY:       return "VK_ERROR_OUT_OF_POOL_MEMORY";
    case VK_ERROR_INVALID_EXTERNAL_HANDLE:  return "VK_ERROR_INVALID_EXTERNAL_HANDLE";
    case VK_ERROR_FRAGMENTATION:            return "VK_ERROR_FRAGMENTATION";
    default:                                return "VkResult";
    }
}

bool vk_ok(VkResult result, const char *what)
{
    if (result == VK_SUCCESS)
        return true;
    applog(LOG_ERR, "Vulkan: %s failed: %s (%d)", what,
           vk_result_name(result), static_cast<int>(result));
    return false;
}

std::string vk_driver_version_string(uint32_t vendor_id, uint32_t version)
{
    char buf[32];

    if (vendor_id == 0x10de) {  // NVIDIA
        std::snprintf(buf, sizeof buf, "%u.%u.%u.%u",
                      (version >> 22) & 0x3ff, (version >> 14) & 0x0ff,
                      (version >> 6) & 0x0ff, version & 0x03f);
        return buf;
    }
#ifdef WIN32
    if (vendor_id == 0x8086) {  // Intel, but only on Windows
        std::snprintf(buf, sizeof buf, "%u.%u", version >> 14, version & 0x3fff);
        return buf;
    }
#endif
    return version_string(version);
}

}  // namespace vkminer
