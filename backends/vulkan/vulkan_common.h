// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared plumbing for the Vulkan backend: the loader header, the log, and the
// two things every call site needs -- a readable name for a VkResult, and a
// check that logs where it failed.

#ifndef VKMINER_BACKENDS_VULKAN_COMMON_H__
#define VKMINER_BACKENDS_VULKAN_COMMON_H__

#include <volk.h>

#include "backends/backend.h"

#include <cstdint>
#include <string>

extern "C" {
#include "core/miner.h"
}

namespace vkminer {

// True once the validation layers have actually been enabled, which is not
// the same as having asked for them: the layer may not be installed.
extern bool vk_validation_enabled;

// Validation messages seen so far, by severity. A test fails on the error
// count; the miner uses it to say plainly whether the driver complained,
// because a validation error found and ignored is worse than none at all.
extern unsigned vk_validation_errors;
extern unsigned vk_validation_warnings;

const char *vk_result_name(VkResult result);

// Log `what` and return false when `result` is not VK_SUCCESS. Written as a
// function rather than a macro so that it can be used in an if-condition
// without swallowing the else of the caller.
bool vk_ok(VkResult result, const char *what);

// A driver version is not packed the same way by every vendor: NVIDIA and
// Intel-on-Windows use their own layouts, and decoding them with the standard
// macros produces a number that matches nothing the vendor publishes.
std::string vk_driver_version_string(uint32_t vendor_id, uint32_t version);

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_COMMON_H__
