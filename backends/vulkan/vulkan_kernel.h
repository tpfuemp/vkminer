// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One algorithm running on one device: a pipeline, the buffer solutions come
// back in, and the command buffers that carry a dispatch between them. It is
// the whole of what the Vulkan backend does per hash and it knows nothing about
// hashing -- the push constants are bytes the algorithm produced, the results
// are words the algorithm's shader wrote, and this file reads neither.

#ifndef VKMINER_BACKENDS_VULKAN_KERNEL_H__
#define VKMINER_BACKENDS_VULKAN_KERNEL_H__

#include "backends/backend.h"
#include "backends/vulkan/vulkan_device.h"

#include <memory>

namespace vkminer {

// Returns null, having logged why, if the pipeline or its buffers could not be
// created. `cache` may be VK_NULL_HANDLE.
std::unique_ptr<Kernel> make_vulkan_kernel(VulkanDevice &device,
                                           VkPipelineCache cache,
                                           const KernelSpec &spec);

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_KERNEL_H__
