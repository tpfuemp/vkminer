// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A VkPipelineCache backed by a file, so that compiling a kernel is something
// that happens on the first run rather than on every run. Compiling a mining
// shader takes long enough on some drivers to be noticeable next to a restart.
//
// The file is keyed by the device's pipelineCacheUUID: a driver update changes
// it, and a cache written by the old driver is then simply not found rather
// than fed to a driver that would have to reject it. Rejection is specified to
// be safe, and is not, on every driver anyone has tried.

#ifndef VKMINER_BACKENDS_VULKAN_PIPELINE_CACHE_H__
#define VKMINER_BACKENDS_VULKAN_PIPELINE_CACHE_H__

#include "backends/vulkan/vulkan_device.h"

#include <memory>
#include <string>

namespace vkminer {

class PipelineCache {
public:
    // Never fails in a way the caller has to handle: a cache that cannot be
    // read, written or created is a slower start, not an error, and the
    // returned object then simply holds VK_NULL_HANDLE.
    static std::unique_ptr<PipelineCache> open(VulkanDevice &device);

    ~PipelineCache();

    PipelineCache(const PipelineCache &) = delete;
    PipelineCache &operator=(const PipelineCache &) = delete;

    VkPipelineCache handle() const { return cache_; }

    // Write the cache back. Called by the destructor; public because a miner
    // is usually killed rather than asked to exit, and the caller may want to
    // do this at a moment of its own choosing.
    bool save();

private:
    PipelineCache() = default;

    VulkanDevice   *device_ = nullptr;
    VkPipelineCache cache_  = VK_NULL_HANDLE;
    std::string     path_;
    size_t          loaded_bytes_ = 0;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_PIPELINE_CACHE_H__
