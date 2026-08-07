// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/pipeline_cache.h"

#include "core/paths.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace vkminer {
namespace {

std::string uuid_hex(const uint8_t uuid[VK_UUID_SIZE])
{
    char buf[VK_UUID_SIZE * 2 + 1];
    for (uint32_t i = 0; i < VK_UUID_SIZE; i++)
        std::snprintf(buf + i * 2, 3, "%02x", uuid[i]);
    return buf;
}

// A cache file starts with a header the driver is required to check, but a
// truncated or foreign file is a documented crash on more than one driver, so
// the parts that identify the device are checked here first.
bool header_matches(const std::vector<uint8_t> &data,
                    const VkPhysicalDeviceProperties &props)
{
    // headerSize, headerVersion, vendorID, deviceID, then the UUID.
    const size_t minimum = 16 + VK_UUID_SIZE;
    if (data.size() < minimum)
        return false;

    uint32_t field[4];
    std::memcpy(field, data.data(), sizeof field);

    if (field[0] < minimum || field[0] > data.size())
        return false;
    if (field[1] != VK_PIPELINE_CACHE_HEADER_VERSION_ONE)
        return false;
    if (field[2] != props.vendorID || field[3] != props.deviceID)
        return false;
    return std::memcmp(data.data() + 16, props.pipelineCacheUUID,
                       VK_UUID_SIZE) == 0;
}

bool read_file(const std::string &path, std::vector<uint8_t> *out)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
        return false;

    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        std::fclose(f);
        return false;
    }

    out->resize(static_cast<size_t>(size));
    const size_t read = std::fread(out->data(), 1, out->size(), f);
    std::fclose(f);
    return read == out->size();
}

}  // namespace

std::unique_ptr<PipelineCache> PipelineCache::open(VulkanDevice &device)
{
    std::unique_ptr<PipelineCache> cache(new PipelineCache());
    cache->device_ = &device;

    VkPhysicalDeviceProperties props{};
    vkGetPhysicalDeviceProperties(device.physical(), &props);

    const std::string dir = cache_directory();
    if (!dir.empty())
        cache->path_ = dir + "/" + uuid_hex(props.pipelineCacheUUID) + ".cache";

    std::vector<uint8_t> data;
    if (!cache->path_.empty() && read_file(cache->path_, &data)
        && !header_matches(data, props)) {
        applog(LOG_INFO, "Vulkan: ignoring a pipeline cache written by another "
                         "device or driver");
        data.clear();
    }

    VkPipelineCacheCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
    info.initialDataSize = data.size();
    info.pInitialData = data.empty() ? nullptr : data.data();

    if (!vk_ok(device.fn().vkCreatePipelineCache(device.handle(), &info,
                                                 nullptr, &cache->cache_),
               "vkCreatePipelineCache"))
        cache->cache_ = VK_NULL_HANDLE;  // slower, not broken

    cache->loaded_bytes_ = data.size();
    return cache;
}

PipelineCache::~PipelineCache()
{
    if (cache_ == VK_NULL_HANDLE)
        return;

    save();
    device_->fn().vkDestroyPipelineCache(device_->handle(), cache_, nullptr);
}

bool PipelineCache::save()
{
    if (cache_ == VK_NULL_HANDLE || path_.empty())
        return false;

    size_t size = 0;
    if (device_->fn().vkGetPipelineCacheData(device_->handle(), cache_, &size,
                                             nullptr) != VK_SUCCESS
        || size == 0)
        return false;

    // Nothing was compiled that was not already in the file. Rewriting it
    // would only risk truncating a good cache for no gain.
    if (size == loaded_bytes_)
        return true;

    std::vector<uint8_t> data(size);
    if (device_->fn().vkGetPipelineCacheData(device_->handle(), cache_, &size,
                                             data.data()) != VK_SUCCESS)
        return false;

    // Written beside the real file and moved into place, so that a miner
    // killed mid-write leaves the previous cache intact rather than a
    // half-written one for the next start to read.
    const std::string tmp = path_ + ".tmp";
    FILE *f = std::fopen(tmp.c_str(), "wb");
    if (!f)
        return false;

    const bool written = std::fwrite(data.data(), 1, size, f) == size;
    std::fclose(f);
    if (!written) {
        std::remove(tmp.c_str());
        return false;
    }

    std::remove(path_.c_str());  // Windows rename will not overwrite
    if (std::rename(tmp.c_str(), path_.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }

    loaded_bytes_ = size;
    return true;
}

}  // namespace vkminer
