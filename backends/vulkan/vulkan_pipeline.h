// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One compute pipeline: a shader, the storage buffers it reads and writes, and
// the push constants that tell it what to do this dispatch. Every kernel in
// this miner has that shape, so it is built once here rather than per
// algorithm.
//
// The workgroup size is a specialization constant rather than a number in the
// GLSL, so that one SPIR-V module can be built at the size a given device
// wants -- 64 on AMD, 32 on NVIDIA, 16 on some mobile parts -- without
// shipping one shader per vendor.

#ifndef VKMINER_BACKENDS_VULKAN_PIPELINE_H__
#define VKMINER_BACKENDS_VULKAN_PIPELINE_H__

#include "backends/vulkan/vulkan_device.h"

#include <memory>
#include <string>
#include <vector>

namespace vkminer {

// Read a compiled shader. SPIR-V is a stream of 32-bit words and Vulkan wants
// it aligned as such, which is why this returns words and not bytes.
bool read_spirv(const std::string &path, std::vector<uint32_t> *out);

struct ComputePipelineDesc {
    const uint32_t *spirv       = nullptr;
    size_t          spirv_words = 0;

    uint32_t storage_buffers     = 0;  // bound at set 0, bindings 0..n-1
    uint32_t push_constant_bytes = 0;  // 0 for a shader with no push block
    uint32_t local_size_x        = 0;  // specialization constant 0
};

class ComputePipeline {
public:
    // `cache` may be VK_NULL_HANDLE. Returns null and logs on failure,
    // including when local_size_x exceeds what the device allows -- which is
    // worth catching here, because the driver's own message for it names the
    // limit but not the shader.
    static std::unique_ptr<ComputePipeline> create(VulkanDevice &device,
                                                   const ComputePipelineDesc &desc,
                                                   VkPipelineCache cache);

    ~ComputePipeline();

    ComputePipeline(const ComputePipeline &) = delete;
    ComputePipeline &operator=(const ComputePipeline &) = delete;

    // Point the descriptor set at these buffers, in binding order. Recorded
    // into no command buffer: a descriptor set may not be updated while a
    // command buffer using it is executing, so this belongs between dispatches.
    void bind(const Buffer *buffers, uint32_t count);

    // Record a dispatch of `groups` workgroups, with `push` bytes of push
    // constants (may be null when the pipeline has none).
    void record(VkCommandBuffer cmd, uint32_t groups, const void *push,
                uint32_t push_bytes) const;

    uint32_t local_size_x() const { return local_size_x_; }

private:
    ComputePipeline() = default;

    VulkanDevice         *device_    = nullptr;
    VkDescriptorSetLayout set_layout_ = VK_NULL_HANDLE;
    VkDescriptorPool      pool_      = VK_NULL_HANDLE;
    VkDescriptorSet       set_       = VK_NULL_HANDLE;
    VkPipelineLayout      layout_    = VK_NULL_HANDLE;
    VkPipeline            pipeline_  = VK_NULL_HANDLE;
    uint32_t              local_size_x_ = 0;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_PIPELINE_H__
