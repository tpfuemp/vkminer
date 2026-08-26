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

#include "backends/backend.h"
#include "backends/vulkan/vulkan_device.h"

#include <memory>
#include <string>
#include <vector>

namespace vkminer {

// Read a compiled shader. SPIR-V is a stream of 32-bit words and Vulkan wants
// it aligned as such, which is why this returns words and not bytes.
bool read_spirv(const std::string &path, std::vector<uint32_t> *out);

// Where a kernel's own constants start. Zero to three are this backend's --
// the workgroup width, the probe, and the two the shared table is addressed
// with -- and four to seven are left for the next one of those, so that adding
// one does not renumber every program constant in every shader that has any.
constexpr uint32_t kProgramConstantId = 8;

// Where the job-independent ones start: above every program constant a module
// could declare, so that a shader with both never has to know how many of the
// first kind it has.
constexpr uint32_t kKernelConstantId = kProgramConstantId + kMaxProgramConstants;

struct ComputePipelineDesc {
    const uint32_t *spirv       = nullptr;
    size_t          spirv_words = 0;

    uint32_t storage_buffers     = 0;  // bindings 0..n-1 of each set
    uint32_t push_constant_bytes = 0;  // 0 for a shader with no push block
    uint32_t local_size_x        = 0;  // specialization constant 0

    // Specialization constant 1: whether the shader maintains the best-digest
    // word. A constant rather than a uniform so that the atomic is not in the
    // module at all when it is off -- which is what makes it safe to have a
    // debug probe on the path every invocation takes. Compare the two binary
    // sizes under --vk-pipeline-stats to check that it really went.
    bool probe_best = false;

    // Specialization constants 2 and 3: how many pieces the shared table is in
    // on this device, and how many 32-bit words are in one of them. A shader
    // that reads a table too large for one binding turns an index into it into
    // a piece and an offset with these, and both are constants so that the
    // whole selection folds away where there is one piece -- which is every
    // device that can address the table in one go, and every algorithm that
    // has no table at all.
    //
    // Ignored by a module that does not declare them, which is every shader
    // written before KawPoW.
    uint32_t shared_chunks      = 0;
    uint32_t shared_chunk_words = 0;

    // The program this pipeline is the compile of: `program_count` constants
    // from kProgramConstantId upwards, in the order the algorithm wrote them.
    // Null for a module that declares none, which is every shader that computes
    // the same thing whatever the job.
    //
    // Pointed at, not copied. The values must outlive the create() call and
    // nothing else -- the driver has taken what it wants by the time it returns.
    const uint32_t *program = nullptr;
    uint32_t program_count  = 0;

    // Constants that are the same in every pipeline of this kernel:
    // `constant_count` of them from kKernelConstantId upwards. Same ownership
    // rule as `program`.
    const uint32_t *constants = nullptr;
    uint32_t constant_count   = 0;

    // Interchangeable descriptor sets to allocate, all of the same layout. One
    // per dispatch that may be in flight: a set may not be rewritten while a
    // command buffer using it is executing.
    uint32_t sets = 1;
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

    // Point descriptor set `set` at these buffers, in binding order. Recorded
    // into no command buffer: a set may not be updated while a command buffer
    // using it is executing, so this belongs before that set's first dispatch
    // or between two of them.
    void bind(uint32_t set, const Buffer *buffers, uint32_t count);

    // Record a dispatch of `groups` workgroups against descriptor set `set`,
    // with `push` bytes of push constants (may be null when the pipeline has
    // none).
    void record(VkCommandBuffer cmd, uint32_t set, uint32_t groups,
                const void *push, uint32_t push_bytes) const;

    uint32_t local_size_x() const { return local_size_x_; }

    // Log what the driver compiled this pipeline into: register counts, spills,
    // occupancy -- whatever it chose to expose, since the extension standardizes
    // the mechanism and not one statistic name. `label` identifies the pipeline
    // in the output, because a device may have several. A no-op unless the
    // device was created under --vk-pipeline-stats, so it is safe to call
    // unconditionally.
    //
    // Deliberately does not fetch internal representations. The same extension
    // offers them, and on RADV they are the full ISA -- megabytes, per pipeline,
    // through a line-oriented log. That is a file to write, not a thing to
    // print, and nothing needs it yet.
    void report_statistics(const char *label) const;

private:
    ComputePipeline() = default;

    VulkanDevice         *device_    = nullptr;
    VkDescriptorSetLayout set_layout_ = VK_NULL_HANDLE;
    VkDescriptorPool      pool_      = VK_NULL_HANDLE;
    std::vector<VkDescriptorSet> sets_;  // freed with the pool
    VkPipelineLayout      layout_    = VK_NULL_HANDLE;
    VkPipeline            pipeline_  = VK_NULL_HANDLE;
    uint32_t              local_size_x_ = 0;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_PIPELINE_H__
