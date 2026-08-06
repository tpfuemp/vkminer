// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_pipeline.h"

#include <cstdio>

namespace vkminer {

bool read_spirv(const std::string &path, std::vector<uint32_t> *out)
{
    FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) {
        applog(LOG_ERR, "Vulkan: cannot open shader %s", path.c_str());
        return false;
    }

    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);

    if (size <= 0 || size % 4) {
        applog(LOG_ERR, "Vulkan: %s is %ld bytes, which is not SPIR-V",
               path.c_str(), size);
        std::fclose(f);
        return false;
    }

    out->resize(static_cast<size_t>(size) / 4);
    const size_t read = std::fread(out->data(), 4, out->size(), f);
    std::fclose(f);

    if (read != out->size()) {
        applog(LOG_ERR, "Vulkan: short read on %s", path.c_str());
        return false;
    }

    // 0x07230203, and only in this byte order: a big-endian module would be
    // rejected by the driver with a far less specific complaint.
    if ((*out)[0] != 0x07230203u) {
        applog(LOG_ERR, "Vulkan: %s does not start with the SPIR-V magic "
                        "number", path.c_str());
        return false;
    }

    return true;
}

std::unique_ptr<ComputePipeline> ComputePipeline::create(
    VulkanDevice &device, const ComputePipelineDesc &desc, VkPipelineCache cache)
{
    if (!desc.spirv || !desc.spirv_words) {
        applog(LOG_ERR, "Vulkan: pipeline created with no shader");
        return nullptr;
    }
    if (!desc.local_size_x) {
        applog(LOG_ERR, "Vulkan: pipeline created with no workgroup size");
        return nullptr;
    }

    const DeviceInfo &info = device.info();
    if (info.max_workgroup_size && desc.local_size_x > info.max_workgroup_size) {
        applog(LOG_ERR, "Vulkan: workgroup size %u is more than %s allows (%u)",
               desc.local_size_x, info.name.c_str(), info.max_workgroup_size);
        return nullptr;
    }
    if (info.max_invocations && desc.local_size_x > info.max_invocations) {
        applog(LOG_ERR, "Vulkan: workgroup of %u invocations is more than %s "
                        "allows (%u)",
               desc.local_size_x, info.name.c_str(), info.max_invocations);
        return nullptr;
    }

    std::unique_ptr<ComputePipeline> p(new ComputePipeline());
    p->device_ = &device;
    p->local_size_x_ = desc.local_size_x;

    const uint32_t sets = desc.sets ? desc.sets : 1;

    const VolkDeviceTable &fn = device.fn();
    const VkDevice dev = device.handle();

    std::vector<VkDescriptorSetLayoutBinding> bindings(desc.storage_buffers);
    for (uint32_t i = 0; i < desc.storage_buffers; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }

    VkDescriptorSetLayoutCreateInfo set_layout{};
    set_layout.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    set_layout.bindingCount = static_cast<uint32_t>(bindings.size());
    set_layout.pBindings = bindings.data();
    if (!vk_ok(fn.vkCreateDescriptorSetLayout(dev, &set_layout, nullptr,
                                              &p->set_layout_),
               "vkCreateDescriptorSetLayout"))
        return nullptr;

    if (desc.storage_buffers) {
        VkDescriptorPoolSize size{};
        size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        size.descriptorCount = desc.storage_buffers * sets;

        VkDescriptorPoolCreateInfo pool{};
        pool.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        pool.maxSets = sets;
        pool.poolSizeCount = 1;
        pool.pPoolSizes = &size;
        if (!vk_ok(fn.vkCreateDescriptorPool(dev, &pool, nullptr, &p->pool_),
                   "vkCreateDescriptorPool"))
            return nullptr;

        // Every set has the same layout -- they differ only in what they are
        // later pointed at -- but the allocator wants one layout handle per set
        // it is asked for.
        const std::vector<VkDescriptorSetLayout> layouts(sets, p->set_layout_);
        p->sets_.resize(sets);

        VkDescriptorSetAllocateInfo alloc{};
        alloc.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
        alloc.descriptorPool = p->pool_;
        alloc.descriptorSetCount = sets;
        alloc.pSetLayouts = layouts.data();
        if (!vk_ok(fn.vkAllocateDescriptorSets(dev, &alloc, p->sets_.data()),
                   "vkAllocateDescriptorSets")) {
            p->sets_.clear();
            return nullptr;
        }
    }

    VkPushConstantRange push{};
    push.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    push.offset = 0;
    push.size = desc.push_constant_bytes;

    VkPipelineLayoutCreateInfo layout{};
    layout.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    layout.setLayoutCount = 1;
    layout.pSetLayouts = &p->set_layout_;
    layout.pushConstantRangeCount = desc.push_constant_bytes ? 1 : 0;
    layout.pPushConstantRanges = desc.push_constant_bytes ? &push : nullptr;
    if (!vk_ok(fn.vkCreatePipelineLayout(dev, &layout, nullptr, &p->layout_),
               "vkCreatePipelineLayout"))
        return nullptr;

    VkShaderModuleCreateInfo module{};
    module.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    module.codeSize = desc.spirv_words * sizeof(uint32_t);
    module.pCode = desc.spirv;

    VkShaderModule shader = VK_NULL_HANDLE;
    if (!vk_ok(fn.vkCreateShaderModule(dev, &module, nullptr, &shader),
               "vkCreateShaderModule"))
        return nullptr;

    VkSpecializationMapEntry entry{};
    entry.constantID = 0;
    entry.offset = 0;
    entry.size = sizeof(uint32_t);

    VkSpecializationInfo spec{};
    spec.mapEntryCount = 1;
    spec.pMapEntries = &entry;
    spec.dataSize = sizeof(uint32_t);
    spec.pData = &desc.local_size_x;

    VkComputePipelineCreateInfo create{};
    create.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    create.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    create.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    create.stage.module = shader;
    create.stage.pName = "main";
    create.stage.pSpecializationInfo = &spec;
    create.layout = p->layout_;

    const bool ok = vk_ok(fn.vkCreateComputePipelines(dev, cache, 1, &create,
                                                      nullptr, &p->pipeline_),
                          "vkCreateComputePipelines");

    // The module is only needed while the pipeline is being built; the driver
    // has taken whatever it wants from it by now.
    fn.vkDestroyShaderModule(dev, shader, nullptr);

    if (!ok)
        return nullptr;

    return p;
}

ComputePipeline::~ComputePipeline()
{
    if (!device_)
        return;

    const VolkDeviceTable &fn = device_->fn();
    const VkDevice dev = device_->handle();

    if (pipeline_ != VK_NULL_HANDLE)
        fn.vkDestroyPipeline(dev, pipeline_, nullptr);
    if (layout_ != VK_NULL_HANDLE)
        fn.vkDestroyPipelineLayout(dev, layout_, nullptr);
    // The sets are freed with the pool they came from.
    if (pool_ != VK_NULL_HANDLE)
        fn.vkDestroyDescriptorPool(dev, pool_, nullptr);
    if (set_layout_ != VK_NULL_HANDLE)
        fn.vkDestroyDescriptorSetLayout(dev, set_layout_, nullptr);
}

void ComputePipeline::bind(uint32_t set, const Buffer *buffers, uint32_t count)
{
    if (!count || set >= sets_.size())
        return;

    std::vector<VkDescriptorBufferInfo> info(count);
    std::vector<VkWriteDescriptorSet> writes(count);

    for (uint32_t i = 0; i < count; i++) {
        info[i].buffer = buffers[i].handle;
        info[i].offset = 0;
        info[i].range = VK_WHOLE_SIZE;

        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = sets_[set];
        writes[i].dstBinding = i;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        writes[i].pBufferInfo = &info[i];
    }

    device_->fn().vkUpdateDescriptorSets(device_->handle(), count,
                                         writes.data(), 0, nullptr);
}

void ComputePipeline::record(VkCommandBuffer cmd, uint32_t set, uint32_t groups,
                             const void *push, uint32_t push_bytes) const
{
    const VolkDeviceTable &fn = device_->fn();

    fn.vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
    if (set < sets_.size())
        fn.vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, layout_,
                                   0, 1, &sets_[set], 0, nullptr);
    if (push && push_bytes)
        fn.vkCmdPushConstants(cmd, layout_, VK_SHADER_STAGE_COMPUTE_BIT, 0,
                              push_bytes, push);
    fn.vkCmdDispatch(cmd, groups, 1, 1);
}

}  // namespace vkminer
