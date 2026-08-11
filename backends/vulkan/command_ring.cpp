// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/command_ring.h"

namespace vkminer {

std::unique_ptr<CommandRing> CommandRing::create(VulkanDevice &device,
                                                 uint32_t slots)
{
    if (!slots)
        return nullptr;

    std::unique_ptr<CommandRing> ring(new CommandRing());
    ring->device_ = &device;

    const VolkDeviceTable &fn = device.fn();
    const VkDevice dev = device.handle();

    VkCommandPoolCreateInfo pool{};
    pool.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    // Buffers are re-recorded every dispatch with the same handful of commands,
    // so each is reset individually rather than the pool being reset as a whole
    // -- resetting the pool would mean resetting a buffer still in flight.
    pool.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    pool.queueFamilyIndex = device.queue_family();
    if (!vk_ok(fn.vkCreateCommandPool(dev, &pool, nullptr, &ring->pool_),
               "vkCreateCommandPool"))
        return nullptr;

    std::vector<VkCommandBuffer> buffers(slots);
    VkCommandBufferAllocateInfo alloc{};
    alloc.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    alloc.commandPool = ring->pool_;
    alloc.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    alloc.commandBufferCount = slots;
    if (!vk_ok(fn.vkAllocateCommandBuffers(dev, &alloc, buffers.data()),
               "vkAllocateCommandBuffers")) {
        fn.vkDestroyCommandPool(dev, ring->pool_, nullptr);
        return nullptr;
    }

    ring->slots_.resize(slots);
    for (uint32_t i = 0; i < slots; i++) {
        ring->slots_[i].cmd = buffers[i];
        ring->slots_[i].index = i;

        // Created signalled: the first pass through the ring waits on fences
        // for submissions that never happened, and an unsignalled fence would
        // hang there.
        VkFenceCreateInfo fence{};
        fence.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fence.flags = VK_FENCE_CREATE_SIGNALED_BIT;
        if (!vk_ok(fn.vkCreateFence(dev, &fence, nullptr, &ring->slots_[i].fence),
                   "vkCreateFence"))
            return nullptr;  // the destructor cleans up what was made
    }

    return ring;
}

CommandRing::~CommandRing()
{
    if (!device_)
        return;

    const VolkDeviceTable &fn = device_->fn();
    const VkDevice dev = device_->handle();

    // Nothing may be executing when the buffers go away, and a fence wait is
    // not enough on an error path where a submission failed after signalling.
    // Through the device for the same reason submissions go through it: two
    // workers on one card reach here at the same moment when the miner stops,
    // and this call is externally synchronised against every queue as well.
    device_->wait_idle();

    for (Slot &slot : slots_)
        if (slot.fence != VK_NULL_HANDLE)
            fn.vkDestroyFence(dev, slot.fence, nullptr);

    if (pool_ != VK_NULL_HANDLE)
        fn.vkDestroyCommandPool(dev, pool_, nullptr);  // frees its buffers
}

CommandRing::Slot *CommandRing::begin()
{
    Slot &slot = slots_[next_];
    next_ = (next_ + 1) % slots_.size();

    if (slot.pending && !wait(&slot, 10ull * 1000 * 1000 * 1000))
        return nullptr;

    const VolkDeviceTable &fn = device_->fn();

    if (!vk_ok(fn.vkResetCommandBuffer(slot.cmd, 0), "vkResetCommandBuffer"))
        return nullptr;

    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (!vk_ok(fn.vkBeginCommandBuffer(slot.cmd, &begin),
               "vkBeginCommandBuffer"))
        return nullptr;

    return &slot;
}

bool CommandRing::submit(Slot *slot)
{
    const VolkDeviceTable &fn = device_->fn();

    if (!vk_ok(fn.vkEndCommandBuffer(slot->cmd), "vkEndCommandBuffer"))
        return false;
    if (!vk_ok(fn.vkResetFences(device_->handle(), 1, &slot->fence),
               "vkResetFences"))
        return false;

    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &slot->cmd;

    // Through the device rather than onto its queue directly: one card can be
    // driven by several workers, and each has its own ring but they all end at
    // the same queue.
    if (!device_->submit(submit, slot->fence))
        return false;

    slot->pending = true;
    return true;
}

bool CommandRing::wait(Slot *slot, uint64_t timeout_ns)
{
    if (!slot->pending)
        return true;

    const VkResult result = device_->fn().vkWaitForFences(
        device_->handle(), 1, &slot->fence, VK_TRUE, timeout_ns);

    if (result == VK_TIMEOUT) {
        applog(LOG_ERR, "Vulkan: %s did not finish a dispatch within %u ms",
               device_->info().name.c_str(),
               static_cast<unsigned>(timeout_ns / 1000000));
        return false;
    }
    if (!vk_ok(result, "vkWaitForFences"))
        return false;

    slot->pending = false;
    return true;
}

}  // namespace vkminer
