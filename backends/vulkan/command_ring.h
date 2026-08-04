// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A small ring of command buffers, each with its own fence. Two by default:
// one executing on the device while the host records and submits the next, so
// that the device is never idle waiting for the host to catch up. More than
// two buys nothing here, because the host work per dispatch is a handful of
// calls, and each extra slot is another dispatch that has to finish before a
// new job can take effect.
//
// Every slot must have completed before the ring is destroyed. The destructor
// waits, rather than trusting the caller, because the alternative is freeing a
// command buffer the device is still reading.

#ifndef VKMINER_BACKENDS_VULKAN_COMMAND_RING_H__
#define VKMINER_BACKENDS_VULKAN_COMMAND_RING_H__

#include "backends/vulkan/vulkan_device.h"

#include <memory>
#include <vector>

namespace vkminer {

class CommandRing {
public:
    struct Slot {
        VkCommandBuffer cmd     = VK_NULL_HANDLE;
        VkFence         fence   = VK_NULL_HANDLE;
        bool            pending = false;  // submitted, fence not yet waited on
    };

    static std::unique_ptr<CommandRing> create(VulkanDevice &device,
                                               uint32_t slots = 2);

    ~CommandRing();

    CommandRing(const CommandRing &) = delete;
    CommandRing &operator=(const CommandRing &) = delete;

    // The next slot, ready to record into. Blocks until that slot's previous
    // submission has completed. Returns null if the device failed.
    Slot *begin();

    // End recording and submit. The slot stays pending until wait() reports it
    // complete.
    bool submit(Slot *slot);

    // Wait for a submitted slot. `timeout_ns` is a real timeout: a device that
    // stops answering must not hang a miner forever, it must be reported.
    bool wait(Slot *slot, uint64_t timeout_ns);

    uint32_t size() const { return static_cast<uint32_t>(slots_.size()); }

private:
    CommandRing() = default;

    VulkanDevice     *device_ = nullptr;
    VkCommandPool     pool_   = VK_NULL_HANDLE;
    std::vector<Slot> slots_;
    uint32_t          next_   = 0;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_COMMAND_RING_H__
