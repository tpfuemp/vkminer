// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A small ring of command buffers, each with its own fence, so that the host
// can be recording and submitting while the device is still executing what it
// was given before.
//
// How many slots is the caller's decision, and a real trade. Two is the least
// that keeps the device from idling between dispatches; each one beyond that is
// another dispatch the device will finish before it starts anything from a new
// job, and another set of whatever the dispatch writes into -- a slot's buffers
// may not be reused until its results have been read, which is the caller's
// problem and not this class's.
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

        // Which slot this is, so a caller with several dispatches in the air
        // can key its own per-slot resources off it rather than reproducing
        // the ring's order.
        uint32_t        index   = 0;
    };

    static std::unique_ptr<CommandRing> create(VulkanDevice &device,
                                               uint32_t slots = 2);

    ~CommandRing();

    CommandRing(const CommandRing &) = delete;
    CommandRing &operator=(const CommandRing &) = delete;

    // The next slot, ready to record into. Blocks until that slot's previous
    // submission has completed. Returns null if the device failed.
    Slot *begin();

    // A slot by index, for a caller that remembered which one a dispatch went
    // into rather than waiting on it straight away.
    Slot *slot(uint32_t index) { return &slots_[index]; }

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
