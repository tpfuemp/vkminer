// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One buffer of device memory that outlives a dispatch and is shared by every
// kernel on the device: the table an algorithm hashes against rather than
// anything it computes per nonce.
//
// Outside VulkanKernel because the sharing is the point. A kernel owns its
// result buffers and scratchpads, one set per dispatch in flight; this is one
// allocation per device however many kernels look at it. The tuner races four
// candidates and two workers can share a card, so four or eight copies of a
// table measured in gigabytes is a lost device.
//
// The kernels hold shared_ptrs and the backend a weak one, so the memory goes
// when the last kernel that wanted it does.

#ifndef VKMINER_BACKENDS_VULKAN_SHARED_STATE_H__
#define VKMINER_BACKENDS_VULKAN_SHARED_STATE_H__

#include "backends/vulkan/vulkan_device.h"

#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace vkminer {

class Algorithm;

class SharedState {
public:
    // Allocate `spec.shared_bytes` of device-local memory, in as few pieces as
    // this device's allocation and binding limits allow. Returns null, having
    // logged, if it will not give that much or if the shader has fewer bindings
    // than it would take to address it -- both ordinary answers for a table
    // this size, and neither one to find out about on the first dispatch.
    //
    // `spec.setup` is how the contents get made: a module the device runs over
    // the buffer, or nothing, in which case the host fills it and it is copied
    // up. `cache` is the device's pipeline cache and may be VK_NULL_HANDLE.
    static std::shared_ptr<SharedState> create(VulkanDevice &device,
                                               const KernelSpec &spec,
                                               VkPipelineCache cache);

    // How this device would cut a table of `bytes` up: the piece size into
    // `chunk_bytes`, the number of pieces into `count`. False writes why into
    // `why` and logs nothing -- create() logs it, a pre-check reports it.
    //
    // Takes `bytes` rather than spec.shared_bytes so the same rules can be
    // asked about a table that does not exist yet -- the size after the next
    // job, which is what a switch has to leave room for. Allocates nothing and
    // needs no logical device.
    static bool plan(const DeviceInfo &info, const KernelSpec &spec,
                     uint64_t bytes, uint64_t *chunk_bytes, uint64_t *count,
                     char *why, size_t why_bytes);

    ~SharedState();

    SharedState(const SharedState &) = delete;
    SharedState &operator=(const SharedState &) = delete;

    // The pieces the table is in, in order, and how big all but the last one
    // is. One buffer is the ordinary answer, and the code either side of this
    // keeps it the cheap case rather than a special one.
    const std::vector<Buffer> &chunks() const { return chunk_; }
    uint64_t chunk_bytes() const { return chunk_bytes_; }
    uint64_t bytes() const { return bytes_; }

    // Make the contents be the ones `key` names, asking `algorithm` for them if
    // they are not there already. Returns whether they are.
    //
    // Cheap and correct to call before every dispatch: the common case is a
    // comparison against the key that is already loaded. The expensive case
    // rebuilds the whole buffer, which is what a new epoch costs.
    bool ensure(uint64_t key, const Algorithm &algorithm);

private:
    SharedState() = default;

    // Fill `dst` -- one buffer or the whole chunked table -- with `total` bytes
    // from `fill`, through a staging buffer. `what` names the buffer in an
    // error, and `fill(offset, out, bytes)` is one of the algorithm's two
    // producers. Its offset is into the table, not into the chunk being
    // written: which piece a byte lands in is this class's business.
    bool upload(const std::vector<Buffer> &dst, uint64_t total,
                const char *what,
                const std::function<bool(uint64_t, void *, size_t)> &fill);

    // The other way to fill the table: seed the pass's input, then run the pass
    // over the whole of it in slices the device can finish between watchdogs.
    bool generate(uint64_t key, const Algorithm &algorithm);

    VulkanDevice       *device_ = nullptr;
    const char         *name_   = "";
    std::vector<Buffer> chunk_;
    uint64_t            bytes_       = 0;
    uint64_t            chunk_bytes_ = 0;

    KernelSpec::SetupPass setup_{};
    VkPipelineCache       cache_ = VK_NULL_HANDLE;

    // Held across a rebuild, because several kernels on several threads reach
    // this and only one of them should be doing the work. `ready_` says the
    // buffer holds `key_`; anything else means it holds nothing worth hashing
    // against.
    std::mutex lock_;
    uint64_t   key_   = 0;
    bool       ready_ = false;
};

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_SHARED_STATE_H__
