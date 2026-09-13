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
#include "backends/vulkan/shared_state.h"
#include "backends/vulkan/vulkan_device.h"

#include <memory>

namespace vkminer {

// Returns null, having logged why, if the pipeline or its buffers could not be
// created. `cache` may be VK_NULL_HANDLE. `shared` is the device's one table
// for kernels that asked for one and null for the rest; the kernel holds a
// reference to it, which is what keeps it alive while a dispatch reads it.
std::unique_ptr<Kernel> make_vulkan_kernel(VulkanDevice &device,
                                           VkPipelineCache cache,
                                           const KernelSpec &spec,
                                           std::shared_ptr<SharedState> shared);

// The shape a kernel would run in: how wide a workgroup, how many dispatches in
// flight, and how many hashes the scratchpads leave room for.
struct KernelFit {
    uint32_t local_size_x = 0;  // invocations per workgroup
    uint32_t lanes = 1;         // invocations that cooperate on one hash
    uint32_t per_group = 1;     // hashes per workgroup, which is the two above
    uint32_t depth = 0;         // dispatches queued on the device at once
    uint32_t max_batch = 0;     // hashes one dispatch may carry
    uint64_t per_nonce = 0;     // scratch one hash costs across every dispatch
};

// How much of `info`'s memory a kernel's scratchpads may take, and how much a
// single shared table may be. Neither is the whole heap, and both are far less
// than it where the heap is the machine's own RAM.
//
// Two numbers because a scratchpad can give ground -- fewer hashes in flight is
// slower, not broken -- while a table is take it or leave it. Used by the
// pre-check and by the allocation it predicts, so the two refuse on one number.
uint64_t vulkan_scratch_budget(const DeviceInfo &info);
uint64_t vulkan_table_budget(const DeviceInfo &info);

// Work that shape out for `spec` on `info`, with `shared_bytes` of table
// already on the device, and say whether the device has room for it at all.
// False writes why into `why` and logs nothing: this is asked both by the build
// -- which logs -- and by the pre-check, which reports rather than prints.
//
// Separate from the build so that the two cannot disagree. The refusal has to
// be the same arithmetic that would size the allocation, or a device passes a
// check and then fails to start, which is the failure the check was added to
// prevent and is now harder to read.
bool vulkan_kernel_fit(const DeviceInfo &info, const KernelSpec &spec,
                       uint64_t shared_bytes, KernelFit *out, char *why,
                       size_t why_bytes);

}  // namespace vkminer

#endif  // VKMINER_BACKENDS_VULKAN_KERNEL_H__
