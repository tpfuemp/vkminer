// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_kernel.h"

#include "algorithms/algorithm.h"
#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/vulkan_pipeline.h"

#include <chrono>
#include <cstring>

namespace vkminer {
namespace {

// Words per candidate, and how many of them fit. Both halves of a contract with
// shaders/common/candidates.glsl; see the constant of the same name there.
constexpr uint32_t kCandidateWords = 9;

// Far more than a dispatch should ever produce. A batch that fills this is a
// batch sized for a difficulty nobody is mining at, and the host says so rather
// than quietly returning the first few.
constexpr uint32_t kMaxCandidates = 32;

constexpr uint32_t kResultWords = 1 + kMaxCandidates * kCandidateWords;

// How long a dispatch is aimed at. Short enough that a new job costs at most
// this much wasted work and that no watchdog anywhere is close to firing -- the
// Windows TDR is about two seconds -- and long enough that the per-dispatch
// host work is noise beside it.
constexpr double kTargetSeconds = 0.05;

// Not a watchdog of our own: it is the difference between a hung device being
// reported and a miner that stops answering with no explanation.
constexpr uint64_t kTimeoutNs = 10ull * 1000 * 1000 * 1000;

constexpr uint32_t kMinBatch = 1u << 12;
constexpr uint32_t kMaxBatch = 1u << 28;

// Workgroup width. 256 suits every desktop part; the clamps are what make it
// safe on the ones it does not suit, and a size that is not a whole number of
// subgroups wastes the remainder of the last one on every workgroup.
uint32_t choose_local_size(const DeviceInfo &info)
{
    uint32_t local = 256;
    if (info.max_workgroup_size && local > info.max_workgroup_size)
        local = info.max_workgroup_size;
    if (info.max_invocations && local > info.max_invocations)
        local = info.max_invocations;

    if (info.subgroup_size > 1 && local > info.subgroup_size) {
        const uint32_t whole = local - (local % info.subgroup_size);
        if (whole)
            local = whole;
    }
    return local ? local : 1;
}

class VulkanKernel final : public Kernel {
public:
    VulkanKernel() = default;

    ~VulkanKernel() override
    {
        // The ring first: its destructor waits for the device, which is what
        // makes freeing the buffers underneath it safe.
        ring_.reset();
        pipeline_.reset();
        if (device_) {
            device_->destroy_buffer(&results_);
            device_->destroy_buffer(&readback_);
        }
    }

    bool init(VulkanDevice &device, VkPipelineCache cache,
              const KernelSpec &spec)
    {
        device_ = &device;
        algorithm_ = spec.algorithm;
        name_ = spec.name;
        push_bytes_ = spec.push_constant_bytes;

        if (push_bytes_ > sizeof push_) {
            applog(LOG_ERR, "Vulkan: '%s' wants %u bytes of push constants, "
                            "which is more than this backend carries (%u)",
                   name_, push_bytes_, static_cast<unsigned>(sizeof push_));
            return false;
        }

        const DeviceInfo &info = device.info();

        ComputePipelineDesc desc;
        desc.spirv = spec.spirv;
        desc.spirv_words = spec.spirv_words;
        desc.storage_buffers = spec.storage_buffers ? spec.storage_buffers : 1;
        desc.push_constant_bytes = push_bytes_;
        desc.local_size_x = spec.local_size_x ? spec.local_size_x
                                              : choose_local_size(info);

        pipeline_ = ComputePipeline::create(device, desc, cache);
        if (!pipeline_)
            return false;
        local_ = pipeline_->local_size_x();

        const VkDeviceSize bytes = kResultWords * sizeof(uint32_t);
        if (!device.create_buffer(bytes,
                                  VK_BUFFER_USAGE_STORAGE_BUFFER_BIT
                                      | VK_BUFFER_USAGE_TRANSFER_SRC_BIT
                                      | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                  BufferKind::DeviceLocal, &results_)) {
            applog(LOG_ERR, "Vulkan: could not allocate the result buffer "
                            "for '%s'", name_);
            return false;
        }
        if (!device.create_buffer(bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                  BufferKind::Readback, &readback_)) {
            applog(LOG_ERR, "Vulkan: could not allocate a readback buffer "
                            "for '%s'", name_);
            return false;
        }

        // Once, here, and never again: a descriptor set may not be updated
        // while a command buffer using it is in flight, and this one is used by
        // every dispatch from now on.
        pipeline_->bind(&results_, 1);

        ring_ = CommandRing::create(device, 2);
        if (!ring_)
            return false;

        // A first guess, corrected from measurement after the first dispatch.
        // It is deliberately low: too small costs throughput for a fraction of
        // a second, too large risks a watchdog on hardware nobody has tested.
        batch_ = info.kind == DeviceKind::Cpu ? (1u << 18) : (1u << 20);
        clamp_batch(info);

        applog(LOG_INFO, "Vulkan: '%s' on %s, workgroup %u", name_,
               info.name.c_str(), local_);
        return true;
    }

    bool dispatch(const uint32_t *header, const uint32_t *target,
                  uint32_t nonce_start, uint32_t count) override
    {
        if (!count)
            return false;

        Dispatch job;
        job.header = header;
        job.target = target;
        job.nonce_start = nonce_start;
        job.count = count;
        job.capacity = kMaxCandidates;

        // The algorithm fills the block, and it must fill exactly the block the
        // pipeline was built for. Anything else means the shader would read
        // bytes laid out for a different one, which no validation layer can
        // catch: the memory is there and it is the wrong memory.
        const size_t wrote = algorithm_
                           ? algorithm_->prepare(job, push_, sizeof push_) : 0;
        if (wrote != push_bytes_) {
            applog(LOG_ERR, "Vulkan: '%s' declared %u bytes of push constants "
                            "and prepared %zu", name_, push_bytes_, wrote);
            return false;
        }

        CommandRing::Slot *slot = ring_->begin();
        if (!slot)
            return false;

        const VolkDeviceTable &fn = device_->fn();

        // The counter has to start at zero, and the whole buffer is small
        // enough that clearing all of it costs nothing and leaves no stale
        // candidate from the last dispatch anywhere the host could read one.
        fn.vkCmdFillBuffer(slot->cmd, results_.handle, 0, VK_WHOLE_SIZE, 0);

        VkMemoryBarrier cleared{};
        cleared.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        cleared.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        cleared.dstAccessMask = VK_ACCESS_SHADER_READ_BIT
                              | VK_ACCESS_SHADER_WRITE_BIT;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                                VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1,
                                &cleared, 0, nullptr, 0, nullptr);

        const uint32_t groups = (count + local_ - 1) / local_;
        pipeline_->record(slot->cmd, groups, push_, push_bytes_);

        VkMemoryBarrier written{};
        written.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        written.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        written.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                                VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &written,
                                0, nullptr, 0, nullptr);

        VkBufferCopy copy{};
        copy.size = kResultWords * sizeof(uint32_t);
        fn.vkCmdCopyBuffer(slot->cmd, results_.handle, readback_.handle, 1,
                           &copy);

        started_ = std::chrono::steady_clock::now();
        if (!ring_->submit(slot))
            return false;

        pending_ = slot;
        pending_count_ = count;
        return true;
    }

    int collect(Solution *out, int max) override
    {
        if (!pending_)
            return 0;

        CommandRing::Slot *slot = pending_;
        pending_ = nullptr;

        if (!ring_->wait(slot, kTimeoutNs)) {
            applog(LOG_ERR, "Vulkan: '%s' did not finish within %u seconds",
                   name_, static_cast<unsigned>(kTimeoutNs / 1000000000ull));
            return -1;
        }

        const std::chrono::duration<double> elapsed =
            std::chrono::steady_clock::now() - started_;
        retune(elapsed.count());

        if (!device_->invalidate(readback_))
            return -1;

        const uint32_t *result =
            static_cast<const uint32_t *>(readback_.mapped);
        uint32_t found = result[0];

        if (found > kMaxCandidates) {
            applog(LOG_WARNING, "Vulkan: '%s' found %u candidates in one "
                                "dispatch and only %u fit -- %u lost. The "
                                "dispatch is far too large for this difficulty.",
                   name_, found, kMaxCandidates, found - kMaxCandidates);
            found = kMaxCandidates;
        }
        if (max >= 0 && found > static_cast<uint32_t>(max))
            found = static_cast<uint32_t>(max);

        for (uint32_t i = 0; i < found; i++) {
            const uint32_t *candidate = result + 1 + i * kCandidateWords;
            out[i].nonce = candidate[0];
            std::memcpy(out[i].hash, candidate + 1, sizeof out[i].hash);
        }

        return static_cast<int>(found);
    }

    uint32_t preferred_batch() const override { return batch_; }

private:
    // Aim the next dispatch at kTargetSeconds, from how long the last one took.
    // Only full batches are measured: a short one at the end of a nonce range
    // says nothing about how fast the device is.
    void retune(double seconds)
    {
        if (pending_count_ != batch_ || seconds <= 0.)
            return;

        double scale = kTargetSeconds / seconds;
        // Moving by at most 4x per dispatch, so that one descheduled batch
        // cannot send the next one into the watchdog.
        if (scale > 4.) scale = 4.;
        if (scale < 0.25) scale = 0.25;

        const double next = static_cast<double>(batch_) * scale;
        batch_ = next >= static_cast<double>(kMaxBatch)
               ? kMaxBatch : static_cast<uint32_t>(next);
        clamp_batch(device_->info());
    }

    void clamp_batch(const DeviceInfo &info)
    {
        if (batch_ < kMinBatch)
            batch_ = kMinBatch;
        if (batch_ > kMaxBatch)
            batch_ = kMaxBatch;

        // A dispatch is workgroups, and there is a limit on how many of them
        // one call may have. Well above anything wanted here on a desktop
        // driver, and not on every driver.
        if (info.max_workgroup_count) {
            const uint64_t most =
                static_cast<uint64_t>(info.max_workgroup_count) * local_;
            if (static_cast<uint64_t>(batch_) > most)
                batch_ = static_cast<uint32_t>(most);
        }
    }

    VulkanDevice *device_ = nullptr;
    const Algorithm *algorithm_ = nullptr;
    const char *name_ = "";

    std::unique_ptr<ComputePipeline> pipeline_;
    std::unique_ptr<CommandRing> ring_;
    Buffer results_{};
    Buffer readback_{};

    CommandRing::Slot *pending_ = nullptr;
    uint32_t pending_count_ = 0;
    std::chrono::steady_clock::time_point started_;

    // The guaranteed minimum a Vulkan device must offer. An algorithm that
    // wants more than this is refused at kernel creation rather than on a
    // device that happens to allow it.
    unsigned char push_[128] = {0};
    uint32_t push_bytes_ = 0;

    uint32_t local_ = 0;
    uint32_t batch_ = kMinBatch;
};

}  // namespace

std::unique_ptr<Kernel> make_vulkan_kernel(VulkanDevice &device,
                                           VkPipelineCache cache,
                                           const KernelSpec &spec)
{
    std::unique_ptr<VulkanKernel> kernel(new VulkanKernel());
    if (!kernel->init(device, cache, spec))
        return nullptr;
    return kernel;
}

}  // namespace vkminer
