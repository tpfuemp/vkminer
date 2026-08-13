// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_kernel.h"

#include "algorithms/algorithm.h"
#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/vulkan_pipeline.h"

#include <chrono>
#include <cstring>
#include <vector>

namespace vkminer {
namespace {

// Words per candidate, and how many of them fit. Both halves of a contract with
// shaders/common/candidates.glsl; see the constant of the same name there.
constexpr uint32_t kCandidateWords = 9;

// kMaxCandidates is in backends/backend.h, because every caller of collect()
// has to size its array by the same number.

// Word 0 is the count, word 1 the best digest the probe saw, and the candidates
// follow. Both halves of the same contract as above.
constexpr uint32_t kFoundWord = 0;
constexpr uint32_t kBestWord = 1;
constexpr uint32_t kHeaderWords = 2;

constexpr uint32_t kResultWords = kHeaderWords + kMaxCandidates * kCandidateWords;

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

// Dispatches kept queued on the device at once, unless --queue-depth says
// otherwise. Two stops it idling -- one executing while the host reads the
// last one's results and records the next -- and the third is slack for a host
// thread that gets descheduled part way through that.
//
// The cost is latency on a job change: everything outstanding is finished
// first, so depth * kTargetSeconds, well under a fifth of a second here against
// a job that lasts tens. Each also needs its own result buffer and descriptor
// set, neither being touchable while a command buffer using it executes.
constexpr uint32_t kDefaultDepth = 3;

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
        // makes freeing the buffers underneath it safe. With several dispatches
        // possibly still queued that is not a formality.
        ring_.reset();
        pipeline_.reset();
        if (device_)
            for (Slot &slot : slot_) {
                device_->destroy_buffer(&slot.results);
                device_->destroy_buffer(&slot.readback);
                device_->destroy_buffer(&slot.scratch);
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

        // The spec first: a caller that named a depth wants that one and no
        // other, which is how the tuner runs one kernel at several. Then the
        // option, validated where it is parsed, so all that is left here is
        // whether it was given.
        //
        // Everything below sizes off depth_, so depth 1 is one of each
        // resource -- the submit-and-wait loop this had before it was
        // pipelined, from the same binary.
        depth_ = spec.queue_depth              ? spec.queue_depth
               : opt_queue_depth > 0           ? static_cast<uint32_t>(opt_queue_depth)
                                               : kDefaultDepth;

        ComputePipelineDesc desc;
        desc.spirv = spec.spirv;
        desc.spirv_words = spec.spirv_words;
        desc.storage_buffers = spec.storage_buffers ? spec.storage_buffers : 1;
        desc.push_constant_bytes = push_bytes_;
        // The width by the same rule as the depth: the spec, then the option,
        // then this device's default.
        desc.local_size_x = spec.local_size_x  ? spec.local_size_x
                          : opt_workgroup > 0  ? static_cast<uint32_t>(opt_workgroup)
                                               : choose_local_size(info);
        probe_best_ = opt_vk_probe_best;
        desc.probe_best = probe_best_;
        desc.sets = depth_;

        pipeline_ = ComputePipeline::create(device, desc, cache);
        if (!pipeline_)
            return false;
        local_ = pipeline_->local_size_x();

        // Here rather than at the call site: this is the only place that knows
        // both the pipeline and which algorithm it belongs to, and the tuner
        // builds one of these per candidate workgroup size -- which is exactly
        // the sweep worth seeing the register cost of. A no-op unless asked.
        pipeline_->report_statistics(name_);

        // One result buffer per in-flight dispatch, not one shared: the host
        // reads a dispatch's results long after the next has started writing,
        // and they would be the two of them in the same words. A kilobyte each.
        // Dispatches overlap and every invocation in one owns a scratchpad, so
        // the bill is depth * batch * scratch and the batch is the only free
        // variable in it.
        scratch_bytes_ = spec.scratch_bytes;
        concurrent_ = spec.concurrent_kernels ? spec.concurrent_kernels : 1;
        if (scratch_bytes_ && !size_scratch(info))
            return false;

        const VkDeviceSize bytes = kResultWords * sizeof(uint32_t);
        slot_.resize(depth_);
        queue_.resize(depth_);
        for (uint32_t i = 0; i < depth_; i++) {
            if (!device.create_buffer(bytes,
                                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT
                                          | VK_BUFFER_USAGE_TRANSFER_SRC_BIT
                                          | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                      BufferKind::DeviceLocal,
                                      &slot_[i].results)) {
                applog(LOG_ERR, "Vulkan: could not allocate result buffer %u "
                                "for '%s'", i, name_);
                return false;
            }
            if (!device.create_buffer(bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                      BufferKind::Readback,
                                      &slot_[i].readback)) {
                applog(LOG_ERR, "Vulkan: could not allocate readback buffer %u "
                                "for '%s'", i, name_);
                return false;
            }

            if (scratch_bytes_) {
                const VkDeviceSize scratch =
                    static_cast<VkDeviceSize>(max_batch_) * scratch_bytes_;
                if (!device.create_buffer(scratch,
                                          VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                                          BufferKind::DeviceLocal,
                                          &slot_[i].scratch)) {
                    applog(LOG_ERR, "Vulkan: could not allocate a %llu MiB "
                                    "scratchpad for '%s' (slot %u of %u)",
                           static_cast<unsigned long long>(scratch >> 20),
                           name_, i, depth_);
                    return false;
                }
            }

            // Once, here, and never again: a set may not be updated while a
            // command buffer using it is in flight, and once the pipeline is
            // full there is no instant at which none of them is.
            const Buffer bound[2] = { slot_[i].results, slot_[i].scratch };
            pipeline_->bind(i, bound, scratch_bytes_ ? 2 : 1);
        }

        ring_ = CommandRing::create(device, depth_);
        if (!ring_)
            return false;

        // A first guess, corrected from measurement after the first dispatch.
        // It is deliberately low: too small costs throughput for a fraction of
        // a second, too large risks a watchdog on hardware nobody has tested.
        batch_ = info.kind == DeviceKind::Cpu ? (1u << 18) : (1u << 20);
        clamp_batch(info);

        // The depth is on this line so that a log says which run it was --
        // comparing one against another is the point of the option existing.
        // The variant is there for the same reason, where the algorithm has
        // more than one kernel and the tuner may have preferred either.
        applog(LOG_INFO, "Vulkan: '%s' on %s, workgroup %u, %u dispatch%s in "
                         "flight%s%s", name_, info.name.c_str(), local_, depth_,
               depth_ == 1 ? "" : "es",
               spec.variant && spec.variant[0] ? ", kernel " : "",
               spec.variant ? spec.variant : "");
        return true;
    }

    bool dispatch(const uint32_t *header, const uint32_t *target,
                  uint32_t nonce_start, uint32_t count) override
    {
        if (!count)
            return false;

        // Scratch is indexed by invocation and only max_batch_ of them were
        // allocated. Past that the device writes wherever the arithmetic lands:
        // no fault, no validation error, just a wrong digest somewhere the host
        // will never look.
        if (count > max_batch_) {
            applog(LOG_ERR, "Vulkan: '%s' was handed %u nonces, and has "
                            "scratchpads for %u", name_, count, max_batch_);
            return false;
        }

        // The caller is told how many it may have outstanding. Refusing beats
        // overwriting: the alternative is a dispatch's results silently
        // replaced by the next one's.
        if (inflight_ >= depth_) {
            applog(LOG_ERR, "Vulkan: '%s' was handed a dispatch with %u already "
                            "outstanding, which is all it holds", name_,
                   inflight_);
            return false;
        }

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

        // Which buffers and descriptor set this dispatch owns until its results
        // are read. Taken from the ring's slot rather than tracked separately,
        // so the two orders cannot drift.
        const uint32_t index = slot->index;
        Slot &mine = slot_[index];

        const VolkDeviceTable &fn = device_->fn();

        // The counter has to start at zero, and the whole buffer is small
        // enough that clearing all of it costs nothing and leaves no stale
        // candidate from the last dispatch anywhere the host could read one.
        //
        // Three fills rather than one because the probe's word starts at the
        // opposite end of the range: a running minimum initialized to zero
        // stays zero. They cover disjoint bytes, which is what lets them go in
        // without a barrier between them -- two transfer writes to the same
        // word would have no defined order.
        fn.vkCmdFillBuffer(slot->cmd, mine.results.handle,
                           kFoundWord * sizeof(uint32_t), sizeof(uint32_t), 0);
        fn.vkCmdFillBuffer(slot->cmd, mine.results.handle,
                           kBestWord * sizeof(uint32_t), sizeof(uint32_t),
                           0xffffffffu);
        fn.vkCmdFillBuffer(slot->cmd, mine.results.handle,
                           kHeaderWords * sizeof(uint32_t), VK_WHOLE_SIZE, 0);

        VkMemoryBarrier cleared{};
        cleared.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        cleared.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        cleared.dstAccessMask = VK_ACCESS_SHADER_READ_BIT
                              | VK_ACCESS_SHADER_WRITE_BIT;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                                VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1,
                                &cleared, 0, nullptr, 0, nullptr);

        const uint32_t groups = (count + local_ - 1) / local_;
        pipeline_->record(slot->cmd, index, groups, push_, push_bytes_);

        VkMemoryBarrier written{};
        written.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
        written.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        written.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                                VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &written,
                                0, nullptr, 0, nullptr);

        VkBufferCopy copy{};
        copy.size = kResultWords * sizeof(uint32_t);
        fn.vkCmdCopyBuffer(slot->cmd, mine.results.handle, mine.readback.handle,
                           1, &copy);

        if (!ring_->submit(slot))
            return false;

        Pending &entry = queue_[(head_ + inflight_) % depth_];
        entry.slot = index;
        entry.count = count;
        entry.full_batch = count == batch_;
        inflight_++;
        return true;
    }

    int collect(Solution *out, int max) override
    {
        if (!inflight_)
            return 0;

        // Retired before anything that can fail, so a caller emptying the
        // pipeline after a device error gets through it instead of being handed
        // the same dead dispatch forever.
        const Pending entry = queue_[head_];
        head_ = (head_ + 1) % depth_;
        const bool was_full = inflight_ == depth_;
        inflight_--;

        if (!ring_->wait(ring_->slot(entry.slot), kTimeoutNs)) {
            applog(LOG_ERR, "Vulkan: '%s' did not finish within %u seconds",
                   name_, static_cast<unsigned>(kTimeoutNs / 1000000000ull));
            return -1;
        }

        // From one completion to the next, not from submit to complete: a
        // dispatch queued behind two others waits for both, so submit-to-
        // complete reads as depth times the truth and would divide every batch
        // by it forever. Completions are the rate the device retires work at,
        // which is what kTargetSeconds is about.
        //
        // Only while the queue stayed full across the interval -- a completion
        // with nothing queued behind it measures how late the host was.
        const auto now = std::chrono::steady_clock::now();
        if (was_full && prev_full_ && entry.full_batch)
            retune(std::chrono::duration<double>(now - last_done_).count());
        prev_full_ = was_full;
        last_done_ = now;

        const Slot &mine = slot_[entry.slot];
        if (!device_->invalidate(mine.readback))
            return -1;

        const uint32_t *result =
            static_cast<const uint32_t *>(mine.readback.mapped);
        uint32_t found = result[kFoundWord];

        // One dispatch's minimum is a sample rather than an observation about
        // the kernel, so it is scaled into a quantity whose expected value is
        // one and added to the others. Scaled by this dispatch's own nonce
        // count, not by the current batch size: they differ for the last
        // dispatch of a job and for every dispatch made while the tuner was
        // still moving, which is most of the first few seconds of a run.
        //
        // Nothing accumulates when the probe is off, so a caller that did not
        // ask sees that it asked nothing rather than seeing a number.
        if (probe_best_) {
            best_ratio_sum_ += static_cast<double>(result[kBestWord])
                             * static_cast<double>(entry.count) / 4294967296.;
            best_samples_++;
        }

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
            const uint32_t *candidate =
                result + kHeaderWords + i * kCandidateWords;
            out[i].nonce = candidate[0];
            std::memcpy(out[i].hash, candidate + 1, sizeof out[i].hash);
        }

        return static_cast<int>(found);
    }

    uint32_t preferred_batch() const override { return batch_; }

    uint32_t max_batch() const override { return max_batch_; }

    uint32_t local_size() const override { return local_; }

    uint32_t queue_depth() const override { return depth_; }

    BestDigest best_digest() const override
    {
        return BestDigest{best_ratio_sum_, best_samples_};
    }

private:
    // Aim the next dispatch at kTargetSeconds, from the interval the device is
    // retiring them at. The caller decides when a measurement is worth
    // believing; this decides what to do about one.
    void retune(double seconds)
    {
        if (seconds <= 0.)
            return;

        // Dispatches at the previous size are still queued, and the intervals
        // between their completions describe that size, not the new one.
        // Sitting out a queue's worth is the difference between converging and
        // measuring every change against the size it replaced, both ways.
        if (hold_) {
            hold_--;
            return;
        }

        double scale = kTargetSeconds / seconds;
        // Moving by at most 4x per dispatch, so that one descheduled batch
        // cannot send the next one into the watchdog.
        if (scale > 4.) scale = 4.;
        if (scale < 0.25) scale = 0.25;

        const uint32_t before = batch_;
        const double next = static_cast<double>(batch_) * scale;
        batch_ = next >= static_cast<double>(kMaxBatch)
               ? kMaxBatch : static_cast<uint32_t>(next);
        clamp_batch(device_->info());

        if (batch_ != before)
            hold_ = depth_;
    }

    // How many invocations this device can afford in flight at once. Sets
    // max_batch_, within which the time-based tuning below then chooses, and
    // fails rather than allocating something that will not run: a device
    // without room should say so at startup and not mid-dispatch.
    bool size_scratch(const DeviceInfo &info)
    {
        if (!info.memory) {
            applog(LOG_ERR, "Vulkan: '%s' needs %llu bytes of scratch per hash "
                            "and %s does not report how much memory it has",
                   name_, static_cast<unsigned long long>(scratch_bytes_),
                   info.name.c_str());
            return false;
        }

        // Not the whole heap. The driver, the command buffers, the result
        // buffers and -- on a device also driving a display -- a framebuffer
        // this cannot see all live there too. VK_EXT_memory_budget would give a
        // real answer; this is the honest guess without it.
        //
        // A software rasterizer gets far less, and not out of politeness: its
        // "device memory" is the host's RAM, so three quarters of it is a
        // swapping machine. It is there to say whether the kernel is correct,
        // which takes a few thousand invocations and not a few million.
        const bool soft = info.kind == DeviceKind::Cpu;
        const uint64_t usable =
            soft ? static_cast<uint64_t>(static_cast<double>(info.memory) * 0.15)
                 : static_cast<uint64_t>(static_cast<double>(info.memory) * 0.75);
        const uint64_t ceiling = soft ? (256ull << 20) : ~0ull;
        uint64_t budget = usable < ceiling ? usable : ceiling;

        // Split with whoever else the caller is about to build. Nothing here
        // can see them, and a driver that over-commits lets them all succeed
        // and then loses the device on the first dispatch that touches what it
        // paged out.
        budget /= concurrent_;

        // Every dispatch in flight owns a full set of scratchpads, so the depth
        // is a multiplier on the memory and not just on the latency.
        const uint64_t per_invocation = scratch_bytes_ * depth_;
        uint64_t fits = budget / (per_invocation ? per_invocation : 1);

        if (fits > kMaxBatch)
            fits = kMaxBatch;

        // Below a workgroup there is nothing to dispatch: the device saying it
        // cannot run this algorithm, which is a real answer.
        if (fits < local_) {
            applog(LOG_ERR, "Vulkan: '%s' needs %llu KiB per hash, and %s has "
                            "room for %llu at a time -- fewer than the %u in a "
                            "workgroup", name_,
                   static_cast<unsigned long long>(scratch_bytes_ >> 10),
                   info.name.c_str(), static_cast<unsigned long long>(fits),
                   local_);
            return false;
        }

        // Whole workgroups, so that the last one is not a partial dispatch that
        // indexes scratch nobody allocated.
        max_batch_ = static_cast<uint32_t>(fits / local_) * local_;

        applog(LOG_INFO, "Vulkan: '%s' takes %llu MiB of scratch on %s -- "
                         "%u hashes in flight, %llu KiB each%s",
               name_,
               static_cast<unsigned long long>(
                   (static_cast<uint64_t>(max_batch_) * per_invocation) >> 20),
               info.name.c_str(), max_batch_,
               static_cast<unsigned long long>(scratch_bytes_ >> 10),
               concurrent_ > 1 ? ", sharing the device" : "");
        return true;
    }

    void clamp_batch(const DeviceInfo &info)
    {
        if (batch_ < kMinBatch)
            batch_ = kMinBatch;
        if (batch_ > kMaxBatch)
            batch_ = kMaxBatch;

        // The scratchpads were allocated for max_batch_ invocations and a
        // dispatch indexes them by invocation, so this is not a preference.
        if (batch_ > max_batch_)
            batch_ = max_batch_;

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

    // What one in-flight dispatch writes into. Paired with the ring's slot of
    // the same index, and untouchable between submit and fence.
    struct Slot {
        Buffer results{};
        Buffer readback{};
        // Only for a kernel that asked for scratch, and one per slot rather
        // than shared: dispatches overlap, and two of them in one scratchpad
        // would both be wrong, differently on every run.
        Buffer scratch{};
    };
    std::vector<Slot> slot_;

    // What the host must remember about a dispatch to make sense of it when it
    // comes back. A ring in submission order; `head_` is the oldest, which is
    // the one collect() answers for.
    struct Pending {
        uint32_t slot = 0;
        uint32_t count = 0;
        // A batch the tuner chose, rather than one truncated at the end of a
        // nonce range. A short batch finishing quickly says nothing about how
        // fast the device is.
        bool full_batch = false;
    };
    std::vector<Pending> queue_;

    // How many of each of the above. Fixed for the kernel's life: changing it
    // would reallocate buffers a queued command buffer still points at.
    uint32_t depth_ = kDefaultDepth;
    uint32_t head_ = 0;
    uint32_t inflight_ = 0;

    // What retune() measures, and whether it means anything: `prev_full_` says
    // the queue was full at the previous completion too, so the interval
    // between them covers a device that was never waiting for the host.
    std::chrono::steady_clock::time_point last_done_;
    bool prev_full_ = false;

    // Completions left to ignore because they were launched at the previous
    // batch size.
    uint32_t hold_ = 0;

    // The guaranteed minimum a Vulkan device must offer. An algorithm that
    // wants more than this is refused at kernel creation rather than on a
    // device that happens to allow it.
    unsigned char push_[128] = {0};
    uint32_t push_bytes_ = 0;

    uint32_t local_ = 0;
    uint32_t batch_ = kMinBatch;

    // Device-local bytes per invocation, the batch that many of them fit in,
    // and how many kernels the spec says share this device. Zero and kMaxBatch
    // for a kernel wanting no scratch, which leaves every compute-bound
    // algorithm on the path it had.
    uint64_t scratch_bytes_ = 0;
    uint32_t max_batch_ = kMaxBatch;
    uint32_t concurrent_ = 1;

    // The per-dispatch minima the probe has reported, each scaled to an
    // expected value of one, and how many contributed. Both stay at zero
    // unless the probe is on.
    double best_ratio_sum_ = 0.;
    uint64_t best_samples_ = 0;
    bool probe_best_ = false;
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
