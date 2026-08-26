// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/vulkan_kernel.h"

#include "algorithms/algorithm.h"
#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/vulkan_pipeline.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <numeric>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace vkminer {
namespace {

// Words per candidate, and how many of them fit. Both halves of a contract with
// shaders/common/candidates.glsl; see the constant of the same name there.
constexpr uint32_t kCandidateWords = 10;

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
        // Before anything else: a thread building the next program is holding
        // this device and this kernel's descriptor layout, and it has to be
        // finished with both before either goes.
        if (ahead_.joinable())
            ahead_.join();

        // The ring next: its destructor waits for the device, which is what
        // makes freeing the buffers underneath it safe. With several dispatches
        // possibly still queued that is not a formality.
        ring_.reset();
        pipeline_.reset();
        retiring_.reset();
        ahead_pipeline_.reset();
        if (device_)
            for (Slot &slot : slot_) {
                device_->destroy_buffer(&slot.results);
                device_->destroy_buffer(&slot.readback);
                device_->destroy_buffer(&slot.scratch);
            }
    }

    bool init(VulkanDevice &device, VkPipelineCache cache,
              const KernelSpec &spec, std::shared_ptr<SharedState> shared)
    {
        device_ = &device;
        algorithm_ = spec.algorithm;
        name_ = spec.name;

        // Statistics are printed per pipeline, and an algorithm offering
        // several kernels builds several -- so the label has to carry the
        // variant or the numbers cannot be told apart afterwards.
        stats_label_ = name_ ? name_ : "";
        if (spec.variant && spec.variant[0]) {
            stats_label_ += ", kernel ";
            stats_label_ += spec.variant;
        }
        push_bytes_ = spec.push_constant_bytes;
        shared_ = std::move(shared);

        // The spec asked for state and the backend did not hand any over, which
        // is a wiring error rather than a device that ran out: dispatching
        // would read whatever the unbound descriptor points at.
        if (spec.shared_bytes && !shared_) {
            applog(LOG_ERR, "Vulkan: '%s' wants %llu MiB of shared state and "
                            "was given none", name_,
                   static_cast<unsigned long long>(spec.shared_bytes >> 20));
            return false;
        }

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

        // Results, then the scratchpad, then the shared table -- the order the
        // shaders declare their bindings in and the order they are written
        // below. A descriptor nobody wrote reads as whatever the driver left
        // there rather than as an error.
        //
        // The table takes as many bindings as the shader split itself into,
        // whatever this device needs: the count is compiled into the module.
        shared_chunks_ = spec.shared_bytes
                       ? (spec.shared_chunks ? spec.shared_chunks : 1u) : 0u;
        if (shared_chunks_ > kMaxSharedChunks) {
            applog(LOG_ERR, "Vulkan: '%s' declares %u bindings for its shared "
                            "state and a shader may have %u", name_,
                   shared_chunks_, kMaxSharedChunks);
            return false;
        }
        const uint32_t needed = 1 + (spec.scratch_bytes ? 1u : 0u)
                                  + shared_chunks_;
        if (desc.storage_buffers < needed) {
            applog(LOG_ERR, "Vulkan: '%s' declares %u storage buffers and has "
                            "%u to bind", name_, desc.storage_buffers, needed);
            return false;
        }
        desc.push_constant_bytes = push_bytes_;
        // The width by the same rule as the depth: the spec, then the option,
        // then this device's default.
        desc.local_size_x = spec.local_size_x  ? spec.local_size_x
                          : opt_workgroup > 0  ? static_cast<uint32_t>(opt_workgroup)
                                               : choose_local_size(info);

        // A workgroup holds whole nonces or the lanes of the last one have
        // nobody to exchange with. Rounded down rather than refused: the width
        // is swept by the tuner and asked for on the command line, and this is
        // the nearest number of invocations that arranges into whole hashes.
        lanes_ = spec.lanes ? spec.lanes : 1;
        if (info.max_invocations && lanes_ > info.max_invocations) {
            applog(LOG_ERR, "Vulkan: '%s' wants %u invocations per hash and %s "
                            "runs %u in a workgroup", name_, lanes_,
                   info.name.c_str(), info.max_invocations);
            return false;
        }
        if (lanes_ > 1) {
            const uint32_t whole = desc.local_size_x
                                 - desc.local_size_x % lanes_;
            desc.local_size_x = whole ? whole : lanes_;
        }

        // And whole subgroups, for a kernel whose lanes exchange through them:
        // a width that is a multiple of both is a multiple of their least
        // common multiple, rounded down by the same argument as above.
        //
        // A device that will not say what its subgroup is cannot be asked for
        // whole ones. The algorithm reads the same zero from DeviceInfo and
        // does not offer such a kernel there, so a zero here is its bug.
        if (spec.full_subgroups) {
            const uint32_t step = std::lcm(lanes_, info.subgroup_size);
            if (!step || (info.max_invocations && step > info.max_invocations)) {
                applog(LOG_ERR, "Vulkan: '%s' wants whole subgroups and %s "
                                "reports a subgroup of %u against %u "
                                "invocations", name_, info.name.c_str(),
                       info.subgroup_size, info.max_invocations);
                return false;
            }
            const uint32_t whole = desc.local_size_x - desc.local_size_x % step;
            desc.local_size_x = whole ? whole : step;
        }
        probe_best_ = opt_vk_probe_best;
        desc.probe_best = probe_best_;
        desc.sets = depth_;

        // What the table came out as on this device, which the shader needs to
        // find a word in it and cannot work out for itself.
        if (shared_) {
            desc.shared_chunks =
                static_cast<uint32_t>(shared_->chunks().size());
            desc.shared_chunk_words =
                static_cast<uint32_t>(shared_->chunk_bytes()
                                      / sizeof(uint32_t));
        }

        // The algorithm's fixed constants, in every pipeline built below.
        // Pointed at rather than copied, which is why the spec must outlive
        // this kernel -- the same rule as its SPIR-V.
        desc.constants = spec.constants;
        desc.constant_count = static_cast<uint32_t>(spec.constant_count);

        // How many constants the program is, where this module is built per
        // program. The pipeline cannot exist yet -- nothing here knows which
        // program, and the module's own defaults are nobody's -- so the first
        // prepare_program builds it, and reports a width this device rejects.
        program_constants_ = spec.program_constants;
        if (program_constants_ > kMaxProgramConstants) {
            applog(LOG_ERR, "Vulkan: '%s' wants %u program constants and this "
                            "backend passes %u", name_, program_constants_,
                   kMaxProgramConstants);
            return false;
        }
        desc_ = desc;
        cache_ = cache;

        local_ = desc.local_size_x;
        // Nonces per workgroup, which is the unit a dispatch is counted in and
        // the width only where an invocation is a hash.
        per_group_ = local_ / lanes_;
        if (!per_group_)
            per_group_ = 1;

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

            // What set `i` points at, written once and never rewritten: a set
            // may not be updated while a command buffer using it is in flight,
            // and once the pipeline is full there is no instant at which none
            // of them is. Kept rather than dropped, because a kernel built per
            // program builds another pipeline, with its own sets, per program.
            //
            // The table's descriptor is written here too and never rewritten,
            // which is why a rebuild refills that buffer rather than
            // allocating another.
            std::vector<Buffer> bound;
            bound.reserve(2 + kMaxSharedChunks);
            bound.push_back(slot_[i].results);
            if (scratch_bytes_)
                bound.push_back(slot_[i].scratch);

            // Every binding the shader declared for the table, needed here or
            // not: the spare ones repeat the last real piece, since a
            // descriptor nothing wrote points into whatever the driver left
            // there. The chain that selects between them never reaches the
            // repeats, so they only have to name a real buffer.
            if (shared_) {
                const std::vector<Buffer> &pieces = shared_->chunks();
                for (uint32_t c = 0; c < shared_chunks_; c++)
                    bound.push_back(c < pieces.size() ? pieces[c]
                                                      : pieces.back());
            }
            bound_.push_back(std::move(bound));
        }

        // The one pipeline, where the module is the whole program. A kernel
        // built per program has none until it is told which, and dispatch
        // refuses until then for the same reason it refuses without its shared
        // state: the alternative is hashing fluently against the wrong thing.
        if (!program_constants_) {
            pipeline_ = build_pipeline(nullptr);
            if (!pipeline_)
                return false;
        }

        ring_ = CommandRing::create(device, depth_);
        if (!ring_)
            return false;

        // A first guess, corrected from measurement after the first dispatch --
        // so what matters is not that it is close but that it can finish. A
        // dispatch that runs into the timeout returns no measurement to correct
        // from and the next one is the same size, which makes this the one
        // number here with no way back from being wrong.
        //
        // Deliberately low, and lower per lane for the reason the floor is:
        // sixteen lanes to a hash is sixteen times the work at the same count.
        // A software rasterizer starts at the floor outright, because per-nonce
        // cost there spans four orders of magnitude between sha256d and KawPoW
        // and no single count is both useful for the first and survivable for
        // the last. Climbing from it costs milliseconds on a device nobody
        // measures a rate on.
        batch_ = info.kind == DeviceKind::Cpu ? 0 : (1u << 20) / lanes_;
        clamp_batch(info);

        // The depth is on this line so that a log says which run it was --
        // comparing one against another is the point of the option existing.
        // The variant is there for the same reason, where the algorithm has
        // more than one kernel and the tuner may have preferred either.
        char lanes[48] = "";
        if (lanes_ > 1)
            std::snprintf(lanes, sizeof lanes, ", %u lanes to a hash", lanes_);
        applog(LOG_INFO, "Vulkan: '%s' on %s, workgroup %u%s, %u dispatch%s in "
                         "flight%s%s", name_, info.name.c_str(), local_, lanes,
               depth_, depth_ == 1 ? "" : "es",
               spec.variant && spec.variant[0] ? ", kernel " : "",
               spec.variant ? spec.variant : "");
        return true;
    }

    bool prepare_state(uint64_t key) override
    {
        if (!shared_)
            return true;
        if (!algorithm_) {
            applog(LOG_ERR, "Vulkan: '%s' has shared state and no algorithm to "
                            "fill it", name_);
            return false;
        }

        // Under the state's own lock, so two workers on one device asking for
        // the same epoch at the same moment build it once. The one that loses
        // the race waits for the winner and finds it ready, which is the same
        // wait it would have had if it had asked first.
        if (!shared_->ensure(key, *algorithm_))
            return false;

        state_key_ = key;
        state_ready_ = true;
        return true;
    }

    bool prepare_program(uint64_t key) override
    {
        if (!program_constants_)
            return true;
        // The common case by a very long way: a comparison, once per dispatch,
        // against a program that lasts minutes.
        if (program_ready_ && key == program_key_)
            return true;

        // Whatever the background thread was building is collected here first,
        // whether or not it is wanted: it holds a pipeline, and nothing may
        // touch that while the thread that is creating it runs.
        std::unique_ptr<ComputePipeline> next;
        if (ahead_.joinable()) {
            ahead_.join();
            if (ahead_key_ == key && ahead_pipeline_) {
                next = std::move(ahead_pipeline_);
                ahead_used_++;
            }
            ahead_pipeline_.reset();
        }

        // Not prepared, or prepared for a program the chain did not go on to
        // use. Either way this is the compile the whole mechanism exists to
        // keep off this thread, and it is on it.
        if (!next) {
            next = build_program(key);
            if (!next)
                return false;
        }

        retire(std::move(pipeline_));
        pipeline_ = std::move(next);
        program_key_ = key;
        program_ready_ = true;

        // And the next one, now, while this one mines. The algorithm may not
        // know what follows -- a pool that changes coins does not tell anyone
        // in advance -- and then the miner simply pays the compile at the
        // boundary, which is what it would have paid anyway.
        start_ahead(algorithm_ ? algorithm_->next_program_key(key) : 0);
        return true;
    }

    ProgramStats program_stats() const override
    {
        ProgramStats stats;
        stats.builds = builds_.load(std::memory_order_relaxed);
        stats.ahead = ahead_used_;
        return stats;
    }

    bool dispatch(const uint32_t *header, const uint32_t *target,
                  uint64_t nonce_start, uint32_t count) override
    {
        if (!count)
            return false;

        // A kernel with a table nobody built would hash against whatever the
        // allocation happened to contain and return candidates that fail
        // verification -- slowly, and looking like a hardware fault. It is a
        // caller that forgot prepare_state, so say that.
        if (shared_) {
            if (!state_ready_) {
                applog(LOG_ERR, "Vulkan: '%s' was dispatched before its shared "
                                "state was built", name_);
                return false;
            }
            // Almost always a comparison and nothing else. It is not nothing
            // when somebody else on this device has swapped the contents since
            // the last dispatch, and this is where that is put right.
            if (!shared_->ensure(state_key_, *algorithm_))
                return false;
        }

        // The same for the program, and the same reason: a pipeline built from
        // the module's defaults would hash every nonce against instructions no
        // chain ever ran.
        if (program_constants_ && !program_ready_) {
            applog(LOG_ERR, "Vulkan: '%s' was dispatched before its program "
                            "was built", name_);
            return false;
        }

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

        // The counter starts at zero, and the buffer is small enough that
        // clearing all of it costs nothing and leaves no stale candidate the
        // host could read.
        //
        // Three fills rather than one because the probe's word starts at the
        // other end of the range: a running minimum initialized to zero stays
        // zero. They cover disjoint bytes, which is what lets them go in
        // without a barrier between them.
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

        const uint32_t groups = (count + per_group_ - 1) / per_group_;
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

        // With nothing outstanding, nothing on the device can still be reading
        // the pipeline a program change replaced.
        if (!inflight_)
            retiring_.reset();

        if (!ring_->wait(ring_->slot(entry.slot), kTimeoutNs)) {
            applog(LOG_ERR, "Vulkan: '%s' did not finish within %u seconds",
                   name_, static_cast<unsigned>(kTimeoutNs / 1000000000ull));
            return -1;
        }

        // From one completion to the next, not from submit to complete: a
        // dispatch queued behind two others waits for both, so submit-to-
        // complete reads as depth times the truth. Completions are the rate the
        // device retires work at, which is what kTargetSeconds is about.
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
            // Low word first, as the shader wrote it.
            out[i].nonce = static_cast<uint64_t>(candidate[0])
                         | static_cast<uint64_t>(candidate[1]) << 32;
            std::memcpy(out[i].hash, candidate + 2, sizeof out[i].hash);
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
    // One pipeline for this kernel's module, its descriptor sets pointed at the
    // buffers allocated above, built from `program` where the module has one.
    // Everything about it is fixed except that: two pipelines from here differ
    // in nothing but which instructions they contain.
    std::unique_ptr<ComputePipeline> build_pipeline(const uint32_t *program)
    {
        ComputePipelineDesc desc = desc_;
        desc.program = program;
        desc.program_count = program ? program_constants_ : 0;

        std::unique_ptr<ComputePipeline> built =
            ComputePipeline::create(*device_, desc, cache_);
        if (!built)
            return nullptr;

        for (uint32_t i = 0; i < bound_.size(); i++)
            built->bind(i, bound_[i].data(),
                        static_cast<uint32_t>(bound_[i].size()));

        builds_.fetch_add(1, std::memory_order_relaxed);

        // A no-op unless asked, and worth asking for here rather than only at
        // startup: whether the driver folds a program's constants into straight
        // line code, or leaves a switch per operation, is the whole question a
        // kernel built per program is betting on.
        built->report_statistics(stats_label_.c_str());
        return built;
    }

    // The program `key` names, from the algorithm, as a pipeline. Runs on this
    // thread or on the one below it, which is why it takes nothing from the
    // kernel that the other could be changing.
    std::unique_ptr<ComputePipeline> build_program(uint64_t key)
    {
        uint32_t values[kMaxProgramConstants];
        const size_t wrote =
            algorithm_ ? algorithm_->program_values(key, values,
                                                    program_constants_) : 0;
        if (wrote != program_constants_) {
            applog(LOG_ERR, "Vulkan: '%s' is built from %u program constants "
                            "and the algorithm wrote %zu", name_,
                   program_constants_, wrote);
            return nullptr;
        }
        return build_pipeline(values);
    }

    // Build `key`'s pipeline while the current one mines. One at a time and
    // never for the program already loaded: the point is the boundary that is
    // coming, and a second thread would only be racing this one to the same
    // compile.
    void start_ahead(uint64_t key)
    {
        if (!key || ahead_.joinable())
            return;
        if (program_ready_ && key == program_key_)
            return;

        ahead_key_ = key;
        ahead_pipeline_.reset();
        ahead_ = std::thread([this, key] { ahead_pipeline_ = build_program(key); });
    }

    // Keep the pipeline a program change replaced alive until the dispatches
    // recorded against it have finished: destroying one under an executing
    // command buffer shows up as a device lost on somebody else's hardware.
    //
    // One is kept. A second retirement with the first still pending would mean
    // the program changed twice inside a queue's worth of dispatches, which no
    // chain does, and waiting the device out there costs a fraction of a
    // second in a place that has just paid for a compile.
    void retire(std::unique_ptr<ComputePipeline> old)
    {
        if (!old)
            return;
        if (retiring_) {
            device_->wait_idle();
            retiring_.reset();
        }
        if (inflight_)
            retiring_ = std::move(old);
    }

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

        // Not the whole heap: the driver, the command buffers, the result
        // buffers and -- on a device also driving a display -- a framebuffer
        // this cannot see all live there. VK_EXT_memory_budget would give a
        // real answer; this is the honest guess without it.
        //
        // A software rasterizer gets far less, because its "device memory" is
        // the host's RAM and three quarters of that is a swapping machine. It
        // is there to say whether the kernel is correct, which takes a few
        // thousand invocations.
        const bool soft = info.kind == DeviceKind::Cpu;
        const uint64_t usable =
            soft ? static_cast<uint64_t>(static_cast<double>(info.memory) * 0.15)
                 : static_cast<uint64_t>(static_cast<double>(info.memory) * 0.75);
        const uint64_t ceiling = soft ? (256ull << 20) : ~0ull;
        uint64_t budget = usable < ceiling ? usable : ceiling;

        // The shared table is already on the device and is not scratch: taken
        // off the top, before the split, because there is one of it however
        // many kernels are about to divide what is left.
        const uint64_t shared = shared_ ? shared_->bytes() : 0;
        if (shared >= budget) {
            applog(LOG_ERR, "Vulkan: '%s' has %llu MiB of shared state on %s "
                            "and no room left for scratch", name_,
                   static_cast<unsigned long long>(shared >> 20),
                   info.name.c_str());
            return false;
        }
        budget -= shared;

        // Split with whoever else the caller is about to build. Nothing here
        // can see them, and a driver that over-commits lets them all succeed
        // and then loses the device on the first dispatch that touches what it
        // paged out.
        budget /= concurrent_;

        // Every dispatch in flight owns a full set of scratchpads, so the depth
        // is a multiplier on the memory and not just on the latency. And where
        // several invocations share a nonce they each want their own, so a
        // nonce costs the scratch of all of its lanes.
        const uint64_t per_invocation = scratch_bytes_ * depth_;
        const uint64_t per_nonce = per_invocation * lanes_;
        uint64_t fits = budget / (per_nonce ? per_nonce : 1);

        if (fits > kMaxBatch)
            fits = kMaxBatch;

        // Below a workgroup there is nothing to dispatch: the device saying it
        // cannot run this algorithm, which is a real answer.
        if (fits < per_group_) {
            applog(LOG_ERR, "Vulkan: '%s' needs %llu KiB per hash, and %s has "
                            "room for %llu at a time -- fewer than the %u in a "
                            "workgroup", name_,
                   static_cast<unsigned long long>(scratch_bytes_ >> 10),
                   info.name.c_str(), static_cast<unsigned long long>(fits),
                   per_group_);
            return false;
        }

        // Whole workgroups, so that the last one is not a partial dispatch that
        // indexes scratch nobody allocated.
        max_batch_ = static_cast<uint32_t>(fits / per_group_) * per_group_;

        applog(LOG_INFO, "Vulkan: '%s' takes %llu MiB of scratch on %s -- "
                         "%u hashes in flight, %llu KiB each%s",
               name_,
               static_cast<unsigned long long>(
                   (static_cast<uint64_t>(max_batch_) * per_nonce) >> 20),
               info.name.c_str(), max_batch_,
               static_cast<unsigned long long>(scratch_bytes_ >> 10),
               concurrent_ > 1 ? ", sharing the device" : "");
        return true;
    }

    void clamp_batch(const DeviceInfo &info)
    {
        // The floor is a count of invocations rather than of nonces, because
        // what it is for is giving a dispatch enough parallelism to fill a
        // device, and a lane is a fraction of a hash and not another one.
        // Sixteen lanes to the nonce made it sixteen times the intended size,
        // and a floor the tuning cannot descend below is a floor it has to run
        // at: on a software rasterizer that is a KawPoW dispatch of seconds
        // where the aim is fifty milliseconds.
        uint32_t least = kMinBatch / lanes_;
        if (least < per_group_)
            least = per_group_;
        if (batch_ < least)
            batch_ = least;
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
                static_cast<uint64_t>(info.max_workgroup_count) * per_group_;
            if (static_cast<uint64_t>(batch_) > most)
                batch_ = static_cast<uint32_t>(most);
        }
    }

    VulkanDevice *device_ = nullptr;
    const Algorithm *algorithm_ = nullptr;
    const char *name_ = "";
    std::string stats_label_;

    std::unique_ptr<ComputePipeline> pipeline_;
    std::unique_ptr<CommandRing> ring_;

    // What another pipeline for this kernel would be built from: everything
    // that was decided at init, and the buffers each descriptor set points at.
    // Unused by a kernel with one pipeline, which is every one whose module is
    // its whole program.
    ComputePipelineDesc desc_{};
    VkPipelineCache cache_ = VK_NULL_HANDLE;
    std::vector<std::vector<Buffer>> bound_;

    // Constants the module declares for its program, and which program is
    // loaded. Zero constants is a kernel that has one pipeline and never comes
    // near any of this.
    uint32_t program_constants_ = 0;
    uint64_t program_key_ = 0;
    bool program_ready_ = false;

    // The pipeline the last program change replaced, held until the dispatches
    // that were recorded against it have retired.
    std::unique_ptr<ComputePipeline> retiring_;

    // The next program, being compiled while this one mines. Only the thread
    // that calls prepare_program touches any of these, and only with `ahead_`
    // joined -- which is the whole of the synchronization here.
    std::thread ahead_;
    uint64_t ahead_key_ = 0;
    std::unique_ptr<ComputePipeline> ahead_pipeline_;

    // Pipelines compiled, and how many of them were already being built when
    // they were asked for. `builds_` is written by both threads; `ahead_used_`
    // only by the one that joins.
    std::atomic<uint64_t> builds_{0};
    uint64_t ahead_used_ = 0;

    // The device's shared table, or null for a kernel that wanted none. Shared
    // rather than owned: the tuner's four candidates and both workers on a card
    // hold the same one, and it goes when the last of them does.
    //
    // `state_key_` is what this kernel was last told to hash against and
    // `state_ready_` says it has been told. Kept because this kernel is not the
    // only one that can change the buffer: two workers on one card, on two
    // chains, would otherwise dispatch against each other's table. Checked
    // again at dispatch, one uncontended lock per fiftieth of a second.
    std::shared_ptr<SharedState> shared_;
    uint64_t state_key_ = 0;
    bool state_ready_ = false;

    // Bindings this shader has for that state, which is what the module was
    // compiled with and not what the device turned out to want. Zero for a
    // kernel with no shared state at all.
    uint32_t shared_chunks_ = 0;

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

    // Invocations per nonce, and the nonces a workgroup of them holds. One and
    // the width for every kernel where an invocation is a hash.
    uint32_t lanes_ = 1;
    uint32_t per_group_ = 1;

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
                                           const KernelSpec &spec,
                                           std::shared_ptr<SharedState> shared)
{
    std::unique_ptr<VulkanKernel> kernel(new VulkanKernel());
    if (!kernel->init(device, cache, spec, std::move(shared)))
        return nullptr;
    return kernel;
}

}  // namespace vkminer
