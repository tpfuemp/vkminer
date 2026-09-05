// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "backends/vulkan/shared_state.h"

#include "algorithms/algorithm.h"
#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/vulkan_pipeline.h"

#include <chrono>

namespace vkminer {

namespace {

// How much is staged at a time. The device cannot see host memory, so every
// byte goes through a host-visible buffer and a copy, and this is the size of
// that buffer -- big enough that the per-copy submit is noise, small enough
// to allocate on a mobile part and to hand back when the build is over.
constexpr VkDeviceSize kStagingBytes = 8u << 20;

// A rebuild is not a dispatch and has no watchdog to worry about, but a device
// that has stopped answering must still be reported rather than hung on.
constexpr uint64_t kTimeoutNs = 60ull * 1000 * 1000 * 1000;

// A setup pass *is* dispatches, and they are on the same queue and under the
// same watchdog as everything else -- two seconds on Windows, and a driver
// reset rather than a slow build if one overruns it. So the pass is sliced,
// and the first slice is small because nothing here knows yet whether an item
// costs a microsecond or a millisecond on this device.
//
// After that the size is measurement: aim at a fraction of a second per
// dispatch, which is short enough to be safe on any watchdog and long enough
// that the submit-and-wait around it is noise.
constexpr uint32_t kFirstSlice    = 1u << 10;
constexpr uint32_t kMaxSlice      = 1u << 20;
constexpr double   kSliceSeconds  = 0.25;
constexpr double   kSliceGrowth   = 4.;   // per step, so a bad guess is bounded

// The largest power of two that is not more than `n`, for n >= 1.
uint64_t floor_pow2(uint64_t n)
{
    uint64_t p = 1;
    while (p <= n / 2)
        p *= 2;
    return p;
}

}  // namespace

std::shared_ptr<SharedState> SharedState::create(VulkanDevice &device,
                                                 const KernelSpec &spec,
                                                 VkPipelineCache cache)
{
    const DeviceInfo &info = device.info();
    const uint64_t    bytes = spec.shared_bytes;
    const char       *name  = spec.name;

    // The most one binding can be, which is two device limits and not one:
    // they are different numbers and a device can pass one and fail the other.
    // A shader cannot address past maxStorageBufferRange even where the
    // allocation succeeded, and that failure is silently wrong answers rather
    // than an error -- the worse of the two. Both are asked here, before
    // anything is allocated.
    uint64_t most = bytes;
    if (info.max_allocation && info.max_allocation < most)
        most = info.max_allocation;
    if (info.max_binding_range && info.max_binding_range < most)
        most = info.max_binding_range;
    if (!most) {
        applog(LOG_ERR, "Vulkan: '%s' asked for no shared state", name);
        return nullptr;
    }

    // Where the whole table fits in one binding it is one buffer, exactly the
    // size asked for, and everything below this is arithmetic that comes out
    // at a count of 1. Where it does not, the pieces are a power of two: the
    // shader turns an index into the table into a piece and an offset within
    // it, and a power of two makes that a shift and a mask rather than a
    // division on every word it reads.
    //
    // A spec that names a piece size gets that instead, rounded the same way.
    // That is a test forcing the path on a device whose own limits would never
    // reach for it, which is the only reason to ask.
    uint64_t chunk = bytes;
    if (spec.shared_chunk_bytes && spec.shared_chunk_bytes < chunk)
        chunk = spec.shared_chunk_bytes;
    if (chunk > most)
        chunk = most;
    if (chunk < bytes)
        chunk = floor_pow2(chunk);

    const uint64_t count = (bytes + chunk - 1) / chunk;

    // Every piece a whole number of 16-byte quads, the short last one included.
    // shared_table.glsl declares these bindings as `uvec4 quad[]`, so a piece
    // ending mid-quad leaves its last words off the end of that array, where a
    // read returns whatever the device's robustness rules say. A check and not
    // arithmetic that rounds: rounding would silently make a table's tail
    // unreadable, and every size here is a power of two or the table itself.
    if ((bytes % 16) || (chunk % 16)) {
        applog(LOG_ERR, "Vulkan: '%s' asked for %llu bytes of shared state in "
                        "pieces of %llu, and a piece has to be a whole number "
                        "of 16 bytes", name,
               static_cast<unsigned long long>(bytes),
               static_cast<unsigned long long>(chunk));
        return nullptr;
    }

    // How many bindings the shader has for it. Zero and one both mean the one
    // binding every kernel before KawPoW had, and the chain that would select
    // between several is not in those shaders at all.
    const uint64_t declared = spec.shared_chunks ? spec.shared_chunks : 1;
    if (declared > kMaxSharedChunks) {
        applog(LOG_ERR, "Vulkan: '%s' declares %llu bindings for its shared "
                        "state and a shader may have %u", name,
               static_cast<unsigned long long>(declared), kMaxSharedChunks);
        return nullptr;
    }
    if (count > declared) {
        applog(LOG_ERR, "Vulkan: '%s' wants %llu MiB of shared state, a shader "
                        "on %s can address %llu MiB in one binding, and it "
                        "declares %llu of them", name,
               static_cast<unsigned long long>(bytes >> 20), info.name.c_str(),
               static_cast<unsigned long long>(chunk >> 20),
               static_cast<unsigned long long>(declared));
        return nullptr;
    }

    std::shared_ptr<SharedState> state(new SharedState());
    state->device_ = &device;
    state->name_ = name;
    state->setup_ = spec.setup;
    state->cache_ = cache;
    state->bytes_ = bytes;
    state->chunk_bytes_ = chunk;

    for (uint64_t first = 0; first < bytes; first += chunk) {
        const uint64_t left = bytes - first;
        Buffer piece{};
        if (!device.create_buffer(static_cast<VkDeviceSize>(left < chunk ? left
                                                                        : chunk),
                                  VK_BUFFER_USAGE_STORAGE_BUFFER_BIT
                                      | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                  BufferKind::DeviceLocal, &piece)) {
            applog(LOG_ERR, "Vulkan: could not allocate %llu MiB of shared "
                            "state for '%s' on %s (piece %llu of %llu)",
                   static_cast<unsigned long long>(bytes >> 20), name,
                   info.name.c_str(),
                   static_cast<unsigned long long>(
                       state->chunk_.size() + 1),
                   static_cast<unsigned long long>(count));
            return nullptr;
        }
        state->chunk_.push_back(piece);
    }

    // In whichever unit says something, by the same rule as the build line
    // below: a real table is gigabytes and a test's is a few hundred kilobytes,
    // and rounding the second one to megabytes reports it as nothing at all.
    if (count > 1) {
        const bool big = chunk >= (1u << 20);
        applog(LOG_INFO, "Vulkan: '%s' holds its %llu %s of shared state on %s "
                         "in %llu pieces of %llu %s", name,
               static_cast<unsigned long long>(big ? bytes >> 20 : bytes >> 10),
               big ? "MiB" : "KiB", info.name.c_str(),
               static_cast<unsigned long long>(count),
               static_cast<unsigned long long>(big ? chunk >> 20 : chunk >> 10),
               big ? "MiB" : "KiB");
    }

    return state;
}

SharedState::~SharedState()
{
    if (device_) {
        // The kernels that were reading this are gone -- they hold the
        // references that keep it alive -- but their command buffers were
        // waited on by their own rings and nothing here can see that. The
        // device is idle by the time this runs or the ring's destructor did
        // not do its job; this is the cheap insurance against that.
        device_->wait_idle();
        for (Buffer &piece : chunk_)
            device_->destroy_buffer(&piece);
    }
}

bool SharedState::ensure(uint64_t key, const Algorithm &algorithm)
{
    std::lock_guard<std::mutex> held(lock_);
    if (ready_ && key_ == key)
        return true;

    if (ready_) {
        // Somebody else's dispatch may be reading these bytes right now: two
        // workers can share a device and the tuner races several kernels over
        // this one buffer. A barrier cannot help -- it orders work inside a
        // command buffer, and the ones at issue were submitted already -- so
        // the whole device is waited for before a byte of it is overwritten.
        device_->wait_idle();
        ready_ = false;
    }

    const auto started = std::chrono::steady_clock::now();

    // Two ways to fill it, and the algorithm chose which when it declared its
    // spec. Everything either side of this line -- the lock, the wait, the
    // bookkeeping -- is the same for both.
    const bool ok = setup_.spirv
                  ? generate(key, algorithm)
                  : upload(chunk_, bytes_, "shared state",
                           [&](uint64_t offset, void *out, size_t span) {
                               return algorithm.shared_state(key, offset, out,
                                                             span);
                           });
    if (!ok)
        return false;

    const double seconds = std::chrono::duration<double>(
                               std::chrono::steady_clock::now() - started).count();

    // In whichever unit says something: a real table is gigabytes, and a test
    // that builds a few hundred kilobytes of one should not be told it built
    // nothing.
    const uint64_t total = bytes();
    const bool big = total >= (1u << 20);
    applog(LOG_INFO, "Vulkan: '%s' built %llu %s of shared state on %s in "
                     "%.1f s", name_,
           static_cast<unsigned long long>(big ? total >> 20 : total >> 10),
           big ? "MiB" : "KiB", device_->info().name.c_str(), seconds);

    key_ = key;
    ready_ = true;
    return true;
}

bool SharedState::upload(const std::vector<Buffer> &dst, uint64_t total,
                         const char *what,
                         const std::function<bool(uint64_t, void *, size_t)> &fill)
{
    const VkDeviceSize chunk = total < kStagingBytes
                             ? static_cast<VkDeviceSize>(total) : kStagingBytes;

    // Staged rather than kept: a fill happens at startup and at an epoch
    // boundary, and holding a permanent upload buffer for it would be memory
    // taken from the batch size forever to save an allocation a few times a
    // day.
    Buffer staging{};
    if (!device_->create_buffer(chunk, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                                BufferKind::Upload, &staging)) {
        applog(LOG_ERR, "Vulkan: could not allocate a %llu MiB staging buffer "
                        "to build '%s' %s",
               static_cast<unsigned long long>(chunk >> 20), name_, what);
        return false;
    }

    // One slot, and one submit-and-wait per chunk. Two would let the copy of
    // one chunk overlap the host filling the next, and it is not worth the
    // second staging buffer: what an algorithm does to produce these bytes --
    // a DAG item is a hundred hashes -- is orders of magnitude more than the
    // copy of them.
    std::unique_ptr<CommandRing> ring = CommandRing::create(*device_, 1);
    if (!ring) {
        device_->destroy_buffer(&staging);
        return false;
    }

    bool ok = true;

    // Ascending through the table whatever the table is in: `offset` is into
    // it, which is the only index the algorithm is ever asked about, and
    // `within` is into the piece those bytes land in, which is what a copy is
    // recorded against. One copy cannot cross a piece, so a staging load stops
    // at whichever boundary comes first.
    uint64_t offset = 0;   // into the table
    size_t   piece  = 0;   // which buffer those bytes are in
    uint64_t within = 0;   // and where in that one

    while (offset < total) {
        if (piece < dst.size() && within == dst[piece].size) {
            piece++;
            within = 0;
        }
        if (piece >= dst.size()) {
            applog(LOG_ERR, "Vulkan: '%s' %s is %llu MiB and the buffers for "
                            "it hold %llu MiB", name_, what,
                   static_cast<unsigned long long>(total >> 20),
                   static_cast<unsigned long long>(offset >> 20));
            ok = false;
            break;
        }

        VkDeviceSize span = chunk;
        if (span > dst[piece].size - within)
            span = static_cast<VkDeviceSize>(dst[piece].size - within);
        if (span > total - offset)
            span = static_cast<VkDeviceSize>(total - offset);

        if (!fill(offset, staging.mapped, static_cast<size_t>(span))) {
            applog(LOG_ERR, "Vulkan: '%s' could not produce its %s at offset "
                            "%llu MiB", name_, what,
                   static_cast<unsigned long long>(offset >> 20));
            ok = false;
            break;
        }
        if (!device_->flush(staging)) {
            ok = false;
            break;
        }

        CommandRing::Slot *slot = ring->begin();
        if (!slot) {
            ok = false;
            break;
        }

        const VolkDeviceTable &fn = device_->fn();

        VkBufferCopy copy{};
        copy.dstOffset = static_cast<VkDeviceSize>(within);
        copy.size = span;
        fn.vkCmdCopyBuffer(slot->cmd, staging.handle, dst[piece].handle, 1,
                           &copy);

        // A fence tells the host the copy finished; it does not make those
        // bytes visible to a shader. The barrier does, and its second scope
        // covers everything submitted after it on this queue -- which is every
        // dispatch that will ever read this buffer.
        VkBufferMemoryBarrier written{};
        written.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        written.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        written.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        written.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        written.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        written.buffer = dst[piece].handle;
        written.offset = static_cast<VkDeviceSize>(within);
        written.size = span;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                                VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 0,
                                nullptr, 1, &written, 0, nullptr);

        if (!ring->submit(slot) || !ring->wait(slot, kTimeoutNs)) {
            applog(LOG_ERR, "Vulkan: the copy of '%s' %s did not complete",
                   name_, what);
            ok = false;
            break;
        }

        offset += span;
        within += span;
    }

    // Before the buffers go, and by the ring's own rule: it waits for the
    // device in its destructor, which is what makes freeing the staging buffer
    // underneath it safe.
    ring.reset();
    device_->destroy_buffer(&staging);
    return ok;
}

bool SharedState::generate(uint64_t key, const Algorithm &algorithm)
{
    // The seed first, because the pass reads it. It is device-local like the
    // state it produces: every invocation of every slice reads it, and a
    // host-visible buffer would be read across the bus a hundred times per
    // item.
    Buffer seed{};
    if (setup_.seed_bytes) {
        if (!device_->create_buffer(static_cast<VkDeviceSize>(setup_.seed_bytes),
                                    VK_BUFFER_USAGE_STORAGE_BUFFER_BIT
                                        | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                    BufferKind::DeviceLocal, &seed)) {
            applog(LOG_ERR, "Vulkan: could not allocate %llu MiB to seed '%s'",
                   static_cast<unsigned long long>(setup_.seed_bytes >> 20),
                   name_);
            return false;
        }
        if (!upload(std::vector<Buffer>(1, seed), setup_.seed_bytes,
                    "setup seed",
                    [&](uint64_t offset, void *out, size_t span) {
                        return algorithm.setup_seed(key, offset, out, span);
                    })) {
            device_->destroy_buffer(&seed);
            return false;
        }
    }

    // Two bindings, in the order the shader declares them: what it writes,
    // then what it reads. One descriptor set, because the slices are executed
    // one at a time -- this is not a pipeline to keep full, it is a long job
    // cut up so the watchdog does not see it as one dispatch.
    ComputePipelineDesc desc;
    desc.spirv = setup_.spirv;
    desc.spirv_words = setup_.spirv_words;
    desc.storage_buffers = setup_.seed_bytes ? 2 : 1;
    desc.push_constant_bytes = setup_.push_constant_bytes;
    desc.sets = 1;

    // A width the device will accept, and no attempt to find a good one: an
    // item of the sort this pass generates is a hundred hashes of work, so
    // what the build costs is arithmetic rather than occupancy, and it happens
    // a few times a day. The tuner is for the kernel that runs every second.
    const DeviceInfo &info = device_->info();
    desc.local_size_x = setup_.local_size_x ? setup_.local_size_x : 64;
    if (info.max_workgroup_size && desc.local_size_x > info.max_workgroup_size)
        desc.local_size_x = info.max_workgroup_size;
    if (info.max_invocations && desc.local_size_x > info.max_invocations)
        desc.local_size_x = info.max_invocations;

    std::unique_ptr<ComputePipeline> pipeline =
        ComputePipeline::create(*device_, desc, cache_);
    std::unique_ptr<CommandRing> ring;
    bool ok = pipeline != nullptr;

    if (ok) {
        ring = CommandRing::create(*device_, 1);
        ok = ring != nullptr;
    }

    // Items per piece of the table. The pass counts items and the pieces are
    // bytes, so a piece must be a whole number of them: an item that straddled
    // two would be half in a buffer the dispatch writing it cannot see. It
    // always is one -- a piece is a power of two and an item is a small one --
    // and it is checked because the alternative to checking is one torn item
    // per boundary and a hash rate that looks perfectly healthy.
    uint64_t per_chunk = setup_.items;
    if (ok && chunk_.size() > 1) {
        const uint64_t item_bytes = setup_.items ? bytes_ / setup_.items : 0;
        if (!item_bytes || item_bytes * setup_.items != bytes_
            || (chunk_bytes_ % item_bytes)) {
            applog(LOG_ERR, "Vulkan: '%s' generates %llu items into %llu MiB, "
                            "which does not divide the %llu MiB pieces it is "
                            "held in", name_,
                   static_cast<unsigned long long>(setup_.items),
                   static_cast<unsigned long long>(bytes_ >> 20),
                   static_cast<unsigned long long>(chunk_bytes_ >> 20));
            ok = false;
        } else {
            per_chunk = chunk_bytes_ / item_bytes;
        }
    }

    const uint32_t local = ok ? pipeline->local_size_x() : 1;
    uint32_t slice = kFirstSlice;
    unsigned char push[128];

    // Which piece of the table is bound. The shader has one binding for what
    // it writes, so the pass runs over one piece at a time and a slice stops
    // at the boundary between two -- and the algorithm is told both which
    // items these are and where in the bound piece they land, which are the
    // same number for every device that can address the whole table at once.
    size_t bound_piece = chunk_.size();

    // Advanced at the bottom rather than in the header, by the slice this
    // iteration ran: the size for the next one is re-decided from what this
    // one cost, and stepping by it here would skip items or repeat them.
    for (uint64_t first = 0; ok && first < setup_.items; ) {
        const size_t   piece = static_cast<size_t>(first / per_chunk);
        const uint64_t place = first - piece * per_chunk;   // in that piece
        if (piece != bound_piece) {
            const Buffer bound[2] = { chunk_[piece], seed };
            pipeline->bind(0, bound, desc.storage_buffers);
            bound_piece = piece;
        }

        uint64_t left = setup_.items - first;
        if (left > per_chunk - place)
            left = per_chunk - place;
        const uint32_t count = left < slice ? static_cast<uint32_t>(left)
                                            : slice;

        // The same contract as a mining dispatch: the block the algorithm
        // writes must be the block the module was built for, and a mismatch is
        // a shader reading bytes laid out for something else.
        const size_t wrote = algorithm.setup_push(key, first, place, count,
                                                  push, sizeof push);
        if (wrote != setup_.push_constant_bytes) {
            applog(LOG_ERR, "Vulkan: '%s' declared %u bytes of setup push "
                            "constants and prepared %zu", name_,
                   setup_.push_constant_bytes, wrote);
            ok = false;
            break;
        }

        CommandRing::Slot *slot = ring->begin();
        if (!slot) {
            ok = false;
            break;
        }

        pipeline->record(slot->cmd, 0, (count + local - 1) / local, push,
                         setup_.push_constant_bytes);

        // Between this slice and everything that reads what it wrote: the next
        // slice, which may read items this one produced, and every mining
        // dispatch after the build is over.
        const VolkDeviceTable &fn = device_->fn();
        VkBufferMemoryBarrier written{};
        written.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
        written.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
        written.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
        written.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        written.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        written.buffer = chunk_[piece].handle;
        written.offset = 0;
        written.size = VK_WHOLE_SIZE;
        fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                                VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 0,
                                nullptr, 1, &written, 0, nullptr);

        const auto began = std::chrono::steady_clock::now();
        if (!ring->submit(slot) || !ring->wait(slot, kTimeoutNs)) {
            applog(LOG_ERR, "Vulkan: the '%s' setup pass did not complete at "
                            "item %llu", name_,
                   static_cast<unsigned long long>(first));
            ok = false;
            break;
        }
        const double seconds = std::chrono::duration<double>(
                                   std::chrono::steady_clock::now() - began).count();

        // Aimed at kSliceSeconds, from what this slice actually cost, and
        // never more than kSliceGrowth times bigger than the last -- a first
        // slice that finished too fast to measure would otherwise ask for the
        // whole table in one dispatch on the strength of one noisy reading.
        double want = seconds > 0. ? slice * (kSliceSeconds / seconds)
                                   : slice * kSliceGrowth;
        if (want > slice * kSliceGrowth)
            want = slice * kSliceGrowth;
        if (want < 1.)
            want = 1.;
        slice = want > kMaxSlice ? kMaxSlice : static_cast<uint32_t>(want);

        first += count;
    }

    // The ring waits for the device in its destructor, which is what makes
    // freeing the pipeline the slices were recorded against safe.
    ring.reset();
    pipeline.reset();
    if (seed.handle != VK_NULL_HANDLE)
        device_->destroy_buffer(&seed);
    return ok;
}

}  // namespace vkminer
