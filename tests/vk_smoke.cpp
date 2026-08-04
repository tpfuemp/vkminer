// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Round-trip test for the Vulkan backend: a shader that writes a value the
// host can predict, dispatched over a million invocations, read back and
// checked element by element. It proves the whole chain -- instance, device,
// allocator, descriptor set, specialization constant, push constants, command
// buffer, fence, barrier, copy -- because every one of them being wrong
// produces wrong or missing data here and nowhere earlier.
//
// It runs on every device the backend finds, with the validation layers on,
// and fails if the layers reported an error even when the numbers came back
// right. A dispatch that produces correct output through undefined behaviour
// is not a passing test; it is a test that will fail on someone else's driver.

#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/pipeline_cache.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_pipeline.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and the option parser reach for and no more.
extern "C" {
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
struct thr_info *thr_info = nullptr;
double *thr_hashrates = nullptr;
struct work_restart *work_restart = nullptr;
int work_thr_id = 0;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
}

namespace {

constexpr uint32_t kSentinel = 0xdeadbeefu;
constexpr uint64_t kTimeoutNs = 10ull * 1000 * 1000 * 1000;

int failures = 0;

void fail(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::printf("FAIL ");
    std::vprintf(fmt, args);
    std::printf("\n");
    va_end(args);
    failures++;
}

struct Push {
    uint32_t count;
    uint32_t bias;
};

// One dispatch, from an empty command buffer to verified host memory.
bool run_pass(vkminer::VulkanDevice &device, vkminer::ComputePipeline &pipeline,
              vkminer::CommandRing &ring, const vkminer::Buffer &storage,
              const vkminer::Buffer &readback, uint32_t elements,
              uint32_t count, uint32_t bias)
{
    const VolkDeviceTable &fn = device.fn();

    vkminer::CommandRing::Slot *slot = ring.begin();
    if (!slot) {
        fail("could not begin a command buffer");
        return false;
    }

    // Everything the shader must not touch is set to a value it never writes,
    // so that "the tail was left alone" and "the tail was never reached" are
    // distinguishable.
    fn.vkCmdFillBuffer(slot->cmd, storage.handle, 0, VK_WHOLE_SIZE, kSentinel);

    VkMemoryBarrier fill_done{};
    fill_done.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    fill_done.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    fill_done.dstAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                            VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1,
                            &fill_done, 0, nullptr, 0, nullptr);

    const uint32_t local = pipeline.local_size_x();
    const uint32_t groups = (count + local - 1) / local;

    const Push push{count, bias};
    pipeline.record(slot->cmd, groups, &push, sizeof push);

    // Without this the copy below may read memory the shader has not finished
    // writing. It is the single most common way a dispatch appears to work on
    // one driver and returns garbage on another.
    VkMemoryBarrier shader_done{};
    shader_done.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    shader_done.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    shader_done.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
    fn.vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &shader_done,
                            0, nullptr, 0, nullptr);

    VkBufferCopy copy{};
    copy.size = static_cast<VkDeviceSize>(elements) * sizeof(uint32_t);
    fn.vkCmdCopyBuffer(slot->cmd, storage.handle, readback.handle, 1, &copy);

    if (!ring.submit(slot)) {
        fail("could not submit");
        return false;
    }
    if (!ring.wait(slot, kTimeoutNs)) {
        fail("the dispatch did not complete");
        return false;
    }
    if (!device.invalidate(readback)) {
        fail("could not invalidate the readback buffer");
        return false;
    }

    const uint32_t *got = static_cast<const uint32_t *>(readback.mapped);
    for (uint32_t i = 0; i < elements; i++) {
        const uint32_t expect = i < count ? i + bias : kSentinel;
        if (got[i] != expect) {
            fail("element %u is 0x%08x, expected 0x%08x (%u of %u invocations, "
                 "bias %u, workgroup %u)",
                 i, got[i], expect, count, elements, bias, local);
            return false;
        }
    }

    return true;
}

// Where the shader is. Beside the test binary first, because a cross build
// bakes in a path that exists on the machine that compiled the test and not on
// the one running it -- which is every Windows and aarch64 run here.
std::string spirv_path(const char *argv0)
{
    std::string dir(argv0 ? argv0 : "");
    const size_t cut = dir.find_last_of("/\\");
    dir = cut == std::string::npos ? std::string(".") : dir.substr(0, cut);

    const std::string beside = dir + "/vk-smoke.spv";
    if (FILE *f = std::fopen(beside.c_str(), "rb")) {
        std::fclose(f);
        return beside;
    }
    return VK_SMOKE_SPV;
}

bool run_device(vkminer::VulkanBackend &backend, const vkminer::DeviceInfo &info,
                const std::string &spirv_file)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    vkminer::VulkanDevice *device = backend.device(info.index);
    if (!device) {
        fail("could not create a logical device");
        return false;
    }

    std::vector<uint32_t> spirv;
    if (!vkminer::read_spirv(spirv_file, &spirv)) {
        fail("could not read %s", spirv_file.c_str());
        return false;
    }

    // As wide as the device allows, up to 256: the point is to be a size the
    // shader was not written for, so that a specialization constant that never
    // arrived shows up as a wrong dispatch rather than as a slow one.
    uint32_t local = 256;
    if (info.max_workgroup_size && local > info.max_workgroup_size)
        local = info.max_workgroup_size;
    if (info.max_invocations && local > info.max_invocations)
        local = info.max_invocations;

    std::unique_ptr<vkminer::PipelineCache> cache =
        vkminer::PipelineCache::open(*device);

    vkminer::ComputePipelineDesc desc;
    desc.spirv = spirv.data();
    desc.spirv_words = spirv.size();
    desc.storage_buffers = 1;
    desc.push_constant_bytes = sizeof(Push);
    desc.local_size_x = local;

    std::unique_ptr<vkminer::ComputePipeline> pipeline =
        vkminer::ComputePipeline::create(*device, desc, cache->handle());
    if (!pipeline) {
        fail("could not create the pipeline");
        return false;
    }

    constexpr uint32_t kElements = 1u << 20;  // 1,048,576 invocations, 4 MiB
    const VkDeviceSize bytes =
        static_cast<VkDeviceSize>(kElements) * sizeof(uint32_t);

    vkminer::Buffer storage;
    vkminer::Buffer readback;
    if (!device->create_buffer(bytes,
                               VK_BUFFER_USAGE_STORAGE_BUFFER_BIT
                                   | VK_BUFFER_USAGE_TRANSFER_SRC_BIT
                                   | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                               vkminer::BufferKind::DeviceLocal, &storage)) {
        // MiB rather than bytes: mingw's printf and gcc's format checking do
        // not agree on how to spell a 64-bit conversion, and this number does
        // not need the precision.
        fail("could not allocate %u MiB of device memory",
             static_cast<unsigned>(bytes >> 20));
        return false;
    }
    if (!device->create_buffer(bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                               vkminer::BufferKind::Readback, &readback)) {
        device->destroy_buffer(&storage);
        fail("could not allocate a readback buffer");
        return false;
    }

    pipeline->bind(&storage, 1);

    std::unique_ptr<vkminer::CommandRing> ring =
        vkminer::CommandRing::create(*device, 2);
    if (!ring) {
        device->destroy_buffer(&storage);
        device->destroy_buffer(&readback);
        fail("could not create the command ring");
        return false;
    }

    struct Pass {
        const char *what;
        uint32_t count;
        uint32_t bias;
    };
    // The third and fourth passes matter as much as the first: they reuse the
    // ring, so a fence that was never reset, or a command buffer reused while
    // still executing, fails here and not on the first dispatch.
    static const Pass passes[] = {
        { "every element", kElements, 0 },
        { "every element, biased", kElements, 0x01000000u },
        { "a partial last workgroup", kElements - 7, 3 },
        { "one invocation", 1, 42 },
    };

    bool ok = true;
    for (const Pass &pass : passes) {
        if (run_pass(*device, *pipeline, *ring, storage, readback, kElements,
                     pass.count, pass.bias)) {
            std::printf("ok   %s\n", pass.what);
        } else {
            std::printf("     ...while testing %s\n", pass.what);
            ok = false;
            break;  // a device that failed once will fail the rest noisily
        }
    }

    // The ring goes first: it waits for the device to be idle, which is what
    // makes freeing the buffers safe.
    ring.reset();
    device->destroy_buffer(&storage);
    device->destroy_buffer(&readback);
    return ok;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    const std::string spirv_file =
        argc > 1 ? std::string(argv[1]) : spirv_path(argv[0]);

    // The layers are the point of this test, not an option of it.
    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    for (const vkminer::DeviceInfo &info : backend.devices())
        run_device(backend, info, spirv_file);

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (vkminer::vk_validation_enabled) {
        std::printf("\nok   no validation errors\n");
    } else {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the numbers came back right\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
