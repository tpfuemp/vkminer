// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shabal-512, Whirlpool and Tiger on the device against the scalar
// references, over 64- and 80-byte messages. Both modules where the device
// has shaderInt64. Validation layers are on; any error fails the test.

#include "backends/vulkan/command_ring.h"
#include "backends/vulkan/pipeline_cache.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_pipeline.h"

extern "C" {
#include "core/miner.h"
#include "core/shabal512.h"
#include "core/tiger192.h"
#include "core/whirlpool512.h"
}

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

// A hang guard, not a speed limit: llvmpipe compiles at the first dispatch,
// which with a cold cache takes tens of seconds.
constexpr uint64_t kTimeoutNs = 300ull * 1000 * 1000 * 1000;

// primitives-test.glsl's layout: twenty message words, then sixteen out.
constexpr uint32_t kStride = 36;
constexpr uint32_t kMessages = 300;  // more than one workgroup, and a partial

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
    uint32_t which;
    uint32_t words;
};

struct Primitive {
    const char *name;
    void (*fn)(void *, const void *, size_t);
    size_t digest_bytes;
};

const Primitive kPrimitives[] = {
    { "Shabal-512", shabal512_full, 64 },
    { "Whirlpool", whirlpool512_full, 64 },
    { "Tiger", tiger192_full, 24 },
};

// Messages nobody chose: a 64-bit LCG, different for every case.
uint32_t next_word(uint64_t *state)
{
    *state = *state * 6364136223846793005ull + 1442695040888963407ull;
    return static_cast<uint32_t>(*state >> 32);
}

void hex(const char *label, const unsigned char *bytes, size_t n)
{
    std::printf("  %-5s ", label);
    for (size_t i = 0; i < n; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// One primitive at one length through one pipeline, from a buffer of messages
// to digests compared byte for byte.
bool run_case(vkminer::VulkanDevice &device, vkminer::ComputePipeline &pipeline,
              vkminer::CommandRing &ring, const vkminer::Buffer &buffer,
              uint32_t which, uint32_t words)
{
    const Primitive &prim = kPrimitives[which];
    uint32_t *data = static_cast<uint32_t *>(buffer.mapped);

    uint64_t seed = 0x9e3779b97f4a7c15ull * (which * 32 + words + 1);
    for (uint32_t i = 0; i < kMessages * kStride; i++)
        data[i] = next_word(&seed);
    if (!device.flush(buffer)) {
        fail("could not flush the messages");
        return false;
    }

    vkminer::CommandRing::Slot *slot = ring.begin();
    if (!slot) {
        fail("could not begin a command buffer");
        return false;
    }

    VkMemoryBarrier host_done{};
    host_done.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    host_done.srcAccessMask = VK_ACCESS_HOST_WRITE_BIT;
    host_done.dstAccessMask = VK_ACCESS_SHADER_READ_BIT;
    device.fn().vkCmdPipelineBarrier(slot->cmd, VK_PIPELINE_STAGE_HOST_BIT,
                                     VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0, 1,
                                     &host_done, 0, nullptr, 0, nullptr);

    const uint32_t local = pipeline.local_size_x();
    const Push push{kMessages, which, words};
    pipeline.record(slot->cmd, 0, (kMessages + local - 1) / local, &push,
                    sizeof push);

    VkMemoryBarrier shader_done{};
    shader_done.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    shader_done.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    shader_done.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    device.fn().vkCmdPipelineBarrier(slot->cmd,
                                     VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                                     VK_PIPELINE_STAGE_HOST_BIT, 0, 1,
                                     &shader_done, 0, nullptr, 0, nullptr);

    if (!ring.submit(slot)) {
        fail("could not submit");
        return false;
    }
    if (!ring.wait(slot, kTimeoutNs)) {
        fail("the dispatch did not complete");
        return false;
    }
    if (!device.invalidate(buffer)) {
        fail("could not invalidate the buffer");
        return false;
    }

    for (uint32_t i = 0; i < kMessages; i++) {
        unsigned char msg[80], want[64], got[64];
        for (uint32_t k = 0; k < 20; k++)
            le32enc(msg + 4 * k, data[i * kStride + k]);
        for (uint32_t k = 0; k < 16; k++)
            le32enc(got + 4 * k, data[i * kStride + 20 + k]);
        prim.fn(want, msg, words * 4);

        if (std::memcmp(want, got, prim.digest_bytes) != 0) {
            fail("%s of %u bytes, message %u", prim.name, words * 4, i);
            hex("want", want, prim.digest_bytes);
            hex("got", got, prim.digest_bytes);
            return false;
        }
    }
    return true;
}

// Where a shader is. Beside the test binary first, because a cross build bakes
// in a path that exists on the machine that compiled the test and not on the
// one running it.
std::string spirv_path(const char *argv0, const char *file, const char *baked)
{
    std::string dir(argv0 ? argv0 : "");
    const size_t cut = dir.find_last_of("/\\");
    dir = cut == std::string::npos ? std::string(".") : dir.substr(0, cut);

    const std::string beside = dir + "/" + file;
    if (FILE *f = std::fopen(beside.c_str(), "rb")) {
        std::fclose(f);
        return beside;
    }
    return baked;
}

void run_module(vkminer::VulkanDevice &device, const vkminer::DeviceInfo &info,
                const char *label, const std::string &spirv_file)
{
    std::vector<uint32_t> spirv;
    if (!vkminer::read_spirv(spirv_file, &spirv)) {
        fail("could not read %s", spirv_file.c_str());
        return;
    }

    uint32_t local = 64;
    if (info.max_workgroup_size && local > info.max_workgroup_size)
        local = info.max_workgroup_size;
    if (info.max_invocations && local > info.max_invocations)
        local = info.max_invocations;

    std::unique_ptr<vkminer::PipelineCache> cache =
        vkminer::PipelineCache::open(device);

    vkminer::ComputePipelineDesc desc;
    desc.spirv = spirv.data();
    desc.spirv_words = spirv.size();
    desc.storage_buffers = 1;
    desc.push_constant_bytes = sizeof(Push);
    desc.local_size_x = local;

    std::unique_ptr<vkminer::ComputePipeline> pipeline =
        vkminer::ComputePipeline::create(device, desc, cache->handle());
    if (!pipeline) {
        fail("could not create the %s pipeline", label);
        return;
    }

    // Host-visible, so the messages go in and the digests come out without a
    // staging copy; a test's few kilobytes do not care where they live.
    vkminer::Buffer buffer;
    if (!device.create_buffer(kMessages * kStride * sizeof(uint32_t),
                              VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                              vkminer::BufferKind::Readback, &buffer)) {
        fail("could not allocate the buffer");
        return;
    }
    pipeline->bind(0, &buffer, 1);

    std::unique_ptr<vkminer::CommandRing> ring =
        vkminer::CommandRing::create(device, 2);
    if (!ring) {
        device.destroy_buffer(&buffer);
        fail("could not create the command ring");
        return;
    }

    for (uint32_t which = 0; which < 3; which++)
        for (uint32_t words : { 16u, 20u })
            if (run_case(device, *pipeline, *ring, buffer, which, words))
                std::printf("ok   %-6s %s of %u bytes\n", label,
                            kPrimitives[which].name, words * 4);

    ring.reset();
    device.destroy_buffer(&buffer);
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    const std::string spirv32 =
        spirv_path(argc > 0 ? argv[0] : nullptr, "primitives-test.spv",
                   PRIMITIVES_TEST_SPV);
    const std::string spirv64 =
        spirv_path(argc > 0 ? argv[0] : nullptr, "primitives-test64.spv",
                   PRIMITIVES_TEST64_SPV);

    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;
    }

    for (const vkminer::DeviceInfo &info : backend.devices()) {
        std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                    vkminer::device_kind_name(info.kind));
        vkminer::VulkanDevice *device = backend.device(info.index);
        if (!device) {
            fail("could not create a logical device");
            continue;
        }
        run_module(*device, info, "2x32", spirv32);
        if (info.int64)
            run_module(*device, info, "int64", spirv64);
        else
            std::printf("skip int64: the device has no shaderInt64\n");
    }

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (vkminer::vk_validation_enabled) {
        std::printf("\nok   no validation errors\n");
    } else {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the digests came back right\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
