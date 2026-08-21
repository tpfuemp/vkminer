// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/kawpow/kawpow_dag.h"

// The internal header, not the public one: build_light_cache and
// calculate_dataset_item_512 are what a DAG is made of, and the public API
// only offers whole hashes. It is vendored, so "internal" means internal to
// that library and not unstable underneath us.
#include "third_party/ethash/lib/ethash/ethash-internal.hpp"

#include <cstring>
#include <mutex>

namespace vkminer {
namespace kawpow {

namespace {

// The vendored copy is the fork's, and this is where that is asserted rather
// than assumed: an epoch length of 30000 would give every size below a
// different answer and every one of them would look plausible.
static_assert(static_cast<int>(kEpochLength) == ethash::epoch_length,
              "the vendored ethash is not built for KawPoW's epoch length");
static_assert(static_cast<int>(kItemBytes) == ethash::light_cache_item_size,
              "a light cache item is not 64 bytes");
static_assert(static_cast<int>(2 * kItemBytes) == ethash::full_dataset_item_size,
              "a full dataset item is not two 64-byte items");

// The last epoch's cache, kept because building one is a second of keccak and
// both of this file's real entry points want it. One at a time: a miner is on
// one epoch, and the moment it moves the old cache is dead weight measured in
// megabytes.
//
// The lock is held for the whole of every call rather than only around the
// swap, so that a caller cannot be reading a cache another thread is
// replacing. Two devices asking for two epochs at once would serialize, which
// costs a second at an epoch boundary and cannot go wrong.
std::mutex cache_lock;
int cached_epoch = -1;
ethash::epoch_context_ptr cached{nullptr, nullptr};

// The context for `epoch`, built if it is not the one in hand. Null if it
// could not be allocated, which for a cache this size is a real possibility on
// a small machine. Call with cache_lock held.
const ethash::epoch_context *context(uint32_t epoch)
{
    const int number = static_cast<int>(epoch);
    if (cached && cached_epoch == number)
        return cached.get();

    cached = ethash::create_epoch_context(number);
    cached_epoch = cached ? number : -1;
    return cached.get();
}

}  // namespace

uint32_t epoch_of(uint64_t block_height)
{
    return static_cast<uint32_t>(block_height / kEpochLength);
}

uint32_t light_cache_items(uint32_t epoch)
{
    return static_cast<uint32_t>(
        ethash::calculate_light_cache_num_items(static_cast<int>(epoch)));
}

uint64_t light_cache_bytes(uint32_t epoch)
{
    return static_cast<uint64_t>(light_cache_items(epoch)) * kItemBytes;
}

uint64_t dag_items(uint32_t epoch)
{
    // Ethash counts 128-byte items; one invocation of the kernel writes 64
    // bytes, so there are twice as many of the thing being counted here.
    return 2ull * static_cast<uint64_t>(
        ethash::calculate_full_dataset_num_items(static_cast<int>(epoch)));
}

uint64_t dag_bytes(uint32_t epoch)
{
    return dag_items(epoch) * kItemBytes;
}

bool light_cache(uint32_t epoch, uint64_t offset, void *out, size_t bytes)
{
    const uint64_t total = light_cache_bytes(epoch);
    if (offset > total || bytes > total - offset)
        return false;

    std::lock_guard<std::mutex> held(cache_lock);
    const ethash::epoch_context *ctx = context(epoch);
    if (!ctx)
        return false;

    // Bytes, not words. What the device wants is the byte string the cache is
    // defined as, which is what it is stored as here; reading it as words is
    // the shader's business and is right on the little-endian machine every
    // GPU is.
    const char *from = reinterpret_cast<const char *>(ctx->light_cache);
    std::memcpy(out, from + offset, bytes);
    return true;
}

bool dataset_item(uint32_t epoch, uint64_t index, uint32_t out[kItemWords])
{
    if (index >= dag_items(epoch))
        return false;

    std::lock_guard<std::mutex> held(cache_lock);
    const ethash::epoch_context *ctx = context(epoch);
    if (!ctx)
        return false;

    const ethash::hash512 item =
        ethash::calculate_dataset_item_512(*ctx, static_cast<int64_t>(index));

    // le::uint32 is the identity on the machines this runs on and a byte swap
    // on the machines it does not: what the shader produces is the item's
    // bytes read as little-endian words, and this says so rather than relying
    // on the host being one.
    for (uint32_t i = 0; i < kItemWords; i++)
        out[i] = ethash::le::uint32(item.word32s[i]);
    return true;
}

}  // namespace kawpow
}  // namespace vkminer
