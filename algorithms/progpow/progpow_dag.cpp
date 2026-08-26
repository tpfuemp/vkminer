// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/progpow/progpow_dag.h"

// The internal header, not the public one: build_light_cache and
// calculate_dataset_item_512 are what a DAG is made of, and the public API
// only offers whole hashes. It is vendored, so "internal" means internal to
// that library and not unstable underneath us.
#include "third_party/ethash/lib/ethash/ethash-internal.hpp"

#include <cstring>
#include <mutex>
#include <new>
#include <vector>

namespace vkminer {
namespace progpow {

namespace {

static_assert(static_cast<int>(kItemBytes) == ethash::light_cache_item_size,
              "a light cache item is not 64 bytes");
static_assert(static_cast<int>(2 * kItemBytes) == ethash::full_dataset_item_size,
              "a full dataset item is not two 64-byte items");

// The last cache built, kept because building one is a second of keccak and
// both of this file's real entry points want it. One at a time: a miner is on
// one epoch, and the moment it moves the old cache is dead weight measured in
// megabytes.
//
// Built here rather than through ethash::create_epoch_context, because that
// call derives the size and the seed from one number and this family is the
// case where those differ. build_light_cache takes them apart, and
// calculate_dataset_item_512 reads nothing from a context but the cache pointer
// and its item count -- so the context dataset_item hands it is a stack value
// over this vector and owns nothing.
//
// The lock is held for the whole of every call rather than only around the
// swap, so that a caller cannot be reading a cache another thread is
// replacing. Two devices asking for two epochs at once would serialize, which
// costs a second at an epoch boundary and cannot go wrong.
std::mutex cache_lock;
Epochs cached_epochs = {~0u, ~0u, ~0u};
std::vector<ethash::hash512> cached_cache;

bool same(const Epochs &a, const Epochs &b)
{
    return a.seed == b.seed && a.light == b.light && a.full == b.full;
}

// The cache for `epochs`, built if it is not the one in hand. Null if it could
// not be allocated, which at these sizes is a real possibility on a small
// machine. Call with cache_lock held; what it returns is valid until the next
// call.
const ethash::hash512 *cache_for(const Epochs &epochs)
{
    if (!cached_cache.empty() && same(cached_epochs, epochs))
        return cached_cache.data();

    const int items = static_cast<int>(light_cache_items(epochs.light));
    cached_cache.clear();
    try {
        cached_cache.resize(static_cast<size_t>(items));
    } catch (const std::bad_alloc &) {
        cached_cache.clear();
        return nullptr;
    }

    // The size from one epoch, the seed from another. This line is the whole
    // reason the three numbers are carried around separately.
    ethash::build_light_cache(
        cached_cache.data(), items,
        ethash::calculate_epoch_seed(static_cast<int>(epochs.seed)));
    cached_epochs = epochs;
    return cached_cache.data();
}

}  // namespace

Epochs epochs_for(const Params &params, uint32_t seed_epoch)
{
    // The multiplier applies from one epoch onwards and to both derived
    // numbers; the offset applies to the dataset alone and always. No fork uses
    // more than one of them, but this is the order the reference composes them
    // in and there is nothing to gain by refusing the other.
    const uint32_t scaled =
        (params.dagchange_epoch && seed_epoch >= params.dagchange_epoch)
            ? seed_epoch * params.dag_epoch_mul
            : seed_epoch;

    Epochs out;
    out.seed  = seed_epoch;
    out.light = scaled;
    out.full  = scaled + params.dag_full_off;
    return out;
}

Epochs epochs_of(const Params &params, uint64_t block_height)
{
    return epochs_for(params,
                      static_cast<uint32_t>(block_height / params.epoch_length));
}

void epoch_seed(uint32_t seed_epoch, unsigned char out[32])
{
    const ethash::hash256 seed =
        ethash::calculate_epoch_seed(static_cast<int>(seed_epoch));
    std::memcpy(out, seed.bytes, 32);
}

uint32_t light_cache_items(uint32_t light_epoch)
{
    return static_cast<uint32_t>(
        ethash::calculate_light_cache_num_items(static_cast<int>(light_epoch)));
}

uint64_t light_cache_bytes(uint32_t light_epoch)
{
    return static_cast<uint64_t>(light_cache_items(light_epoch)) * kItemBytes;
}

uint64_t dag_items(uint32_t full_epoch)
{
    // Ethash counts 128-byte items; one invocation of the kernel writes 64
    // bytes, so there are twice as many of the thing being counted here.
    return 2ull * static_cast<uint64_t>(
        ethash::calculate_full_dataset_num_items(static_cast<int>(full_epoch)));
}

uint64_t dag_bytes(uint32_t full_epoch)
{
    return dag_items(full_epoch) * kItemBytes;
}

bool light_cache(const Epochs &epochs, uint64_t offset, void *out, size_t bytes)
{
    const uint64_t total = light_cache_bytes(epochs.light);
    if (offset > total || bytes > total - offset)
        return false;

    std::lock_guard<std::mutex> held(cache_lock);
    const ethash::hash512 *cache = cache_for(epochs);
    if (!cache)
        return false;

    // Bytes, not words. What the device wants is the byte string the cache is
    // defined as, which is what it is stored as here; reading it as words is
    // the shader's business and is right on the little-endian machine every
    // GPU is.
    const char *from = reinterpret_cast<const char *>(cache);
    std::memcpy(out, from + offset, bytes);
    return true;
}

bool dataset_item(const Epochs &epochs, uint64_t index, uint32_t out[kItemWords])
{
    if (index >= dag_items(epochs.full))
        return false;

    std::lock_guard<std::mutex> held(cache_lock);
    const ethash::hash512 *cache = cache_for(epochs);
    if (!cache)
        return false;

    // A stack context over the cache in hand. calculate_dataset_item_512 reads
    // only the two fields filled in here; the rest are what the struct needs to
    // exist, not what the call needs to work.
    const ethash::epoch_context ctx{
        static_cast<int>(epochs.seed),
        static_cast<int>(light_cache_items(epochs.light)),
        cache,
        nullptr,
        static_cast<int>(dag_items(epochs.full) / 2),
    };

    const ethash::hash512 item =
        ethash::calculate_dataset_item_512(ctx, static_cast<int64_t>(index));

    // le::uint32 is the identity on the machines this runs on and a byte swap
    // on the machines it does not: what the shader produces is the item's
    // bytes read as little-endian words, and this says so rather than relying
    // on the host being one.
    for (uint32_t i = 0; i < kItemWords; i++)
        out[i] = ethash::le::uint32(item.word32s[i]);
    return true;
}

}  // namespace progpow
}  // namespace vkminer
