// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The host half of the KawPoW DAG: how big it is for an epoch, what seeds it,
// and what any one item of it should be.
//
// Not an Algorithm: this is what an algorithm and its setup pass have to agree
// on -- the sizes a spec is filled in from, the light cache the device
// generates from, and the reference a generated item is checked against. The
// hashing that reads the finished DAG is elsewhere.
//
// Implemented against the vendored ethash, for the reason
// third_party/CMakeLists gives. Nothing here exposes it.

#ifndef VKMINER_ALGORITHMS_KAWPOW_KAWPOW_DAG_H__
#define VKMINER_ALGORITHMS_KAWPOW_KAWPOW_DAG_H__

#include <cstddef>
#include <cstdint>

namespace vkminer {
namespace kawpow {

// A DAG item and a light cache item are both 64 bytes, and the kernel works in
// 32-bit words because that is what a storage buffer of uints is.
constexpr uint32_t kItemBytes = 64;
constexpr uint32_t kItemWords = kItemBytes / sizeof(uint32_t);

// Blocks per epoch. Ravencoin's, not Ethereum's 30000: a DAG built to the
// wrong one hashes correctly and shares nothing.
constexpr uint32_t kEpochLength = 7500;

uint32_t epoch_of(uint64_t block_height);

// 64-byte items in the light cache, and the bytes that is. The cache is what
// the device generates from and is a few megabytes; the DAG is what it hashes
// against and is a few gigabytes.
uint32_t light_cache_items(uint32_t epoch);
uint64_t light_cache_bytes(uint32_t epoch);

// 64-byte items in the full DAG, and the bytes that is. Ethash's own count is
// of 128-byte items, because that is what one hash reads; this one counts what
// one invocation of the generation kernel writes, which is half of it.
uint64_t dag_items(uint32_t epoch);
uint64_t dag_bytes(uint32_t epoch);

// `bytes` of the light cache for `epoch`, `offset` bytes in, as it goes to the
// device: the canonical byte string, which a little-endian shader reads as the
// words it wants. False if the range is outside the cache.
//
// Building a cache costs a second or so, so the last one is kept: asking for
// the same epoch again is a copy, and asking for a different one throws the
// previous away.
bool light_cache(uint32_t epoch, uint64_t offset, void *out, size_t bytes);

// The item at `index` of the DAG for `epoch`, as 16 little-endian words -- the
// oracle a generated item is compared against, one item at a time, because the
// whole DAG is far too large to have on the host. False if the index is past
// the end of that epoch's DAG.
bool dataset_item(uint32_t epoch, uint64_t index, uint32_t out[kItemWords]);

// The push block algorithms/kawpow/dag.comp takes, one per slice of the setup
// pass. `first` is where in the DAG the slice starts and `slot` is where in the
// buffer bound to that dispatch it lands -- the same number only when that
// buffer is the whole DAG, which it is not on a device that would not address
// it in one binding.
struct DagPush {
    uint32_t count;
    uint32_t first;
    uint32_t slot;
    uint32_t cache_items;
};

}  // namespace kawpow
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_KAWPOW_KAWPOW_DAG_H__
