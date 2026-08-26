// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The host half of a ProgPoW fork's DAG: how big it is, what seeds it, and what
// any one item of it should be.
//
// Not an Algorithm: this is what an algorithm and its setup pass have to agree
// on -- the sizes a spec is filled in from, the light cache the device
// generates from, and the reference a generated item is checked against. The
// hashing that reads the finished DAG is elsewhere.
//
// Implemented against the vendored ethash, for the reason
// third_party/CMakeLists gives. Nothing here exposes it.

#ifndef VKMINER_ALGORITHMS_PROGPOW_PROGPOW_DAG_H__
#define VKMINER_ALGORITHMS_PROGPOW_PROGPOW_DAG_H__

#include "algorithms/progpow/progpow_params.h"

#include <cstddef>
#include <cstdint>

namespace vkminer {
namespace progpow {

// A DAG item and a light cache item are both 64 bytes, and the kernel works in
// 32-bit words because that is what a storage buffer of uints is.
constexpr uint32_t kItemBytes = 64;
constexpr uint32_t kItemWords = kItemBytes / sizeof(uint32_t);

// An epoch is three numbers in this family, not one, and they are only equal
// for KawPoW. A fork that wanted a larger dataset without moving the seed hash
// its pool sends scales or offsets the size while leaving the seed at the real
// epoch, so:
//
//   seed  -- what epoch_seed() is taken of, and what the pool agrees with
//   light -- how many items the light cache holds
//   full  -- how many items the dataset holds
//
// The light cache is both at once: sized at `light`, seeded from `seed`.
// Getting that pair wrong on the one fork that separates them gives a cache of
// exactly the right size full of another epoch's bytes -- every hash wrong, no
// size out of place, nothing to see.
struct Epochs {
    uint32_t seed;
    uint32_t light;
    uint32_t full;
};

// The triple for a block, and the triple for a seed epoch already in hand. The
// seed epoch determines the other two, which is why it alone can key a DAG.
Epochs epochs_of(const Params &params, uint64_t block_height);
Epochs epochs_for(const Params &params, uint32_t seed_epoch);

// The 32 bytes ethash defines as the epoch's seed: nothing for epoch 0, and
// keccak-256 of the one before it after that. Every ProgPoW pool states this in
// its notify, and it is the one number a miner and a pool can compare before a
// single share is submitted -- so this exists to be checked against, not to be
// used. Taken of the *seed* epoch, which is the whole point of Epochs::seed.
void epoch_seed(uint32_t seed_epoch, unsigned char out[32]);

// 64-byte items in the light cache, and the bytes that is. The cache is what
// the device generates from and is a few megabytes; the DAG is what it hashes
// against and is a few gigabytes.
uint32_t light_cache_items(uint32_t light_epoch);
uint64_t light_cache_bytes(uint32_t light_epoch);

// 64-byte items in the full DAG, and the bytes that is. Ethash's own count is
// of 128-byte items, because that is what one hash reads; this one counts what
// one invocation of the generation kernel writes, which is half of it.
uint64_t dag_items(uint32_t full_epoch);
uint64_t dag_bytes(uint32_t full_epoch);

// `bytes` of the light cache for `epochs`, `offset` bytes in, as it goes to the
// device: the canonical byte string, which a little-endian shader reads as the
// words it wants. False if the range is outside the cache.
//
// Building a cache costs a second or so, so the last one is kept: asking for
// the same epochs again is a copy, and asking for different ones throws the
// previous away.
bool light_cache(const Epochs &epochs, uint64_t offset, void *out, size_t bytes);

// The item at `index` of the DAG for `epochs`, as 16 little-endian words -- the
// oracle a generated item is compared against, one item at a time, because the
// whole DAG is far too large to have on the host. False if the index is past
// the end of that DAG.
bool dataset_item(const Epochs &epochs, uint64_t index, uint32_t out[kItemWords]);

// The push block algorithms/progpow/dag.comp takes, one per slice of the setup
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

}  // namespace progpow
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_PROGPOW_PROGPOW_DAG_H__
