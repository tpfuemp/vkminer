// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_ALGORITHMS_KAWPOW_KAWPOW_H__
#define VKMINER_ALGORITHMS_KAWPOW_KAWPOW_H__

#include "algorithms/algorithm.h"
#include "algorithms/kawpow/kawpow_params.h"

#include <memory>

namespace vkminer {

// A ProgPoW fork -- `params` says which -- against the DAG for `epoch`,
// generated on the device.
//
// `epoch` is the *seed* epoch and a starting point rather than a setting: the
// table's size decides the buffer's and the descriptors are written when the
// kernel is built, so crossing an epoch means a rebuilt kernel. A caller asks
// retarget() before each job and builds one again when the answer is true,
// which makes zero the right starting point for a miner about to connect.
std::unique_ptr<Algorithm> make_progpow(const kawpow::Params &params,
                                        uint32_t epoch);

// The same algorithm, hashing against a table the *host* builds and uploads:
// `lines` of 256 bytes from the head of that epoch's DAG, and nothing beyond.
//
// For the differential test. Generating a real 1023 MiB DAG on the device under
// test would leave a test that can fail for two reasons at once; a truncated
// table decides neither question by accident, since the line index is taken
// modulo `lines` on both sides and what is left under test is the hash.
//
// `lines` must be at least 64: the first 16 KiB of the DAG is also the cache
// the program's read operations use, and a shorter table is one the kernel
// would index past the end of.
std::unique_ptr<Algorithm> make_progpow_host_dag(const kawpow::Params &params,
                                                 uint32_t epoch,
                                                 uint64_t lines);

}  // namespace vkminer

// What progpow_seed_hash_agrees in core/miner.h points at once a fork of this
// family is the chosen algorithm. Declared here rather than there because the
// Stratum client is linked without this layer and must not name it; main.cpp
// links both and installs the pointer.
extern "C" bool progpow_seed_hash_check(uint64_t height,
                                        const unsigned char seed[32]);

#endif  // VKMINER_ALGORITHMS_KAWPOW_KAWPOW_H__
