// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// What a tuning sweep found, and where it is kept between runs.
//
// A sweep costs seconds of a device's time, so its answer is written down. The
// danger is a stale entry, which is worse than none: a number nobody will
// measure again, applied to hardware or a shader it never ran on. So the key
// names everything the answer depends on -- device, driver build, algorithm and
// the shader itself -- and any change to those simply misses.
//
// One file for every device on the machine, keyed rather than positional, so
// tuning a second GPU does not disturb the first.

#ifndef VKMINER_TUNE_CACHE_H__
#define VKMINER_TUNE_CACHE_H__

#include "backends/backend.h"

#include <string>

namespace vkminer {

struct Tuning {
    uint32_t local_size_x = 0;
    uint32_t queue_depth  = 0;

    // Which of the algorithm's kernels won, where it has more than one. Empty
    // means the one the algorithm would have chosen unaided, which is also how
    // an entry written before there was a second kernel reads -- correctly, it
    // was measured on the only one there was.
    std::string variant;

    // What the sweep measured, and how long the device had been under load when
    // it did. The second is not decoration: a card reading 20% faster cold than
    // soaked disagrees with its own file for no reason but temperature, and
    // whoever compares the two needs to know which they are holding.
    double rate = 0.;
    double soak_seconds = 0.;
};

// Everything the tuning depends on, in one string: the device, the driver
// build, the algorithm, and a digest of the SPIR-V that was actually run. A
// driver update or an edited shader therefore misses rather than matching a
// measurement taken on something else.
std::string tune_key(const DeviceInfo &device, const char *algo,
                     const uint32_t *spirv, size_t spirv_words);

// The file, or empty when the environment does not say where a config
// directory is -- in which case the sweep still runs, it just runs every time.
std::string tune_cache_path();

// Read one entry. False when the file, the version or the key is not there,
// which are all the same thing to a caller: nothing is known about this
// combination yet.
bool tune_cache_load(const std::string &path, const std::string &key,
                     Tuning *out);

// Write one entry, leaving every other entry in the file alone. `description`
// is for whoever opens the file: the key identifies, it does not explain.
bool tune_cache_store(const std::string &path, const std::string &key,
                      const std::string &description, const Tuning &tuning);

}  // namespace vkminer

#endif  // VKMINER_TUNE_CACHE_H__
