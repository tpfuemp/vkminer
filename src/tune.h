// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Finding out what this particular GPU likes, rather than being told.
//
// The width a shader runs best at is not a property of the shader: it follows
// the subgroup size, the register file and how much of the device a dispatch
// must fill to stop being latency, and those differ between vendors, between
// two cards of one vendor, and across a driver update. A number compiled into
// the binary is right where it was picked and a guess everywhere else, so it is
// measured here instead -- on the machine and with the shader that will run.
//
// The sweep uses the algorithm's published test vector, never pool work: it is
// throwaway hashing, and a live job would have a job's worth of nonces scanned
// at a size chosen to be discarded.
//
// Never fatal. A device that will not tune mines at the backend's defaults,
// which is what every run before this did.

#ifndef VKMINER_TUNE_H__
#define VKMINER_TUNE_H__

#include "backends/backend.h"

#include <vector>

namespace vkminer {

// Settle the tuning for each of `device_indices`: from the cache where there
// is an entry for this exact device, driver, algorithm and shader, and from a
// sweep where there is not. Call once, before any worker starts.
void tune_devices(ComputeBackend &backend,
                  const std::vector<int> &device_indices,
                  const char *algo_name);

// Apply what was settled for this device to a spec the algorithm just built.
// A no-op where nothing was, so a caller applies it unconditionally rather
// than having to ask first.
void apply_tuning(int device_index, KernelSpec *spec);

}  // namespace vkminer

#endif  // VKMINER_TUNE_H__
