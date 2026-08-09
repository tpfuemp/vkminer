// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Re-run the candidates a previous run captured, on this machine's devices.
//
// A capture preserves what a log line does not -- the exact header, target and
// nonce -- so the failing dispatch is repeatable on demand. One run says which
// of the two bugs it is: a reproducible one that can be bisected, or a
// disagreement that does not survive the same input on the same device.

#ifndef VKMINER_REPLAY_H__
#define VKMINER_REPLAY_H__

#include <string>
#include <vector>

namespace vkminer {

class ComputeBackend;

// Replays every capture in `path` on the selected devices. Returns false if
// the file could not be read, or if any capture still disagrees -- which is
// the outcome that means the bug is still here.
bool replay_captures(ComputeBackend &backend, const std::vector<int> &devices,
                     const char *algo_name, const std::string &path);

}  // namespace vkminer

#endif  // VKMINER_REPLAY_H__
