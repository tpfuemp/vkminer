// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// What the miner checks about itself before it asks anyone for work.
//
// A CPU miner that hashes wrongly wastes its own electricity. A GPU miner that
// hashes wrongly does that on a machine whose driver, clocks and memory the
// author has never seen, and the first symptom is a pool quietly rejecting
// everything. So the binary proves, on this machine and this driver, that it
// reproduces published block hashes -- through its own reference and through
// every device it is about to mine on -- and it does it before the first
// packet, because there is no point connecting if the answer is no.

#ifndef VKMINER_SELF_TEST_H__
#define VKMINER_SELF_TEST_H__

#include "backends/backend.h"

#include <vector>

namespace vkminer {

// Runs the algorithm's known-answer vectors through its scalar reference and
// then through a kernel on each of `device_indices`. Returns false, having
// logged exactly what disagreed, if any of it does not match -- which is a
// reason to stop, not a reason to warn.
bool self_test(ComputeBackend &backend, const std::vector<int> &device_indices,
               const char *algo_name);

}  // namespace vkminer

#endif  // VKMINER_SELF_TEST_H__
