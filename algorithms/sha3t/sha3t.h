// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_ALGORITHMS_SHA3T_H__
#define VKMINER_ALGORITHMS_SHA3T_H__

#include "algorithms/algorithm.h"

#include <memory>

namespace vkminer {

std::unique_ptr<Algorithm> make_sha3t();

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_SHA3T_H__
