// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_ALGORITHMS_X16RV2_H__
#define VKMINER_ALGORITHMS_X16RV2_H__

#include "algorithms/algorithm.h"

#include <memory>

namespace vkminer {

std::unique_ptr<Algorithm> make_x16rv2();

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_X16RV2_H__
