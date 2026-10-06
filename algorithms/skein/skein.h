// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_ALGORITHMS_SKEIN_H__
#define VKMINER_ALGORITHMS_SKEIN_H__

#include "algorithms/algorithm.h"

#include <memory>

namespace vkminer {

std::unique_ptr<Algorithm> make_skein();

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_SKEIN_H__
