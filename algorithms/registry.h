// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Name to Algorithm. One place decides which names exist, so that --algo, the
// usage text and the self-test cannot disagree about what this miner supports.

#ifndef VKMINER_ALGORITHMS_REGISTRY_H__
#define VKMINER_ALGORITHMS_REGISTRY_H__

#include "algorithms/algorithm.h"

#include <memory>
#include <string>

namespace vkminer {

// A fresh instance, or null if nothing answers to that name. Case is ignored,
// because the option parser lowercases what it is given and a user typing
// SHA256D means the same thing.
std::unique_ptr<Algorithm> create_algorithm(const char *name);

// Whether the name resolves, without building anything. For validating --algo
// before the miner commits to a pool connection.
bool algorithm_exists(const char *name);

// The names, comma separated, for an error message that tells the user what
// they could have typed instead.
std::string algorithm_names();

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_REGISTRY_H__
