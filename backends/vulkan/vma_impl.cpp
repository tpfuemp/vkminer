// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The one translation unit that compiles VulkanMemoryAllocator. It is its own
// file, and its own library target, because it is upstream's code: it is not
// held to this project's warning flags and it is not worth recompiling when
// anything of ours changes.

#define VMA_IMPLEMENTATION
#include "backends/vulkan/vma.h"
