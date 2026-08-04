// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// VulkanMemoryAllocator, configured. Every translation unit that touches VMA
// must include this one and not vk_mem_alloc.h directly: the macros below
// change the layout of VmaVulkanFunctions, so a file that sets them
// differently would agree with the rest of the program at compile time and
// disagree at run time.

#ifndef VKMINER_BACKENDS_VULKAN_VMA_H__
#define VKMINER_BACKENDS_VULKAN_VMA_H__

#include <volk.h>

// No static linkage to a Vulkan library: the prototypes VMA would otherwise
// call are not there to link against, because volk resolves everything at run
// time. Both of these off means VMA takes the function pointers it is given
// and asks for nothing itself.
#define VMA_STATIC_VULKAN_FUNCTIONS 0
#define VMA_DYNAMIC_VULKAN_FUNCTIONS 0

// The project baseline. VMA otherwise picks this from the headers, which are
// far newer than the version this miner requires of a device, and the choice
// is not cosmetic: it decides which fields VmaVulkanFunctions has.
#define VMA_VULKAN_VERSION 1001000

#include <vk_mem_alloc.h>

#endif  // VKMINER_BACKENDS_VULKAN_VMA_H__
