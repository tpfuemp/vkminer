# Vendored dependencies.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Not first-party code: no warning flags and no style rules are imposed here,
# and the include directories are marked SYSTEM so upstream warnings cannot
# fail our build. See VERSIONS for the pinned revisions, update.sh to refresh.

# Vulkan headers.
#
# VK_NO_PROTOTYPES is not optional. volk resolves every entry point at run
# time; leaving the static prototypes visible would let a call link against a
# system Vulkan library, which is exactly the dependency this project does
# not want to have.
add_library(vulkan_headers INTERFACE)
target_include_directories(vulkan_headers SYSTEM INTERFACE Vulkan-Headers/include)
target_compile_definitions(vulkan_headers INTERFACE VK_NO_PROTOTYPES)

# volk: the meta-loader. Opens the platform loader (vulkan-1.dll,
# libvulkan.so.1) itself, so no target in this project links a Vulkan
# library and the build needs no Vulkan SDK.
add_library(volk STATIC volk/volk.c)
target_include_directories(volk SYSTEM PUBLIC volk)
target_link_libraries(volk PUBLIC vulkan_headers)
if(WIN32)
    target_compile_definitions(volk PRIVATE VK_USE_PLATFORM_WIN32_KHR)
else()
    target_link_libraries(volk PUBLIC ${CMAKE_DL_LIBS})
endif()

# VulkanMemoryAllocator: header-only until a translation unit defines
# VMA_IMPLEMENTATION, which happens when the Vulkan backend lands.
add_library(vma INTERFACE)
target_include_directories(vma SYSTEM INTERFACE VulkanMemoryAllocator/include)
target_link_libraries(vma INTERFACE vulkan_headers)
