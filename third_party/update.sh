#!/usr/bin/env bash
#
# Re-vendor the third-party dependencies at the pinned versions below.
#
#     third_party/update.sh
#
# Sources are copied into the tree rather than pulled in as submodules, so a
# plain "git clone" is enough to build. Only the files the build needs are
# copied; upstream tests, docs and build systems are left behind.
#
# volk and Vulkan-Headers are kept on the same Vulkan SDK tag on purpose --
# volk's generated loader must match the header revision it dispatches for.
#
set -euo pipefail

VOLK_TAG="vulkan-sdk-1.4.357.0"
VMA_TAG="v3.4.0"
HEADERS_TAG="vulkan-sdk-1.4.357.0"

VOLK_URL="https://github.com/zeux/volk"
VMA_URL="https://github.com/GPUOpen-LibrariesAndSDKs/VulkanMemoryAllocator"
HEADERS_URL="https://github.com/KhronosGroup/Vulkan-Headers"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {  # fetch <name> <url> <tag>  -> prints the commit sha
    git -C "$work" clone --quiet --depth 1 --branch "$3" "$2" "$1"
    git -C "$work/$1" rev-parse HEAD
}

echo "vendoring into $here"

# ----------------------------------------------------------------- volk
echo "  volk            $VOLK_TAG"
volk_sha=$(fetch volk "$VOLK_URL" "$VOLK_TAG")
rm -rf "$here/volk"; mkdir -p "$here/volk"
cp "$work/volk/volk.h" "$work/volk/volk.c" "$work/volk/LICENSE.md" "$here/volk/"

# ------------------------------------------------ VulkanMemoryAllocator
echo "  VMA             $VMA_TAG"
vma_sha=$(fetch vma "$VMA_URL" "$VMA_TAG")
rm -rf "$here/VulkanMemoryAllocator"; mkdir -p "$here/VulkanMemoryAllocator/include"
cp "$work/vma/include/vk_mem_alloc.h" "$here/VulkanMemoryAllocator/include/"
cp "$work/vma/LICENSE.txt"            "$here/VulkanMemoryAllocator/"

# -------------------------------------------------------- Vulkan-Headers
echo "  Vulkan-Headers  $HEADERS_TAG"
hdr_sha=$(fetch headers "$HEADERS_URL" "$HEADERS_TAG")
rm -rf "$here/Vulkan-Headers"
mkdir -p "$here/Vulkan-Headers/include/vulkan" "$here/Vulkan-Headers/include/vk_video"
# C headers only. The C++ bindings (vulkan_*.hpp and the .cppm modules) come to
# ~19 MB against 1.5 MB for everything else, and nothing here uses them -- the
# backend drives the C API through volk.
cp "$work/headers/include/vulkan"/*.h   "$here/Vulkan-Headers/include/vulkan/"
cp "$work/headers/include/vk_video"/*.h "$here/Vulkan-Headers/include/vk_video/"
cp "$work/headers/LICENSE.md"           "$here/Vulkan-Headers/"

# ------------------------------------------------------------- manifest
cat > "$here/VERSIONS" <<EOF
Vendored third-party sources. Regenerate with third_party/update.sh; do not
edit the copies in place -- a local fix would be silently lost on the next
update. Patches belong upstream, or in a patch file applied by that script.

volk
  $VOLK_URL
  tag     $VOLK_TAG
  commit  $volk_sha
  license MIT (volk/LICENSE.md)

VulkanMemoryAllocator
  $VMA_URL
  tag     $VMA_TAG
  commit  $vma_sha
  license MIT (VulkanMemoryAllocator/LICENSE.txt)

Vulkan-Headers
  $HEADERS_URL
  tag     $HEADERS_TAG
  commit  $hdr_sha
  license Apache-2.0 OR MIT (Vulkan-Headers/LICENSE.md)
EOF

echo "done:"
sed 's/^/  /' "$here/VERSIONS"
