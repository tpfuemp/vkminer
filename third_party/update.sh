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
ETHASH_TAG="1.2.0"

VOLK_URL="https://github.com/zeux/volk"
VMA_URL="https://github.com/GPUOpen-LibrariesAndSDKs/VulkanMemoryAllocator"
HEADERS_URL="https://github.com/KhronosGroup/Vulkan-Headers"
ETHASH_URL="https://github.com/RavenCommunity/cpp-kawpow"

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

# --------------------------------------------------------------- ethash
# The CPU reference for the Ethash/ProgPoW family: light cache, dataset item,
# keccak-f800 and the ProgPoW hash itself. Taken from RavenCommunity's fork
# rather than from chfast/ethash upstream, because KawPoW *is* the fork: the
# epoch is 7500 blocks instead of 30000 and the final keccak absorbs a
# Ravencoin constant, so the two produce different digests for the same header
# and only this one agrees with the network. Its own version string still says
# ethash 0.5.1-alpha.1, which is where it forked from.
#
# Nothing device-side comes from here. This is the host half of the differential
# test and the re-verification behind every submitted share.
echo "  cpp-kawpow      $ETHASH_TAG"
ethash_sha=$(fetch ethash "$ETHASH_URL" "$ETHASH_TAG")
rm -rf "$here/ethash"
mkdir -p "$here/ethash/include/ethash" "$here/ethash/lib/ethash" \
         "$here/ethash/lib/keccak" "$here/ethash/lib/support"
cp "$work/ethash/include/ethash"/*.h "$work/ethash/include/ethash"/*.hpp \
   "$here/ethash/include/ethash/"
# managed.cpp is left behind: it is a process-global epoch-context cache behind
# a mutex, and this miner owns that lifetime itself -- one DAG per device, built
# when the epoch changes. Everything else in lib/ethash is needed.
for f in bit_manipulation.h builtins.h endianness.hpp ethash-internal.hpp \
         ethash.cpp kiss99.hpp primes.c primes.h progpow.cpp; do
    cp "$work/ethash/lib/ethash/$f" "$here/ethash/lib/ethash/"
done
cp "$work/ethash/lib/keccak"/*.c        "$here/ethash/lib/keccak/"
cp "$work/ethash/lib/support/attributes.h" "$here/ethash/lib/support/"
cp "$work/ethash/LICENSE"               "$here/ethash/"

# The one patch, and it is upstream's bug: progpow.cpp includes a header from
# the unit tests, for the sake of a to_hex() call that is commented out. Copying
# a test header into a library to satisfy an include nothing uses is worse than
# deleting the line, and a build that dropped test/ would fail without this.
sed -i '\|#include "../../test/unittests/helpers.hpp"|d' \
    "$here/ethash/lib/ethash/progpow.cpp"
if grep -q 'unittests/helpers.hpp' "$here/ethash/lib/ethash/progpow.cpp"; then
    echo "the helpers.hpp patch no longer applies" >&2
    exit 1
fi

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

cpp-kawpow
  $ETHASH_URL
  tag     $ETHASH_TAG
  commit  $ethash_sha
  license Apache-2.0 (ethash/LICENSE)
  note    the KawPoW fork of chfast/ethash, whose version string it keeps
          (0.5.1-alpha.1). lib/ethash/managed.cpp and the upstream build
          files are not vendored; progpow.cpp loses one include, see above
EOF

echo "done:"
sed 's/^/  /' "$here/VERSIONS"
