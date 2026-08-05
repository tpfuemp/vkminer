#!/usr/bin/env bash
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Configure and build for this machine.
#
#     ./build-linux.sh              build, configuring first if needed
#     ./build-linux.sh -t           and then run the tests
#     ./build-linux.sh -c -d        from scratch, with debug info
#     ./build-linux.sh -- -DX=y     anything after -- is passed to cmake
#
# The build directory is remembered by cmake, so a plain run after the first
# one is just the build step. Nothing here is required: it is the same two
# cmake commands the README gives, with the flags that are easy to forget.

set -euo pipefail

cd "$(dirname "$0")"

# Override to build somewhere other than the source tree. Worth doing when the
# sources sit on a filesystem shared with another OS: those are reached over a
# network protocol even when the disk is local, and a build on one takes
# roughly an order of magnitude longer than the same build on a native one.
BUILD_DIR="${VKMINER_BUILD_DIR:-build}"

BUILD_TYPE=Release
CLEAN=0
RUN_TESTS=0
JOBS=""

usage() {
    cat <<'EOF'
usage: ./build-linux.sh [-c] [-d] [-t] [-j N] [-B dir] [-- cmake args...]

  -c        delete the build directory first
  -d        Debug build (default is Release)
  -t        run ctest when the build succeeds
  -j N      parallel jobs (default: let the generator decide)
  -B dir    build directory (default: build, or $VKMINER_BUILD_DIR)
  -h        this message
EOF
}

while getopts ':cdtj:B:h' opt; do
    case "$opt" in
        c) CLEAN=1 ;;
        d) BUILD_TYPE=Debug ;;
        t) RUN_TESTS=1 ;;
        j) JOBS="$OPTARG" ;;
        B) BUILD_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) echo "-$OPTARG needs an argument" >&2; exit 2 ;;
        \?) echo "unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# Ninja is what the project is developed against, but a machine without it
# should still build rather than stop at a missing generator.
if command -v ninja > /dev/null 2>&1; then
    GENERATOR=Ninja
else
    GENERATOR="Unix Makefiles"
    echo "note: ninja not found, using make"
fi

if [ "$CLEAN" -eq 1 ]; then
    rm -rf "$BUILD_DIR"
fi

cmake -B "$BUILD_DIR" -G "$GENERATOR" \
      -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$@"

if [ -n "$JOBS" ]; then
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
else
    cmake --build "$BUILD_DIR"
fi

if [ "$RUN_TESTS" -eq 1 ]; then
    # The differential test needs a Vulkan device and skips itself when there
    # is none, so this is worth running on a machine with no GPU as well.
    ctest --test-dir "$BUILD_DIR" --output-on-failure
fi

echo
echo "built: $BUILD_DIR/vkminer"
