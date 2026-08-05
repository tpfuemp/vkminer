#!/usr/bin/env bash
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Cross-compile a Windows binary with mingw-w64, from Linux.
#
#     ./build-win.sh                build, configuring first if needed
#     ./build-win.sh -c             from scratch
#     ./build-win.sh -- -DX=y       anything after -- is passed to cmake
#
# The tests are built too, but not run: they are Windows binaries. Where a
# Windows binary can be launched from this shell -- WSL does this -- run
# build-win/tests/diff_test.exe by hand.

set -euo pipefail

cd "$(dirname "$0")"

BUILD_DIR="${VKMINER_WIN_BUILD_DIR:-build-win}"
TOOLCHAIN=cmake/mingw-w64-x86_64.cmake

BUILD_TYPE=Release
CLEAN=0
JOBS=""

usage() {
    cat <<'EOF'
usage: ./build-win.sh [-c] [-d] [-j N] [-B dir] [-- cmake args...]

  -c        delete the build directory first
  -d        Debug build (default is Release)
  -j N      parallel jobs (default: let the generator decide)
  -B dir    build directory (default: build-win, or $VKMINER_WIN_BUILD_DIR)
  -h        this message

libcurl for the target is not packaged by Debian or Ubuntu and has to be built
by hand; point the build at it with

    ./build-win.sh -- -DVKMINER_CROSS_PREFIX=/path/to/prefix
EOF
}

while getopts ':cdj:B:h' opt; do
    case "$opt" in
        c) CLEAN=1 ;;
        d) BUILD_TYPE=Debug ;;
        j) JOBS="$OPTARG" ;;
        B) BUILD_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) echo "-$OPTARG needs an argument" >&2; exit 2 ;;
        \?) echo "unknown option -$OPTARG" >&2; usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

# Everything Windows needs at runtime is linked in, so the .exe can be copied
# to a machine that has none of this installed. That is only true as long as
# nothing new arrives as an import, which is what this checks: an -l flag from
# a dependency's pkg-config file is resolved before the linker sees it, and can
# quietly bring in an import library that -static has no say over. The symptom
# is a binary that starts here and not on any other machine.
system_dll() {
    case "$1" in
    api-ms-win-*|ext-ms-win-*) return 0 ;;
    advapi32.dll|bcrypt.dll|comctl32.dll|comdlg32.dll|crypt32.dll|dbghelp.dll) return 0 ;;
    gdi32.dll|iphlpapi.dll|kernel32.dll|msvcrt.dll|ncrypt.dll|ntdll.dll) return 0 ;;
    ole32.dll|oleaut32.dll|psapi.dll|rpcrt4.dll|secur32.dll|setupapi.dll) return 0 ;;
    shell32.dll|shlwapi.dll|ucrtbase.dll|user32.dll|userenv.dll|uuid.dll) return 0 ;;
    version.dll|winmm.dll|winspool.drv|wintrust.dll|ws2_32.dll) return 0 ;;
    esac
    return 1
}

check_imports() {
    local exe=$1 objdump dll
    objdump=$(command -v x86_64-w64-mingw32-objdump || true)
    if [ -z "$objdump" ]; then
        echo "note: no mingw objdump, not checking the imports of $exe"
        return 0
    fi

    local strays=()
    while read -r dll; do
        [ -z "$dll" ] && continue
        system_dll "$dll" || strays+=("$dll")
    done < <("$objdump" -p "$exe" | awk '/DLL Name:/ { print tolower($3) }' | sort -u)

    if [ "${#strays[@]}" -gt 0 ]; then
        echo >&2
        echo "$exe imports DLLs that Windows does not ship:" >&2
        printf '    %s\n' "${strays[@]}" >&2
        echo >&2
        echo "It will fail to start on a machine without them. Either ship them" >&2
        echo "alongside it, or link that dependency statically." >&2
        return 1
    fi
    echo "imports: system DLLs only, nothing to ship alongside it"
}

if [ "$CLEAN" -eq 1 ]; then
    rm -rf "$BUILD_DIR"
fi

cmake -B "$BUILD_DIR" -G Ninja \
      -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
      -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" "$@"

if [ -n "$JOBS" ]; then
    cmake --build "$BUILD_DIR" --parallel "$JOBS"
else
    cmake --build "$BUILD_DIR"
fi

echo
check_imports "$BUILD_DIR/vkminer.exe"
echo "built: $BUILD_DIR/vkminer.exe"
