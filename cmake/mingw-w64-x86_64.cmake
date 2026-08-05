# Cross-compile a 64-bit Windows binary with mingw-w64.
# SPDX-License-Identifier: GPL-3.0-or-later
#
#     cmake -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release \
#           -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake
#
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# Prefer the POSIX-threads compilers where the distribution ships both.
#
# This is not a preference, it is a requirement: with the win32 threading
# model mingw's libstdc++ is built without <thread>, <mutex> and
# <condition_variable>, so std::thread does not exist and the miner -- which
# is threads all the way down -- will not compile. Debian and Ubuntu default
# the unsuffixed compiler to the win32 model, so selecting it explicitly here
# is more reliable than depending on update-alternatives having been run.
find_program(MINGW_C_COMPILER
    NAMES ${TOOLCHAIN_PREFIX}-gcc-posix ${TOOLCHAIN_PREFIX}-gcc)
find_program(MINGW_CXX_COMPILER
    NAMES ${TOOLCHAIN_PREFIX}-g++-posix ${TOOLCHAIN_PREFIX}-g++)

if(NOT MINGW_C_COMPILER OR NOT MINGW_CXX_COMPILER)
    message(FATAL_ERROR
        "mingw-w64 compilers not found. On Debian/Ubuntu:\n"
        "    sudo apt install mingw-w64 mingw-w64-tools")
endif()

set(CMAKE_C_COMPILER   ${MINGW_C_COMPILER})
set(CMAKE_CXX_COMPILER ${MINGW_CXX_COMPILER})
set(CMAKE_RC_COMPILER  ${TOOLCHAIN_PREFIX}-windres)

# Look for libraries and headers in the cross sysroot, and in any prefixes the
# user points at with -DVKMINER_CROSS_PREFIX. Ubuntu has no mingw libcurl, so
# it has to be cross built by hand and installed somewhere private; each entry
# here is a prefix containing include/ and lib/, not a library directory.
set(VKMINER_CROSS_PREFIX "$ENV{HOME}/usr/lib/curl"
    CACHE STRING "Extra prefixes holding hand-built mingw dependencies")
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX} ${VKMINER_CROSS_PREFIX})

# pkg-config has to answer for the target as well.
#
# CMake's FindCURL consults pkg-config before it reads curlver.h, so with the
# host tool a Windows build is told it has the host's libcurl -- wrong version,
# wrong flags, and no warning that anything is off. The mingw wrapper restricts
# itself to the cross sysroot, and PKG_CONFIG_PATH adds the hand-built prefixes
# on top of that.
find_program(MINGW_PKG_CONFIG NAMES ${TOOLCHAIN_PREFIX}-pkg-config)
if(MINGW_PKG_CONFIG)
    set(PKG_CONFIG_EXECUTABLE ${MINGW_PKG_CONFIG} CACHE FILEPATH
        "pkg-config for the cross target" FORCE)
endif()
foreach(_prefix IN LISTS VKMINER_CROSS_PREFIX)
    set(ENV{PKG_CONFIG_PATH} "${_prefix}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

# Minimum Windows API level: Windows 7.
#
# mingw-w64 still defaults to a much older _WIN32_WINNT, which hides APIs that
# current libraries assume are present -- libcurl 8.x refuses to configure
# without at least Vista. Set it once here so the miner and everything cross
# built for it agree on the same baseline.
add_compile_definitions(_WIN32_WINNT=0x0601 WINVER=0x0601)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Link the runtime statically. The resulting .exe carries no libgcc,
# libstdc++ or libwinpthread DLL alongside it, which matters because this
# binary is normally launched straight from a Linux shell, where a DLL
# sitting next to it in the build tree would not be found.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")

# -static does not make the link static by itself: the library search order has
# to agree with it. That lives in the top-level CMakeLists rather than here,
# because Platform/Windows-GNU.cmake overwrites CMAKE_FIND_LIBRARY_SUFFIXES
# after this file has been read.
