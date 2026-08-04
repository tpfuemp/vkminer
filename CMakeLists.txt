# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)

project(vkminer
        VERSION     0.1.0
        DESCRIPTION "Vulkan compute cryptocurrency miner"
        LANGUAGES   C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not supported. Use a build directory:\n"
        "    cmake -B build -G Ninja")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# C++17 for new code. Inherited C from cpuminer-opt stays C.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(VKMINER_BUILD_SHADERS "Compile the GLSL shaders to SPIR-V" ON)
option(VKMINER_BUILD_TESTS "Build the correctness tests" ON)

# ------------------------------------------------------------------ threads
#
# Checked at configure time rather than discovered at link time, because the
# usual way to fail this is subtle: mingw-w64 built for the win32 threading
# model ships a libstdc++ without <thread>, and Debian and Ubuntu make that
# the default compiler. The error it produces is "'thread' is not a member of
# 'std'" in whichever file happens to include <thread> first, which does not
# point at the toolchain at all.
find_package(Threads REQUIRED)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <thread>
    #include <mutex>
    #include <condition_variable>
    int main() { std::thread t([]{}); t.join(); return 0; }
" VKMINER_HAVE_STD_THREAD)

if(NOT VKMINER_HAVE_STD_THREAD)
    message(FATAL_ERROR
        "This C++ toolchain has no std::thread.\n"
        "If you are cross-compiling with mingw-w64, the compiler is using "
        "the win32 threading model. Use the POSIX variant:\n"
        "    -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake\n"
        "which selects x86_64-w64-mingw32-g++-posix explicitly.")
endif()

# ------------------------------------------------------------------ warnings
#
# An INTERFACE target rather than global flags, because it must apply to
# first-party code only. The Stratum client and option parsing inherited from
# cpuminer-opt arrive with their own warning history, and -Werror on that
# would mean rewriting working protocol code as the price of importing it.
add_library(vkminer_warnings INTERFACE)
if(MSVC)
    target_compile_options(vkminer_warnings INTERFACE /W4 /WX /permissive-)
else()
    target_compile_options(vkminer_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Werror
        -Wshadow -Wcast-qual -Wpointer-arith -Wformat=2)
endif()

# ------------------------------------------------------------------ config.h
#
# Replaces cpuminer-opt's autotools-generated cpuminer-config.h. Only the two
# probes the ported code actually tests survive.
include(CheckIncludeFile)
include(CheckSymbolExists)

check_include_file(syslog.h HAVE_SYSLOG_H)
check_symbol_exists(getopt_long "getopt.h" HAVE_GETOPT_LONG)

set(VKMINER_VERSION "${PROJECT_VERSION}-dev")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/generated/core/config.h"
               @ONLY)

# -------------------------------------------------------------- third party
add_subdirectory(third_party)

# ---------------------------------------------------------------- libcurl
#
# The Windows build wants the schannel backend, which is a property of how
# libcurl was built, not of how it is used -- see the toolchain file for where
# a hand-built cross libcurl is looked for.
#
# pkg-config is asked first, because a static libcurl needs more than its own
# archive: CURL_STATICLIB while compiling, or the headers declare every entry
# point dllimport and the link fails looking for __imp_curl_easy_init, plus the
# system libraries curl itself was linked against. Its .pc file names both.
# CMake's FindCURL looks for the library file and names neither.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CURL_PC QUIET IMPORTED_TARGET libcurl)
endif()

add_library(vkminer_curl INTERFACE)
if(TARGET PkgConfig::CURL_PC)
    target_link_libraries(vkminer_curl INTERFACE PkgConfig::CURL_PC)
    set(VKMINER_CURL "${CURL_PC_VERSION} (pkg-config)")
else()
    find_package(CURL REQUIRED)
    target_link_libraries(vkminer_curl INTERFACE CURL::libcurl)
    set(VKMINER_CURL "${CURL_VERSION_STRING}")
endif()

# ---------------------------------------------------------------- jansson
#
# Preferred from the system, because a distribution jansson gets security
# updates and this one does not: the bundled copy is 2.6, released in 2013,
# inherited from cpuminer-opt unmodified. It exists for the mingw cross build,
# where Debian and Ubuntu ship no jansson for the target and building one by
# hand for a JSON parser is not a reasonable thing to ask of a contributor.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(JANSSON QUIET IMPORTED_TARGET jansson>=2.6)
endif()

if(TARGET PkgConfig::JANSSON)
    add_library(vkminer_jansson INTERFACE)
    target_link_libraries(vkminer_jansson INTERFACE PkgConfig::JANSSON)
    set(VKMINER_JANSSON "system ${JANSSON_VERSION}")
else()
    file(GLOB VKMINER_JANSSON_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/compat/jansson/*.c")
    add_library(vkminer_jansson STATIC ${VKMINER_JANSSON_SOURCES})
    # SYSTEM so that this directory's own config.h -- which defines PACKAGE_NAME
    # to "jansson" -- cannot be picked up by anything but jansson itself, and so
    # that 2013's warnings are not this project's problem.
    target_include_directories(vkminer_jansson SYSTEM PUBLIC
                               "${CMAKE_CURRENT_SOURCE_DIR}/compat/jansson")
    target_compile_definitions(vkminer_jansson PRIVATE HAVE_CONFIG_H)
    set(VKMINER_JANSSON "bundled 2.6")
endif()

# ------------------------------------------------------------------- sha256
#
# First-party, so it is held to the project's warning flags. Separate from the
# inherited library below only because that one is not.
add_library(vkminer_sha256 STATIC src/core/sha256.c)
target_include_directories(vkminer_sha256 PUBLIC src)
target_link_libraries(vkminer_sha256 PRIVATE vkminer_warnings)

# ----------------------------------------------------- inherited C sources
#
# Deliberately not linked against vkminer_warnings. This is cpuminer-opt's
# network and protocol code, ported rather than rewritten; its value is that
# it is debugged, and it is left alone.
set(VKMINER_INHERITED_SOURCES
    src/core/options.c
    src/core/util.c
    src/core/work.c
    src/net/json_rpc.c
    src/stratum/stratum.c
    src/stratum/stratum_thread.c)

if(WIN32)
    list(APPEND VKMINER_INHERITED_SOURCES compat/winansi.c)
endif()
if(NOT HAVE_GETOPT_LONG)
    list(APPEND VKMINER_INHERITED_SOURCES compat/getopt/getopt_long.c)
endif()

add_library(vkminer_inherited STATIC ${VKMINER_INHERITED_SOURCES})
target_include_directories(vkminer_inherited PUBLIC
    src
    compat
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
if(NOT HAVE_GETOPT_LONG)
    target_include_directories(vkminer_inherited PUBLIC compat/getopt)
endif()
target_link_libraries(vkminer_inherited PUBLIC
    vkminer_jansson vkminer_curl Threads::Threads)
target_link_libraries(vkminer_inherited PRIVATE vkminer_sha256)
if(WIN32)
    target_link_libraries(vkminer_inherited PUBLIC ws2_32)
endif()

# ------------------------------------------------------------------ shaders
if(VKMINER_BUILD_SHADERS)
    include(CompileShaders)
    # A single trivial shader, built for every configuration. It is not used
    # by the miner; it exists so that a broken or missing GLSL toolchain is a
    # build failure here rather than a surprise when the first real kernel is
    # written.
    add_spirv_shaders(vkminer_shader_toolchain_check
                      SOURCES shaders/toolchain-check.comp)
endif()

# ------------------------------------------------------------------- binary
add_executable(vkminer
    src/main.cpp
    src/scheduler/worker.cpp
    backends/null/null_backend.cpp)

target_include_directories(vkminer PRIVATE src "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer PRIVATE
    volk vkminer_warnings vkminer_inherited Threads::Threads)
target_compile_definitions(vkminer PRIVATE
    VKMINER_VERSION="${PROJECT_VERSION}-dev")

install(TARGETS vkminer RUNTIME DESTINATION bin)

# -------------------------------------------------------------------- tests
if(VKMINER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

message(STATUS "")
message(STATUS "vkminer ${PROJECT_VERSION}")
message(STATUS "  target     ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  compiler   ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  build type ${CMAKE_BUILD_TYPE}")
message(STATUS "  shaders    ${VKMINER_SHADER_COMPILER}")
message(STATUS "  libcurl    ${VKMINER_CURL}")
message(STATUS "  jansson    ${VKMINER_JANSSON}")
message(STATUS "")
