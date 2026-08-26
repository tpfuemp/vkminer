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

# On mingw, find a library's static archive before its import library.
#
# The cross toolchain file links -static so that the .exe can be copied to a
# Windows machine on its own. That covers what the compiler driver adds, and
# nothing else: CMake's mingw platform searches .dll.a first, and a -l flag
# coming from a dependency's .pc file is resolved by find_library before it
# reaches the link line. So libcurl's -lz became an absolute path to
# libz.dll.a, the link stayed dynamic in that one spot, and the binary failed
# to start with "zlib1.dll is missing" on every machine that did not happen to
# have one. This has to be set here and not in the toolchain file, which is
# read before Platform/Windows-GNU.cmake assigns the same variable.
if(MINGW)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".dll.a" ".lib")
endif()

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

# ------------------------------------------------------------------- paths
#
# Where this program may leave files. Its own library because both the backend
# -- for the pipeline cache -- and the tuner need it, and neither is below the
# other.
add_library(vkminer_paths STATIC src/core/paths.cpp)
target_include_directories(vkminer_paths PUBLIC src)
target_link_libraries(vkminer_paths PRIVATE vkminer_warnings)

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

# --------------------------------------------------------------- algorithms
#
# The other axis. Nothing in here knows what a Vulkan device is; it holds each
# algorithm's scalar reference, the shader it wants, and the table that turns
# an --algo name into one of them.
add_library(vkminer_algorithms STATIC
    algorithms/algorithm.cpp
    algorithms/registry.cpp
    algorithms/sha256d/sha256d.cpp
    algorithms/blake2s/blake2s.cpp
    algorithms/scrypt/scrypt.cpp
    algorithms/sha3t/sha3t.cpp
    algorithms/kawpow/kawpow.cpp
    algorithms/kawpow/kawpow_dag.cpp
    algorithms/kawpow/kawpow_hash.cpp
    algorithms/kawpow/kawpow_params.cpp
    algorithms/kawpow/kawpow_program.cpp)

target_include_directories(vkminer_algorithms PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer_algorithms PUBLIC vkminer_inherited)
# ethash for the KawPoW DAG, and privately: what it computes is the reference a
# kernel is judged against, and nothing outside algorithms/kawpow/ has any
# business including it.
target_link_libraries(vkminer_algorithms PRIVATE
    vkminer_sha256 vkminer_warnings ethash)

# ------------------------------------------------------------------ shaders
if(VKMINER_BUILD_SHADERS)
    include(CompileShaders)
    # Every module the binary carries. toolchain-check.comp is not one of the
    # miner's kernels: it exists so that a broken or missing GLSL toolchain is
    # a build failure here rather than a surprise later, and it is what the
    # embedding machinery is checked on independently of any algorithm.
    #
    # The include path is the root of the tree, so that a kernel names what it
    # includes the same way a .cpp does.
    add_spirv_shaders(vkminer_shader_kernels
                      SOURCES shaders/toolchain-check.comp
                              algorithms/sha256d/sha256d.comp
                              algorithms/blake2s/blake2s.comp
                              algorithms/scrypt/scrypt.comp
                              algorithms/sha3t/sha3t.comp
                              algorithms/sha3t/sha3t32.comp
                              algorithms/kawpow/kawpow.comp
                              algorithms/kawpow/kawpow_spec.comp
                              algorithms/kawpow/kawpow_spec_sub.comp
                              algorithms/kawpow/dag.comp
                      INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
                      EMBED "${CMAKE_CURRENT_BINARY_DIR}/generated/embedded_spirv.cpp")

    # The kernels the binary carries, and the --algo-dir override that replaces
    # one of them at run time.
    add_library(vkminer_shaders STATIC
        shaders/shader_source.cpp
        "${vkminer_shader_kernels_EMBED_SOURCE}")
    add_dependencies(vkminer_shaders vkminer_shader_kernels)
    target_include_directories(vkminer_shaders PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(vkminer_shaders PUBLIC vkminer_inherited)
    target_link_libraries(vkminer_shaders PRIVATE vkminer_warnings)

    # Declared above this block, so it is linked here rather than there: an
    # algorithm is what asks for its own SPIR-V.
    target_link_libraries(vkminer_algorithms PUBLIC vkminer_shaders)
    target_compile_definitions(vkminer_algorithms PRIVATE VKMINER_HAVE_SHADERS=1)

    if(VKMINER_BUILD_TESTS)
        add_spirv_shaders(vkminer_shader_vk_smoke
                          SOURCES shaders/vk-smoke.comp)
        set(VKMINER_VK_SMOKE_SPV "${CMAKE_CURRENT_BINARY_DIR}/spv/vk-smoke.spv")

        # The include dir is the candidate buffer's: this one goes through the
        # backend's own kernel path, so it reports what it read the way every
        # real kernel does.
        add_spirv_shaders(vkminer_shader_shared_state
                          SOURCES shaders/shared-state.comp
                          INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")
        set(VKMINER_SHARED_STATE_SPV
            "${CMAKE_CURRENT_BINARY_DIR}/spv/shared-state.spv")

        # The DAG generation kernel is embedded with the rest, the KawPoW
        # algorithm having become the thing that dispatches it. It is still
        # written out as a loose .spv, which is what dag_test reads: that test
        # drives the setup pass through an algorithm of its own and never loads
        # the miner's shader table.
        set(VKMINER_DAG_SPV "${CMAKE_CURRENT_BINARY_DIR}/spv/dag.spv")
    endif()
endif()

# ---------------------------------------------------------------------- vma
#
# VulkanMemoryAllocator's implementation, in a library of its own so that it is
# compiled once and so that upstream's warnings are upstream's business. The
# header it includes decides how the allocator is configured; see vma.h.
add_library(vkminer_vma STATIC backends/vulkan/vma_impl.cpp)
target_include_directories(vkminer_vma PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer_vma PUBLIC vma volk)

# ----------------------------------------------------------------- backends
#
# A library rather than sources of the executable, so that a test can drive a
# real device without linking the miner's main().
add_library(vkminer_backends STATIC
    backends/backend.cpp
    backends/cpu/cpu_backend.cpp
    backends/null/null_backend.cpp
    backends/vulkan/command_ring.cpp
    backends/vulkan/pipeline_cache.cpp
    backends/vulkan/shared_state.cpp
    backends/vulkan/vulkan_backend.cpp
    backends/vulkan/vulkan_common.cpp
    backends/vulkan/vulkan_device.cpp
    backends/vulkan/vulkan_kernel.cpp
    backends/vulkan/vulkan_pipeline.cpp)

target_include_directories(vkminer_backends PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer_backends PUBLIC
    volk vkminer_vma vkminer_inherited vkminer_algorithms)
target_link_libraries(vkminer_backends PRIVATE vkminer_warnings vkminer_paths)

# -------------------------------------------------------------- tune cache
#
# The file a sweep's answer is kept in, separated from the sweep itself so that
# the format and its keying can be tested on a machine with no GPU -- which is
# every machine the CI runs on.
add_library(vkminer_tune_cache STATIC src/tune_cache.cpp)
target_include_directories(vkminer_tune_cache PUBLIC
    src "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer_tune_cache PUBLIC vkminer_jansson)
target_link_libraries(vkminer_tune_cache PRIVATE
    vkminer_sha256 vkminer_paths vkminer_warnings)

# ------------------------------------------------------------------- binary
add_executable(vkminer
    src/main.cpp
    src/replay.cpp
    src/self_test.cpp
    src/tune.cpp
    src/scheduler/candidate_log.cpp
    src/scheduler/worker.cpp)

target_include_directories(vkminer PRIVATE src "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(vkminer PRIVATE
    vkminer_backends vkminer_tune_cache vkminer_warnings vkminer_inherited
    vkminer_paths Threads::Threads)
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
