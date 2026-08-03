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

# -------------------------------------------------------------- third party
add_subdirectory(third_party)

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
add_executable(vkminer src/main.cpp)

target_include_directories(vkminer PRIVATE src)
target_link_libraries(vkminer PRIVATE volk vkminer_warnings Threads::Threads)
target_compile_definitions(vkminer PRIVATE
    VKMINER_VERSION="${PROJECT_VERSION}-dev")

install(TARGETS vkminer RUNTIME DESTINATION bin)

message(STATUS "")
message(STATUS "vkminer ${PROJECT_VERSION}")
message(STATUS "  target     ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "  compiler   ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  build type ${CMAKE_BUILD_TYPE}")
message(STATUS "  shaders    ${VKMINER_SHADER_COMPILER}")
message(STATUS "")
