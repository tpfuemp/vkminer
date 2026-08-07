# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later

# First-party, so the project's warning flags apply here too.
add_executable(sha256_kat sha256_kat.c)
target_link_libraries(sha256_kat PRIVATE vkminer_sha256 vkminer_warnings)
add_test(NAME sha256_kat COMMAND sha256_kat)

# The same question one level up: not whether SHA-256 is right, but whether the
# algorithm object turns struct work's words into the header that gets hashed.
add_executable(sha256d_kat sha256d_kat.cpp)
target_link_libraries(sha256d_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME sha256d_kat COMMAND sha256d_kat)

# One level up again: not whether a header hashes correctly, but whether a
# mining.notify turns into the right header in the first place.
add_executable(stratum_header_kat stratum_header_kat.cpp)
target_link_libraries(stratum_header_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME stratum_header_kat COMMAND stratum_header_kat)

# The tuning file: whether an entry comes back only for the device, driver,
# algorithm and shader it was measured on. Needs no GPU, because what is being
# checked is the bookkeeping around a measurement rather than the measurement.
add_executable(tune_cache_test tune_cache_test.cpp)
target_link_libraries(tune_cache_test PRIVATE
    vkminer_tune_cache vkminer_warnings Threads::Threads)
add_test(NAME tune_cache COMMAND tune_cache_test)

# The first test of the assembled binary rather than of something linked out of
# it. It exists because --time-limit shipped parsed-but-never-read: accepted,
# documented in --help, and doing nothing. It asserts only that the miner stops
# by itself and stops with 0 -- CTest's TIMEOUT catches the regression, because
# the bug guarded against looks exactly like a miner that runs forever.
#
# The null backend keeps it honest on a machine with no GPU: no device, no
# shaders, no skip, so this runs everywhere the project builds.
add_test(NAME time_limit
    COMMAND vkminer --backend null -a sha256d --benchmark --time-limit 3)
set_tests_properties(time_limit PROPERTIES TIMEOUT 20)

# Reconnect, against a Stratum server written to misbehave. The three ways a
# pool connection ends -- the socket breaking, the pool going quiet, and the
# pool sending client.reconnect -- each reach the recovery path by a different
# route, and none of them can be provoked on cue from a real pool.
#
# On the null backend, so it needs no GPU -- which leaves shares uncovered;
# point it at --backend vulkan by hand for those. Three of its four assertions
# are about something not happening for a while, which makes it much the
# slowest test here, so it is labelled for ctest -LE slow.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME reconnect COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/reconnect_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null)
    set_tests_properties(reconnect
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300 LABELS slow)
endif()

# Only exists where shaders were compiled, because there is nothing to embed
# otherwise. No device needed: this is about which bytes get loaded, not about
# running them.
if(TARGET vkminer_shaders)
    add_executable(shader_source_test shader_source_test.cpp)
    target_link_libraries(shader_source_test PRIVATE
        vkminer_shaders vkminer_warnings Threads::Threads)
    add_test(NAME shader_source COMMAND shader_source_test)
    set_tests_properties(shader_source PROPERTIES SKIP_RETURN_CODE 77)
endif()

# Needs a device, so it is not built where there are no shaders to run on one.
# It reports SKIP rather than failing when the machine has no Vulkan: a build
# machine without a GPU is a normal thing, a wrong result is not.
if(VKMINER_VK_SMOKE_SPV)
    add_executable(vk_smoke vk_smoke.cpp)
    target_link_libraries(vk_smoke PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    target_compile_definitions(vk_smoke PRIVATE
        VK_SMOKE_SPV="${VKMINER_VK_SMOKE_SPV}")
    add_dependencies(vk_smoke vkminer_shader_vk_smoke)

    # Beside the binary, so that the test can be copied to the machine with the
    # GPU -- which for the cross builds is never the machine that compiled it.
    add_custom_command(TARGET vk_smoke POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VKMINER_VK_SMOKE_SPV}" "$<TARGET_FILE_DIR:vk_smoke>")

    add_test(NAME vk_smoke COMMAND vk_smoke)
    set_tests_properties(vk_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()

# The shader against the scalar reference, over a nonce range. Needs the
# embedded SPIR-V, so it exists only where the shaders were compiled; it finds
# its own device and SKIPs when there is none. The generous timeout is for the
# software rasterizer, which is the only device some build machines have.
if(TARGET vkminer_shaders)
    add_executable(diff_test diff_test.cpp)
    target_link_libraries(diff_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME diff_test COMMAND diff_test sha256d 100000)
    set_tests_properties(diff_test PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # The same range with the queue held to one dispatch -- the path
    # --queue-depth 1 selects, and the baseline the pipelining is measured
    # against. It catches a kernel that only works with something queued behind
    # it, and costs one more run of a shader and reference it already has.
    add_test(NAME diff_test_depth1 COMMAND diff_test sha256d 100000 1)
    set_tests_properties(diff_test_depth1
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)
endif()
