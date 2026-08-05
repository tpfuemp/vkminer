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
endif()
