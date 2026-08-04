# Compile GLSL compute shaders to SPIR-V at build time.
# SPDX-License-Identifier: GPL-3.0-or-later
#
#     add_spirv_shaders(<target>
#                       SOURCES     <a.comp> [<b.comp> ...]
#                       [TARGET_ENV <env>]     # default vulkan1.1
#                       [OUTPUT_DIR <dir>]     # default <builddir>/spv
#                       [EMBED      <file.cpp>])
#
# EMBED additionally generates a C++ source file holding the compiled modules
# as arrays, so that the binary carries its own kernels. The variable
# <target>_EMBED_SOURCE is set in the caller's scope to that file.
#
# Shaders are compiled here, never at run time: the miner must not depend on
# a shader compiler being installed on the mining machine.
#
# The Vulkan 1.1 target environment is the default deliberately. Compiling
# against a newer environment would silently permit instructions that mobile
# and older drivers cannot execute, and the failure would show up as a
# device-lost on someone else's hardware rather than as a build error here.

find_program(VKMINER_GLSLC NAMES glslc)
find_program(VKMINER_GLSLANG NAMES glslangValidator)

if(VKMINER_GLSLC)
    set(VKMINER_SHADER_COMPILER "${VKMINER_GLSLC}" CACHE INTERNAL "")
    set(VKMINER_SHADER_COMPILER_KIND glslc CACHE INTERNAL "")
elseif(VKMINER_GLSLANG)
    set(VKMINER_SHADER_COMPILER "${VKMINER_GLSLANG}" CACHE INTERNAL "")
    set(VKMINER_SHADER_COMPILER_KIND glslang CACHE INTERNAL "")
else()
    message(FATAL_ERROR
        "No GLSL compiler found. Install glslc or glslangValidator "
        "(Debian/Ubuntu: glslang-tools, or the LunarG Vulkan SDK).")
endif()

function(add_spirv_shaders target)
    cmake_parse_arguments(ARG "" "TARGET_ENV;OUTPUT_DIR;EMBED" "SOURCES" ${ARGN})

    if(NOT ARG_SOURCES)
        message(FATAL_ERROR "add_spirv_shaders(${target}): no SOURCES given")
    endif()
    if(NOT ARG_TARGET_ENV)
        set(ARG_TARGET_ENV vulkan1.1)
    endif()
    if(NOT ARG_OUTPUT_DIR)
        set(ARG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/spv")
    endif()

    set(outputs "")
    set(names "")
    foreach(src IN LISTS ARG_SOURCES)
        get_filename_component(src_abs "${src}" ABSOLUTE)
        get_filename_component(name "${src}" NAME_WE)
        set(out "${ARG_OUTPUT_DIR}/${name}.spv")

        if(VKMINER_SHADER_COMPILER_KIND STREQUAL glslc)
            set(cmd "${VKMINER_SHADER_COMPILER}"
                    --target-env=${ARG_TARGET_ENV} -O
                    -MD -MF "${out}.d"
                    -o "${out}" "${src_abs}")
            set(depfile DEPFILE "${out}.d")
        else()
            # glslangValidator has no depfile support, so an edit to an
            # included .glsl will not trigger a rebuild of the shaders that
            # include it. Use glslc where include files are involved.
            set(cmd "${VKMINER_SHADER_COMPILER}"
                    -V --target-env ${ARG_TARGET_ENV}
                    -o "${out}" "${src_abs}")
            set(depfile "")
        endif()

        add_custom_command(
            OUTPUT  "${out}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ARG_OUTPUT_DIR}"
            COMMAND ${cmd}
            DEPENDS "${src_abs}"
            ${depfile}
            COMMENT "SPIR-V ${name}.spv (${ARG_TARGET_ENV})"
            VERBATIM)
        list(APPEND outputs "${out}")
        list(APPEND names "${name}")
    endforeach()

    if(ARG_EMBED)
        get_filename_component(embed_dir "${ARG_EMBED}" DIRECTORY)
        add_custom_command(
            OUTPUT  "${ARG_EMBED}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${embed_dir}"
            COMMAND ${CMAKE_COMMAND}
                    "-DOUTPUT=${ARG_EMBED}"
                    "-DNAMES=${names}"
                    "-DFILES=${outputs}"
                    "-DCOMPILER=${VKMINER_SHADER_COMPILER_KIND}"
                    -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/EmbedSpirv.cmake"
            DEPENDS ${outputs}
                    "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/EmbedSpirv.cmake"
            COMMENT "Embedding SPIR-V into ${ARG_EMBED}"
            VERBATIM)
        list(APPEND outputs "${ARG_EMBED}")
        set(${target}_EMBED_SOURCE "${ARG_EMBED}" PARENT_SCOPE)
    endif()

    add_custom_target(${target} ALL DEPENDS ${outputs})
    set_property(TARGET ${target} PROPERTY VKMINER_SPIRV_OUTPUTS "${outputs}")
endfunction()
