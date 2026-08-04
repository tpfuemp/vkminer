// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The SPIR-V compiled into the binary. A mining machine must not need a GLSL
// compiler installed, and a miner that loads its kernels from files beside the
// executable is a miner that runs whatever those files happen to contain, so
// the shipped modules live in the binary itself.
//
// The definitions are generated at build time from the compiled .spv files;
// see EmbedSpirv.cmake.

#ifndef VKMINER_SHADERS_EMBEDDED_H__
#define VKMINER_SHADERS_EMBEDDED_H__

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vkminer {

struct SpirvBlob {
    const char *name;       // the shader's source file, without .comp
    const uint32_t *words;
    size_t word_count;
};

// Null if this build has no module of that name.
const SpirvBlob *find_embedded_spirv(const char *name);

// Which GLSL compiler produced the modules above -- "glslc" or "glslang".
// They do not agree byte for byte, so a shader that has been proven on one is
// not thereby proven on the other, and a bug report needs to say which.
const char *embedded_spirv_compiler();

}  // namespace vkminer

#endif  // VKMINER_SHADERS_EMBEDDED_H__
