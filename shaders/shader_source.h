// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Where a kernel's SPIR-V comes from. Normally the binary's own copy; with
// --algo-dir, loose .spv files in a directory, so that a shader can be edited,
// recompiled and tried without rebuilding the miner.
//
// The override is a development tool and says so in the log every time it is
// used. A miner silently running a kernel from a file beside the executable is
// a miner whose results mean nothing.

#ifndef VKMINER_SHADERS_SHADER_SOURCE_H__
#define VKMINER_SHADERS_SHADER_SOURCE_H__

#include <cstdint>
#include <string>
#include <vector>

namespace vkminer {

struct ShaderModule {
    std::vector<uint32_t> words;

    // Zero means "as the algorithm declared it". A manifest only has to say
    // anything here when a replacement shader has a different layout from the
    // one that shipped, which is exactly when the algorithm's own numbers
    // would be wrong.
    uint32_t storage_buffers     = 0;
    uint32_t push_constant_bytes = 0;
    uint32_t local_size_x        = 0;

    // Where it came from, for the log line. Never empty on success.
    std::string origin;
};

// Load the module named `name` -- a shader source file's stem, not an
// algorithm name, though for most algorithms they are the same string.
// Returns false, having logged why, if nothing has it.
bool load_shader(const char *name, ShaderModule *out);

}  // namespace vkminer

#endif  // VKMINER_SHADERS_SHADER_SOURCE_H__
