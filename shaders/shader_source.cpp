// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shaders/shader_source.h"

#include "shaders/embedded.h"

extern "C" {
#include "core/miner.h"
}

#include <jansson.h>

#include <cstdio>

namespace vkminer {
namespace {

// SPIR-V's first word. Checked on everything loaded from a file: the common
// way to arrive here is with a .comp, a text file or a truncated download
// where a module was meant to be, and the driver's answer to that is a crash
// somewhere else.
constexpr uint32_t kSpirvMagic = 0x07230203u;

std::string join_path(const char *dir, const std::string &leaf)
{
    std::string path = dir;
    if (!path.empty() && path.back() != '/' && path.back() != '\\')
        path += '/';
    return path + leaf;
}

// Bytes to words, little endian, rather than reading straight into the vector.
// A .spv file is little endian wherever it was built, and this way so is the
// result wherever it is read.
bool read_spirv(const std::string &path, std::vector<uint32_t> *out)
{
    FILE *f = fopen(path.c_str(), "rb");
    if (!f)
        return false;  // absence is the caller's to report, and is not an error

    std::vector<unsigned char> bytes;
    unsigned char buf[4096];
    size_t got;
    while ((got = fread(buf, 1, sizeof buf, f)) > 0)
        bytes.insert(bytes.end(), buf, buf + got);
    const bool io_error = ferror(f) != 0;
    fclose(f);

    if (io_error) {
        applog(LOG_ERR, "--algo-dir: could not read %s", path.c_str());
        return false;
    }
    if (bytes.empty() || bytes.size() % 4 != 0) {
        applog(LOG_ERR, "--algo-dir: %s is %zu bytes, which is not a whole "
                        "number of SPIR-V words", path.c_str(), bytes.size());
        return false;
    }

    out->clear();
    out->reserve(bytes.size() / 4);
    for (size_t i = 0; i < bytes.size(); i += 4)
        out->push_back(static_cast<uint32_t>(bytes[i])
                       | (static_cast<uint32_t>(bytes[i + 1]) << 8)
                       | (static_cast<uint32_t>(bytes[i + 2]) << 16)
                       | (static_cast<uint32_t>(bytes[i + 3]) << 24));

    if ((*out)[0] != kSpirvMagic) {
        applog(LOG_ERR, "--algo-dir: %s is not SPIR-V (first word is %08x, "
                        "not %08x)", path.c_str(), (*out)[0], kSpirvMagic);
        out->clear();
        return false;
    }
    return true;
}

uint32_t json_u32(json_t *obj, const char *key)
{
    json_t *value = json_object_get(obj, key);
    if (!json_is_integer(value))
        return 0;
    const json_int_t n = json_integer_value(value);
    return n > 0 ? static_cast<uint32_t>(n) : 0;
}

// The manifest is optional: a directory holding <name>.spv and nothing else
// works, and is what an edit-compile-run loop actually produces. It exists for
// the case where the replacement shader's resource layout differs from the one
// the algorithm declares, which the algorithm cannot know about.
//
//   { "shaders": { "sha256d": { "file": "sha256d.spv",
//                               "storage_buffers": 2,
//                               "push_constant_bytes": 16,
//                               "local_size_x": 256 } } }
bool read_manifest(const char *dir, const char *name, std::string *file,
                   ShaderModule *out)
{
    const std::string path = join_path(dir, "manifest.json");

    json_error_t err;
    json_t *root = json_load_file(path.c_str(), 0, &err);
    if (!root)
        return false;  // no manifest is the ordinary case, not a failure

    bool found = false;
    json_t *shaders = json_object_get(root, "shaders");
    json_t *entry = json_is_object(shaders)
                  ? json_object_get(shaders, name) : nullptr;
    if (json_is_object(entry)) {
        json_t *file_value = json_object_get(entry, "file");
        if (json_is_string(file_value))
            *file = json_string_value(file_value);

        out->storage_buffers     = json_u32(entry, "storage_buffers");
        out->push_constant_bytes = json_u32(entry, "push_constant_bytes");
        out->local_size_x        = json_u32(entry, "local_size_x");
        found = true;
    }

    json_decref(root);
    return found;
}

}  // namespace

bool load_shader(const char *name, ShaderModule *out)
{
    if (!name || !*name || !out)
        return false;

    *out = ShaderModule();

    if (opt_algo_dir && *opt_algo_dir) {
        std::string file = std::string(name) + ".spv";
        const bool from_manifest = read_manifest(opt_algo_dir, name, &file, out);
        const std::string path = join_path(opt_algo_dir, file);

        if (read_spirv(path, &out->words)) {
            out->origin = path;
            // Loud, every time, and not only under --debug. A share found by
            // a kernel nobody can reproduce is worth nothing, and this is the
            // one line that says which kernel was running.
            applog(LOG_WARNING, "Using %s from %s%s", name, path.c_str(),
                   from_manifest ? " (manifest.json)" : "");
            return true;
        }

        // Falling back rather than failing, because --algo-dir is normally set
        // to override one shader out of several. Saying so matters: the run is
        // not testing what the user thinks it is testing.
        applog(LOG_WARNING, "--algo-dir: %s has no usable %s; "
                            "using the built-in one", opt_algo_dir, name);
        *out = ShaderModule();
    }

    const SpirvBlob *blob = find_embedded_spirv(name);
    if (!blob) {
        applog(LOG_ERR, "No shader called '%s' in this build", name);
        return false;
    }

    out->words.assign(blob->words, blob->words + blob->word_count);
    out->origin = std::string("built in (") + embedded_spirv_compiler() + ")";
    return true;
}

}  // namespace vkminer
