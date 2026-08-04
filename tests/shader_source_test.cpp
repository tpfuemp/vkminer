// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Where kernels come from: the copy in the binary, and the --algo-dir override
// that replaces it. Both paths are exercised here because both of them decide
// what code a GPU ends up executing, and the override in particular is the one
// that can quietly leave a run testing a shader nobody meant to test.
//
// No device is involved. What is checked is that the right bytes are found,
// that a file which is not SPIR-V is refused rather than handed to a driver,
// and that a manifest's numbers arrive.

#include "shaders/embedded.h"
#include "shaders/shader_source.h"

extern "C" {
#include "core/miner.h"
}

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

// The inherited C expects the miner to own these; applog reaches for the
// first one on every line the loader logs.
extern "C" {
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
struct thr_info *thr_info = nullptr;
double *thr_hashrates = nullptr;
struct work_restart *work_restart = nullptr;
int work_thr_id = 0;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
}

namespace {

// The one shader every configuration builds. Phase 4's kernels will be listed
// here too; until then this is what proves the mechanism.
const char *kShaderName = "toolchain-check";

int failures = 0;

void fail(const char *what)
{
    std::printf("FAIL: %s\n", what);
    failures++;
}

// The loader builds its paths with '/' whatever the platform, which Windows
// accepts and std::filesystem::path::string() does not produce. Comparing the
// files rather than the spellings is what the test actually means.
bool same_file(const std::string &reported, const std::filesystem::path &expected)
{
    std::error_code ec;
    return std::filesystem::equivalent(std::filesystem::path(reported),
                                       expected, ec);
}

void write_bytes(const std::filesystem::path &path,
                 const std::vector<unsigned char> &bytes)
{
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char *>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

// Words back to the little-endian file they came from, so the test writes a
// module a driver would accept rather than a copy of this host's memory.
std::vector<unsigned char> to_le_bytes(const std::vector<uint32_t> &words)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(words.size() * 4);
    for (uint32_t w : words) {
        bytes.push_back(static_cast<unsigned char>(w & 0xff));
        bytes.push_back(static_cast<unsigned char>((w >> 8) & 0xff));
        bytes.push_back(static_cast<unsigned char>((w >> 16) & 0xff));
        bytes.push_back(static_cast<unsigned char>((w >> 24) & 0xff));
    }
    return bytes;
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);

    // ---------------------------------------------------------- built in
    const vkminer::SpirvBlob *blob = vkminer::find_embedded_spirv(kShaderName);
    if (!blob) {
        std::printf("FAIL: '%s' was not embedded in this build\n", kShaderName);
        return 1;
    }
    if (blob->word_count < 5 || blob->words[0] != 0x07230203u)
        fail("the embedded module does not begin with the SPIR-V magic");
    if (vkminer::find_embedded_spirv("no-such-shader"))
        fail("the embedded table answered to a name it does not have");

    vkminer::ShaderModule mod;
    if (!vkminer::load_shader(kShaderName, &mod)) {
        std::printf("FAIL: load_shader could not find the built-in '%s'\n",
                    kShaderName);
        return 1;
    }
    if (mod.words.size() != blob->word_count
        || std::memcmp(mod.words.data(), blob->words,
                       blob->word_count * sizeof(uint32_t)) != 0)
        fail("load_shader returned something other than the embedded module");
    if (mod.origin.empty())
        fail("load_shader did not say where the module came from");

    // The compiler that built the modules is recorded, because glslc and
    // glslangValidator do not produce the same bytes and a module is only
    // proven on the toolchain that emitted it.
    const char *built_with = vkminer::embedded_spirv_compiler();
    if (!built_with || !*built_with)
        fail("the build did not record which GLSL compiler produced the modules");

    // ---------------------------------------------------------- override
    std::error_code ec;
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path(ec) / "vkminer_algo_dir_test";
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        std::printf("SKIP: no writable temporary directory (%s)\n",
                    ec.message().c_str());
        return failures ? 1 : 77;
    }

    const std::string dir_string = dir.string();
    opt_algo_dir = const_cast<char *>(dir_string.c_str());

    // A directory with nothing in it must not silently look like a shader.
    // The built-in is used instead, and the loader says so.
    vkminer::ShaderModule empty_dir;
    if (!vkminer::load_shader(kShaderName, &empty_dir))
        fail("an empty --algo-dir should fall back to the built-in module");
    else if (empty_dir.words.size() != blob->word_count)
        fail("an empty --algo-dir did not fall back to the built-in module");

    // A real module in the directory, with no manifest: the edit-compile-run
    // case, and the one that has to work without ceremony.
    const std::filesystem::path spv = dir / (std::string(kShaderName) + ".spv");
    write_bytes(spv, to_le_bytes(mod.words));

    vkminer::ShaderModule loose;
    if (!vkminer::load_shader(kShaderName, &loose)) {
        fail("a loose .spv in --algo-dir was not loaded");
    } else {
        if (loose.words != mod.words)
            fail("the loose .spv did not round-trip through the loader");
        if (!same_file(loose.origin, spv))
            fail("the loader did not report the file it loaded");
        if (loose.local_size_x != 0)
            fail("a layout was invented for a shader with no manifest");
    }

    // With a manifest, which is how a replacement shader declares a layout
    // that differs from the one its algorithm expects.
    {
        std::ofstream manifest(dir / "manifest.json");
        manifest << "{\n  \"shaders\": {\n    \"" << kShaderName << "\": {\n"
                 << "      \"file\": \"renamed.spv\",\n"
                 << "      \"storage_buffers\": 3,\n"
                 << "      \"push_constant_bytes\": 24,\n"
                 << "      \"local_size_x\": 128\n"
                 << "    }\n  }\n}\n";
    }
    std::filesystem::copy_file(spv, dir / "renamed.spv",
                               std::filesystem::copy_options::overwrite_existing,
                               ec);

    vkminer::ShaderModule manifested;
    if (!vkminer::load_shader(kShaderName, &manifested)) {
        fail("the manifest's shader was not loaded");
    } else {
        if (!same_file(manifested.origin, dir / "renamed.spv"))
            fail("the manifest's 'file' was ignored");
        if (manifested.storage_buffers != 3
            || manifested.push_constant_bytes != 24
            || manifested.local_size_x != 128)
            fail("the manifest's layout did not reach the caller");
    }

    // Something that is not SPIR-V. This is the case the check exists for: a
    // .comp, a text file or a truncated copy left where a module belongs, and
    // a driver handed one of those does not fail politely.
    {
        std::ofstream text(dir / "renamed.spv", std::ios::binary);
        text << "#version 450\nvoid main() {}\n";
    }
    vkminer::ShaderModule rejected;
    if (!vkminer::load_shader(kShaderName, &rejected))
        fail("a bad module in --algo-dir should fall back, not fail outright");
    else if (rejected.words.size() != blob->word_count)
        fail("a file that is not SPIR-V was loaded as though it were");

    opt_algo_dir = nullptr;
    std::filesystem::remove_all(dir, ec);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("shaders: %zu word module built with %s, --algo-dir override "
                "works\n", blob->word_count, built_with);
    return 0;
}
