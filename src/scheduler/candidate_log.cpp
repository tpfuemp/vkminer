// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "scheduler/candidate_log.h"

#include "core/paths.h"

extern "C" {
#include "core/miner.h"
}

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace vkminer {
namespace {

// Records one run may leave behind. A kernel that disagrees with the host about
// one nonce in a million produces a handful of these overnight; one that
// disagrees about all of them produces this many and then stops, which is
// enough to diagnose it and not enough to matter to a disk.
constexpr uint64_t kMaxRecords = 64;

// Line format, in the first field of every record so that a file written by an
// older build is refused rather than misread. It changes when a field is added,
// which is a thing a capture format does.
constexpr int kFormat = 1;

const char kFileName[] = "failed-candidates.log";

std::atomic<uint64_t> g_below_target{0};
std::atomic<uint64_t> g_wrong_digest{0};
std::atomic<uint64_t> g_written{0};

// One writer at a time. Workers hit this from several threads and a record is
// several fprintf calls; interleaving two of them would produce a file that
// parses as neither.
std::mutex g_lock;

const char *fault_name(CandidateFault fault)
{
    return fault == CandidateFault::WrongDigest ? "digest" : "target";
}

bool fault_from_name(const char *name, CandidateFault *out)
{
    if (!std::strcmp(name, "digest")) {
        *out = CandidateFault::WrongDigest;
        return true;
    }
    if (!std::strcmp(name, "target")) {
        *out = CandidateFault::BelowTarget;
        return true;
    }
    return false;
}

void write_words(std::FILE *f, const uint32_t *words, size_t count)
{
    // Word order, not byte order, and every word the width it is: this is the
    // form the algorithm hashes in, so a capture read back by hand can be
    // compared against a log line without anybody reversing anything.
    std::fputc(' ', f);
    for (size_t i = 0; i < count; i++)
        std::fprintf(f, "%08x", words[i]);
}

bool read_words(const char *text, uint32_t *words, size_t count)
{
    if (std::strlen(text) != count * 8)
        return false;
    for (size_t i = 0; i < count; i++) {
        char word[9];
        std::memcpy(word, text + i * 8, 8);
        word[8] = '\0';
        char *end = nullptr;
        words[i] = static_cast<uint32_t>(std::strtoul(word, &end, 16));
        if (end != word + 8)
            return false;
    }
    return true;
}

}  // namespace

std::string capture_candidate(const CapturedCandidate &bad)
{
    if (bad.fault == CandidateFault::WrongDigest)
        g_wrong_digest.fetch_add(1, std::memory_order_relaxed);
    else
        g_below_target.fetch_add(1, std::memory_order_relaxed);

    std::lock_guard<std::mutex> held(g_lock);

    const uint64_t written = g_written.load(std::memory_order_relaxed);
    if (written >= kMaxRecords)
        return std::string();

    const std::string path = config_directory() + "/" + kFileName;
    std::FILE *f = std::fopen(path.c_str(), "a");
    if (!f) {
        applog(LOG_ERR, "Cannot write %s: a candidate the device and the host "
                        "disagree about is being counted and not kept", path.c_str());
        return std::string();
    }

    // A header on a new file, so that somebody who finds one knows what it is
    // without having this source in front of them.
    std::fseek(f, 0, SEEK_END);
    if (std::ftell(f) == 0)
        std::fprintf(f, "# vkminer: candidates a device reported and the host "
                        "did not confirm.\n"
                        "# fields: format fault device nonce header target "
                        "device-digest host-digest\n"
                        "# Words are hex, most significant word of a digest "
                        "last, as the target is compared.\n"
                        "# Re-run them with: vkminer -a ALGO --replay <this "
                        "file>\n");

    std::fprintf(f, "%d %s %d %08x", kFormat, fault_name(bad.fault), bad.device,
                 bad.nonce);
    write_words(f, bad.header, 20);
    write_words(f, bad.target, 8);
    write_words(f, bad.device_hash, 8);
    write_words(f, bad.host_hash, 8);
    std::fputc('\n', f);

    const bool ok = std::ferror(f) == 0;
    std::fclose(f);
    if (!ok)
        return std::string();

    g_written.store(written + 1, std::memory_order_relaxed);
    if (written + 1 == kMaxRecords)
        applog(LOG_WARNING, "%s now holds %d captures, which is as many as one "
                            "run keeps. Later ones are counted only.",
               path.c_str(), static_cast<int>(kMaxRecords));
    return path;
}

uint64_t candidates_below_target()
{
    return g_below_target.load(std::memory_order_relaxed);
}

uint64_t candidates_wrong_digest()
{
    return g_wrong_digest.load(std::memory_order_relaxed);
}

bool read_captures(const std::string &path, std::vector<CapturedCandidate> *out)
{
    std::FILE *f = std::fopen(path.c_str(), "r");
    if (!f) {
        applog(LOG_ERR, "--replay: cannot read %s", path.c_str());
        return false;
    }

    out->clear();
    char line[1024];
    int number = 0;
    bool ok = true;

    while (std::fgets(line, sizeof line, f)) {
        number++;
        if (line[0] == '#' || line[0] == '\n')
            continue;

        int format = 0, device = 0;
        char fault[16] = {0};
        char nonce[16] = {0}, header[192] = {0}, target[80] = {0};
        char device_hash[80] = {0}, host_hash[80] = {0};

        // Widths on every string so that a corrupt line cannot write past the
        // buffers above -- this file is read after something already went
        // wrong, which is not the moment to trust its contents.
        const int fields = std::sscanf(line, "%d %15s %d %15s %191s %79s %79s %79s",
                                       &format, fault, &device, nonce, header,
                                       target, device_hash, host_hash);

        CapturedCandidate bad;
        if (fields != 8 || format != kFormat
            || !fault_from_name(fault, &bad.fault)
            || !read_words(nonce, &bad.nonce, 1)
            || !read_words(header, bad.header, 20)
            || !read_words(target, bad.target, 8)
            || !read_words(device_hash, bad.device_hash, 8)
            || !read_words(host_hash, bad.host_hash, 8)) {
            applog(LOG_ERR, "--replay: %s line %d is not a capture this build "
                            "understands", path.c_str(), number);
            ok = false;
            break;
        }

        bad.device = device;
        out->push_back(bad);
    }

    std::fclose(f);
    if (ok && out->empty()) {
        applog(LOG_ERR, "--replay: %s holds no captures", path.c_str());
        return false;
    }
    return ok;
}

}  // namespace vkminer
