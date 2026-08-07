// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "tune_cache.h"

#include "core/paths.h"

#include "core/sha256.h"

#include <jansson.h>

#include <cstdio>
#include <ctime>

namespace vkminer {
namespace {

// Bumped when an entry written by an older build would be read wrongly rather
// than merely be incomplete. A file at another version is ignored whole: a
// tuning read out of shape is a wrong dispatch size, not a missing one.
constexpr json_int_t kVersion = 1;

std::string hex(const unsigned char *bytes, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out.push_back(digits[bytes[i] >> 4]);
        out.push_back(digits[bytes[i] & 15]);
    }
    return out;
}

// Startup, on one thread, which is the whole reason gmtime's shared buffer is
// acceptable here.
std::string now_utc()
{
    const std::time_t t = std::time(nullptr);
    const std::tm *tm = std::gmtime(&t);
    if (!tm)
        return std::string();

    char buf[32];
    if (!std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", tm))
        return std::string();
    return buf;
}

// The file's entries, or null. Also answers "is this file ours and at a
// version we read", so a caller never has to check that twice.
json_t *entries_of(json_t *root)
{
    if (!json_is_object(root))
        return nullptr;

    json_t *version = json_object_get(root, "version");
    if (!json_is_integer(version) || json_integer_value(version) != kVersion)
        return nullptr;

    json_t *entries = json_object_get(root, "entries");
    return json_is_object(entries) ? entries : nullptr;
}

uint32_t positive_integer(json_t *object, const char *field)
{
    json_t *value = json_object_get(object, field);
    if (!json_is_integer(value))
        return 0;
    const json_int_t n = json_integer_value(value);
    if (n <= 0 || n > 0xffffffffll)
        return 0;
    return static_cast<uint32_t>(n);
}

}  // namespace

std::string tune_key(const DeviceInfo &device, const char *algo,
                     const uint32_t *spirv, size_t spirv_words)
{
    unsigned char digest[32];
    sha256_full(digest, spirv, spirv_words * sizeof(uint32_t));

    char head[32];
    std::snprintf(head, sizeof head, "%08x-%08x-%08x-", device.vendor_id,
                  device.device_id, device.driver_version);

    // Eight bytes of the digest, not thirty-two: nothing here defends against a
    // chosen collision -- the file is the user's own -- and the key is meant to
    // be read in a text editor by someone asking why their GPU tuned as it did.
    std::string key = head;
    key += algo;
    key += '-';
    key += hex(digest, 8);
    return key;
}

std::string tune_cache_path()
{
    const std::string dir = config_directory();
    if (dir.empty())
        return std::string();
    return dir + "/tune.json";
}

bool tune_cache_load(const std::string &path, const std::string &key,
                     Tuning *out)
{
    if (path.empty())
        return false;

    json_error_t error;
    json_t *root = json_load_file(path.c_str(), 0, &error);
    if (!root)
        return false;  // absent or unreadable, and both mean "not tuned yet"

    bool found = false;
    if (json_t *entries = entries_of(root)) {
        json_t *entry = json_object_get(entries, key.c_str());
        if (json_is_object(entry)) {
            Tuning tuning;
            tuning.local_size_x = positive_integer(entry, "local_size_x");
            tuning.queue_depth = positive_integer(entry, "queue_depth");
            tuning.rate = json_number_value(json_object_get(entry, "rate"));
            tuning.soak_seconds =
                json_number_value(json_object_get(entry, "soak_seconds"));

            // Both, or neither. An entry missing half of what it decides would
            // otherwise silently tune one axis and leave the other at a
            // default that was never measured against it.
            if (tuning.local_size_x && tuning.queue_depth) {
                *out = tuning;
                found = true;
            }
        }
    }

    json_decref(root);
    return found;
}

bool tune_cache_store(const std::string &path, const std::string &key,
                      const std::string &description, const Tuning &tuning)
{
    if (path.empty())
        return false;

    // Read, modify, write: this machine's other devices are in the same file
    // and none of them is being tuned right now.
    json_error_t error;
    json_t *root = json_load_file(path.c_str(), 0, &error);
    json_t *entries = root ? entries_of(root) : nullptr;
    if (!entries) {
        // No file, or one this build does not read. Either way what is written
        // now is a fresh one; nothing readable is being discarded.
        if (root)
            json_decref(root);
        root = json_object();
        entries = json_object();
        json_object_set_new(root, "version", json_integer(kVersion));
        json_object_set_new(root, "entries", entries);
    }

    json_t *entry = json_object();
    json_object_set_new(entry, "device", json_string(description.c_str()));
    json_object_set_new(entry, "local_size_x",
                        json_integer(tuning.local_size_x));
    json_object_set_new(entry, "queue_depth", json_integer(tuning.queue_depth));
    json_object_set_new(entry, "rate", json_real(tuning.rate));
    json_object_set_new(entry, "soak_seconds", json_real(tuning.soak_seconds));
    json_object_set_new(entry, "measured", json_string(now_utc().c_str()));
    json_object_set_new(entries, key.c_str(), entry);

    // Written beside the real file and moved into place, so a miner killed
    // mid-write leaves the previous tuning intact rather than a truncated file
    // the next start has to decide what to do about.
    const std::string tmp = path + ".tmp";
    const int wrote = json_dump_file(root, tmp.c_str(),
                                     JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);

    if (wrote != 0) {
        std::remove(tmp.c_str());
        return false;
    }

    std::remove(path.c_str());  // Windows rename will not overwrite
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
    return true;
}

}  // namespace vkminer
