// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The tuning file, without a GPU anywhere near it.
//
// Not whether a sweep picks the right width -- that needs the device it is
// measuring. What is tested is the property that makes writing the answer down
// safe: an entry comes back only for the exact device, driver build, algorithm
// and shader it was measured on.
//
// The failure that prevents is a silent one. A tuning applied to a shader it
// never ran on is not a crash and not a rejected share, just a miner a few
// percent slow with nothing in the log to say why.

#include "tune_cache.h"

#include <cstdarg>
#include <cstdio>
#include <string>

namespace {

int failures = 0;

void fail(const char *fmt, ...)
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

// A device that does not exist, described completely enough to be keyed.
vkminer::DeviceInfo a_device()
{
    vkminer::DeviceInfo info;
    info.name = "Test Device";
    info.driver = "test 1.0";
    info.vendor_id = 0x10de;
    info.device_id = 0x2504;
    info.driver_version = 0x8ac00000;
    return info;
}

const uint32_t kShader[] = {0x07230203, 0x00010000, 0x0008000a, 0x0000002a};

bool same(const vkminer::Tuning &a, const vkminer::Tuning &b)
{
    return a.local_size_x == b.local_size_x && a.queue_depth == b.queue_depth
        && a.variant == b.variant && a.rate == b.rate
        && a.soak_seconds == b.soak_seconds;
}

// Everything the key is made of, changed one at a time -- each a real way a
// stale entry reaches hardware it was never measured on.
void check_keys_differ()
{
    const vkminer::DeviceInfo base = a_device();
    const std::string original =
        vkminer::tune_key(base, "sha256d", kShader, 4);

    struct Change {
        const char *what;
        std::string key;
    };

    vkminer::DeviceInfo other = base;
    other.driver_version = 0x8ac00001;
    const std::string newer_driver =
        vkminer::tune_key(other, "sha256d", kShader, 4);

    other = base;
    other.device_id = 0x2505;
    const std::string other_card =
        vkminer::tune_key(other, "sha256d", kShader, 4);

    other = base;
    other.vendor_id = 0x1002;
    const std::string other_vendor =
        vkminer::tune_key(other, "sha256d", kShader, 4);

    uint32_t edited[4];
    for (int i = 0; i < 4; i++)
        edited[i] = kShader[i];
    edited[3] ^= 1u;

    const Change changes[] = {
        {"a driver update", newer_driver},
        {"a different card", other_card},
        {"a different vendor", other_vendor},
        {"a different algorithm", vkminer::tune_key(base, "blake2s", kShader, 4)},
        {"an edited shader", vkminer::tune_key(base, "sha256d", edited, 4)},
        {"a shorter shader", vkminer::tune_key(base, "sha256d", kShader, 3)},
    };

    for (const Change &change : changes)
        if (change.key == original)
            fail("%s produces the same key, so a stale tuning would be used",
                 change.what);

    // The other half of the property: a key that changed for no reason would
    // mean never using a tuning at all.
    if (vkminer::tune_key(base, "sha256d", kShader, 4) != original)
        fail("the same device and shader keyed differently twice");
}

void check_round_trip(const std::string &path)
{
    const vkminer::DeviceInfo device = a_device();
    const std::string key = vkminer::tune_key(device, "sha256d", kShader, 4);

    vkminer::Tuning wrote;
    wrote.local_size_x = 128;
    wrote.queue_depth = 2;
    wrote.variant = "2x32";
    wrote.rate = 1452000000.;
    wrote.soak_seconds = 6.5;

    if (!vkminer::tune_cache_store(path, key, "Test Device, sha256d", wrote)) {
        fail("could not write %s", path.c_str());
        return;
    }

    vkminer::Tuning read;
    if (!vkminer::tune_cache_load(path, key, &read)) {
        fail("what was just written could not be read back");
        return;
    }
    if (!same(wrote, read))
        fail("read back %u/%u '%s' at %.0f, wrote %u/%u '%s' at %.0f",
             read.local_size_x, read.queue_depth, read.variant.c_str(),
             read.rate, wrote.local_size_x, wrote.queue_depth,
             wrote.variant.c_str(), wrote.rate);

    // Not what the entry is for, but what somebody comparing two runs reads. A
    // double written through as an integer is quietly wrong, not missing.
    if (read.soak_seconds != wrote.soak_seconds)
        fail("soak time came back as %.3f, not %.3f", read.soak_seconds,
             wrote.soak_seconds);

    vkminer::DeviceInfo updated = device;
    updated.driver_version += 1;
    if (vkminer::tune_cache_load(path,
                                 vkminer::tune_key(updated, "sha256d", kShader, 4),
                                 &read))
        fail("a tuning measured on the previous driver was returned for the "
             "new one");
}

// A second device on the same machine. The file is shared, so tuning one must
// not lose the other -- which a writer that rewrote it from nothing would do,
// silently, on any two-GPU box.
void check_second_device_kept(const std::string &path)
{
    const vkminer::DeviceInfo first = a_device();
    const std::string first_key =
        vkminer::tune_key(first, "sha256d", kShader, 4);

    vkminer::DeviceInfo second = a_device();
    second.device_id = 0x1b06;
    const std::string second_key =
        vkminer::tune_key(second, "sha256d", kShader, 4);

    vkminer::Tuning theirs;
    theirs.local_size_x = 512;
    theirs.queue_depth = 4;
    theirs.rate = 900000000.;
    vkminer::tune_cache_store(path, second_key, "Other Device, sha256d", theirs);

    vkminer::Tuning read;
    if (!vkminer::tune_cache_load(path, first_key, &read))
        fail("tuning a second device dropped the first one's entry");
    if (!vkminer::tune_cache_load(path, second_key, &read))
        fail("the second device's own entry was not written");
    else if (read.local_size_x != 512 || read.queue_depth != 4)
        fail("the second device read back as %u/%u", read.local_size_x,
             read.queue_depth);
}

// Files this build should refuse. Written by hand rather than through
// tune_cache_store, because the point is a file this code did not produce.
void check_refuses_junk(const std::string &path)
{
    const std::string key =
        vkminer::tune_key(a_device(), "sha256d", kShader, 4);

    struct Junk {
        const char *what;
        const char *body;
    };

    // KEY stands in for the key, so each of these is the file a user with a
    // text editor would have to produce to hit the case.
    const Junk junk[] = {
        {"a future version",
         "{\"version\": 99, \"entries\": {\"KEY\": "
         "{\"local_size_x\": 64, \"queue_depth\": 2}}}"},
        {"no version at all",
         "{\"entries\": {\"KEY\": {\"local_size_x\": 64, \"queue_depth\": 2}}}"},
        {"an entry with no depth",
         "{\"version\": 1, \"entries\": {\"KEY\": {\"local_size_x\": 64}}}"},
        {"an entry with no width",
         "{\"version\": 1, \"entries\": {\"KEY\": {\"queue_depth\": 2}}}"},
        {"a zero width",
         "{\"version\": 1, \"entries\": {\"KEY\": "
         "{\"local_size_x\": 0, \"queue_depth\": 2}}}"},
        {"not JSON", "this is not a tuning file"},
    };

    for (const Junk &j : junk) {
        std::string body = j.body;
        const size_t at = body.find("KEY");
        if (at != std::string::npos)
            body.replace(at, 3, key);

        FILE *f = std::fopen(path.c_str(), "wb");
        if (!f) {
            fail("could not write %s", path.c_str());
            return;
        }
        std::fwrite(body.data(), 1, body.size(), f);
        std::fclose(f);

        vkminer::Tuning read;
        if (vkminer::tune_cache_load(path, key, &read))
            fail("%s was accepted as a tuning", j.what);
    }

    // And a file that is not there at all, which is every first run.
    std::remove(path.c_str());
    vkminer::Tuning read;
    if (vkminer::tune_cache_load(path, key, &read))
        fail("a tuning was read out of a file that does not exist");
}

// The entry every file written before there was a second kernel looks like. It
// has to keep meaning what it meant -- the algorithm's own choice, measured on
// the only kernel there was -- rather than be rejected or versioned away.
void check_no_variant_is_the_default(const std::string &path)
{
    const std::string key =
        vkminer::tune_key(a_device(), "sha256d", kShader, 4);

    std::string body = "{\"version\": 1, \"entries\": {\"KEY\": "
                       "{\"local_size_x\": 64, \"queue_depth\": 2}}}";
    body.replace(body.find("KEY"), 3, key);

    FILE *f = std::fopen(path.c_str(), "wb");
    if (!f) {
        fail("could not write %s", path.c_str());
        return;
    }
    std::fwrite(body.data(), 1, body.size(), f);
    std::fclose(f);

    vkminer::Tuning read;
    if (!vkminer::tune_cache_load(path, key, &read))
        fail("an entry written before kernels had names was refused");
    else if (!read.variant.empty())
        fail("an entry naming no kernel read back as '%s'",
             read.variant.c_str());
}

}  // namespace

int main()
{
    // Beside whatever ran this, not in the user's config directory: a test that
    // overwrote the tuning of its own machine would cost a sweep to have run.
    const std::string path = "tune_cache_test.json";
    std::remove(path.c_str());

    check_keys_differ();
    check_round_trip(path);
    check_second_device_kept(path);
    check_refuses_junk(path);
    check_no_variant_is_the_default(path);

    std::remove(path.c_str());

    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }
    std::printf("ok   tune cache\n");
    return 0;
}
