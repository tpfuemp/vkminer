// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The hwmon reader, against a sysfs tree this test builds itself.
//
// It cannot check that a card is 62 degrees -- that needs the card, and the
// machines this suite runs on include two software rasterizers. What it checks
// is everything between the kernel's numbers and the API's: the units (hwmon
// reports millidegrees, microwatts and a 0-255 duty cycle, and every one of
// those is a factor this code applies by hand), the join key, and the two
// silences -- a device with no sensors at all, and a device whose driver
// publishes some attributes and not others.
//
// The failure it exists to prevent is a plausible wrong number. A temperature
// off by a thousand is obvious; a fan percentage computed as raw/255 truncated
// to 0, or a power reading left in microwatts, is a dashboard that looks like
// it works.

#include "core/sensors.h"
#include "backends/backend.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include <ftw.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace {

int failures = 0;

// Every tree this run made, removed at the end. A test that left them behind
// would still pass, and the build directory would grow one scratch tree per
// ctest invocation until somebody noticed.
std::vector<std::string> roots;

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

// Every component of the path, because mkdir makes one level.
void make_path(const std::string &path)
{
    for (size_t i = 1; i < path.size(); i++) {
        if (path[i] == '/')
            mkdir(path.substr(0, i).c_str(), 0755);
    }
    mkdir(path.c_str(), 0755);
}

void write_attribute(const std::string &dir, const char *name,
                     const char *value)
{
    const std::string path = dir + "/" + name;
    std::FILE *f = std::fopen(path.c_str(), "wb");
    if (!f) {
        fail("could not write %s", path.c_str());
        return;
    }
    std::fprintf(f, "%s\n", value);
    std::fclose(f);
}

template <typename T>
void expect(const char *what, const std::optional<T> &got, T wanted)
{
    if (!got) {
        fail("%s: empty, wanted a reading", what);
        return;
    }
    if (*got != wanted) {
        fail("%s: wrong reading", what);
    }
}

void expect_empty(const char *what, bool has_value)
{
    if (has_value)
        fail("%s: reported a reading where the tree holds none", what);
}

std::string scratch_root()
{
    // Under the directory ctest runs in, so a run leaves nothing outside its
    // own build tree and two builds on one machine do not share a tree.
    char name[] = "vkminer-sensors-XXXXXX";
    const char *made = mkdtemp(name);
    if (!made) {
        fail("could not make a scratch directory");
        std::exit(1);
    }
    roots.push_back(made);
    return made;
}

int remove_entry(const char *path, const struct stat *, int, struct FTW *)
{
    return std::remove(path);
}

void remove_roots()
{
    for (const std::string &root : roots)
        nftw(root.c_str(), remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

// An amdgpu-shaped node: it is the driver that publishes the most of this
// interface, so it is the one that exercises every conversion.
void build_amd_tree(const std::string &root, const std::string &bdf)
{
    const std::string dir = root + "/bus/pci/devices/" + bdf + "/hwmon/hwmon3";
    make_path(dir);

    write_attribute(dir, "name", "amdgpu");
    write_attribute(dir, "temp1_input", "62000");      // millidegrees
    write_attribute(dir, "power1_average", "153000000");  // microwatts
    write_attribute(dir, "power1_cap", "200000000");
    write_attribute(dir, "fan1_input", "1450");        // rpm
    write_attribute(dir, "pwm1", "128");               // of 255
    write_attribute(dir, "freq1_input", "1800000000"); // hertz
    write_attribute(dir, "freq2_input", "875000000");
}

void check_full_node()
{
    const std::string root = scratch_root();
    const std::string bdf = "0000:0a:00.0";
    build_amd_tree(root, bdf);

    const vkminer::DeviceSensors s =
        vkminer::hwmon_device_sensors(root, bdf);

    expect("temperature", s.temp_c, 62.);
    expect<uint64_t>("power", s.power_mw, 153000);
    expect<uint64_t>("power limit", s.power_limit_mw, 200000);
    expect("fan rpm", s.fan_rpm, 1450);

    // 128 of 255 is 50.2%, and the rounding is the point: a percentage
    // computed with integer division would read 50 here and 0 for any duty
    // under 1/100th, which is a stopped fan and a slow one reported alike.
    expect("fan per cent", s.fan_pct, 50);

    expect<uint32_t>("core clock", s.clock_mhz, 1800);
    expect<uint32_t>("memory clock", s.mem_clock_mhz, 875);
}

// What an NVIDIA card's hwmon node actually looks like: a temperature and
// nothing else. The fields the driver does not publish have to stay empty
// rather than becoming zeroes -- an idle-looking card is the one reading a
// dashboard cannot tell from a real one.
void check_partial_node()
{
    const std::string root = scratch_root();
    const std::string bdf = "0000:01:00.0";
    const std::string dir = root + "/bus/pci/devices/" + bdf + "/hwmon/hwmon1";
    make_path(dir);

    write_attribute(dir, "name", "nvidia");
    write_attribute(dir, "temp1_input", "71000");

    const vkminer::DeviceSensors s =
        vkminer::hwmon_device_sensors(root, bdf);

    expect("temperature", s.temp_c, 71.);
    expect_empty("power", s.power_mw.has_value());
    expect_empty("power limit", s.power_limit_mw.has_value());
    expect_empty("fan rpm", s.fan_rpm.has_value());
    expect_empty("fan per cent", s.fan_pct.has_value());
    expect_empty("core clock", s.clock_mhz.has_value());
    expect_empty("memory clock", s.mem_clock_mhz.has_value());
}

// The join. A tree holding one card must say nothing about another, and an
// address the tree does not have is the ordinary case on any machine with a
// GPU the kernel registered no hwmon node for.
void check_join()
{
    const std::string root = scratch_root();
    build_amd_tree(root, "0000:0a:00.0");

    const vkminer::DeviceSensors other =
        vkminer::hwmon_device_sensors(root, "0000:0b:00.0");
    expect_empty("a second card's temperature",
                 other.temp_c.has_value());

    // The empty address a device that would not report its bus gives. It must
    // not become a path that happens to exist.
    const vkminer::DeviceSensors none =
        vkminer::hwmon_device_sensors(root, "");
    expect_empty("an unaddressed device's temperature", none.temp_c.has_value());
}

// The CPU sensor is found by the chip's name and never by its hwmon number:
// numbering is registration order, so hwmon0 is a different chip between two
// boots. This tree puts the processor second on purpose, behind a node that
// would be picked by any code counting from zero.
void check_cpu_by_name()
{
    const std::string root = scratch_root();

    const std::string first = root + "/class/hwmon/hwmon0";
    make_path(first);
    write_attribute(first, "name", "acpitz");
    write_attribute(first, "temp1_input", "27800");

    const std::string second = root + "/class/hwmon/hwmon1";
    make_path(second);
    write_attribute(second, "name", "k10temp");
    write_attribute(second, "temp1_input", "48500");

    const std::optional<double> temp = vkminer::hwmon_cpu_temperature_c(root);
    expect("cpu temperature", temp, 48.5);

    const std::string bare = scratch_root();
    expect_empty("cpu temperature with no sensors",
                 vkminer::hwmon_cpu_temperature_c(bare).has_value());
}

// The string the whole join is made of. Both consumers read it back -- sysfs
// as a directory name, NVML as an argument -- so its spelling is an interface
// and not a display choice.
void check_address_format()
{
    vkminer::DeviceInfo info;
    if (!vkminer::pci_address(info).empty())
        fail("a device with no bus info produced an address");

    info.pci = true;
    info.pci_domain = 0;
    info.pci_bus = 0x0a;
    info.pci_device = 0;
    info.pci_function = 0;
    if (vkminer::pci_address(info) != "0000:0a:00.0")
        fail("address spelled as '%s'", vkminer::pci_address(info).c_str());

    info.pci_domain = 0x10000;
    info.pci_bus = 0xff;
    info.pci_device = 0x1f;
    info.pci_function = 7;
    if (vkminer::pci_address(info) != "10000:ff:1f.7")
        fail("wide address spelled as '%s'",
             vkminer::pci_address(info).c_str());
}

}  // namespace

int main()
{
    check_full_node();
    check_partial_node();
    check_join();
    check_cpu_by_name();
    check_address_format();
    remove_roots();

    if (failures) {
        std::printf("sensors_test: %d failure(s)\n", failures);
        return 1;
    }

    std::printf("sensors_test: ok\n");
    return 0;
}
