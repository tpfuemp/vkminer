// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/sensors.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <map>
#include <mutex>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <dlfcn.h>
#endif

namespace vkminer {
namespace {

// --------------------------------------------------------------- small reads
//
// Only hwmon reads files, and NVML is a library call, so on Windows these have
// no user -- where -Wunused-function is right about them.
#ifndef _WIN32

// One number out of one file, which is the whole of the hwmon interface. A file
// that is absent, unreadable or holds something else is a reading this machine
// does not offer, never an error: drivers differ in which of these exist.
bool read_number(const std::string &path, long long *out)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
        return false;

    char buf[64] = {0};
    const size_t got = std::fread(buf, 1, sizeof buf - 1, f);
    std::fclose(f);
    if (!got)
        return false;

    char *end = nullptr;
    const long long value = std::strtoll(buf, &end, 10);
    if (end == buf)
        return false;

    *out = value;
    return true;
}

bool read_line(const std::string &path, std::string *out)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f)
        return false;

    char buf[128] = {0};
    const size_t got = std::fread(buf, 1, sizeof buf - 1, f);
    std::fclose(f);
    if (!got)
        return false;

    std::string text(buf, got);
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
        text.pop_back();
    *out = text;
    return true;
}

#endif  // !_WIN32

// ---------------------------------------------------------------------- NVML
//
// Loaded by name at run time and never linked against: linking it would put an
// NVIDIA SDK in the build requirements of a miner that runs on any Vulkan
// driver, and would make a binary that refuses to start beside an AMD card. So
// the few entry points used here are declared from the documented signatures
// rather than included, and a machine without the library has no NVML readings.
//
// nvmlDevice_t is an opaque pointer and nvmlReturn_t an enum, so void * and int
// are the right shapes on every platform this builds for.
constexpr int kNvmlSuccess = 0;
constexpr int kNvmlTemperatureGpu = 0;
constexpr int kNvmlClockGraphics = 0;
constexpr int kNvmlClockMem = 2;

struct Nvml {
    int (*init)(void) = nullptr;
    int (*handle_by_pci)(const char *, void **) = nullptr;
    int (*temperature)(void *, int, unsigned int *) = nullptr;
    int (*power_usage)(void *, unsigned int *) = nullptr;
    int (*power_limit)(void *, unsigned int *) = nullptr;
    int (*fan_speed)(void *, unsigned int *) = nullptr;
    int (*clock_info)(void *, int, unsigned int *) = nullptr;

    bool ready = false;
};

// A symbol stays the platform's own idea of one -- FARPROC, or void * from
// dlsym -- and becomes callable only through the memcpy in bind() below.
// Casting between the two kinds of pointer directly is conditionally supported
// in ISO C++, and this tree builds with -Wpedantic -Werror.
#ifdef _WIN32
using LibHandle = HMODULE;
using LibSymbol = FARPROC;
LibHandle lib_open(const char *name) { return LoadLibraryA(name); }
LibSymbol lib_symbol(LibHandle lib, const char *name)
{
    return GetProcAddress(lib, name);
}
#else
using LibHandle = void *;
using LibSymbol = void *;
LibHandle lib_open(const char *name) { return dlopen(name, RTLD_LAZY); }
LibSymbol lib_symbol(LibHandle lib, const char *name)
{
    return dlsym(lib, name);
}
#endif

template <typename Fn>
void bind(LibHandle lib, Fn *slot, const char *name, const char *older = nullptr)
{
    static_assert(sizeof(Fn) == sizeof(LibSymbol),
                  "a symbol and a function pointer are not the same width");

    // The _v2 spellings are the current ones, but the unsuffixed names are
    // still exported, so an old driver is one fallback away rather than a
    // silent no-readings.
    LibSymbol sym = lib_symbol(lib, name);
    if (!sym && older)
        sym = lib_symbol(lib, older);

    if (sym)
        std::memcpy(slot, &sym, sizeof sym);
}

const Nvml *nvml()
{
    // Opened once and kept for the life of the process. No nvmlShutdown,
    // deliberately: there is no destruction order to rely on here, and tearing
    // the library down under an in-flight API request would crash a miner that
    // is otherwise mining fine.
    static Nvml state = [] {
        Nvml n;

        LibHandle lib = nullptr;
#ifdef _WIN32
        lib = lib_open("nvml.dll");
        if (!lib) {
            // Where the installer used to put it, before it moved into the
            // system directory. From the environment, since Program Files is
            // not always on the same drive.
            if (const char *program_files = std::getenv("ProgramFiles")) {
                const std::string path = std::string(program_files)
                    + "\\NVIDIA Corporation\\NVSMI\\nvml.dll";
                lib = lib_open(path.c_str());
            }
        }
#else
        lib = lib_open("libnvidia-ml.so.1");
        if (!lib)
            lib = lib_open("libnvidia-ml.so");
#endif
        if (!lib)
            return n;

        bind(lib, &n.init, "nvmlInit_v2", "nvmlInit");
        bind(lib, &n.handle_by_pci, "nvmlDeviceGetHandleByPciBusId_v2",
             "nvmlDeviceGetHandleByPciBusId");
        bind(lib, &n.temperature, "nvmlDeviceGetTemperature");
        bind(lib, &n.power_usage, "nvmlDeviceGetPowerUsage");
        bind(lib, &n.power_limit, "nvmlDeviceGetEnforcedPowerLimit");
        bind(lib, &n.fan_speed, "nvmlDeviceGetFanSpeed");
        bind(lib, &n.clock_info, "nvmlDeviceGetClockInfo");

        // The two that make the rest reachable. The others are checked at their
        // call sites, since a driver may implement one reading and not another
        // -- a laptop GPU with no fan of its own is the usual case.
        if (!n.init || !n.handle_by_pci)
            return n;

        n.ready = n.init() == kNvmlSuccess;
        return n;
    }();

    return &state;
}

bool nvml_sensors(const std::string &pci_address, DeviceSensors *out)
{
    const Nvml *n = nvml();
    if (!n->ready)
        return false;

    void *dev = nullptr;
    if (n->handle_by_pci(pci_address.c_str(), &dev) != kNvmlSuccess || !dev)
        return false;

    unsigned int value = 0;
    if (n->temperature && n->temperature(dev, kNvmlTemperatureGpu, &value)
                              == kNvmlSuccess)
        out->temp_c = static_cast<double>(value);

    if (n->power_usage && n->power_usage(dev, &value) == kNvmlSuccess)
        out->power_mw = value;

    if (n->power_limit && n->power_limit(dev, &value) == kNvmlSuccess)
        out->power_limit_mw = value;

    // Per cent of the fan's range, which is not a speed. NVML offers no rpm, so
    // fan_rpm stays empty rather than being derived from a percentage.
    if (n->fan_speed && n->fan_speed(dev, &value) == kNvmlSuccess)
        out->fan_pct = static_cast<int>(value);

    if (n->clock_info
        && n->clock_info(dev, kNvmlClockGraphics, &value) == kNvmlSuccess)
        out->clock_mhz = value;

    if (n->clock_info
        && n->clock_info(dev, kNvmlClockMem, &value) == kNvmlSuccess)
        out->mem_clock_mhz = value;

    return true;
}

}  // namespace

// --------------------------------------------------------------- Linux hwmon

#ifndef _WIN32
namespace {

// The hwmon instances the kernel hung off this PCI device. Normally one; a
// card with a separate sensor chip can present more, so they are all read and
// the first answer for each attribute wins.
std::vector<std::string> hwmon_directories(const std::string &parent)
{
    std::vector<std::string> found;

    DIR *dir = opendir(parent.c_str());
    if (!dir)
        return found;

    while (const struct dirent *entry = readdir(dir)) {
        if (std::strncmp(entry->d_name, "hwmon", 5) == 0)
            found.push_back(parent + "/" + entry->d_name);
    }
    closedir(dir);

    // readdir order is the filesystem's, and a card with two instances would
    // otherwise report whichever the kernel happened to hand back first.
    std::sort(found.begin(), found.end());
    return found;
}

}  // namespace

DeviceSensors hwmon_device_sensors(const std::string &sys_root,
                                   const std::string &pci_address)
{
    DeviceSensors out;
    if (pci_address.empty())
        return out;

    const std::string base =
        sys_root + "/bus/pci/devices/" + pci_address + "/hwmon";

    long long raw = 0;
    for (const std::string &hwmon : hwmon_directories(base)) {
        // Millidegrees, microwatts, rpm, and 0-255 for pwm. The units are the
        // kernel's hwmon interface rather than the driver's, so these
        // conversions hold for anything that registers one.
        if (!out.temp_c && read_number(hwmon + "/temp1_input", &raw))
            out.temp_c = static_cast<double>(raw) / 1000.;

        if (!out.power_mw && read_number(hwmon + "/power1_average", &raw))
            out.power_mw = static_cast<uint64_t>(raw / 1000);
        if (!out.power_mw && read_number(hwmon + "/power1_input", &raw))
            out.power_mw = static_cast<uint64_t>(raw / 1000);

        if (!out.power_limit_mw && read_number(hwmon + "/power1_cap", &raw))
            out.power_limit_mw = static_cast<uint64_t>(raw / 1000);

        if (!out.fan_rpm && read_number(hwmon + "/fan1_input", &raw))
            out.fan_rpm = static_cast<int>(raw);

        // pwm1 is the duty cycle the driver is *asking* for, not a speed: a fan
        // held at 40% that is physically stopped reads 40 here and 0 in
        // fan1_input above, and those are two different facts.
        if (!out.fan_pct && read_number(hwmon + "/pwm1", &raw))
            out.fan_pct = static_cast<int>((raw * 100 + 127) / 255);

        // Hertz, and only amdgpu publishes these.
        if (!out.clock_mhz && read_number(hwmon + "/freq1_input", &raw))
            out.clock_mhz = static_cast<uint32_t>(raw / 1000000);
        if (!out.mem_clock_mhz && read_number(hwmon + "/freq2_input", &raw))
            out.mem_clock_mhz = static_cast<uint32_t>(raw / 1000000);
    }

    return out;
}

std::optional<double> hwmon_cpu_temperature_c(const std::string &sys_root)
{
    // Matched by name, not by number: hwmon numbering is registration order, so
    // hwmon0 is whichever driver loaded first and can be a different chip
    // between two boots of one machine. Intel, AMD, AMD's third-party
    // alternative, and the name ARM boards use.
    static const char *const kCpuSensors[] = {
        "coretemp", "k10temp", "zenpower", "cpu_thermal",
    };

    const std::string base = sys_root + "/class/hwmon";
    for (const std::string &hwmon : hwmon_directories(base)) {
        std::string name;
        if (!read_line(hwmon + "/name", &name))
            continue;

        bool wanted = false;
        for (const char *candidate : kCpuSensors)
            wanted = wanted || name == candidate;
        if (!wanted)
            continue;

        long long raw = 0;
        if (read_number(hwmon + "/temp1_input", &raw))
            return static_cast<double>(raw) / 1000.;
    }

    return std::nullopt;
}
#endif  // !_WIN32

// -------------------------------------------------------------------- public

namespace {

// How long one sample stands for. These quantities have thermal inertia
// measured in seconds, so sampling faster buys no information -- and the API
// routes are written to be polled, one NVML round trip per card per request.
constexpr double kSampleSeconds = 1.;

struct CachedSample {
    DeviceSensors value;
    std::chrono::steady_clock::time_point taken;
    bool filled = false;
};

std::mutex g_sensors_mutex;
std::map<std::string, CachedSample> g_samples;

}  // namespace

DeviceSensors device_sensors(const std::string &pci_address)
{
    if (pci_address.empty())
        return DeviceSensors();

    const std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> hold(g_sensors_mutex);

    CachedSample &cached = g_samples[pci_address];
    if (cached.filled) {
        const std::chrono::duration<double> age = now - cached.taken;
        if (age.count() < kSampleSeconds)
            return cached.value;
    }

    DeviceSensors fresh;

    // NVML first where it answers: an NVIDIA card's hwmon node carries a
    // temperature and little else. Where it does not -- an AMD or Intel card,
    // or no NVIDIA driver at all -- hwmon is the only source.
    if (!nvml_sensors(pci_address, &fresh)) {
#ifndef _WIN32
        fresh = hwmon_device_sensors("/sys", pci_address);
#endif
    }

    cached.value = fresh;
    cached.taken = now;
    cached.filled = true;
    return fresh;
}

std::optional<double> cpu_temperature_c()
{
#ifdef _WIN32
    // The only route on Windows is a detour through a kernel driver, which is
    // far more machinery than a status field is worth. Empty here is honest; a
    // made-up number is not.
    return std::nullopt;
#else
    return hwmon_cpu_temperature_c("/sys");
#endif
}

}  // namespace vkminer
