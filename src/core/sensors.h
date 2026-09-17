// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Temperature, power, fan and clock, for a device the miner already knows by
// its PCI address.
//
// None of it comes from Vulkan, which says what a device can compute and nothing
// about how hot it is. Readings come from NVML or the kernel's hwmon tree and are
// joined back to the Vulkan device by bus address, because vendor and device ids
// name a *model*: two of one card are indistinguishable by them.
//
// Every field is optional and an absent one is not an error -- no sensor source,
// an unknown device and a declined reading all look the same here. Absent is
// reported as null and never as zero, which would plot as a cold idle card.

#ifndef VKMINER_CORE_SENSORS_H__
#define VKMINER_CORE_SENSORS_H__

#include <cstdint>
#include <optional>
#include <string>

namespace vkminer {

struct DeviceSensors {
    std::optional<double>   temp_c;
    std::optional<int>      fan_pct;
    std::optional<int>      fan_rpm;
    std::optional<uint32_t> clock_mhz;
    std::optional<uint32_t> mem_clock_mhz;
    std::optional<uint64_t> power_mw;
    std::optional<uint64_t> power_limit_mw;
};

// What can be read about the card at `pci_address`, spelled as pci_address() in
// backends/backend.h spells it. Empty for an empty address, which is what a
// device that would not report its bus gives. Cheap to call repeatedly -- a
// sample stands for a short interval -- and callable from any thread.
DeviceSensors device_sensors(const std::string &pci_address);

// The processor's, for the one system field asking the same question. Empty on
// Windows -- see the note in the implementation.
std::optional<double> cpu_temperature_c();

// Testing seams: the readers above with the directory to read as an argument, so
// parsing can be tested against a tree a test builds rather than against whatever
// hardware the machine has. Present only where hwmon is.
#ifndef _WIN32
DeviceSensors hwmon_device_sensors(const std::string &sys_root,
                                   const std::string &pci_address);
std::optional<double> hwmon_cpu_temperature_c(const std::string &sys_root);
#endif

}  // namespace vkminer

#endif  // VKMINER_CORE_SENSORS_H__
