// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The parts of the compute axis that are the same whatever the backend: how a
// device is described to a human. Kept out of the Vulkan backend so that the
// code printing a device list does not have to include a Vulkan header.

#include "backends/backend.h"

#include <cstdio>

namespace vkminer {

const char *device_kind_name(DeviceKind kind)
{
    switch (kind) {
    case DeviceKind::IntegratedGpu: return "integrated GPU";
    case DeviceKind::DiscreteGpu:   return "discrete GPU";
    case DeviceKind::VirtualGpu:    return "virtual GPU";
    // Just "CPU": under Vulkan this is a software rasterizer, under the CPU
    // backend it is the processor itself, and the backend's own caveat line
    // says which without this having to guess.
    case DeviceKind::Cpu:           return "CPU";
    default:                        return "other";
    }
}

std::string version_string(uint32_t version)
{
    // Vulkan's packing: 7 bits of variant, 7 major, 10 minor, 12 patch. Open
    // coded rather than taken from the Vulkan headers so that this file has
    // none, and because the layout is fixed by the specification for good.
    char buf[32];
    std::snprintf(buf, sizeof buf, "%u.%u.%u", (version >> 22) & 0x7f,
                  (version >> 12) & 0x3ff, version & 0xfff);
    return buf;
}

std::string pci_address(const DeviceInfo &info)
{
    if (!info.pci)
        return std::string();

    // Lower case, domain padded to four digits: the spelling Linux gives the
    // directories under /sys/bus/pci/devices, and the one NVML documents for
    // nvmlDeviceGetHandleByPciBusId. Both consumers read this string back, so
    // the format is part of the interface rather than a display choice.
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04x:%02x:%02x.%x", info.pci_domain,
                  info.pci_bus, info.pci_device, info.pci_function);
    return buf;
}

}  // namespace vkminer
