// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Where this program is allowed to leave files on someone else's machine.
//
// Two directories rather than one, because the two things kept there answer
// differently to being deleted: a pipeline cache is a copy of something the
// driver can rebuild in seconds, and a tuning file is a measurement that costs
// a sweep to take again. The platform conventions already separate them.

#ifndef VKMINER_CORE_PATHS_H__
#define VKMINER_CORE_PATHS_H__

#include <string>

namespace vkminer {

// %LOCALAPPDATA%/vkminer, or $XDG_CACHE_HOME/vkminer, or ~/.cache/vkminer.
// Created if it is not there.
std::string cache_directory();

// %APPDATA%/vkminer, or $XDG_CONFIG_HOME/vkminer, or ~/.config/vkminer.
std::string config_directory();

}  // namespace vkminer

#endif  // VKMINER_CORE_PATHS_H__
