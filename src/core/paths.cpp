// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/paths.h"

#include <cerrno>
#include <cstdlib>

// _WIN32, not the WIN32 spelled elsewhere: that name comes from windows.h,
// which this file deliberately does not reach, and -std=c++17 predefines only
// the underscored one. WIN32 here would silently take the POSIX branch.
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace vkminer {
namespace {

bool make_directory(const std::string &path)
{
#ifdef _WIN32
    return _mkdir(path.c_str()) == 0 || errno == EEXIST;
#else
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

// The directory named by `xdg`, or `home` plus `fallback` when it is unset.
// Empty when the environment says neither, which is a reason to do without the
// file rather than to guess at a path and write somewhere unexpected.
std::string user_directory(const char *windows_var, const char *xdg,
                           const char *fallback)
{
    std::string base;

#ifdef _WIN32
    (void)xdg;
    (void)fallback;
    if (const char *dir = std::getenv(windows_var))
        base = dir;
#else
    (void)windows_var;
    if (const char *dir = std::getenv(xdg)) {
        base = dir;
    } else if (const char *home = std::getenv("HOME")) {
        base = std::string(home) + fallback;
        if (!make_directory(base))
            return std::string();
    }
#endif

    if (base.empty())
        return std::string();

    base += "/vkminer";
    if (!make_directory(base))
        return std::string();
    return base;
}

}  // namespace

std::string cache_directory()
{
    return user_directory("LOCALAPPDATA", "XDG_CACHE_HOME", "/.cache");
}

std::string config_directory()
{
    return user_directory("APPDATA", "XDG_CONFIG_HOME", "/.config");
}

}  // namespace vkminer
