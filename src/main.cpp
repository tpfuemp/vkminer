// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdio>
#include <cstring>

#include <vulkan/vulkan_core.h>

#ifndef VKMINER_VERSION
#define VKMINER_VERSION "unknown"
#endif

namespace {

void print_version()
{
    std::printf("vkminer %s\n", VKMINER_VERSION);
    std::printf("Vulkan headers %u.%u.%u\n",
                VK_API_VERSION_MAJOR(VK_HEADER_VERSION_COMPLETE),
                VK_API_VERSION_MINOR(VK_HEADER_VERSION_COMPLETE),
                VK_API_VERSION_PATCH(VK_HEADER_VERSION_COMPLETE));
}

void print_usage(std::FILE *out)
{
    std::fprintf(out,
        "usage: vkminer [options]\n"
        "\n"
        "  -V, --version   print version and exit\n"
        "  -h, --help      print this message and exit\n"
        "\n"
        "This is an early development build. No mining options are\n"
        "implemented yet and nothing is mined.\n");
}

} // namespace

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (!std::strcmp(arg, "-V") || !std::strcmp(arg, "--version")) {
            print_version();
            return 0;
        }
        if (!std::strcmp(arg, "-h") || !std::strcmp(arg, "--help")) {
            print_usage(stdout);
            return 0;
        }

        std::fprintf(stderr, "vkminer: unrecognised option '%s'\n", arg);
        print_usage(stderr);
        return 1;
    }

    print_version();
    print_usage(stdout);
    return 0;
}
