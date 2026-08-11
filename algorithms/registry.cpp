// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/registry.h"

#include "algorithms/blake2s/blake2s.h"
#include "algorithms/scrypt/scrypt.h"
#include "algorithms/sha256d/sha256d.h"
#include "algorithms/sha3t/sha3t.h"

#include <cstring>
#include <string>

namespace vkminer {
namespace {

struct Entry {
    const char *name;
    // An alternative spelling that some pool or some other miner established.
    // Empty where there is none: inventing an alias is how a miner ends up
    // supporting a name nobody uses and cannot later drop.
    const char *alias;
    std::unique_ptr<Algorithm> (*make)();
};

const Entry kAlgorithms[] = {
    { "sha256d", "", make_sha256d },
    { "blake2s", "", make_blake2s },
    { "scrypt",  "", make_scrypt  },
    { "sha3t",   "", make_sha3t   },
};

bool same_name(const char *a, const char *b)
{
    if (!a || !b || !*b)
        return false;
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y)
            return false;
    }
    return !*a && !*b;
}

const Entry *find(const char *name)
{
    if (!name)
        return nullptr;
    for (const Entry &e : kAlgorithms)
        if (same_name(name, e.name) || same_name(name, e.alias))
            return &e;
    return nullptr;
}

}  // namespace

std::unique_ptr<Algorithm> create_algorithm(const char *name)
{
    const Entry *entry = find(name);
    return entry ? entry->make() : nullptr;
}

bool algorithm_exists(const char *name)
{
    return find(name) != nullptr;
}

std::string algorithm_names()
{
    std::string out;
    for (const Entry &e : kAlgorithms) {
        if (!out.empty())
            out += ", ";
        out += e.name;
    }
    return out;
}

}  // namespace vkminer
