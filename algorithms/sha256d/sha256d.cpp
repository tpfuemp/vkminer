// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SHA-256d: SHA-256 applied twice over an 80-byte block header. Bitcoin's
// algorithm, and the bring-up target here because it is simple enough to check
// by reading and has published test vectors going back to 2009.
//
// The whole of the difficulty is byte order, and it is worth stating exactly
// once. struct work carries the header as twenty 32-bit words in host order,
// each word holding a field the way the pool sent it. SHA-256 consumes bytes,
// big-endian. So each word is written out big-endian before hashing, and the
// digest that comes back is read as little-endian words, which is the order
// fulltest() compares in and the order Bitcoin prints a block hash reversed
// from. Getting this wrong produces a miner that benchmarks perfectly and has
// every share rejected -- see the known-answer test, which exists to make that
// failure impossible to ship.

#include "algorithms/sha256d/sha256d.h"

extern "C" {
#include "core/miner.h"
#include "core/sha256.h"
}

#include <cstring>

namespace vkminer {
namespace {

class Sha256d final : public Algorithm {
public:
    const char *name() const override { return "sha256d"; }

    KernelSpec kernel(const DeviceInfo &device) const override
    {
        (void)device;
        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        // No shader yet. A backend that needs one says so; the CPU backend
        // does not look.
        return spec;
    }

    void hash(const uint32_t *header, uint32_t nonce,
              uint32_t out[8]) const override
    {
        // 80 bytes: 19 header words as the pool sent them, then the nonce.
        unsigned char data[80];
        for (size_t i = 0; i < 19; i++)
            be32enc(data + i * 4, header[i]);
        be32enc(data + 19 * 4, nonce);

        sha256d(out, data, sizeof data);
    }
};

}  // namespace

std::unique_ptr<Algorithm> make_sha256d()
{
    return std::unique_ptr<Algorithm>(new Sha256d());
}

}  // namespace vkminer
