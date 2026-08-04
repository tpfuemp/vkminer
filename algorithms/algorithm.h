// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The algorithm axis. An Algorithm knows what a block header means, how to
// hash one, and which kernel computes that hash on a given device. It does not
// know how a kernel is dispatched, what a queue is, or that Vulkan exists.
//
// Every algorithm carries a scalar reference implementation, and that is not
// negotiable: a GPU miner cannot submit what only the GPU has seen. Candidates
// come back from a device, the host re-hashes them here, and only then are
// they shares. It is the sole defence against a driver bug, an unstable clock
// or an off-by-one in a shader turning into a run of rejected shares -- and it
// is the oracle the differential test measures the shader against, which is
// why it must stay simple and must never be optimized.

#ifndef VKMINER_ALGORITHMS_ALGORITHM_H__
#define VKMINER_ALGORITHMS_ALGORITHM_H__

#include "backends/backend.h"

#include <cstdint>

namespace vkminer {

class Algorithm {
public:
    virtual ~Algorithm() = default;

    // The canonical name, which is what --algo takes and what the log prints.
    virtual const char *name() const = 0;

    // Bytes of block header this algorithm hashes: 80 for everything that
    // descends from Bitcoin, which so far is everything here.
    virtual size_t header_bytes() const { return 80; }

    // Which word of the header the nonce goes in. The scheduler substitutes
    // it; the algorithm decides where, because equihash-class headers put it
    // elsewhere and a hard-coded 19 would be a lie the day one is added.
    virtual size_t nonce_word() const { return 19; }

    // What to run on this device. Passing the device lets an algorithm choose
    // a variant off what the hardware reports -- a 64-bit kernel where
    // shaderInt64 is present, a 2x32-bit one where it is not.
    virtual KernelSpec kernel(const DeviceInfo &device) const = 0;

    // The scalar reference. `header` is the header as struct work carries it,
    // one 32-bit word per field in host order, with the nonce word ignored:
    // `nonce` is substituted. `out` receives the 8-word hash in the order
    // fulltest() compares, most significant word last.
    virtual void hash(const uint32_t *header, uint32_t nonce,
                      uint32_t out[8]) const = 0;

    // Does that nonce actually solve the header at this target? The default is
    // hash() followed by the inherited fulltest(), which is what the miner has
    // always used to decide; an algorithm overrides it only if its comparison
    // is genuinely different, and none so far is.
    virtual bool verify(const uint32_t *header, uint32_t nonce,
                        const uint32_t *target, uint32_t out[8]) const;
};

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_ALGORITHM_H__
