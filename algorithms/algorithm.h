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

// A published test vector: a header, a nonce, and the digest the world agrees
// that pair produces. Everything is bytes rather than words, because a vector
// written as words is a vector that bakes in the endianness of whichever
// machine it was written on and stops testing the thing it exists for.
//
// These are what the miner checks itself against before it connects to
// anything, so their value is entirely in being verifiable somewhere else: a
// block explorer, a standards document, the algorithm's own publication. A
// vector produced by running this code is not a test vector.
struct KnownAnswer {
    const char *label;             // where it came from, for the log line
    const unsigned char *header;   // header_bytes() of it, as it went over the wire
    uint32_t nonce;                // in struct work's spelling, not the pool's
    const unsigned char *digest;   // 32 bytes, in the order hash() writes them
};

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

    // The factor between the scale a pool quotes difficulty in and the scale
    // this algorithm's target is compared in. One where a difficulty of d means
    // 2^32 * d hashes, which is everything descended from Bitcoin; 65536 for
    // scrypt, whose pools all speak the convention its first miners set.
    virtual double target_factor() const { return 1.; }

    // What to run on this device. Passing the device lets an algorithm choose
    // a variant off what the hardware reports -- a 64-bit kernel where
    // shaderInt64 is present, a 2x32-bit one where it is not.
    virtual KernelSpec kernel(const DeviceInfo &device) const = 0;

    // Every kernel this device could run, best guess first, written to `out`
    // and counted by the return. The default is the one kernel() chose, which
    // is the whole answer for an algorithm with a single shader.
    //
    // An algorithm overrides this where the guess is only a guess -- sha3t's
    // 2x32 module also runs where shaderInt64 is present, and which is faster
    // is a measurement. Only kernels this device can build belong here: a
    // module it would reject is not a candidate, it is a failure to race.
    virtual size_t kernels(const DeviceInfo &device, KernelSpec *out,
                           size_t max) const;

    // Write the push constants for one dispatch, and return how many bytes
    // that was -- which must be the push_constant_bytes the spec declared, or
    // the backend refuses to dispatch rather than let a shader read a block
    // that was filled in to a different shape.
    //
    // This is where the work that is the same for every nonce in a dispatch
    // gets done: a midstate, a target rearranged into whatever order the
    // comparison is cheapest in. The default writes nothing, which is right
    // for an algorithm that has a reference and no shader yet.
    virtual size_t prepare(const Dispatch &dispatch, void *out,
                           size_t capacity) const;

    // The vectors this algorithm is checked against at startup, written to
    // `out`, with the count returned. The default has none, which is right for
    // an algorithm still being written and is refused by the self-test: a
    // miner that cannot demonstrate it hashes correctly has no business
    // asking a pool for work.
    virtual size_t known_answers(const KnownAnswer **out) const;

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
