// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/algorithm.h"

extern "C" {
#include "core/miner.h"
}

namespace vkminer {

size_t Algorithm::prepare(const Dispatch &dispatch, void *out,
                          size_t capacity) const
{
    (void)dispatch;
    (void)out;
    (void)capacity;
    return 0;
}

size_t Algorithm::kernels(const DeviceInfo &device, KernelSpec *out,
                          size_t max) const
{
    if (!max)
        return 0;
    out[0] = kernel(device);
    return out[0].spirv ? 1 : 0;
}

uint64_t Algorithm::state_key(const uint32_t *header) const
{
    (void)header;
    return 0;
}

bool Algorithm::shared_state(uint64_t key, uint64_t offset, void *out,
                             size_t bytes) const
{
    (void)key;
    (void)offset;
    (void)out;
    (void)bytes;
    // Not reachable from an algorithm that left shared_bytes at zero, and the
    // only way to get here is to have asked for a buffer with nothing to put
    // in it. Saying so beats returning a zeroed table that hashes.
    applog(LOG_ERR, "'%s' asked for shared device state and cannot fill it",
           name());
    return false;
}

bool Algorithm::setup_seed(uint64_t key, uint64_t offset, void *out,
                           size_t bytes) const
{
    (void)key;
    (void)offset;
    (void)out;
    (void)bytes;
    // Same argument as above, one level in: an algorithm that declared a setup
    // pass and did not write this would have the device generate its table out
    // of an uninitialized buffer.
    applog(LOG_ERR, "'%s' declared a setup pass and cannot seed it", name());
    return false;
}

size_t Algorithm::setup_push(uint64_t key, uint64_t first, uint64_t slot,
                             uint32_t count, void *out, size_t capacity) const
{
    (void)key;
    (void)first;
    (void)slot;
    (void)count;
    (void)out;
    (void)capacity;
    return 0;
}

uint64_t Algorithm::program_key(const uint32_t *header) const
{
    (void)header;
    return 0;
}

size_t Algorithm::program_values(uint64_t key, uint32_t *out, size_t max) const
{
    (void)key;
    (void)out;
    (void)max;
    // Only reachable from a kernel whose module declared specialization
    // constants for a program, which an algorithm that has no program would
    // not have offered. Zero fails the build rather than compiling the shader
    // against its own defaults, which is a program that runs and is nobody's.
    applog(LOG_ERR, "'%s' has a kernel built per program and no program to "
                    "build it from", name());
    return 0;
}

uint64_t Algorithm::next_program_key(uint64_t key) const
{
    (void)key;
    return 0;
}

bool Algorithm::submit_mix(const uint32_t *header, uint64_t nonce,
                           unsigned char out[32]) const
{
    (void)header;
    (void)nonce;
    (void)out;
    return false;
}

bool Algorithm::retarget(const uint32_t *header)
{
    (void)header;
    return false;
}

size_t Algorithm::known_answers(const KnownAnswer **out) const
{
    *out = nullptr;
    return 0;
}

size_t Algorithm::reference_answers(const KnownAnswer **out) const
{
    *out = nullptr;
    return 0;
}

size_t startup_answers(const Algorithm &algo, const KnownAnswer **out,
                       bool *published)
{
    const size_t count = algo.known_answers(out);
    if (count) {
        if (published)
            *published = true;
        return count;
    }

    if (published)
        *published = false;
    return algo.reference_answers(out);
}

bool Algorithm::verify(const uint32_t *header, uint64_t nonce,
                       const uint32_t *target, uint32_t out[8]) const
{
    hash(header, nonce, out);
    // fulltest() is inherited and has decided what a share is for as long as
    // this family of miners has existed. Reimplementing the comparison here to
    // save a call would mean two answers to the same question.
    return fulltest(out, target);
}

}  // namespace vkminer
