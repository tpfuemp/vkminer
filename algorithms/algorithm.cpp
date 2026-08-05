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

size_t Algorithm::known_answers(const KnownAnswer **out) const
{
    *out = nullptr;
    return 0;
}

bool Algorithm::verify(const uint32_t *header, uint32_t nonce,
                       const uint32_t *target, uint32_t out[8]) const
{
    hash(header, nonce, out);
    // fulltest() is inherited and has decided what a share is for as long as
    // this family of miners has existed. Reimplementing the comparison here to
    // save a call would mean two answers to the same question.
    return fulltest(out, target);
}

}  // namespace vkminer
