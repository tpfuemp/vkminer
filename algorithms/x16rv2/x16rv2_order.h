// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Which sixteen stages an x16rv2 header runs, and in what order.
//
// The first eight bytes of the previous block's hash, read as sixteen nibbles
// from the last byte down, high nibble first: the last sixteen hex digits of
// that hash as an explorer prints it. A wrong order still hashes cleanly, so
// it is tested on its own in tests/x16rv2_order_test.cpp.

#ifndef VKMINER_ALGORITHMS_X16RV2_X16RV2_ORDER_H__
#define VKMINER_ALGORITHMS_X16RV2_X16RV2_ORDER_H__

#include <cstdint>

namespace vkminer {
namespace x16rv2 {

// The stages a nibble names, in ccminer's `enum Algo` order (consensus).
enum Stage : unsigned {
    kBlake = 0,
    kBmw,
    kGroestl,
    kJh,
    kKeccak,
    kSkein,
    kLuffa,
    kCubehash,
    kShavite,
    kSimd,
    kEcho,
    kHamsi,
    kFugue,
    kShabal,
    kWhirlpool,
    kSha512,
};

constexpr unsigned kStages = 16;

// A header's order, position i in bits 4i..4i+3. `header` is the miner's
// words, which be32enc() turns back into the wire bytes.
uint64_t order_of(const uint32_t *header);

// The stage at position i, 0..15.
inline unsigned stage_at(uint64_t order, unsigned i)
{
    return static_cast<unsigned>(order >> (4 * i)) & 0xf;
}

// What v2 changed: these three stages hash a Tiger-192 digest of their input,
// zero-padded to 64 bytes, rather than the input itself.
inline bool tiger_first(unsigned stage)
{
    return stage == kKeccak || stage == kLuffa || stage == kSha512;
}

// Primitive passes the order costs: sixteen, and one more for each Tiger.
unsigned passes(uint64_t order);

// ccminer's name for a stage, for log lines.
const char *stage_name(unsigned stage);

// The order as ccminer prints it: sixteen hex digits, position 0 first.
// `out` holds at least 17 characters.
void order_string(uint64_t order, char *out);

}  // namespace x16rv2
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_X16RV2_X16RV2_ORDER_H__
