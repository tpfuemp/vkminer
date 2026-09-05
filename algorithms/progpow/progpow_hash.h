// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A ProgPoW fork's hash, on the host: keccak-f800 at each end and, between
// them, the period's program interpreted once per round over sixteen lanes.
//
// Written the way the kernel is written rather than the way a CPU would prefer:
// the lanes are the inner loop, the program is read rather than drawn, and every
// input is assembled from bytes. An oracle whose shape differs from the thing it
// judges can only be compared at the very end, where a disagreement is two
// 256-bit numbers and nothing else.
//
// This is also what the miner re-hashes candidates with, so it must stay simple
// and must never be optimized; candidates arrive a few times a minute.

#ifndef VKMINER_ALGORITHMS_PROGPOW_PROGPOW_HASH_H__
#define VKMINER_ALGORITHMS_PROGPOW_PROGPOW_HASH_H__

#include "algorithms/progpow/progpow_program.h"

#include <cstdint>

namespace vkminer {
namespace progpow {

// Words in the piece of dataset one round reads: sixteen lanes taking four
// words each, which is 256 bytes and four of the 64-byte items the generation
// kernel writes. This is where the two counts are reconciled, and nowhere
// else -- a "DAG item" is 64 bytes to the setup pass and 256 bytes here.
constexpr uint32_t kLineWords = kLanes * kDagLoads;

// The specialized shaders take a lane's four words as one 16-byte load, which
// addresses only if the lane's run starts on a 16-byte boundary. That index is
// line * kLineWords + lane * kDagLoads, so both counts must be multiples of
// four -- as they are in every fork and in the specification. Asserted here
// because GLSL cannot say it, and asserted at all because the failure is
// silent: a misaligned quad reads the four words around the wrong boundary.
static_assert(kDagLoads % 4 == 0,
              "a lane's DAG words must be a whole number of 16-byte quads");
static_assert(kLineWords % 4 == 0,
              "a DAG line must be a whole number of 16-byte quads");

// Where those lines come from. The interpreter reads 64 words per round and
// does not care whether they were generated, uploaded or computed on demand.
class DagLines {
public:
    virtual ~DagLines() = default;

    // Line `index` of the dataset, as the little-endian words a shader reading
    // that buffer would see. False if it cannot be produced, which fails the
    // hash rather than returning one computed from whatever was in `out`.
    virtual bool line(uint64_t index, uint32_t out[kLineWords]) const = 0;
};

// What one hash produces. Both halves, because a KawPoW share is the nonce and
// the mix hash together.
//
// Little-endian words, the order KawPoW states them in and the order they go
// back to bytes for a wire. Not the order the target comparison is made in;
// that reordering belongs to the algorithm that compares.
struct Hash {
    uint32_t mix[8];
    uint32_t digest[8];
};

// One nonce against one header. `header` is the 32-byte header hash as eight
// little-endian words, `l1` is the first 16 KiB of the dataset as kL1Words
// words, and `dag_lines` is how many 256-byte lines the dataset holds -- the
// number every item index is taken modulo, and the one thing that says which
// epoch this is once the bytes are in hand.
//
// False if a line could not be read; `out` is then untouched.
bool hash(const Params &params, const Program &program, const uint32_t *l1,
          uint64_t dag_lines, const DagLines &dag, const uint32_t header[8],
          uint64_t nonce, Hash *out);

}  // namespace progpow
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_PROGPOW_PROGPOW_HASH_H__
