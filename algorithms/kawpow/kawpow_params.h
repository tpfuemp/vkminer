// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// What separates one ProgPoW fork from another.
//
// KawPoW, MeowPow, EvrProgPow, FiroPoW and MeraKi are one algorithm with
// different numbers in it: the same keccak-f800, the same KISS99 program
// generator, the same sixteen lanes over the same 16 KiB. Everything a chain
// changed is a constant, and every one of those constants is here rather than
// in the code that reads it -- so a variant is a row in this table and the
// hash, the generator, the DAG and all three shaders stay written once. What a
// row cannot do is ask for more operations than the program is laid out for;
// that bound is kawpow_program.h's.
//
// The namespace is still `kawpow`: it is the family's first member and the one
// this implementation was built and verified against.

#ifndef VKMINER_ALGORITHMS_KAWPOW_KAWPOW_PARAMS_H__
#define VKMINER_ALGORITHMS_KAWPOW_KAWPOW_PARAMS_H__

#include <cstdint>

namespace vkminer {
namespace kawpow {

// The seal is what the two keccaks absorb after the data: fifteen words at
// state[10..24] for the first, nine at state[16..24] for the second. Three of
// these forks brand it with their name in ASCII; FiroPoW leaves the padding a
// plain 25-word absorb produces, which is two set words among thirteen zeros.
// Both are fifteen words written unconditionally, so this is a pair of arrays
// and never a branch -- and it has to be a pair, because a branded fork's
// second seal is the first nine words of its first and FiroPoW's is not.
constexpr uint32_t kSealSeedWords  = 15;
constexpr uint32_t kSealFinalWords = 9;

struct Params {
    // The algorithm name the registry and the pool use.
    const char *name;

    uint32_t epoch_length;   // blocks per DAG epoch
    uint32_t period_length;  // blocks one generated program lasts

    // The shape of a round. Each is bounded by the corresponding kMax in
    // kawpow_program.h, which is what the program layout is sized for.
    uint32_t regs;       // mix registers per lane
    uint32_t cache_ops;  // reads of the 16 KiB cache per round
    uint32_t math_ops;   // arithmetic operations per round
    uint32_t rounds;     // rounds, each reading one DAG line

    // How the dataset's size comes loose from its seed -- see epochs_of(),
    // which is where these three turn into the numbers anything else uses. A
    // fork that left the sizing alone is 0/1/0, the identity.
    uint32_t dagchange_epoch;  // first epoch the multiplier applies to; 0 never
    uint32_t dag_epoch_mul;
    uint32_t dag_full_off;

    uint32_t seal_seed[kSealSeedWords];
    uint32_t seal_final[kSealFinalWords];
};

// Ravencoin. The seed words are nearly "RAVENCOINKAWPOW" in ASCII -- nearly,
// because the first is 0x72, a lower-case 'r'. Upstream's table says `//R`
// beside it and means it, and every miner on the network has hashed the typo
// since. Written as numbers here because writing them as characters is how it
// gets silently corrected: 'R' costs nothing, changes every hash, and looks
// more right than the thing that works.
extern const Params kKawpow;

// Meowcoin. Its name, with no typo in it, and the one fork that scales the
// dataset rather than offsetting it.
extern const Params kMeowpow;

// Evrmore. The seed words contain a literal '-' (0x2D) at index 7; it is not a
// typo and must not be tidied.
extern const Params kEvrprogpow;

// Firo. The only unbranded seal, and the only period of one block.
extern const Params kFiropow;

// Telestai. Ravencoin's seal words, typo and all -- the only fork here that
// shares another's seal, so the seal cannot tell the two apart. What can is the
// round: twelve cache reads, five arithmetic operations, half the rounds.
extern const Params kMeraki;

// The fork of that name, or null. For code that has an algorithm name and no
// Algorithm -- the Stratum client, which is C and reaches the epoch arithmetic
// through this. Matched against Params::name, which is the name the registry
// registers and the miner reports, so there is one spelling and not two.
const Params *find(const char *name);

}  // namespace kawpow
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_KAWPOW_KAWPOW_PARAMS_H__
