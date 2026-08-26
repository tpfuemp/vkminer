// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The program a ProgPoW fork runs, and where it comes from.
//
// ProgPoW's inner loop is not fixed. Every `period` -- three blocks on
// Ravencoin, one on Firo, six on Meowcoin -- a pseudo-random sequence of
// arithmetic is derived from the period number, and that is what the rounds
// execute: a fork's cache reads, its arithmetic operations, and four DAG
// merges, each a few small integers naming registers and selecting operations.
// 134 words at the largest shape any of them asks for.
//
// The same generator exists on the device, so a hashing kernel needs no buffer
// uploaded every three minutes; this copy is what says the device's program is
// right, and what a kernel specialized per period is built from.
//
// The draw order is the specification: every value comes off one KISS99 stream,
// so a call made in the wrong order, or made at all, changes every value after
// it and no individual line looks wrong. Read this against progpow.cpp's
// `round()` and `mix_rng_state`, not against a description of them.

#ifndef VKMINER_ALGORITHMS_PROGPOW_PROGPOW_PROGRAM_H__
#define VKMINER_ALGORITHMS_PROGPOW_PROGPOW_PROGRAM_H__

#include "algorithms/progpow/progpow_params.h"

#include <cstdint>

namespace vkminer {
namespace progpow {

// The one part of the shape no fork in this family has ever moved: sixteen
// invocations cooperate on a nonce, and that is what makes a DAG line 256
// bytes. Pinned by the KAT against the published vectors; not a tuning knob.
constexpr uint32_t kLanes = 16;

// The rest of the shape is per-fork -- Params::regs, cache_ops, math_ops and
// rounds -- and these are the most any of them may ask for. They are the
// program layout, so moving one renumbers every specialization constant in
// every shader; a fork wanting more is a layout change and not a table entry.
// They are KawPoW's own values but for the cache reads, where MeraKi asks for
// one more.
constexpr uint32_t kMaxRegs     = 32;
constexpr uint32_t kMaxCacheOps = 12;
constexpr uint32_t kMaxMathOps  = 18;
constexpr uint32_t kMaxRounds   = 64;

// Words of a DAG item one lane takes, and so how many merges end a round:
// sixteen lanes over a 256-byte item is four words each.
constexpr uint32_t kDagLoads = 4;

// The 16 KiB the cache operations read, in words. It is the first 16 KiB of the
// DAG itself, which is why nothing separate has to be uploaded for it.
constexpr uint32_t kL1Words = 16 * 1024 / 4;

// Where each kind of operation starts in the program, in words. A cache
// operation is (src, dst, sel); a math operation is (src1, src2, sel1, dst,
// sel2); a DAG merge is (dst, sel). Laid out by kind rather than in draw order
// because that is how they are executed: the shader walks the cache and math
// arrays together, then the DAG array.
//
// Sized for the maxima above and the same for every fork, so a fork using fewer
// operations leaves the tail of a section zero rather than shifting the section
// after it. That costs a handful of dead constants in a pipeline and buys one
// constant ID layout across the whole family.
constexpr uint32_t kCacheWords = 3;
constexpr uint32_t kMathWords  = 5;
constexpr uint32_t kDagWords   = 2;

constexpr uint32_t kCacheBase = 0;
constexpr uint32_t kMathBase  = kCacheBase + kMaxCacheOps * kCacheWords;
constexpr uint32_t kDagBase   = kMathBase + kMaxMathOps * kMathWords;
constexpr uint32_t kProgramWords = kDagBase + kDagLoads * kDagWords;

// FNV-1a over one word, and KISS99: the whole source of randomness in KawPoW.
// This pair seeds the program below, and the same pair seeded four other ways
// fills the mix registers a hash starts from -- which is why they are here
// rather than inside the generator.
constexpr uint32_t kFnvPrime = 0x01000193;
constexpr uint32_t kFnvOffsetBasis = 0x811c9dc5;

inline uint32_t fnv1a(uint32_t u, uint32_t v)
{
    return (u ^ v) * kFnvPrime;
}

// KISS99, by the 1999 specification: three cheap generators combined. Written
// out rather than taken from the vendored copy, because the device runs this
// same arithmetic and the two have to be readable side by side.
class Kiss99 {
public:
    Kiss99(uint32_t z, uint32_t w, uint32_t jsr, uint32_t jcong)
        : z_(z), w_(w), jsr_(jsr), jcong_(jcong) {}

    uint32_t operator()()
    {
        z_ = 36969u * (z_ & 0xffffu) + (z_ >> 16);
        w_ = 18000u * (w_ & 0xffffu) + (w_ >> 16);

        jcong_ = 69069u * jcong_ + 1234567u;

        jsr_ ^= jsr_ << 17;
        jsr_ ^= jsr_ >> 13;
        jsr_ ^= jsr_ << 5;

        return (((z_ << 16) + w_) ^ jcong_) + jsr_;
    }

private:
    uint32_t z_, w_, jsr_, jcong_;
};

// One period's program. Small enough to copy freely and to keep in workgroup
// memory on the device, which is the whole reason it is worth materializing.
struct Program {
    uint32_t word[kProgramWords];
};

// Which program a block runs. A fork's period_length blocks share one, and the
// period rather than the height seeds the generator -- so FiroPoW, at a period
// of one, draws a new program every block.
inline uint64_t period_of(const Params &params, uint64_t block_height)
{
    return block_height / params.period_length;
}

// Generate `period`'s program for `params`. Deterministic and cheap, with those
// two as its only inputs. Words the fork's shape does not reach are zeroed
// rather than left alone.
void build_program(const Params &params, uint64_t period, Program *out);

// Whether word `i` names a mix register rather than selecting an operation. A
// register word is used as an index and nothing reduces it, in either
// interpreter, so a program carrying params.regs there indexes a register that
// does not exist. build_program always writes in range; this is for code that
// makes up a program of its own.
inline bool names_a_register(uint32_t i)
{
    if (i < kMathBase)                                  // src, dst
        return (i - kCacheBase) % kCacheWords < 2;
    if (i < kDagBase) {                                 // src1, src2, dst
        const uint32_t field = (i - kMathBase) % kMathWords;
        return field == 0 || field == 1 || field == 3;
    }
    return (i - kDagBase) % kDagWords == 0;             // dst
}

}  // namespace progpow
}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_PROGPOW_PROGPOW_PROGRAM_H__
