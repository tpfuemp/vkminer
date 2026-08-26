// The ProgPoW family's shape, as specialization constants.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// KawPoW and the forks of it differ in numbers and nothing else: how many
// registers a lane keeps, how many operations a round is, how many rounds, and
// the words the two keccaks absorb. All of that is specialized in here, so one
// module serves every fork and the driver folds the difference away at
// vkCreateComputePipelines.
//
// The IDs run from kKernelConstantId upwards -- above every constant a program
// could occupy, so a shader with both never has to know how many of the first
// kind it has -- in the order kawpow.cpp fills them. That order is the
// contract, and a constant declared at the wrong ID gets another fork's number
// without anything failing to build.
//
// The defaults are KawPoW's, which is the fork this was written against; the
// algorithm supplies the whole block either way.

#ifndef VKMINER_SHADERS_COMMON_PROGPOW_PARAMS_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_PROGPOW_PARAMS_GLSL_INCLUDED

// Invariant across the family, and not table entries: sixteen lanes to a hash
// and four DAG words to a lane per round. A fork changing either would change
// the lane exchange and the shape of a DAG line with it.
const uint kLanes    = 16u;
const uint kDagLoads = 4u;

// The widest fork's shape. This is what the mix is sized for and where the
// program's words sit, so moving one renumbers every program constant in every
// shader -- see kawpow_program.h.
const uint kMaxRegs     = 32u;
const uint kMaxCacheOps = 12u;
const uint kMaxMathOps  = 18u;

// This fork's, which is never more than the above.
layout(constant_id = 264) const uint kRegs     = 32u;
layout(constant_id = 265) const uint kCacheOps = 11u;
layout(constant_id = 266) const uint kMathOps  = 18u;
layout(constant_id = 267) const uint kRounds   = 64u;

// The fifteen words the first keccak absorbs after the header and the nonce,
// and the nine the last one absorbs after the mix hash. They are the whole of
// what separates one chain's hash from another's here, which is why they are
// numbers on the host and numbers here: written as characters is how a typo in
// a coin's own constant gets silently corrected into a different chain.
layout(constant_id = 268) const uint kSealSeed0  = 0x00000072u;
layout(constant_id = 269) const uint kSealSeed1  = 0x00000041u;
layout(constant_id = 270) const uint kSealSeed2  = 0x00000056u;
layout(constant_id = 271) const uint kSealSeed3  = 0x00000045u;
layout(constant_id = 272) const uint kSealSeed4  = 0x0000004eu;
layout(constant_id = 273) const uint kSealSeed5  = 0x00000043u;
layout(constant_id = 274) const uint kSealSeed6  = 0x0000004fu;
layout(constant_id = 275) const uint kSealSeed7  = 0x00000049u;
layout(constant_id = 276) const uint kSealSeed8  = 0x0000004eu;
layout(constant_id = 277) const uint kSealSeed9  = 0x0000004bu;
layout(constant_id = 278) const uint kSealSeed10 = 0x00000041u;
layout(constant_id = 279) const uint kSealSeed11 = 0x00000057u;
layout(constant_id = 280) const uint kSealSeed12 = 0x00000050u;
layout(constant_id = 281) const uint kSealSeed13 = 0x0000004fu;
layout(constant_id = 282) const uint kSealSeed14 = 0x00000057u;

layout(constant_id = 283) const uint kSealFinal0 = 0x00000072u;
layout(constant_id = 284) const uint kSealFinal1 = 0x00000041u;
layout(constant_id = 285) const uint kSealFinal2 = 0x00000056u;
layout(constant_id = 286) const uint kSealFinal3 = 0x00000045u;
layout(constant_id = 287) const uint kSealFinal4 = 0x0000004eu;
layout(constant_id = 288) const uint kSealFinal5 = 0x00000043u;
layout(constant_id = 289) const uint kSealFinal6 = 0x0000004fu;
layout(constant_id = 290) const uint kSealFinal7 = 0x00000049u;
layout(constant_id = 291) const uint kSealFinal8 = 0x0000004eu;

// Words of a 256-byte DAG line, and words of the 16 KiB the cache operations
// read. That cache is the first 16 KiB of the DAG itself -- word i of it is
// word i of the table -- so there is nothing separate to bind.
const uint kLineWords = kLanes * kDagLoads;
const uint kL1Words   = 16u * 1024u / 4u;

const uint kFnvPrime = 0x01000193u;
const uint kFnvOffsetBasis = 0x811c9dc5u;

// Where each kind of operation starts in the program. A cache operation is
// (src, dst, sel), a math operation is (src1, src2, sel1, dst, sel2), a DAG
// merge is (dst, sel). The bases are the maxima's, not this fork's: a narrower
// fork leaves the tail of each run zeroed and unread, so that the layout is one
// thing and not four.
const uint kCacheWords = 3u;
const uint kMathWords  = 5u;
const uint kDagWords   = 2u;

const uint kCacheBase = 0u;
const uint kMathBase  = kCacheBase + kMaxCacheOps * kCacheWords;
const uint kDagBase   = kMathBase + kMaxMathOps * kMathWords;
const uint kProgramWords = kDagBase + kDagLoads * kDagWords;

// The two absorbs, written out rather than looped over an array: an array of
// specialization constants is a composite no shader can index with a variable,
// and the loop that would read it is fifteen assignments either way.
void progpow_absorb_seed(inout uint state[25])
{
    state[10] = kSealSeed0;
    state[11] = kSealSeed1;
    state[12] = kSealSeed2;
    state[13] = kSealSeed3;
    state[14] = kSealSeed4;
    state[15] = kSealSeed5;
    state[16] = kSealSeed6;
    state[17] = kSealSeed7;
    state[18] = kSealSeed8;
    state[19] = kSealSeed9;
    state[20] = kSealSeed10;
    state[21] = kSealSeed11;
    state[22] = kSealSeed12;
    state[23] = kSealSeed13;
    state[24] = kSealSeed14;
}

void progpow_absorb_final(inout uint state[25])
{
    state[16] = kSealFinal0;
    state[17] = kSealFinal1;
    state[18] = kSealFinal2;
    state[19] = kSealFinal3;
    state[20] = kSealFinal4;
    state[21] = kSealFinal5;
    state[22] = kSealFinal6;
    state[23] = kSealFinal7;
    state[24] = kSealFinal8;
}

#endif  // VKMINER_SHADERS_COMMON_PROGPOW_PARAMS_GLSL_INCLUDED
