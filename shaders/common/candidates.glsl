// How a kernel hands a solution back to the host.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// One buffer, one layout, shared by every algorithm: the backend reads results
// without knowing which kernel wrote them, and that is only possible while
// there is exactly one spelling of "here is a candidate".
//
// The counter is incremented before the capacity is checked, so it can end a
// dispatch larger than the number of candidates actually stored. That is
// deliberate: the host can then say how many were lost rather than silently
// returning a full buffer, and "the buffer filled up" is a real event -- it
// means the dispatch is far too large for the difficulty it is being run at.

#ifndef VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED

// Words per candidate: the nonce, then the eight digest words in the order the
// host compares them. The host has the same number; they are two halves of one
// contract, and a change to either is a change to both.
const uint kCandidateWords = 9u;

layout(std430, set = 0, binding = 0) buffer Candidates {
    uint found;   // total candidates this dispatch produced, capacity or not
    uint word[];  // kCandidateWords each, for the first `capacity` of them
} candidates;

// `hash` is the digest as the host reads it: eight little-endian words, most
// significant last, which is the order the target comparison is made in.
void emit_candidate(uint capacity, uint nonce, uint hash[8])
{
    uint slot = atomicAdd(candidates.found, 1u);
    if (slot >= capacity)
        return;

    uint base = slot * kCandidateWords;
    candidates.word[base] = nonce;
    for (uint i = 0u; i < 8u; i++)
        candidates.word[base + 1u + i] = hash[i];
}

#endif  // VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED
