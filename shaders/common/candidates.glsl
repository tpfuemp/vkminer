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
//
// The buffer also carries one word that is not a result: the best digest any
// invocation saw. It answers what a candidate count cannot -- whether the
// kernel is missing valid nonces, which produces no reject and no failed check,
// only worse luck than it should have had. See Kernel::BestDigest in
// backends/backend.h for what the host makes of it.

#ifndef VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED

// Words per candidate: the nonce, then the eight digest words in the order the
// host compares them. The host has the same number; they are two halves of one
// contract, and a change to either is a change to both.
const uint kCandidateWords = 9u;

layout(std430, set = 0, binding = 0) buffer Candidates {
    uint found;   // total candidates this dispatch produced, capacity or not
    uint best;    // smallest top digest word seen, or ~0 with the probe off
    uint word[];  // kCandidateWords each, for the first `capacity` of them
} candidates;

// Whether to keep `best` up to date. Off in every pipeline the miner builds to
// mine with, and folded away entirely when it is: one atomic to one address
// from every invocation on the device is contention on a scale nothing else
// here has, so this is a diagnostic to switch on for a run and not a counter to
// leave running. The host asks for it with --vk-probe-best.
layout(constant_id = 1) const bool kProbeBest = false;

// The best digest word this invocation computed, offered to the running
// minimum. `top` is the most significant word of the digest as the target
// comparison reads it, which is the word that decides all but one nonce in
// 2^32 -- so a kernel is searching correctly exactly when this descends.
void probe_best(uint top)
{
    if (kProbeBest)
        atomicMin(candidates.best, top);
}

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
