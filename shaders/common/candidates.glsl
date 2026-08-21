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
// only worse luck than it should have had.

#ifndef VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED

// Words per candidate: the nonce as two words, low first, then the eight digest
// words in the order the host compares them. The host has the same number; they
// are two halves of one contract, and a change to either is a change to both.
//
// Two words because the host carries 64 bits of nonce. Most kernels here fit
// in the low word and write a zero to the high one, on a path taken once in
// billions of invocations; KawPoW's calls the two-word emit below.
const uint kCandidateWords = 10u;

layout(std430, set = 0, binding = 0) buffer Candidates {
    uint found;   // total candidates this dispatch produced, capacity or not
    uint best;    // smallest top digest word seen, or ~0 with the probe off
    uint word[];  // kCandidateWords each, for the first `capacity` of them
} candidates;

// Whether to keep `best` up to date. Off in every pipeline the miner builds to
// mine with, and folded away when it is: one atomic to one address from every
// invocation is contention on a scale nothing else here has. A diagnostic for a
// run, asked for with --vk-probe-best, not a counter to leave on.
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
void emit_candidate64(uint capacity, uint nonce_lo, uint nonce_hi, uint hash[8])
{
    uint slot = atomicAdd(candidates.found, 1u);
    if (slot >= capacity)
        return;

    uint base = slot * kCandidateWords;
    candidates.word[base] = nonce_lo;
    candidates.word[base + 1u] = nonce_hi;
    for (uint i = 0u; i < 8u; i++)
        candidates.word[base + 2u + i] = hash[i];
}

// The same, for the kernels whose nonce is 32 bits wide.
void emit_candidate(uint capacity, uint nonce, uint hash[8])
{
    emit_candidate64(capacity, nonce, 0u, hash);
}

#endif  // VKMINER_SHADERS_COMMON_CANDIDATES_GLSL_INCLUDED
