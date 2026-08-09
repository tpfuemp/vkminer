// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// What happens when a device reports a candidate the host does not agree with.
//
// The host re-hashes every candidate before it becomes a share, so a wrong
// kernel costs a dropped share and nothing worse -- which is also why such a
// bug survives for weeks, as one warning line under a hash rate that looks
// fine. So the disagreement is counted into the periodic report, and the case
// is written out in full: header, target, and both digests, everything needed
// to hash that nonce again. --replay feeds them back through the same shader.

#ifndef VKMINER_SCHEDULER_CANDIDATE_LOG_H__
#define VKMINER_SCHEDULER_CANDIDATE_LOG_H__

#include <cstdint>
#include <string>
#include <vector>

namespace vkminer {

// Which of the two ways a candidate can disagree with the host. They are
// different bugs: the first is a kernel that reports nonces it should not, the
// second a kernel that reports the right nonce and the wrong digest for it --
// which means the comparison and the hash disagree with each other.
enum class CandidateFault {
    BelowTarget,  // the host says this nonce does not meet the target
    WrongDigest,  // it does, but the device's digest is not the host's
};

// One captured disagreement, in the terms the algorithm hashes in: header
// words as struct work carries them, the target as fulltest compares it.
struct CapturedCandidate {
    CandidateFault fault = CandidateFault::BelowTarget;
    int      device = -1;
    uint32_t nonce = 0;
    uint32_t header[20] = {0};
    uint32_t target[8] = {0};
    uint32_t device_hash[8] = {0};
    uint32_t host_hash[8] = {0};
};

// Count it, write it down, and return the path so the caller can name the file
// in its warning -- a capture nobody can find is a capture nobody replays.
// Empty if it could not be written, which is not fatal: the miner is still
// mining and the counter still counts. Bounded, because a kernel wrong about
// every nonce would otherwise fill the disk; the counters carry on past that
// and say so.
std::string capture_candidate(const CapturedCandidate &bad);

// How many disagreements this run has seen, by kind. Read from whichever
// thread prints the report, written from every worker.
uint64_t candidates_below_target();
uint64_t candidates_wrong_digest();

// Read back what capture_candidate wrote. Returns false, having logged, if the
// file cannot be read or holds no record this build understands.
bool read_captures(const std::string &path,
                   std::vector<CapturedCandidate> *out);

}  // namespace vkminer

#endif  // VKMINER_SCHEDULER_CANDIDATE_LOG_H__
