// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The algorithm axis. An Algorithm knows what a block header means, how to
// hash one, and which kernel computes that hash on a given device. It does not
// know how a kernel is dispatched, what a queue is, or that Vulkan exists.
//
// Every algorithm carries a scalar reference implementation, and that is not
// negotiable: candidates come back from a device, the host re-hashes them here,
// and only then are they shares. It is also the oracle the differential test
// measures the shader against, so it must stay simple and never be optimized.

#ifndef VKMINER_ALGORITHMS_ALGORITHM_H__
#define VKMINER_ALGORITHMS_ALGORITHM_H__

#include "backends/backend.h"

#include <cstdint>

namespace vkminer {

// A published test vector: a header, a nonce, and the digest the world agrees
// that pair produces. Bytes rather than words, so a vector does not bake in the
// endianness of the machine it was written on. Its value is in being verifiable
// elsewhere -- an explorer, a standards document -- so a vector produced by
// running this code is not a test vector.
struct KnownAnswer {
    const char *label;             // where it came from, for the log line
    const unsigned char *header;   // header_bytes() of it, as it went over the wire
    uint64_t nonce;                // in struct work's spelling, not the pool's
    const unsigned char *digest;   // 32 bytes, in the order hash() writes them
};

// Which stratum a pool for this algorithm speaks. Fixed at startup from the
// algorithm, never guessed from the methods that arrive: a parser rewired by an
// incoming method misreads jobs on whichever dialect is not being tested.
enum class StratumDialect {
    // job_id, prevhash, the two coinbase halves, the merkle branch, version,
    // nbits, ntime, clean -- and the miner builds the header.
    kBitcoin,
    // job_id, header hash, seed hash, share target, clean, height, nbits. The
    // pool has already hashed the header, so there is nothing to assemble.
    kProgPow,
};

class Algorithm {
public:
    virtual ~Algorithm() = default;

    // The canonical name, which is what --algo takes and what the log prints.
    virtual const char *name() const = 0;

    // Bytes of block header this algorithm hashes: 80 for everything that
    // descends from Bitcoin.
    virtual size_t header_bytes() const { return 80; }

    // Which word of the header the nonce goes in. The scheduler substitutes it;
    // the algorithm decides where, and may answer past the end of the header for
    // a nonce that is not one of its words.
    virtual size_t nonce_word() const { return 19; }

    // The factor between the scale a pool quotes difficulty in and the scale
    // this algorithm's target is compared in. One where a difficulty of d means
    // 2^32 * d hashes; 65536 for scrypt.
    virtual double target_factor() const { return 1.; }

    // Which stratum a pool for this algorithm speaks. Read once at startup.
    virtual StratumDialect stratum_dialect() const
    {
        return StratumDialect::kBitcoin;
    }

    // How much of the nonce is the miner's to walk, in bits, and so how wide a
    // range the workers divide between them. The pool's share is already
    // subtracted: KawPoW's nonce is 64 bits and its pools keep the top two
    // bytes, so the answer is 48. The protocol client refuses a pool that
    // assigns a different number rather than mining nonces it would reject.
    //
    // A nonce wider than 32 bits is walked instead of rolling extranonce2:
    // there is no coinbase to roll, and a miner that invented one would submit
    // against a header the pool did not send.
    virtual uint32_t nonce_bits() const { return 32; }

    // The 32 bytes a pool wants beside the nonce, or false for the algorithms
    // whose submit says nothing but which header and which nonce. A ProgPoW
    // share carries the mix hash, which falls out of the host re-hash every
    // candidate already goes through.
    virtual bool submit_mix(const uint32_t *header, uint64_t nonce,
                            unsigned char out[32]) const;

    // Size this algorithm's kernels for this header from now on, and say
    // whether that changed anything. True means everything the caller built
    // from this object is stale -- the kernel above all -- because a buffer
    // cannot be resized under descriptor sets written when the kernel was
    // built, so the caller builds a new kernel.
    //
    // Not const, and the only method here that is not. The default says
    // "nothing changed", which is right for every algorithm whose shader does
    // not depend on which job it is.
    virtual bool retarget(const uint32_t *header);

    // What to run on this device. Passing the device lets an algorithm choose a
    // variant off what the hardware reports -- a 64-bit kernel where
    // shaderInt64 is present, a 2x32-bit one where it is not.
    virtual KernelSpec kernel(const DeviceInfo &device) const = 0;

    // Every kernel this device could run, best guess first, written to `out`
    // and counted by the return; the tuner races them. Only kernels this device
    // can build belong here: a module it would reject is not a candidate. The
    // default is the one kernel() chose.
    virtual size_t kernels(const DeviceInfo &device, KernelSpec *out,
                           size_t max) const;

    // Which shared device state a header needs, as a number the backend caches
    // by and cannot read: two headers that answer the same are hashed against
    // the same bytes. Zero for an algorithm with no such state.
    virtual uint64_t state_key(const uint32_t *header) const;

    // Fill `bytes` of that state for `key`, starting `offset` bytes into it.
    // Called in ascending order in whatever chunks the backend finds
    // convenient, so an implementation may generate rather than copy and need
    // never hold the whole thing. False fails the job rather than mining
    // against a table that is half right.
    virtual bool shared_state(uint64_t key, uint64_t offset, void *out,
                              size_t bytes) const;

    // The same, for state generated on the device rather than uploaded:
    // `bytes` of the setup pass's input, `offset` bytes in, in ascending order.
    // This is the small thing the large one is made from -- a light cache
    // against a DAG -- uploaded once per build and freed when the pass is over.
    virtual bool setup_seed(uint64_t key, uint64_t offset, void *out,
                            size_t bytes) const;

    // Write the push constants for one slice of the setup pass -- `count` items
    // starting at item `first` of the shared state, landing at item `slot` of
    // the piece of it the shader can see -- and return how many bytes that was,
    // which must be the pass's push_constant_bytes.
    //
    // The two indices are equal whenever the state is one buffer; they part
    // where the backend had to cut it up and the pass runs over one piece at a
    // time. Where the boundaries fall is the backend's decision and all it
    // knows: which items of what these are stays on this axis.
    virtual size_t setup_push(uint64_t key, uint64_t first, uint64_t slot,
                              uint32_t count, void *out, size_t capacity) const;

    // Which program a header runs, as a second opaque number, cached by the
    // backend the same way. Zero for an algorithm whose instructions never
    // change. Separate from state_key because the two differ in kind: state is
    // gigabytes of buffer rebuilt a few times a day, a program is a pipeline
    // rebuilt every few minutes.
    virtual uint64_t program_key(const uint32_t *header) const;

    // The constants that program is built from, written to `out` and counted by
    // the return, which must be the program_constants the spec declared. More
    // than `max` is refused rather than truncated. The backend hands them to the
    // compiler as specialization constants in the order written here.
    //
    // Called from a background thread while the same Algorithm is preparing
    // dispatches on another, so it must derive everything from `key` and touch
    // nothing the object caches.
    virtual size_t program_values(uint64_t key, uint32_t *out,
                                  size_t max) const;

    // The key that comes after `key`, or zero for an algorithm that cannot say.
    // The backend compiles that program on a background thread while the
    // current one is still mining. A guess, not a promise: a wrong answer costs
    // one wasted compile.
    virtual uint64_t next_program_key(uint64_t key) const;

    // Write the push constants for one dispatch, and return how many bytes that
    // was -- which must be the push_constant_bytes the spec declared, or the
    // backend refuses to dispatch. This is where the work that is the same for
    // every nonce in a dispatch gets done: a midstate, a target rearranged into
    // whatever order the comparison is cheapest in.
    virtual size_t prepare(const Dispatch &dispatch, void *out,
                           size_t capacity) const;

    // The vectors this algorithm is checked against at startup, written to
    // `out`, with the count returned. None is refused by the self-test: a miner
    // that cannot demonstrate it hashes correctly has no business asking a pool
    // for work.
    virtual size_t known_answers(const KnownAnswer **out) const;

    // The scalar reference. `header` is the header as struct work carries it,
    // one 32-bit word per field in host order, with the nonce word ignored:
    // `nonce` is substituted. `out` receives the 8-word hash in the order
    // fulltest() compares, most significant word last.
    //
    // The nonce is 64 bits because that is what the two axes carry between them.
    // An algorithm whose nonce is a single header word takes the low 32 bits.
    virtual void hash(const uint32_t *header, uint64_t nonce,
                      uint32_t out[8]) const = 0;

    // Does that nonce actually solve the header at this target? The default is
    // hash() followed by the inherited fulltest().
    virtual bool verify(const uint32_t *header, uint64_t nonce,
                        const uint32_t *target, uint32_t out[8]) const;
};

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_ALGORITHM_H__
