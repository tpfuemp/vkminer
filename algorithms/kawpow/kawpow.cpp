// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// KawPoW: Ravencoin's ProgPoW 0.9.4, and the first algorithm here that is not
// one invocation, one nonce, one hash.
//
// Three things make it different from everything above it in this directory:
//
//   - it hashes against a gigabyte of DAG, which the device builds for itself
//     before the first dispatch (KernelSpec::shared_bytes and the setup pass);
//   - its inner loop is regenerated every three blocks, so the kernel reads the
//     program rather than containing it (kawpow_program.h);
//   - sixteen invocations cooperate on one nonce (KernelSpec::lanes).
//
// What is left here is the ordinary work of an algorithm: what a header is,
// which epoch a job wants, what goes in the push block, and the scalar
// reference every candidate is re-hashed against.
//
// The header is 36 bytes and none of it is a Bitcoin block header: a KawPoW
// pool sends the header *hash* plus the block height, which is the only channel
// through which the epoch and the period reach this file. There is no nonce
// word -- the nonce is a 64-bit field of its own, and the pool owns its top two
// bytes.

#include "algorithms/kawpow/kawpow.h"

#include "algorithms/kawpow/kawpow_dag.h"
#include "algorithms/kawpow/kawpow_hash.h"
#include "algorithms/kawpow/kawpow_program.h"

#ifdef VKMINER_HAVE_SHADERS
#include "shaders/shader_source.h"
#endif

extern "C" {
#include "core/miner.h"
}

#include <cstddef>
#include <cstring>

namespace vkminer {
namespace {

// Words of header this algorithm hashes: the 32-byte header hash, then the
// block height.
constexpr size_t kHeaderWords = 9;

// Specialization constants the specialized kernel is built from: the program's
// words, then the table's length. kawpow_spec.comp declares exactly this many,
// and program_values() fills exactly this many -- the backend refuses a
// mismatch rather than building a pipeline out of half a program.
constexpr size_t kProgramConstants = kawpow::kProgramWords + 1;

// 64-byte items in a 256-byte DAG line, which is what one round reads.
constexpr uint64_t kItemsPerLine = kawpow::kLineWords * 4 / kawpow::kItemBytes;

// Lines of the head of the DAG that are also the cache the program's read
// operations index into. Nothing separate is uploaded for it -- it is the same
// bytes -- but a table shorter than this has no cache in it.
constexpr uint64_t kL1Lines = kawpow::kL1Words * 4 / (kawpow::kLineWords * 4);

// The push constant block algorithms/kawpow/kawpow.comp declares: 92 bytes
// against a guaranteed minimum of 128. The GLSL and this struct are one
// definition written twice, and nothing but the asserts would notice them
// diverging.
struct KawpowPush {
    uint32_t header[8];   // the header hash, as KawPoW absorbs it
    uint32_t target[8];   // as fulltest() compares: little-endian, most significant last
    uint32_t nonce_lo;
    uint32_t nonce_hi;
    uint32_t count;
    uint32_t capacity;
    uint32_t period_lo;   // the program's only input
    uint32_t period_hi;
    uint32_t dag_lines;
};

static_assert(sizeof(KawpowPush) == 92, "kawpow.comp's push block is 92 bytes");
static_assert(sizeof(KawpowPush) <= 128,
              "Vulkan guarantees only 128 bytes of push constants");
static_assert(offsetof(KawpowPush, target) == 32, "push block layout");
static_assert(offsetof(KawpowPush, nonce_lo) == 64, "push block layout");
static_assert(offsetof(KawpowPush, period_lo) == 80, "push block layout");

// The header hash as the hash reads it. The words arrive the way struct work
// carries every other algorithm's -- big-endian-decoded from the wire -- and
// KawPoW absorbs the same bytes little-endian, so this is a byte swap written
// as the round trip it is: what is checkable against a pool or an explorer is
// the byte string in the middle.
void header_words(const uint32_t *header, uint32_t out[8])
{
    unsigned char bytes[32];
    for (size_t i = 0; i < 8; i++)
        be32enc(bytes + i * 4, header[i]);
    for (size_t i = 0; i < 8; i++)
        out[i] = le32dec(bytes + i * 4);
}

// Lines of the DAG, straight from the reference, for the host's own hash. Four
// 64-byte items to a line, and a line is what one round of the mix reads.
//
// Slow on purpose: this re-verifies candidates once per share, and it is the
// oracle the kernel is measured against. An oracle that shares an optimization
// with the thing it checks is not one.
class ReferenceLines final : public kawpow::DagLines {
public:
    explicit ReferenceLines(uint32_t epoch) : epoch_(epoch) {}

    bool line(uint64_t index, uint32_t out[kawpow::kLineWords]) const override
    {
        for (uint64_t i = 0; i < kItemsPerLine; i++)
            if (!kawpow::dataset_item(epoch_, index * kItemsPerLine + i,
                                      out + i * kawpow::kItemWords))
                return false;
        return true;
    }

private:
    uint32_t epoch_;
};

// The largest power of two that is not more than `n`, and never less than a
// line: a chunk boundary in the middle of one would be a line no shader could
// read, whatever the chain of compares did with the index.
uint64_t chunk_floor(uint64_t n)
{
    uint64_t chunk = kawpow::kLineWords * 4;
    while (chunk * 2 <= n)
        chunk *= 2;
    return chunk;
}

// Two of ProgPoW 0.9.4's published cases, the two in epoch 0 -- the only epoch
// whose table is small enough to build at startup beside a real one.
//
// The header is the 32-byte header hash the vector states, then the block
// height big-endian, which is where the epoch and the period come from. Blocks
// 49 and 99 are periods 16 and 33, so they are two different programs.
//
// The digests have no leading zeros -- they are hashes of chosen inputs, not
// solutions -- so neither doubles as a target exactly one nonce meets; see
// src/self_test.cpp.
const unsigned char kHeader49[36] = {
    0x63, 0x15, 0x5f, 0x73, 0x2f, 0x2b, 0xf5, 0x56,
    0x96, 0x7f, 0x90, 0x61, 0x55, 0xb5, 0x10, 0xc9,
    0x17, 0xe4, 0x8e, 0x99, 0x68, 0x5e, 0xad, 0x76,
    0xea, 0x83, 0xf4, 0xec, 0xa0, 0x3a, 0xb1, 0x2b,
    0x00, 0x00, 0x00, 0x31,
};

// Final hash e7ced124598fd2500a55ad9f9f48e3569327fe50493c77a4ac9799b96efb9463,
// byte-reversed, which is the order the target comparison reads it in.
const unsigned char kDigest49[32] = {
    0x63, 0x94, 0xfb, 0x6e, 0xb9, 0x99, 0x97, 0xac,
    0xa4, 0x77, 0x3c, 0x49, 0x50, 0xfe, 0x27, 0x93,
    0x56, 0xe3, 0x48, 0x9f, 0x9f, 0xad, 0x55, 0x0a,
    0x50, 0xd2, 0x8f, 0x59, 0x24, 0xd1, 0xce, 0xe7,
};

const unsigned char kHeader99[36] = {
    0xde, 0x37, 0xe1, 0x82, 0x4c, 0x86, 0xd3, 0x5d,
    0x15, 0x4c, 0xf6, 0x5a, 0x88, 0xde, 0x6d, 0x92,
    0x86, 0xae, 0xc4, 0xf7, 0xf1, 0x0c, 0x3f, 0xc9,
    0xf0, 0xfa, 0x1b, 0xcc, 0x26, 0x87, 0x18, 0x8d,
    0x00, 0x00, 0x00, 0x63,
};

// Final hash aa85340690f2e907054324a5021937910e15edfd1ef1577231843e7d32ec3a61.
const unsigned char kDigest99[32] = {
    0x61, 0x3a, 0xec, 0x32, 0x7d, 0x3e, 0x84, 0x31,
    0x72, 0x57, 0xf1, 0x1e, 0xfd, 0xed, 0x15, 0x0e,
    0x91, 0x37, 0x19, 0x02, 0xa5, 0x24, 0x43, 0x05,
    0x07, 0xe9, 0xf2, 0x90, 0x06, 0x34, 0x85, 0xaa,
};

// The nonces as the vectors state them: a 64-bit number, most significant byte
// first on the wire and no byte swap on the way in. There is no nonce word in
// this header for one to be written into.
const KnownAnswer kAnswers[] = {
    { "ProgPoW 0.9.4 block 49", kHeader49, UINT64_C(0x07073c07), kDigest49 },
    { "ProgPoW 0.9.4 block 99", kHeader99, UINT64_C(0x3917afab), kDigest99 },
};

class Kawpow final : public Algorithm {
public:
    Kawpow(uint32_t epoch, uint64_t lines, bool host_dag)
        : epoch_(epoch), host_dag_(host_dag),
          lines_(lines ? lines : kawpow::dag_items(epoch) / kItemsPerLine) {}

    const char *name() const override { return "kawpow"; }

    // The header hash and the block height, and nothing else: there is no
    // version, no merkle root and no timestamp on this side of a KawPoW pool.
    size_t header_bytes() const override { return kHeaderWords * 4; }

    // Past the end of the header, which is the honest answer: the nonce is a
    // field of its own and no word of what is hashed holds it. Everything that
    // asks checks the answer against the header's width before using it, so
    // this reads as "nowhere" rather than as word nine.
    size_t nonce_word() const override { return kHeaderWords; }

    // Epoch 0's vectors, and only while this object is still epoch 0's: past
    // that, hashing them would put epoch-0 inputs through another epoch's table
    // and get answers nobody published. A test's truncated table is the same
    // argument in a smaller size. Everything that asks runs before the first
    // job.
    size_t known_answers(const KnownAnswer **out) const override
    {
        if (epoch_ != 0 || host_dag_)
            return 0;

        *out = kAnswers;
        return sizeof kAnswers / sizeof kAnswers[0];
    }

    // A pool that has already hashed the header and sends the result. Stated
    // rather than deduced from an incoming method name: see the enum.
    StratumDialect stratum_dialect() const override
    {
        return StratumDialect::kProgPow;
    }

    // Sixty-four bits of nonce less the two bytes every KawPoW pool keeps.
    // Wide enough that no device exhausts it in a session, which is why nothing
    // here answers the extranonce2 roll. The protocol client checks the pool's
    // prefix against this number and refuses a subscribe reply that leaves the
    // miner some other width.
    uint32_t nonce_bits() const override { return 48; }

    // The mix hash, the other half of what a KawPoW share is. The pool re-does
    // the final keccak from the header, the nonce and these 32 bytes and never
    // touches the dataset, so a share costs it one hash instead of a gigabyte
    // of table.
    bool submit_mix(const uint32_t *header, uint64_t nonce,
                    unsigned char out[32]) const override
    {
        kawpow::Hash got;
        if (!full_hash(header, nonce, &got))
            return false;

        // Little-endian words, which is how KawPoW states the mix and how every
        // pool reads the hex string back.
        for (size_t i = 0; i < 8; i++)
            le32enc(out + i * 4, got.mix[i]);
        return true;
    }

    // Which epoch this job wants, and whether that differs from the table this
    // algorithm is sized for. True means every kernel built from this object is
    // stale -- the table's size reached the descriptor sets when the kernel was
    // built -- so the caller rebuilds, and the device regenerates the DAG. Once
    // every 7500 blocks.
    bool retarget(const uint32_t *header) override
    {
        // A test's table is the length the test asked for, at the epoch its
        // vectors are from; resizing it under a differential test would answer
        // a question nobody asked.
        if (host_dag_)
            return false;

        const uint32_t epoch = kawpow::epoch_of(header[8]);
        if (epoch == epoch_)
            return false;

        epoch_ = epoch;
        lines_ = kawpow::dag_items(epoch) / kItemsPerLine;
        l1_ready_ = false;
        return true;
    }

    // The epoch, which is the whole of what a header says about the table it
    // wants. The period is not device state and does not appear here.
    //
    // The algorithm's own epoch rather than the header's: the buffer was sized
    // for it when the kernel was built, so answering with the header's number
    // would refill the old buffer with the head of a longer DAG instead of
    // waiting for retarget() to force a rebuild.
    uint64_t state_key(const uint32_t *header) const override
    {
        (void)header;
        return epoch_;
    }

    // The interpreter, which is the control: nothing but Vulkan 1.1, one
    // pipeline built once, and what every differential test is written against.
    // kernels() offers the specialized kernel beside it and the tuner decides.
    KernelSpec kernel(const DeviceInfo &device) const override
    {
        return spec_for(device, Kind::kInterpreted);
    }

    size_t kernels(const DeviceInfo &device, KernelSpec *out,
                   size_t max) const override
    {
        size_t count = 0;

        auto offer = [&](Kind kind) {
            const KernelSpec spec = spec_for(device, kind);
            if (count < max && spec.spirv)
                out[count++] = spec;
        };

        // Best guess first, and the guess is the one whose program is compiled
        // in: the same 64 rounds without a workgroup array to read them out of.
        offer(Kind::kSpecialized);

        // Then the same kernel with the lane exchange in registers. A guess
        // with nothing behind it: the barriers it saves are between invocations
        // already in lockstep, and what a round waits for is a DAG line.
        if (can_shuffle_lanes(device))
            offer(Kind::kSpecializedSubgroup);

        offer(Kind::kInterpreted);

        return count;
    }

    // Which period a header runs. Not the height: three blocks share one
    // program, so keying on the height would rebuild a pipeline three times as
    // often for the same instructions.
    uint64_t program_key(const uint32_t *header) const override
    {
        return kawpow::period_of(header[8]);
    }

    // That period's 131 words, and the table's length after them. Derived from
    // the key alone, so it is safe to call while this object is preparing
    // dispatches on another thread.
    size_t program_values(uint64_t key, uint32_t *out,
                          size_t max) const override
    {
        if (max < kProgramConstants)
            return 0;

        kawpow::Program program;
        kawpow::build_program(key, &program);
        for (size_t i = 0; i < kawpow::kProgramWords; i++)
            out[i] = program.word[i];

        // The epoch's, not the period's, so it is the same in every program
        // this kernel is built with -- but a constant rather than a push
        // constant, because the line index is taken modulo it once per round
        // and a compile-time modulus is a multiply and a shift.
        out[kawpow::kProgramWords] = static_cast<uint32_t>(lines_);
        return kProgramConstants;
    }

    // Periods are consecutive and blocks arrive in order. Wrong across a
    // reorganization deep enough to cross a period boundary, which costs one
    // compile nobody used.
    uint64_t next_program_key(uint64_t key) const override { return key + 1; }

    // The light cache, which is what the setup pass generates from.
    bool setup_seed(uint64_t key, uint64_t offset, void *out,
                    size_t bytes) const override
    {
        return kawpow::light_cache(static_cast<uint32_t>(key), offset, out,
                                   bytes);
    }

    size_t setup_push(uint64_t key, uint64_t first, uint64_t slot,
                      uint32_t count, void *out, size_t capacity) const override
    {
        if (capacity < sizeof(kawpow::DagPush))
            return 0;

        kawpow::DagPush push;
        push.count = count;
        push.first = static_cast<uint32_t>(first);
        push.slot = static_cast<uint32_t>(slot);
        push.cache_items = kawpow::light_cache_items(static_cast<uint32_t>(key));

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    // The table, built on the host an item at a time. Only the test variant
    // declares no setup pass, so only it is ever asked: a real epoch this way
    // is hours.
    bool shared_state(uint64_t key, uint64_t offset, void *out,
                      size_t bytes) const override
    {
        if (!host_dag_)
            return false;

        const uint32_t epoch = static_cast<uint32_t>(key);
        unsigned char *dst = static_cast<unsigned char *>(out);

        while (bytes) {
            const uint64_t index = offset / kawpow::kItemBytes;
            const size_t at = offset % kawpow::kItemBytes;
            const size_t span = bytes < kawpow::kItemBytes - at
                              ? bytes : kawpow::kItemBytes - at;

            uint32_t item[kawpow::kItemWords];
            if (!kawpow::dataset_item(epoch, index, item))
                return false;

            // The canonical byte string, which a little-endian shader reads
            // back as the words it wants.
            unsigned char bytes64[kawpow::kItemBytes];
            for (uint32_t i = 0; i < kawpow::kItemWords; i++)
                le32enc(bytes64 + i * 4, item[i]);

            std::memcpy(dst, bytes64 + at, span);
            dst += span;
            offset += span;
            bytes -= span;
        }
        return true;
    }

    size_t prepare(const Dispatch &dispatch, void *out,
                   size_t capacity) const override
    {
        if (!dispatch.header || !dispatch.target || capacity < sizeof(KawpowPush))
            return 0;

        KawpowPush push;
        header_words(dispatch.header, push.header);
        std::memcpy(push.target, dispatch.target, sizeof push.target);

        // All 64 bits: the two-byte prefix the pool assigns lives in the top.
        push.nonce_lo = static_cast<uint32_t>(dispatch.nonce_start);
        push.nonce_hi = static_cast<uint32_t>(dispatch.nonce_start >> 32);
        push.count = dispatch.count;
        push.capacity = dispatch.capacity;

        const uint64_t period = kawpow::period_of(dispatch.header[8]);
        push.period_lo = static_cast<uint32_t>(period);
        push.period_hi = static_cast<uint32_t>(period >> 32);

        push.dag_lines = static_cast<uint32_t>(lines_);

        std::memcpy(out, &push, sizeof push);
        return sizeof push;
    }

    void hash(const uint32_t *header, uint64_t nonce,
              uint32_t out[8]) const override
    {
        std::memset(out, 0, 8 * sizeof(uint32_t));

        kawpow::Hash got;
        if (!full_hash(header, nonce, &got))
            return;

        // Both a reversal and a byte swap. KawPoW's digest is eight
        // little-endian words whose first byte is the most significant of the
        // 256-bit number; fulltest() wants the most significant word last, with
        // its own bytes where they already are.
        for (size_t j = 0; j < 8; j++) {
            unsigned char bytes[4];
            le32enc(bytes, got.digest[7 - j]);
            out[j] = be32dec(bytes);
        }
    }

private:
    // Both halves of one hash, in KawPoW's own spelling. hash() takes the
    // digest and reorders it for the target comparison; submit_mix() takes the
    // mix and writes it to a wire. Neither is a separate traversal of the DAG.
    bool full_hash(const uint32_t *header, uint64_t nonce,
                   kawpow::Hash *out) const
    {
        kawpow::Program program;
        kawpow::build_program(kawpow::period_of(header[8]), &program);

        const uint32_t *l1 = l1_cache();
        if (!l1)
            return false;

        uint32_t words[8];
        header_words(header, words);

        const ReferenceLines lines(epoch_);
        return kawpow::hash(program, l1, lines_, lines, words, nonce, out);
    }

    // The three shaders, which differ in whether the period's program is
    // compiled into the pipeline and how the sixteen lanes exchange a word.
    // There is no interpreted-with-shuffles kernel: the interpreter is the
    // control, and a control that varied with the device would compare two
    // unknowns.
    enum class Kind { kInterpreted, kSpecialized, kSpecializedSubgroup };

    // Whether the shuffle kernel can run here: the operation, and a subgroup
    // that is a whole number of sixteens. A subgroup of 8 cannot hold a nonce
    // and one of 24 splits a nonce across two, and either way the lanes would
    // exchange with invocations hashing something else. Software rasterizers
    // report 4 or 8, so the check is not hypothetical.
    static bool can_shuffle_lanes(const DeviceInfo &device)
    {
        return device.subgroup_shuffle
            && device.subgroup_size >= kawpow::kLanes
            && device.subgroup_size % kawpow::kLanes == 0;
    }

    // One kernel or another, described by the same numbers: everything but the
    // shader choice is the table -- how big, how cut up, who fills it -- which
    // does not change with how the program reaches the device.
    KernelSpec spec_for(const DeviceInfo &device, Kind kind) const
    {
        (void)device;

        const bool specialized = kind != Kind::kInterpreted;
        const bool subgroup = kind == Kind::kSpecializedSubgroup;

        KernelSpec spec;
        spec.name = name();
        spec.algorithm = this;
        spec.variant = subgroup ? "spec-sub" : specialized ? "spec" : "interp";

        // Sixteen invocations to a nonce, and for the shuffle kernel a
        // workgroup made of whole subgroups. Rounding the width to that is the
        // backend's job, since the width is also the tuner's.
        spec.lanes = kawpow::kLanes;
        spec.full_subgroups = subgroup;

        spec.shared_bytes = lines_ * kawpow::kLineWords * 4;
        spec.shared_chunks = kMaxSharedChunks;

        // A miner takes the largest binding the device will address, which is
        // one piece on anything with a 4 GiB range. A host-built table is a
        // test's, and splitting it is what keeps the chain of compares and the
        // upload path from being code nothing executes.
        spec.shared_chunk_bytes =
            host_dag_ ? chunk_floor(spec.shared_bytes / 4) : 0;

#ifdef VKMINER_HAVE_SHADERS
        ShaderModule &module = subgroup    ? spec_sub_module_
                             : specialized ? spec_module_
                                           : module_;
        const char *shader = subgroup    ? "kawpow_spec_sub"
                           : specialized ? "kawpow_spec"
                                         : "kawpow";
        if (module.words.empty() && !load_shader(shader, &module))
            return spec;

        spec.spirv = module.words.data();
        spec.spirv_words = module.words.size();

        // The candidate buffer, then the table's bindings. Every one of them is
        // declared by the module whether this device needs it or not.
        spec.storage_buffers = module.storage_buffers
                             ? module.storage_buffers : 1 + kMaxSharedChunks;
        spec.push_constant_bytes = module.push_constant_bytes
                                 ? module.push_constant_bytes
                                 : sizeof(KawpowPush);
        spec.local_size_x = module.local_size_x;  // 0: the backend chooses

        // What makes this kernel one pipeline per period. The backend counts
        // them, asks for the values and builds; it never learns that the
        // number it is keyed on is a period.
        if (specialized)
            spec.program_constants = kProgramConstants;

        // How the table gets filled. A gigabyte of items at a hundred hashes
        // each is a morning's work for a CPU and seconds for the card about to
        // read it, so the miner generates and only a test uploads.
        if (!host_dag_) {
            if (setup_.words.empty() && !load_shader("dag", &setup_))
                return spec;

            spec.setup.spirv = setup_.words.data();
            spec.setup.spirv_words = setup_.words.size();
            spec.setup.push_constant_bytes = sizeof(kawpow::DagPush);
            spec.setup.seed_bytes = kawpow::light_cache_bytes(epoch_);
            spec.setup.items = lines_ * kItemsPerLine;
        }
#endif
        return spec;
    }

    // The 16 KiB the program's read operations index into: the head of the DAG,
    // and so already in the table the device hashes against. Built once here
    // because the host's own hash needs it too and 256 items is a second.
    const uint32_t *l1_cache() const
    {
        if (!l1_ready_) {
            for (uint64_t i = 0; i < kawpow::kL1Words / kawpow::kItemWords; i++)
                if (!kawpow::dataset_item(epoch_, i,
                                          l1_ + i * kawpow::kItemWords))
                    return nullptr;
            l1_ready_ = true;
        }
        return l1_;
    }

    uint32_t epoch_;
    bool host_dag_;

    // 256-byte lines of table, which is what a round reads one of and what the
    // shader takes the line index modulo.
    uint64_t lines_;

    mutable uint32_t l1_[kawpow::kL1Words];
    mutable bool l1_ready_ = false;

#ifdef VKMINER_HAVE_SHADERS
    // Loaded on first use and kept, because the spec hands out a pointer into
    // it. One Algorithm belongs to one worker, so this needs no lock; if that
    // ever stops being true, this is what breaks.
    mutable ShaderModule module_;
    mutable ShaderModule spec_module_;
    mutable ShaderModule spec_sub_module_;
    mutable ShaderModule setup_;
#endif
};

}  // namespace

std::unique_ptr<Algorithm> make_kawpow(uint32_t epoch)
{
    return std::unique_ptr<Algorithm>(new Kawpow(epoch, 0, false));
}

std::unique_ptr<Algorithm> make_kawpow_host_dag(uint32_t epoch, uint64_t lines)
{
    if (lines < kL1Lines)
        lines = kL1Lines;
    return std::unique_ptr<Algorithm>(new Kawpow(epoch, lines, true));
}

}  // namespace vkminer
