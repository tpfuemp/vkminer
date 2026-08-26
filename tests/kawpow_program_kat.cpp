// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// KawPoW's inner loop as a program that is read, rather than as code that is
// written -- on the host, where it can still be debugged.
//
// The vendored reference draws its random operations while it executes them:
// one KISS99 stream feeds `round()`, and every value is consumed in the
// statement after the one that produced it. A GPU cannot work that way --
// sixteen invocations execute the same operation at the same moment on their
// own registers, so the sequence has to exist before any of them starts, as 131
// words built once per period and interpreted 64 times by every lane.
//
// That restructuring is the risk this file exists for, and it is invisible: an
// interpreter that consumes the words in a plausible but wrong order computes a
// perfectly good hash nobody else computes, and the earliest natural place to
// notice is a shader disagreeing with a reference -- two new implementations at
// once, with no way to tell which is wrong.
//
// So this is that interpreter, algorithms/progpow/progpow_hash.cpp, against the
// fork's own published vectors, before there is any shader. It establishes:
//
//   - the thirteen official hashes, mix and final, from the 131 words rather
//     than from a draw-as-you-go stream. If the split into "generate" and
//     "interpret" changes the algorithm, it changes it here.
//   - agreement with the vendored reference on headers nobody published, which
//     says the thirteen were not thirteen coincidences.
//   - that the program is actually read: one word of it perturbed must move the
//     answer, checked word by word. An interpreter that ignored, say, the
//     second source register of a math operation would reproduce every vector
//     above whenever that register happened not to matter.

#include "algorithms/progpow/progpow_hash.h"
#include "algorithms/progpow/progpow_program.h"

#include <ethash/ethash.hpp>
#include <ethash/progpow.hpp>

#include "third_party/ethash/lib/ethash/ethash-internal.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

using vkminer::progpow::Kiss99;
using vkminer::progpow::Program;
using vkminer::progpow::build_program;
using vkminer::progpow::fnv1a;
using vkminer::progpow::period_of;

namespace pp = vkminer::progpow;

// The fork these vectors are from. The generator below is the family's; what it
// is checked against is one member's, and check_fork_table() is what the other
// three get.
const pp::Params &kFork = pp::kKawpow;

int failures = 0;

#if defined(__MINGW_PRINTF_FORMAT)
#define KAT_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#elif defined(__GNUC__)
#define KAT_PRINTF_FORMAT printf
#endif

void fail(const char *fmt, ...)
#if defined(KAT_PRINTF_FORMAT)
    __attribute__((format(KAT_PRINTF_FORMAT, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

// ---------------------------------------------------------------- byte order
//
// Everything KawPoW hashes is a little-endian word, and a GLSL storage buffer of
// `uint` on any device this runs on reads exactly these bytes as exactly these
// words. Assembling by hand rather than casting is what makes that true here as
// well, and it is why the header, the DAG item and the cache all go through
// these two functions.

uint32_t le32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

// ------------------------------------------------------- the dataset it reads
//
// The interpreter asks for 256-byte lines and for the 16 KiB the cache
// operations read. Here both come from the vendored reference, computed on
// demand: what is under test is the hash, and the DAG kernel is what says a
// device can produce the same lines.
//
// Two of the setup pass's items make one line here. The kernel that hashes
// reads 256 bytes where the kernel that generates writes 64, and `hash2048` is
// the size this side counts in.

class EthashLines final : public pp::DagLines {
public:
    explicit EthashLines(const ethash::epoch_context &context)
        : context_(&context) {}

    bool line(uint64_t index, uint32_t out[pp::kLineWords]) const override
    {
        const ethash::hash2048 item = ethash::calculate_dataset_item_2048(
            *context_, static_cast<uint32_t>(index));
        for (uint32_t i = 0; i < pp::kLineWords; i++)
            out[i] = le32(item.bytes + i * 4);
        return true;
    }

private:
    const ethash::epoch_context *context_;
};

// One nonce, start to finish, through the interpreter the miner uses.
void hash_kawpow(const ethash::epoch_context &context, const Program &program,
                 const uint8_t header[32], uint64_t nonce, uint8_t mix_out[32],
                 uint8_t final_out[32])
{
    uint32_t words[8];
    for (uint32_t i = 0; i < 8; i++)
        words[i] = le32(header + i * 4);

    const uint8_t *l1_bytes = reinterpret_cast<const uint8_t *>(context.l1_cache);
    uint32_t l1[pp::kL1Words];
    for (uint32_t i = 0; i < pp::kL1Words; i++)
        l1[i] = le32(l1_bytes + i * 4);

    const EthashLines lines(context);
    const uint64_t dag_lines =
        static_cast<uint64_t>(context.full_dataset_num_items) / 2;

    pp::Hash out;
    if (!pp::hash(kFork, program, l1, dag_lines, lines, words, nonce, &out)) {
        fail("the interpreter refused a hash it has everything for");
        std::memset(mix_out, 0, 32);
        std::memset(final_out, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < 8; i++) {
        put_le32(mix_out + i * 4, out.mix[i]);
        put_le32(final_out + i * 4, out.digest[i]);
    }
}

// -------------------------------------------------------------- the vectors

// One published case. Verbatim from cpp-kawpow's
// test/unittests/progpow_test_vectors.hpp, the same thirteen the vendored
// reference is checked against -- deliberately, so that the two answers to
// "what should this hash be" have one source and a disagreement between them
// can only be about the restructuring.
struct Vector {
    int block;
    const char *header_hash;
    const char *nonce;
    const char *mix_hash;
    const char *final_hash;
};

const Vector kVectors[] = {
    {0, "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000",
     "6e97b47b134fda0c7888802988e1a373affeb28bcd813b6e9a0fc669c935d03a",
     "e601a7257a70dc48fccc97a7330d704d776047623b92883d77111fb36870f3d1"},
    {49, "63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b",
     "0000000007073c07",
     "d36f7e815ee09e74eceb9c96993a3d681edf2bf0921fc7bb710364042db99777",
     "e7ced124598fd2500a55ad9f9f48e3569327fe50493c77a4ac9799b96efb9463"},
    {50, "9e7248f20914913a73d80a70174c331b1d34f260535ac3631d770e656b5dd922",
     "00000000076e482e",
     "d6dc634ae837e2785b347648ea515e25e5d8821ae0b95e1c2a9c2d497e0dcfbd",
     "ab0ad7ef8d8ee317dd12d10310aceed7321d34fb263791c2de5776a6658d177e"},
    {99, "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d",
     "000000003917afab",
     "fa706860e5e0e830d5d1d7157e5bea7f5f8a350c7c8612ac1d1fcf2974d64244",
     "aa85340690f2e907054324a5021937910e15edfd1ef1577231843e7d32ec3a61"},
    {29950, "ac7b55e801511b77e11d52e9599206101550144525b5679f2dab19386f23dcce",
     "005d409dbc23a62a",
     "5359807b77a74878269c3a3044df8618a576ce8dc52e1c48d927d4a60e7c6b79",
     "022019e5408683f7f8326b4e46b42864a3a069f17b6151e434fcaedecaadd918"},
    {29999, "e43d7e0bdc8a4a3f6e291a5ed790b9fa1a0948a2b9e33c844888690847de19f5",
     "005db5fa4c2a3d03",
     "d15de3f9bfedd9b6d0f498273eb3b437115bdc8326c96c6457ac06deb5c9f389",
     "4e93630b81198752f876b24380999189b7b9366c08222ac05e4237b87114f305"},
    {30000, "d34519f72c97cae8892c277776259db3320820cb5279a299d0ef1e155e5c6454",
     "005db8607994ff30",
     "de0348b69bf91dfe2c3d3dba6f0132e9048a5284e57b8d9d20adc5f3dc0d3236",
     "c7953d848cda6e304f77b4c6d735645c8e8508a5e74c9e9814ef37b19087cd6c"},
    {30049, "8b6ce5da0b06d18db7bd8492d9e5717f8b53e7e098d9fef7886d58a6e913ef64",
     "005e2e215a8ca2e7",
     "975c6a9decc89cba7ace69338d4de8510d9619aef42b1d35d0bef7e0ce0614a9",
     "c262d8055e288d04b951a844bfca8ba529f5b4d652b408e3942727d7dd90957a"},
    {30050, "c2c46173481b9ced61123d2e293b42ede5a1b323210eb2a684df0874ffe09047",
     "005e30899481055e",
     "362f2fabdb9699d3634b6499703f939f378ee4eac803396c2b0ed0fe1d154972",
     "4cd7e6e79e0b63d42b2b06716a919ccc7834077ec727a9ea94edcdaff2fefab8"},
    {30099, "ea42197eb2ba79c63cb5e655b8b1f612c5f08aae1a49ff236795a3516d87bc71",
     "005ea6aef136f88b",
     "b1196457261bd05ccb387a8ff3fd02687bf496bd7943d89419465289669e27aa",
     "39d1ebfa783b61a6fa8e9747d0f9f134efae5cfba284a2c80e8deabae6b98676"},
    {59950, "49e15ba4bf501ce8fe8876101c808e24c69a859be15de554bf85dbc095491bd6",
     "02ebe0503bd7b1da",
     "df3dbb1669fd35dbb0ae96bbea2d498f0c6992cbddd092aeace42dd933505f95",
     "b8984cf4021c4433f753654848d721f33a0792b4417241f0cf7c7c2db011a54a"},
    {59999, "f5c50ba5c0d6210ddb16250ec3efda178de857b2b1703d8d5403bd0f848e19cf",
     "02edb6275bd221e3",
     "5017df70e97ca35638cf439cdbe54f30383d335e18eb4a74d6e166736f1038fa",
     "4cf1fa62f25b577ac822a6a28d55f8b7e3ae7fe983abd868ae00927e68c41016"},
    {170915, "5b3e8dfa1aafd3924a51f33e2d672d8dae32fa528d8b1d378d6e4db0ec5d665d",
     "0000000044975727",
     "efb29147484c434f1cc59629da90fd0343e3b047407ecd36e9ad973bd51bbac5",
     "e7e6bb3b2f9acd3864bc86f72f87237eaf475633ef650c726ac80eb0adf116b6"},
};

// Strict, for the reason its sibling in progpow_kat.cpp is: a transcribed
// constant with a digit dropped must fail as a bad vector, not as a bad hash.
bool parse_hash(const char *hex, uint8_t out[32])
{
    if (std::strlen(hex) != 64)
        return false;

    for (int i = 0; i < 32; i++) {
        unsigned byte = 0;
        for (int half = 0; half < 2; half++) {
            const char c = hex[i * 2 + half];
            unsigned digit;
            if (c >= '0' && c <= '9')
                digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = static_cast<unsigned>(c - 'a') + 10;
            else
                return false;
            byte = byte * 16 + digit;
        }
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

bool parse_nonce(const char *hex, uint64_t *out)
{
    if (std::strlen(hex) != 16)
        return false;

    uint64_t value = 0;
    for (int i = 0; i < 16; i++) {
        const char c = hex[i];
        if (c >= '0' && c <= '9')
            value = value * 16 + static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            value = value * 16 + static_cast<uint64_t>(c - 'a') + 10;
        else
            return false;
    }
    *out = value;
    return true;
}

std::string to_hex(const uint8_t hash[32])
{
    char text[65];
    for (int i = 0; i < 32; i++)
        std::snprintf(text + i * 2, 3, "%02x", hash[i]);
    return std::string(text, 64);
}

// The light cache for one epoch, kept across the vectors that share it: building
// one is most of this test's runtime and the vectors are in block order.
class EpochCache {
public:
    const ethash::epoch_context *get(int epoch)
    {
        if (epoch != epoch_ || !context_) {
            context_ = ethash::create_epoch_context(epoch);
            epoch_ = epoch;
        }
        return context_.get();
    }

private:
    int epoch_ = -1;
    ethash::epoch_context_ptr context_{nullptr, nullptr};
};

void check_vector(EpochCache &cache, const Vector &vector)
{
    uint8_t header[32];
    uint8_t unused[32];
    uint64_t nonce = 0;
    if (!parse_hash(vector.header_hash, header) ||
        !parse_hash(vector.mix_hash, unused) ||
        !parse_hash(vector.final_hash, unused) ||
        !parse_nonce(vector.nonce, &nonce)) {
        fail("block %d: the vector itself does not parse", vector.block);
        return;
    }

    const ethash::epoch_context *context =
        cache.get(ethash::get_epoch_number(vector.block));
    if (!context) {
        fail("block %d: no epoch context -- out of memory?", vector.block);
        return;
    }

    Program program;
    build_program(kFork, period_of(kFork, static_cast<uint64_t>(vector.block)),
                  &program);

    uint8_t mix[32];
    uint8_t final_hash[32];
    hash_kawpow(*context, program, header, nonce, mix, final_hash);

    if (to_hex(mix) != vector.mix_hash) {
        fail("block %d: mix hash", vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.mix_hash,
                    to_hex(mix).c_str());
    }
    if (to_hex(final_hash) != vector.final_hash) {
        fail("block %d: final hash", vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.final_hash,
                    to_hex(final_hash).c_str());
    }
}

// The thirteen vectors are thirteen points, chosen by whoever published them.
// This walks nonces nobody chose, against the implementation the network runs:
// same epoch, so it costs no further light cache, and it says the agreement
// above is about the algorithm rather than about the sample.
//
// Epoch 0 on purpose: it is the epoch the device differential uses, because a
// table small enough to build on the host and upload lets "is the DAG right"
// and "is the hash right" fail separately.
void check_against_reference(EpochCache &cache)
{
    const int block = 33;   // period 11, and not a block any vector covers
    const ethash::epoch_context *context =
        cache.get(ethash::get_epoch_number(block));
    if (!context)
        return;   // check_vector has already said so

    Program program;
    build_program(kFork, period_of(kFork, static_cast<uint64_t>(block)),
                  &program);

    // Headers with no structure to them, so that nothing about the mix's first
    // round is accidentally uniform across the sample.
    for (uint32_t trial = 0; trial < 8; trial++) {
        uint8_t header[32];
        Kiss99 rng(trial + 1, 0x1234567u, 0x89abcdefu, trial * 7 + 3);
        for (int i = 0; i < 8; i++)
            put_le32(header + i * 4, rng());

        const uint64_t nonce = (static_cast<uint64_t>(rng()) << 32) | rng();

        uint8_t mix[32];
        uint8_t final_hash[32];
        hash_kawpow(*context, program, header, nonce, mix, final_hash);

        ethash::hash256 reference_header;
        std::memcpy(reference_header.bytes, header, 32);
        const ethash::result want =
            progpow::hash(*context, block, reference_header, nonce);

        if (std::memcmp(mix, want.mix_hash.bytes, 32) != 0 ||
            std::memcmp(final_hash, want.final_hash.bytes, 32) != 0) {
            fail("trial %u: the interpreter and the reference disagree on a "
                 "header nobody published", trial);
            std::printf("  reference mix    %s\n  interpreter mix  %s\n",
                        to_hex(want.mix_hash.bytes).c_str(), to_hex(mix).c_str());
            std::printf("  reference final  %s\n  interpreter fin  %s\n",
                        to_hex(want.final_hash.bytes).c_str(),
                        to_hex(final_hash).c_str());
        }
    }
}

// The one failure the vectors above cannot see. An interpreter that skipped a
// word of the program -- read `src1` twice and never `src2`, took a destination
// from the wrong offset, ignored a selector's high bits -- computes a hash that
// is stable, plausible and wrong only on inputs where that word mattered. The
// vectors would then pass or fail for reasons unrelated to the word.
//
// So every word is perturbed in turn and the answer must move. This says the
// program is live specification word for word and not, say, two words fewer
// with two the interpreter never looks at.
//
// "Every word" means every word this fork's shape reaches. The layout is sized
// for the widest fork of the family rather than for KawPoW, so KawPoW's own
// program leaves the twelfth cache read's three words unwritten -- and those
// must change nothing, which is the same statement about the layout from the
// other side.
bool word_is_live(const pp::Params &fork, uint32_t i)
{
    if (i < pp::kMathBase)
        return i < pp::kCacheBase + fork.cache_ops * pp::kCacheWords;
    if (i < pp::kDagBase)
        return i < pp::kMathBase + fork.math_ops * pp::kMathWords;
    return true;
}

void check_every_word_is_read(EpochCache &cache)
{
    const int block = 0;
    const ethash::epoch_context *context = cache.get(0);
    if (!context)
        return;

    uint8_t header[32];
    uint64_t nonce = 0;
    if (!parse_hash(kVectors[0].header_hash, header) ||
        !parse_nonce(kVectors[0].nonce, &nonce)) {
        fail("the perturbation test's own vector does not parse");
        return;
    }

    Program program;
    build_program(kFork, period_of(kFork, static_cast<uint64_t>(block)),
                  &program);

    uint8_t base_mix[32];
    uint8_t base_final[32];
    hash_kawpow(*context, program, header, nonce, base_mix, base_final);

    for (uint32_t i = 0; i < pp::kProgramWords; i++) {
        Program perturbed = program;
        // Not a single bit: a register index is read modulo nothing and a
        // selector modulo 4 or 11, so flipping the low bit of a register index
        // names a register that exists and flipping a high bit of a selector
        // changes no case. Adding one moves every field it could be.
        //
        // And a register index wraps, because it is an index: 32 registers
        // stop at 31, and a 32 here would be this test handing the interpreter
        // a program no generator can produce and then blaming it for walking off
        // the mix. (It did: one word past a 2 KiB array, padding on x86-64 and
        // the stack canary on aarch64.)
        perturbed.word[i] = pp::names_a_register(i)
                                ? (perturbed.word[i] + 1) % kFork.regs
                                : perturbed.word[i] + 1;

        uint8_t mix[32];
        uint8_t final_hash[32];
        hash_kawpow(*context, perturbed, header, nonce, mix, final_hash);

        const bool moved = std::memcmp(mix, base_mix, 32) != 0;
        if (word_is_live(kFork, i) && !moved)
            fail("program word %u changed nothing -- the interpreter does not "
                 "read it, and it is not part of the specification it looks "
                 "like it is part of", i);
        if (!word_is_live(kFork, i) && moved)
            fail("program word %u is past this fork's shape and changed the "
                 "answer anyway -- the interpreter runs an operation the fork "
                 "does not have", i);
    }
}

// What the program is a function of, stated rather than inferred. A miner that
// rebuilt it per block would waste two rebuilds in three and still mine; one
// that rebuilt it per epoch would mine 2500 blocks on the wrong program and look
// like a broken kernel.
void check_period()
{
    if (kFork.period_length != 3)
        fail("the program changes every %u blocks, not 3", kFork.period_length);

    Program a;
    Program b;
    Program c;
    build_program(kFork, period_of(kFork, 30000), &a);
    build_program(kFork, period_of(kFork, 30002), &b);
    build_program(kFork, period_of(kFork, 30003), &c);

    if (std::memcmp(&a, &b, sizeof a) != 0)
        fail("two blocks of the same period got different programs");
    if (std::memcmp(&a, &c, sizeof a) == 0)
        fail("the next period got the same program -- the height is not "
             "reaching the generator");

    // What the Fisher-Yates shuffle is there for, checked on the program rather
    // than on the shuffle: a round writes 32 destinations -- 11 cache, 18 math
    // and 3 DAG merges, the fourth being fixed at register 0 and drawing
    // nothing -- which is exactly one pass of the shuffled sequence. So the 32
    // must be a permutation of the registers: every register written once per
    // round, none twice, none left holding a whole period's stale value.
    const uint32_t regs = kFork.regs;
    bool seen[pp::kMaxRegs] = {false};
    uint32_t drawn = 0;
    for (uint32_t i = 0; i < kFork.cache_ops; i++) {
        seen[a.word[pp::kCacheBase + i * pp::kCacheWords + 1] % regs] = true;
        drawn++;
    }
    for (uint32_t i = 0; i < kFork.math_ops; i++) {
        seen[a.word[pp::kMathBase + i * pp::kMathWords + 3] % regs] = true;
        drawn++;
    }
    for (uint32_t i = 1; i < pp::kDagLoads; i++) {
        seen[a.word[pp::kDagBase + i * pp::kDagWords] % kFork.regs] = true;
        drawn++;
    }

    // The invariant both interpreters index the mix with unchecked, and the one
    // the perturbation below has to preserve to be testing anything.
    for (uint32_t i = 0; i < pp::kProgramWords; i++)
        if (pp::names_a_register(i) && a.word[i] >= kFork.regs)
            fail("program word %u names register %u, and there are %u", i,
                 a.word[i], kFork.regs);

    uint32_t distinct = 0;
    for (bool s : seen)
        distinct += s ? 1 : 0;
    if (drawn != kFork.regs)
        fail("a round draws %u destinations, not %u -- it is no longer one pass "
             "of the sequence and the permutation says nothing", drawn,
             kFork.regs);
    else if (distinct != drawn)
        fail("the %u destinations of a round name only %u registers -- the "
             "destination sequence is not a permutation", drawn, distinct);
}

// The fork table itself, which is the only thing separating five coins and is
// five rows of numbers nobody can read back off a chain.
//
// Two properties, both of which a typo breaks silently. A fork wider than the
// layout every shader is compiled against would index past the mix; and in each
// branded fork the final absorb repeats the first nine words of the seed
// absorb, which the table states twice so that FiroPoW -- whose two are
// unrelated -- needs no special case. A wrong digit in the second copy mines a
// chain nobody runs, and nothing else here would notice.
void check_fork_table()
{
    const pp::Params *forks[] = {
        &pp::kKawpow, &pp::kMeowpow, &pp::kEvrprogpow, &pp::kFiropow,
        &pp::kMeraki,
    };

    for (const pp::Params *f : forks) {
        if (f->regs > pp::kMaxRegs || f->cache_ops > pp::kMaxCacheOps ||
            f->math_ops > pp::kMaxMathOps || f->rounds > pp::kMaxRounds)
            fail("%s is wider than the layout the shaders are built for",
                 f->name);
        if (!f->period_length || !f->epoch_length)
            fail("%s divides by zero somewhere", f->name);

        // FiroPoW's two absorbs are two different padded states and not one
        // repeated; see the table.
        if (f == &pp::kFiropow)
            continue;
        for (uint32_t i = 0; i < pp::kSealFinalWords; i++)
            if (f->seal_final[i] != f->seal_seed[i])
                fail("%s: seal word %u is 0x%08x where it ends and 0x%08x "
                     "where it starts", f->name, i, f->seal_final[i],
                     f->seal_seed[i]);
    }
}

}  // namespace

int main()
{
    check_fork_table();
    check_period();

    EpochCache cache;
    for (const Vector &vector : kVectors)
        check_vector(cache, vector);

    check_against_reference(cache);
    check_every_word_is_read(cache);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    // KawPoW's own words, not the layout's: the three the widest fork of the
    // family adds are checked above for staying inert here.
    uint32_t live = 0;
    for (uint32_t i = 0; i < pp::kProgramWords; i++)
        live += word_is_live(kFork, i) ? 1u : 0u;

    const size_t vectors = sizeof kVectors / sizeof kVectors[0];
    std::printf("kawpow: %zu official vectors reproduce from a %u-word program, "
                "8 unpublished headers agree with the reference, and every one "
                "of those words changes the answer\n",
                vectors, live);
    return 0;
}
