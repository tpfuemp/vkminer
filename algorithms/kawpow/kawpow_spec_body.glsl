// KawPoW, specialized: the period's program is the pipeline, not the data.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The body of the kernel, included by kawpow_spec.comp and kawpow_spec_sub.comp
// -- one text, two modules, differing in how the sixteen lanes exchange a word.
// See shaders/common/kawpow_lanes.glsl for what that difference is and why it
// cannot be a specialization constant.
//
// The same 64 rounds as kawpow.comp and the same answers, spelled the other
// way. There the program is 131 words in workgroup memory, read an index and a
// selector at a time; here it is 131 specialization constants the driver
// resolves at vkCreateComputePipelines, so a register index becomes a register,
// a selector becomes an instruction, and the switch statements below are not in
// the binary this compiles to.
//
// That makes the pipeline the compile: a new period is a new pipeline, built on
// a background thread while the current one is still mining. The backend keys
// them by a number it cannot read (Algorithm::program_key) and knows nothing
// about periods, blocks or chains.
//
// Everything that is not the program is identical to kawpow.comp line for line
// -- the keccak, the seeding, the lane exchange, the fold and the emit. The two
// are differentially tested against each other, and that test is only worth
// something if the difference between them is the one thing it is about.

#ifndef VKMINER_ALGORITHMS_KAWPOW_SPEC_BODY_GLSL_INCLUDED
#define VKMINER_ALGORITHMS_KAWPOW_SPEC_BODY_GLSL_INCLUDED

#include "shaders/common/bits.glsl"
#include "shaders/common/candidates.glsl"

// The DAG. Binding 0 is the candidate buffer, so the table starts after it.
#define SHARED_TABLE_BINDING 1
#include "shaders/common/shared_table.glsl"

#include "shaders/common/keccak_f800.glsl"

layout(local_size_x_id = 0) in;

// The same 92-byte block kawpow.comp declares and KawpowPush fills: one
// algorithm prepares dispatches for both kernels without knowing which. The
// period and the table's length are dead here, being constants below, but stay
// so the block keeps its layout.
layout(push_constant) uniform Push {
    uint header[8];    // the 32-byte header hash, little-endian words
    uint target[8];    // as fulltest() compares: little-endian, most significant last
    uint nonce_lo;     // the nonce is 64 bits and the pool owns its top two bytes
    uint nonce_hi;
    uint count;        // nonces to test, which is a sixteenth of the invocations
    uint capacity;     // candidates the result buffer can hold
    uint period_lo;    // compiled in here; see kDagSel3 and the constants below
    uint period_hi;
    uint dag_lines;    // compiled in here too, as kDagLines
} push;

// ------------------------------------------------------------- the shape of it
//
// The constants that make this KawPoW rather than another ProgPoW: the
// algorithm, not a tuning point. The host has the same numbers in
// kawpow_program.h.

const uint kLanes    = 16u;
const uint kRegs     = 32u;
const uint kRounds   = 64u;
const uint kDagLoads = 4u;

// Words of a 256-byte DAG line, and words of the 16 KiB the cache operations
// read. That cache is the first 16 KiB of the DAG itself -- word i of it is
// word i of the table -- so there is nothing separate to bind.
const uint kLineWords = kLanes * kDagLoads;
const uint kL1Words   = 16u * 1024u / 4u;

const uint kFnvPrime = 0x01000193u;
const uint kFnvOffsetBasis = 0x811c9dc5u;

// The fifteen words KawPoW pads its keccak state with, where Ethash's ProgPoW
// pads with zeros -- the only thing separating this chain's hash from another
// fork's. The first is 0x72, a lower-case 'r', which is upstream's typo and
// is now what the whole network hashes. Written as numbers because written as
// characters is how it gets silently corrected.
const uint kRavencoinKawpow[15] = uint[15](
    0x00000072u, 0x00000041u, 0x00000056u, 0x00000045u, 0x0000004eu,
    0x00000043u, 0x0000004fu, 0x00000049u, 0x0000004eu, 0x0000004bu,
    0x00000041u, 0x00000057u, 0x00000050u, 0x0000004fu, 0x00000057u);

// -------------------------------------------------------------- the program
//
// One constant per word of what kawpow_program.cpp generates, in that order and
// from constant ID 8 -- zero to three are the backend's own and four to seven
// are spare, see kProgramConstantId. The defaults are not a program: the
// backend refuses to dispatch until a pipeline is built with the period's real
// values.
//
// The order is the contract. The host writes Program::word[] straight into
// these, and a constant declared at the wrong ID produces a plausible program
// that is not this period's.

// The eleven cache reads: which register indexes the 16 KiB, which one the
// result is merged into, and how.
layout(constant_id =   8) const uint kCacheSrc0   = 0u;
layout(constant_id =   9) const uint kCacheDst0   = 0u;
layout(constant_id =  10) const uint kCacheSel0   = 0u;

layout(constant_id =  11) const uint kCacheSrc1   = 0u;
layout(constant_id =  12) const uint kCacheDst1   = 0u;
layout(constant_id =  13) const uint kCacheSel1   = 0u;

layout(constant_id =  14) const uint kCacheSrc2   = 0u;
layout(constant_id =  15) const uint kCacheDst2   = 0u;
layout(constant_id =  16) const uint kCacheSel2   = 0u;

layout(constant_id =  17) const uint kCacheSrc3   = 0u;
layout(constant_id =  18) const uint kCacheDst3   = 0u;
layout(constant_id =  19) const uint kCacheSel3   = 0u;

layout(constant_id =  20) const uint kCacheSrc4   = 0u;
layout(constant_id =  21) const uint kCacheDst4   = 0u;
layout(constant_id =  22) const uint kCacheSel4   = 0u;

layout(constant_id =  23) const uint kCacheSrc5   = 0u;
layout(constant_id =  24) const uint kCacheDst5   = 0u;
layout(constant_id =  25) const uint kCacheSel5   = 0u;

layout(constant_id =  26) const uint kCacheSrc6   = 0u;
layout(constant_id =  27) const uint kCacheDst6   = 0u;
layout(constant_id =  28) const uint kCacheSel6   = 0u;

layout(constant_id =  29) const uint kCacheSrc7   = 0u;
layout(constant_id =  30) const uint kCacheDst7   = 0u;
layout(constant_id =  31) const uint kCacheSel7   = 0u;

layout(constant_id =  32) const uint kCacheSrc8   = 0u;
layout(constant_id =  33) const uint kCacheDst8   = 0u;
layout(constant_id =  34) const uint kCacheSel8   = 0u;

layout(constant_id =  35) const uint kCacheSrc9   = 0u;
layout(constant_id =  36) const uint kCacheDst9   = 0u;
layout(constant_id =  37) const uint kCacheSel9   = 0u;

layout(constant_id =  38) const uint kCacheSrc10  = 0u;
layout(constant_id =  39) const uint kCacheDst10  = 0u;
layout(constant_id =  40) const uint kCacheSel10  = 0u;

// The eighteen arithmetic operations: two source registers, which operation,
// the destination, and how the result is merged into it.
layout(constant_id =  41) const uint kMathA0      = 0u;
layout(constant_id =  42) const uint kMathB0      = 0u;
layout(constant_id =  43) const uint kMathOp0     = 0u;
layout(constant_id =  44) const uint kMathDst0    = 0u;
layout(constant_id =  45) const uint kMathSel0    = 0u;

layout(constant_id =  46) const uint kMathA1      = 0u;
layout(constant_id =  47) const uint kMathB1      = 0u;
layout(constant_id =  48) const uint kMathOp1     = 0u;
layout(constant_id =  49) const uint kMathDst1    = 0u;
layout(constant_id =  50) const uint kMathSel1    = 0u;

layout(constant_id =  51) const uint kMathA2      = 0u;
layout(constant_id =  52) const uint kMathB2      = 0u;
layout(constant_id =  53) const uint kMathOp2     = 0u;
layout(constant_id =  54) const uint kMathDst2    = 0u;
layout(constant_id =  55) const uint kMathSel2    = 0u;

layout(constant_id =  56) const uint kMathA3      = 0u;
layout(constant_id =  57) const uint kMathB3      = 0u;
layout(constant_id =  58) const uint kMathOp3     = 0u;
layout(constant_id =  59) const uint kMathDst3    = 0u;
layout(constant_id =  60) const uint kMathSel3    = 0u;

layout(constant_id =  61) const uint kMathA4      = 0u;
layout(constant_id =  62) const uint kMathB4      = 0u;
layout(constant_id =  63) const uint kMathOp4     = 0u;
layout(constant_id =  64) const uint kMathDst4    = 0u;
layout(constant_id =  65) const uint kMathSel4    = 0u;

layout(constant_id =  66) const uint kMathA5      = 0u;
layout(constant_id =  67) const uint kMathB5      = 0u;
layout(constant_id =  68) const uint kMathOp5     = 0u;
layout(constant_id =  69) const uint kMathDst5    = 0u;
layout(constant_id =  70) const uint kMathSel5    = 0u;

layout(constant_id =  71) const uint kMathA6      = 0u;
layout(constant_id =  72) const uint kMathB6      = 0u;
layout(constant_id =  73) const uint kMathOp6     = 0u;
layout(constant_id =  74) const uint kMathDst6    = 0u;
layout(constant_id =  75) const uint kMathSel6    = 0u;

layout(constant_id =  76) const uint kMathA7      = 0u;
layout(constant_id =  77) const uint kMathB7      = 0u;
layout(constant_id =  78) const uint kMathOp7     = 0u;
layout(constant_id =  79) const uint kMathDst7    = 0u;
layout(constant_id =  80) const uint kMathSel7    = 0u;

layout(constant_id =  81) const uint kMathA8      = 0u;
layout(constant_id =  82) const uint kMathB8      = 0u;
layout(constant_id =  83) const uint kMathOp8     = 0u;
layout(constant_id =  84) const uint kMathDst8    = 0u;
layout(constant_id =  85) const uint kMathSel8    = 0u;

layout(constant_id =  86) const uint kMathA9      = 0u;
layout(constant_id =  87) const uint kMathB9      = 0u;
layout(constant_id =  88) const uint kMathOp9     = 0u;
layout(constant_id =  89) const uint kMathDst9    = 0u;
layout(constant_id =  90) const uint kMathSel9    = 0u;

layout(constant_id =  91) const uint kMathA10     = 0u;
layout(constant_id =  92) const uint kMathB10     = 0u;
layout(constant_id =  93) const uint kMathOp10    = 0u;
layout(constant_id =  94) const uint kMathDst10   = 0u;
layout(constant_id =  95) const uint kMathSel10   = 0u;

layout(constant_id =  96) const uint kMathA11     = 0u;
layout(constant_id =  97) const uint kMathB11     = 0u;
layout(constant_id =  98) const uint kMathOp11    = 0u;
layout(constant_id =  99) const uint kMathDst11   = 0u;
layout(constant_id = 100) const uint kMathSel11   = 0u;

layout(constant_id = 101) const uint kMathA12     = 0u;
layout(constant_id = 102) const uint kMathB12     = 0u;
layout(constant_id = 103) const uint kMathOp12    = 0u;
layout(constant_id = 104) const uint kMathDst12   = 0u;
layout(constant_id = 105) const uint kMathSel12   = 0u;

layout(constant_id = 106) const uint kMathA13     = 0u;
layout(constant_id = 107) const uint kMathB13     = 0u;
layout(constant_id = 108) const uint kMathOp13    = 0u;
layout(constant_id = 109) const uint kMathDst13   = 0u;
layout(constant_id = 110) const uint kMathSel13   = 0u;

layout(constant_id = 111) const uint kMathA14     = 0u;
layout(constant_id = 112) const uint kMathB14     = 0u;
layout(constant_id = 113) const uint kMathOp14    = 0u;
layout(constant_id = 114) const uint kMathDst14   = 0u;
layout(constant_id = 115) const uint kMathSel14   = 0u;

layout(constant_id = 116) const uint kMathA15     = 0u;
layout(constant_id = 117) const uint kMathB15     = 0u;
layout(constant_id = 118) const uint kMathOp15    = 0u;
layout(constant_id = 119) const uint kMathDst15   = 0u;
layout(constant_id = 120) const uint kMathSel15   = 0u;

layout(constant_id = 121) const uint kMathA16     = 0u;
layout(constant_id = 122) const uint kMathB16     = 0u;
layout(constant_id = 123) const uint kMathOp16    = 0u;
layout(constant_id = 124) const uint kMathDst16   = 0u;
layout(constant_id = 125) const uint kMathSel16   = 0u;

layout(constant_id = 126) const uint kMathA17     = 0u;
layout(constant_id = 127) const uint kMathB17     = 0u;
layout(constant_id = 128) const uint kMathOp17    = 0u;
layout(constant_id = 129) const uint kMathDst17   = 0u;
layout(constant_id = 130) const uint kMathSel17   = 0u;

// The four DAG merges that end a round. The first writes register 0 --
// where the next round's line index comes from -- in every period there is.
layout(constant_id = 131) const uint kDagDst0     = 0u;
layout(constant_id = 132) const uint kDagSel0     = 0u;

layout(constant_id = 133) const uint kDagDst1     = 0u;
layout(constant_id = 134) const uint kDagSel1     = 0u;

layout(constant_id = 135) const uint kDagDst2     = 0u;
layout(constant_id = 136) const uint kDagSel2     = 0u;

layout(constant_id = 137) const uint kDagDst3     = 0u;
layout(constant_id = 138) const uint kDagSel3     = 0u;

// Lines in the table, which is the epoch rather than the period. Here for the
// same reason as the rest: a constant modulus is a multiply and a shift, and a
// push constant is a division, once per round for the life of the kernel.
layout(constant_id = 139) const uint kDagLines    = 1u;

// How the lanes talk. Included here rather than at the top because it is
// written in terms of kLanes, declared just above. There is no program array
// here either way: that is the difference this file is.
#include "shaders/common/kawpow_lanes.glsl"

// ------------------------------------------------------------------- the RNGs
//
// FNV-1a and KISS99. In the interpreter this pair does two jobs -- generate the
// program and fill the mix registers a hash starts from. Here the program
// arrived compiled, so only the second is left.

uint fnv1a(uint u, uint v)
{
    return (u ^ v) * kFnvPrime;
}

uint g_z, g_w, g_jsr, g_jcong;

void kiss99_seed(uint z, uint w, uint jsr, uint jcong)
{
    g_z = z;
    g_w = w;
    g_jsr = jsr;
    g_jcong = jcong;
}

uint kiss99()
{
    g_z = 36969u * (g_z & 0xffffu) + (g_z >> 16);
    g_w = 18000u * (g_w & 0xffffu) + (g_w >> 16);

    g_jcong = 69069u * g_jcong + 1234567u;

    g_jsr ^= g_jsr << 17;
    g_jsr ^= g_jsr >> 13;
    g_jsr ^= g_jsr << 5;

    return (((g_z << 16) + g_w) ^ g_jcong) + g_jsr;
}

// ------------------------------------------------- what the program's words do
//
// Byte for byte what kawpow.comp has, and called with constants rather than
// with words read out of a buffer. Each switch is over a specialization
// constant, so the compiler keeps one arm and deletes the statement.

// bits.glsl's rotate is undefined at zero and these are not: the shift count
// comes from the mix, so 0 and 32 both occur. The reference masks to five bits
// and so must this.
uint rot32(uint x, uint n)
{
    n &= 31u;
    return n == 0u ? x : ((x << n) | (x >> (32u - n)));
}

uint mul_hi32(uint a, uint b)
{
    uint hi, lo;
    umulExtended(a, b, hi, lo);
    return hi;
}

// findMSB is -1 for zero, which makes this 32 -- the count the reference's loop
// arrives at, and the one case a leading-zero count has to be told about.
uint clz32(uint x)
{
    return uint(31 - findMSB(x));
}

uint random_math(uint a, uint b, uint selector)
{
    switch (selector % 11u) {
    default:
    case 0u:  return a + b;
    case 1u:  return a * b;
    case 2u:  return mul_hi32(a, b);
    case 3u:  return min(a, b);
    case 4u:  return rot32(a, b);
    case 5u:  return rot32(a, 32u - (b & 31u));
    case 6u:  return a & b;
    case 7u:  return a | b;
    case 8u:  return a ^ b;
    case 9u:  return clz32(a) + clz32(b);
    case 10u: return bitCount(a) + bitCount(b);
    }
}

// Fold `b` into `a`, where `a` is assumed to carry the entropy: every case
// keeps it, which is why there is no `a & b` here and there is one above. The
// rotation comes from the selector's high bits and is forced into 1..31, so
// unlike random_math this one can never rotate by zero.
uint random_merge(uint a, uint b, uint selector)
{
    uint x = (selector >> 16) % 31u + 1u;

    switch (selector % 4u) {
    default:
    case 0u: return (a * 33u) + b;
    case 1u: return (a ^ b) * 33u;
    case 2u: return rot32(a, x) ^ b;
    case 3u: return rot32(a, 32u - x) ^ b;
    }
}

// ------------------------------------------------------------- one round, once
//
// ProgPoW generates a single body and runs it for all 64 rounds -- only the DAG
// line differs -- so the program is written out once and the round loop stays a
// loop. Macros rather than a function per operation, because every argument has
// to reach the compiler as the constant it is and a parameter would be a value.
//
// The interleaving is the specification: one cache read and one arithmetic
// operation per step for as long as there are both, then the arithmetic alone.
// Reordering them into two runs produces a different and entirely
// plausible-looking hash.

#define CACHE_OP(src, dst, sel) \
    mix[dst] = random_merge(mix[dst], shared_word(mix[src] % kL1Words), sel)

#define MATH_OP(a, b, op, dst, sel) \
    mix[dst] = random_merge(mix[dst], random_math(mix[a], mix[b], op), sel)

#define DAG_OP(dst, sel, word) \
    mix[dst] = random_merge(mix[dst], shared_word(word), sel)

// ------------------------------------------------------------------ the kernel

void main()
{
    uint lane = kawpow_lane();
    uint nonce_index = kawpow_nonce_index();

    // No early return for the invocations past the end of the dispatch.
    // Every exchange below has to be reached by every invocation of the group
    // -- a barrier by all of the workgroup, a shuffle by all of the subgroup --
    // so the padding runs the whole hash and only the emit is guarded. It
    // hashes a nonce nobody asked for, in range and harmless.

    uint nonce_lo = push.nonce_lo + nonce_index;
    uint nonce_hi = push.nonce_hi + (nonce_lo < push.nonce_lo ? 1u : 0u);

    // Header, nonce and the fork's fifteen words, absorbed in one go: the state
    // is exactly 25 words and all of them are written, so there is no padding
    // rule and no rate. All sixteen lanes compute the same permutation rather
    // than one broadcasting it -- 22 rounds, against a barrier to save them.
    uint seed[25];
    for (uint i = 0u; i < 8u; i++)
        seed[i] = push.header[i];
    seed[8] = nonce_lo;
    seed[9] = nonce_hi;
    for (uint i = 10u; i < 25u; i++)
        seed[i] = kRavencoinKawpow[i - 10u];
    keccak_f800(seed);

    // The 32 words this lane starts from. Each lane runs its own KISS99, seeded
    // from the digest and from the lane number, so the lanes start different
    // and no lane needs another to fill its registers.
    uint mix[kRegs];
    {
        uint z = fnv1a(kFnvOffsetBasis, seed[0]);
        uint w = fnv1a(z, seed[1]);
        kiss99_seed(z, w, fnv1a(w, lane), fnv1a(fnv1a(w, lane), lane));
        for (uint i = 0u; i < kRegs; i++)
            mix[i] = kiss99();
    }

    for (uint r = 0u; r < kRounds; r++) {
        // The one value a round takes from the mix rather than from the
        // program, and the reason the DAG cannot be prefetched: lane r%16's
        // register 0, read by all sixteen.
        uint line = kawpow_broadcast(mix[0], r % kLanes) % kDagLines;

        CACHE_OP(kCacheSrc0, kCacheDst0, kCacheSel0);
        MATH_OP(kMathA0, kMathB0, kMathOp0, kMathDst0, kMathSel0);
        CACHE_OP(kCacheSrc1, kCacheDst1, kCacheSel1);
        MATH_OP(kMathA1, kMathB1, kMathOp1, kMathDst1, kMathSel1);
        CACHE_OP(kCacheSrc2, kCacheDst2, kCacheSel2);
        MATH_OP(kMathA2, kMathB2, kMathOp2, kMathDst2, kMathSel2);
        CACHE_OP(kCacheSrc3, kCacheDst3, kCacheSel3);
        MATH_OP(kMathA3, kMathB3, kMathOp3, kMathDst3, kMathSel3);
        CACHE_OP(kCacheSrc4, kCacheDst4, kCacheSel4);
        MATH_OP(kMathA4, kMathB4, kMathOp4, kMathDst4, kMathSel4);
        CACHE_OP(kCacheSrc5, kCacheDst5, kCacheSel5);
        MATH_OP(kMathA5, kMathB5, kMathOp5, kMathDst5, kMathSel5);
        CACHE_OP(kCacheSrc6, kCacheDst6, kCacheSel6);
        MATH_OP(kMathA6, kMathB6, kMathOp6, kMathDst6, kMathSel6);
        CACHE_OP(kCacheSrc7, kCacheDst7, kCacheSel7);
        MATH_OP(kMathA7, kMathB7, kMathOp7, kMathDst7, kMathSel7);
        CACHE_OP(kCacheSrc8, kCacheDst8, kCacheSel8);
        MATH_OP(kMathA8, kMathB8, kMathOp8, kMathDst8, kMathSel8);
        CACHE_OP(kCacheSrc9, kCacheDst9, kCacheSel9);
        MATH_OP(kMathA9, kMathB9, kMathOp9, kMathDst9, kMathSel9);
        CACHE_OP(kCacheSrc10, kCacheDst10, kCacheSel10);
        MATH_OP(kMathA10, kMathB10, kMathOp10, kMathDst10, kMathSel10);
        MATH_OP(kMathA11, kMathB11, kMathOp11, kMathDst11, kMathSel11);
        MATH_OP(kMathA12, kMathB12, kMathOp12, kMathDst12, kMathSel12);
        MATH_OP(kMathA13, kMathB13, kMathOp13, kMathDst13, kMathSel13);
        MATH_OP(kMathA14, kMathB14, kMathOp14, kMathDst14, kMathSel14);
        MATH_OP(kMathA15, kMathB15, kMathOp15, kMathDst15, kMathSel15);
        MATH_OP(kMathA16, kMathB16, kMathOp16, kMathDst16, kMathSel16);
        MATH_OP(kMathA17, kMathB17, kMathOp17, kMathDst17, kMathSel17);

        // A lane's four words are not its own quarter of the line: the
        // offset is (lane ^ r), so which lane reads which quarter changes every
        // round and the sixteen between them still cover all 256 bytes.
        uint word = line * kLineWords + ((lane ^ r) % kLanes) * kDagLoads;
        DAG_OP(kDagDst0, kDagSel0, word);
        DAG_OP(kDagDst1, kDagSel1, word + 1u);
        DAG_OP(kDagDst2, kDagSel2, word + 2u);
        DAG_OP(kDagDst3, kDagSel3, word + 3u);
    }

    // 512 words down to 16.
    uint lane_hash = kFnvOffsetBasis;
    for (uint i = 0u; i < kRegs; i++)
        lane_hash = fnv1a(lane_hash, mix[i]);

    kawpow_publish(lane_hash);

    // ...and 16 down to 8, where the lanes finally meet: lane l lands in word
    // l % 8, so each word takes two lanes in lane order.
    uint mix_hash[8];
    for (uint i = 0u; i < 8u; i++)
        mix_hash[i] = kFnvOffsetBasis;
    //
    // All sixteen lanes do this fold and fifteen throw it away. Only lane 0
    // emits, but a shuffle reads a register out of an invocation that must
    // still be running, so no lane may leave before the loop below is over.
    for (uint l = 0u; l < kLanes; l++)
        mix_hash[l % 8u] = fnv1a(mix_hash[l % 8u], kawpow_published(l));

    if (lane != 0u)
        return;

    // The final absorb carries the first keccak's digest forward rather than
    // the header: what a verifier is given is the mix hash and the nonce, and
    // it recomputes this half without touching the DAG at all.
    uint last[25];
    for (uint i = 0u; i < 8u; i++)
        last[i] = seed[i];
    for (uint i = 8u; i < 16u; i++)
        last[i] = mix_hash[i - 8u];
    for (uint i = 16u; i < 25u; i++)
        last[i] = kRavencoinKawpow[i - 16u];
    keccak_f800(last);

    // Both a reversal and a byte swap. KawPoW's digest is eight
    // little-endian words and its first byte is the most significant of the
    // 256-bit number; the target comparison wants the most significant word
    // last, with its own bytes in place. So word j is word 7-j, swapped.
    uint state[8];
    for (uint j = 0u; j < 8u; j++)
        state[j] = bswap32(last[7u - j]);

    if (nonce_index >= push.count)
        return;

    probe_best(state[7]);

    if (state[7] > push.target[7])
        return;

    // The full 256-bit comparison, most significant word first. It repeats the
    // screen deliberately: the screen decides what to skip computing, this
    // decides what is a share.
    for (int i = 7; i >= 0; i--) {
        if (state[i] > push.target[i])
            return;
        if (state[i] < push.target[i])
            break;
    }

    emit_candidate64(push.capacity, nonce_lo, nonce_hi, state);
}

#endif  // VKMINER_ALGORITHMS_KAWPOW_SPEC_BODY_GLSL_INCLUDED
