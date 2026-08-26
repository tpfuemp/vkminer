// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/kawpow/kawpow_hash.h"

namespace vkminer {
namespace kawpow {
namespace {

// ------------------------------------------------------------- keccak-f[800]
//
// Keccak's permutation over 32-bit lanes: the same structure as the f[1600]
// this project already has for sha3t, with 22 rounds instead of 24, the round
// constants truncated to their low half, and the rotation offsets taken mod 32.
// It is a different permutation, not a narrower call into the same one, and
// the one thing it buys is that KawPoW needs no `shaderInt64` at all.
//
// Written as a loop over tables rather than unrolled, because that is the form
// a shader wants and because two implementations that share a shape share their
// mistakes.

const uint32_t kRoundConstants[22] = {
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
    0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
    0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
    0x0000800a, 0x8000000a, 0x80008081, 0x00008080,
};

// Rho, in state order: f[1600]'s offsets reduced mod 32. Lane 0 is not rotated,
// which is why the rotate below has to tolerate a zero.
const uint32_t kRho[25] = {
    0,  1,  30, 28, 27, 4,  12, 6,  23, 20, 3, 10, 11,
    25, 7,  9,  13, 15, 21, 8,  18, 2,  29, 24, 14,
};

uint32_t rotl32(uint32_t x, uint32_t n)
{
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

void keccak_f800(uint32_t st[25])
{
    for (uint32_t round = 0; round < 22; round++) {
        uint32_t c[5];
        for (uint32_t x = 0; x < 5; x++)
            c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];

        for (uint32_t x = 0; x < 5; x++) {
            const uint32_t d = c[(x + 4) % 5] ^ rotl32(c[(x + 1) % 5], 1);
            for (uint32_t y = 0; y < 5; y++)
                st[x + 5 * y] ^= d;
        }

        // Rho and pi together: lane (x, y) rotates by its own offset and moves
        // to (y, 2x + 3y).
        uint32_t b[25];
        for (uint32_t y = 0; y < 5; y++) {
            for (uint32_t x = 0; x < 5; x++) {
                const uint32_t from = x + 5 * y;
                const uint32_t to = y + 5 * ((2 * x + 3 * y) % 5);
                b[to] = rotl32(st[from], kRho[from]);
            }
        }

        for (uint32_t y = 0; y < 5; y++) {
            for (uint32_t x = 0; x < 5; x++)
                st[x + 5 * y] = b[x + 5 * y]
                              ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }

        st[0] ^= kRoundConstants[round];
    }
}

// ----------------------------------------------- what the program's words do
//
// Two operations, selected by a word of the program rather than by anything the
// hash computed, so every lane and every nonce takes the same branch. That is
// the property the whole restructuring rests on: a device can run these as
// sixteen lanes in lockstep, and a specialized kernel can resolve the selector
// at compile time and emit one instruction.

uint32_t clz32(uint32_t x)
{
    uint32_t n = 0;
    while (n < 32 && (x & 0x80000000u) == 0) {
        x <<= 1;
        n++;
    }
    return n;
}

uint32_t popcount32(uint32_t x)
{
    uint32_t n = 0;
    while (x) {
        n += x & 1;
        x >>= 1;
    }
    return n;
}

uint32_t mul_hi32(uint32_t a, uint32_t b)
{
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(a) * static_cast<uint64_t>(b)) >> 32);
}

// Cases 4 and 5 rotate by a value the *mix* produced, so the shift count is
// unconstrained and 0 and 32 both occur. The reference masks it to five bits
// and so must anything else: GLSL's shift by 32 is undefined, and a rotate that
// happens to be a no-op is a legitimate result, not a case to skip.
uint32_t random_math(uint32_t a, uint32_t b, uint32_t selector)
{
    switch (selector % 11) {
    default:
    case 0:
        return a + b;
    case 1:
        return a * b;
    case 2:
        return mul_hi32(a, b);
    case 3:
        return a < b ? a : b;
    case 4:
        return rotl32(a, b & 31);
    case 5:
        return rotl32(a, (32 - (b & 31)) & 31);
    case 6:
        return a & b;
    case 7:
        return a | b;
    case 8:
        return a ^ b;
    case 9:
        return clz32(a) + clz32(b);
    case 10:
        return popcount32(a) + popcount32(b);
    }
}

// Fold `b` into `a`, where `a` is assumed to carry the entropy: every case
// keeps it, which is why there is no `a & b` here and there is one above. The
// rotation amount comes from the selector's high bits and is forced into 1..31,
// so unlike random_math this one can never rotate by zero.
void random_merge(uint32_t *a, uint32_t b, uint32_t selector)
{
    const uint32_t x = (selector >> 16) % 31 + 1;

    switch (selector % 4) {
    case 0:
        *a = (*a * 33) + b;
        break;
    case 1:
        *a = (*a ^ b) * 33;
        break;
    case 2:
        *a = rotl32(*a, x) ^ b;
        break;
    case 3:
        *a = rotl32(*a, 32 - x) ^ b;
        break;
    }
}

// -------------------------------------------------------------- the mix itself

// Sized for the widest fork; a narrower one uses a prefix of each lane's row
// and never reads past params.regs.
using Mix = uint32_t[kLanes][kMaxRegs];

// The words a hash starts from, and the only place the header and the nonce
// reach the mix. Each lane runs its own KISS99, seeded from the keccak digest
// and from the lane number -- so the lanes start different, and so a device can
// fill its own registers without talking to any other lane.
void init_mix(const Params &params, uint32_t seed_lo, uint32_t seed_hi, Mix mix)
{
    const uint32_t z = fnv1a(kFnvOffsetBasis, seed_lo);
    const uint32_t w = fnv1a(z, seed_hi);

    for (uint32_t l = 0; l < kLanes; l++) {
        const uint32_t jsr = fnv1a(w, l);
        const uint32_t jcong = fnv1a(jsr, l);
        Kiss99 rng(z, w, jsr, jcong);

        for (uint32_t r = 0; r < params.regs; r++)
            mix[l][r] = rng();
    }
}

// One of the 64 rounds, and the reason the program exists. Nothing is drawn
// here: every register index and every selector is read out of `program`, and
// the only thing that varies from round to round is which line was fetched and
// which quarter of it each lane takes.
void run_round(const Params &params, const Program &program, uint32_t r, Mix mix,
               const uint32_t *line, const uint32_t *l1)
{
    const uint32_t steps = params.cache_ops > params.math_ops ? params.cache_ops
                                                              : params.math_ops;

    for (uint32_t i = 0; i < steps; i++) {
        if (i < params.cache_ops) {
            const uint32_t *op = program.word + kCacheBase + i * kCacheWords;
            const uint32_t src = op[0];
            const uint32_t dst = op[1];
            const uint32_t sel = op[2];

            for (uint32_t l = 0; l < kLanes; l++) {
                const uint32_t offset = mix[l][src] % kL1Words;
                random_merge(&mix[l][dst], l1[offset], sel);
            }
        }
        if (i < params.math_ops) {
            const uint32_t *op = program.word + kMathBase + i * kMathWords;
            const uint32_t src1 = op[0];
            const uint32_t src2 = op[1];
            const uint32_t sel1 = op[2];
            const uint32_t dst = op[3];
            const uint32_t sel2 = op[4];

            for (uint32_t l = 0; l < kLanes; l++) {
                const uint32_t data =
                    random_math(mix[l][src1], mix[l][src2], sel1);
                random_merge(&mix[l][dst], data, sel2);
            }
        }
    }

    // The lane's four words are not its own quarter of the line: the offset
    // is `(l ^ r)`, so which lane reads which quarter changes every round and
    // the sixteen lanes between them still cover the whole 256 bytes.
    for (uint32_t l = 0; l < kLanes; l++) {
        const uint32_t offset = ((l ^ r) % kLanes) * kDagLoads;
        for (uint32_t i = 0; i < kDagLoads; i++) {
            const uint32_t *op = program.word + kDagBase + i * kDagWords;
            random_merge(&mix[l][op[0]], line[offset + i], op[1]);
        }
    }
}

}  // namespace

bool hash(const Params &params, const Program &program, const uint32_t *l1,
          uint64_t dag_lines, const DagLines &dag, const uint32_t header[8],
          uint64_t nonce, Hash *out)
{
    if (!dag_lines)
        return false;

    // Header, nonce and the fork's fifteen seal words, absorbed in one go: the
    // state is exactly 25 words and every one of them is written, so there is
    // no padding rule and no rate to think about.
    uint32_t seed[25];
    for (uint32_t i = 0; i < 8; i++)
        seed[i] = header[i];
    seed[8] = static_cast<uint32_t>(nonce);
    seed[9] = static_cast<uint32_t>(nonce >> 32);
    for (uint32_t i = 10; i < 25; i++)
        seed[i] = params.seal_seed[i - 10];
    keccak_f800(seed);

    Mix mix;
    init_mix(params, seed[0], seed[1], mix);

    for (uint32_t r = 0; r < params.rounds; r++) {
        // The one value a round takes from the mix rather than the program, and
        // the reason the dataset cannot be prefetched: lane r%16's register 0,
        // read by all sixteen lanes. On a device that is a broadcast, and it is
        // the only cross-lane traffic inside the loop.
        const uint64_t index = mix[r % kLanes][0] % dag_lines;

        uint32_t line[kLineWords];
        if (!dag.line(index, line))
            return false;

        run_round(params, program, r, mix, line, l1);
    }

    // The whole mix down to 16 words, and 16 down to 8. The second fold is
    // where the lanes finally meet: lane l lands in word l % 8, so the eight
    // words each take two lanes and the order they are folded in is the lane
    // order.
    uint32_t lane_hash[kLanes];
    for (uint32_t l = 0; l < kLanes; l++) {
        lane_hash[l] = kFnvOffsetBasis;
        for (uint32_t r = 0; r < params.regs; r++)
            lane_hash[l] = fnv1a(lane_hash[l], mix[l][r]);
    }

    for (uint32_t i = 0; i < 8; i++)
        out->mix[i] = kFnvOffsetBasis;
    for (uint32_t l = 0; l < kLanes; l++)
        out->mix[l % 8] = fnv1a(out->mix[l % 8], lane_hash[l]);

    // The final absorb carries the first keccak's digest forward rather than
    // the header: what a verifier is given is the mix hash and the nonce, and
    // it recomputes this half without touching the dataset at all.
    uint32_t last[25];
    for (uint32_t i = 0; i < 8; i++)
        last[i] = seed[i];
    for (uint32_t i = 8; i < 16; i++)
        last[i] = out->mix[i - 8];
    for (uint32_t i = 16; i < 25; i++)
        last[i] = params.seal_final[i - 16];
    keccak_f800(last);

    for (uint32_t i = 0; i < 8; i++)
        out->digest[i] = last[i];
    return true;
}

}  // namespace kawpow
}  // namespace vkminer
