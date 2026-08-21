// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/kawpow/kawpow_program.h"

namespace vkminer {
namespace kawpow {

void build_program(uint64_t period, Program *out)
{
    const uint32_t lo = static_cast<uint32_t>(period);
    const uint32_t hi = static_cast<uint32_t>(period >> 32);

    const uint32_t z = fnv1a(kFnvOffsetBasis, lo);
    const uint32_t w = fnv1a(z, hi);
    const uint32_t jsr = fnv1a(w, lo);
    const uint32_t jcong = fnv1a(jsr, hi);

    Kiss99 rng(z, w, jsr, jcong);

    // Which register each operation writes, and which it reads, are drawn from
    // two shuffled permutations rather than at random: over one pass of 32
    // operations every register is written exactly once, so no register goes
    // untouched for a whole period and none is written twice while another is
    // ignored. Fisher-Yates, from the top down, and the two sequences are
    // interleaved -- one swap of each per step, destinations first.
    uint32_t dst_seq[kRegs];
    uint32_t src_seq[kRegs];
    for (uint32_t i = 0; i < kRegs; i++) {
        dst_seq[i] = i;
        src_seq[i] = i;
    }
    for (uint32_t i = kRegs; i > 1; i--) {
        const uint32_t d = rng() % i;
        const uint32_t t0 = dst_seq[i - 1];
        dst_seq[i - 1] = dst_seq[d];
        dst_seq[d] = t0;

        const uint32_t s = rng() % i;
        const uint32_t t1 = src_seq[i - 1];
        src_seq[i - 1] = src_seq[s];
        src_seq[s] = t1;
    }

    uint32_t dst_counter = 0;
    uint32_t src_counter = 0;
    auto next_dst = [&] { return dst_seq[dst_counter++ % kRegs]; };
    auto next_src = [&] { return src_seq[src_counter++ % kRegs]; };

    // The two kinds of operation are drawn interleaved, one of each per
    // step, for as long as there are both -- eleven steps with a cache read and
    // a math operation, then seven with only math. Drawing all the cache
    // operations first would produce a different and entirely plausible-looking
    // program.
    const uint32_t steps = kCacheOps > kMathOps ? kCacheOps : kMathOps;
    for (uint32_t i = 0; i < steps; i++) {
        if (i < kCacheOps) {
            const uint32_t src = next_src();
            const uint32_t dst = next_dst();
            const uint32_t sel = rng();

            uint32_t *op = out->word + kCacheBase + i * kCacheWords;
            op[0] = src;
            op[1] = dst;
            op[2] = sel;
        }
        if (i < kMathOps) {
            // Two *different* source registers, from one draw: the second is
            // taken from the range with the first removed and shifted back into
            // place, which is why it is not simply two independent numbers.
            const uint32_t src_rnd = rng() % (kRegs * (kRegs - 1));
            const uint32_t src1 = src_rnd % kRegs;
            uint32_t src2 = src_rnd / kRegs;
            if (src2 >= src1)
                src2++;

            const uint32_t sel1 = rng();
            const uint32_t dst = next_dst();
            const uint32_t sel2 = rng();

            uint32_t *op = out->word + kMathBase + i * kMathWords;
            op[0] = src1;
            op[1] = src2;
            op[2] = sel1;
            op[3] = dst;
            op[4] = sel2;
        }
    }

    // The four words of the DAG item each lane takes, merged into four
    // registers. The first is always register 0 and no draw is made for it:
    // register 0 is what the *next* round's item index is read from, so the DAG
    // has to reach it every round or the walk stops depending on the DAG.
    for (uint32_t i = 0; i < kDagLoads; i++) {
        const uint32_t dst = i == 0 ? 0u : next_dst();
        const uint32_t sel = rng();

        uint32_t *op = out->word + kDagBase + i * kDagWords;
        op[0] = dst;
        op[1] = sel;
    }
}

}  // namespace kawpow
}  // namespace vkminer
