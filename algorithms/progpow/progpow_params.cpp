// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/progpow/progpow_params.h"

#include <cstring>

namespace vkminer {
namespace progpow {

// In every branded fork below, seal_final repeats the first nine words of
// seal_seed -- one array read at two offsets, in the reference. Written out
// twice here because FiroPoW's two are not in that relation, and a
// representation that only holds for three of the four is the one that gets
// used for the fourth by mistake. tests/kawpow_program_kat.cpp asserts the
// repetition, so a typo in one copy fails a test rather than a chain.

const Params kKawpow = {
    /* name          */ "kawpow",
    /* epoch_length  */ 7500,
    /* period_length */ 3,
    /* regs          */ 32,
    /* cache_ops     */ 11,
    /* math_ops      */ 18,
    /* rounds        */ 64,
    /* dagchange     */ 0,
    /* dag_epoch_mul */ 1,
    /* dag_full_off  */ 0,
    /* max_epoch     */ 700,
    /* seal_seed     */ {                              // rAVENCOINKAWPOW
        0x00000072, 0x00000041, 0x00000056, 0x00000045, 0x0000004e,
        0x00000043, 0x0000004f, 0x00000049, 0x0000004e, 0x0000004b,
        0x00000041, 0x00000057, 0x00000050, 0x0000004f, 0x00000057,
    },
    /* seal_final    */ {                              // rAVENCOIN
        0x00000072, 0x00000041, 0x00000056, 0x00000045, 0x0000004e,
        0x00000043, 0x0000004f, 0x00000049, 0x0000004e,
    },
};

const Params kMeowpow = {
    /* name          */ "meowpow",
    /* epoch_length  */ 7500,
    /* period_length */ 6,
    /* regs          */ 16,
    /* cache_ops     */ 6,
    /* math_ops      */ 9,
    /* rounds        */ 64,
    /* dagchange     */ 110,
    /* dag_epoch_mul */ 4,
    /* dag_full_off  */ 0,
    /* max_epoch     */ 400,
    /* seal_seed     */ {                              // MEOWCOINMEOWPOW
        0x0000004d, 0x00000045, 0x0000004f, 0x00000057, 0x00000043,
        0x0000004f, 0x00000049, 0x0000004e, 0x0000004d, 0x00000045,
        0x0000004f, 0x00000057, 0x00000050, 0x0000004f, 0x00000057,
    },
    /* seal_final    */ {                              // MEOWCOINM
        0x0000004d, 0x00000045, 0x0000004f, 0x00000057, 0x00000043,
        0x0000004f, 0x00000049, 0x0000004e, 0x0000004d,
    },
};

const Params kEvrprogpow = {
    /* name          */ "evrprogpow",
    /* epoch_length  */ 12000,
    /* period_length */ 3,
    /* regs          */ 32,
    /* cache_ops     */ 11,
    /* math_ops      */ 18,
    /* rounds        */ 64,
    /* dagchange     */ 0,
    /* dag_epoch_mul */ 1,
    /* dag_full_off  */ 256,
    /* max_epoch     */ 260,
    /* seal_seed     */ {                              // EVRMORE-PROGPOW
        0x00000045, 0x00000056, 0x00000052, 0x0000004d, 0x0000004f,
        0x00000052, 0x00000045, 0x0000002d, 0x00000050, 0x00000052,
        0x0000004f, 0x00000047, 0x00000050, 0x0000004f, 0x00000057,
    },
    /* seal_final    */ {                              // EVRMORE-P
        0x00000045, 0x00000056, 0x00000052, 0x0000004d, 0x0000004f,
        0x00000052, 0x00000045, 0x0000002d, 0x00000050,
    },
};

// FiroPoW absorbs no name at all, so what its two seals hold is keccak's own
// padding for a message that ends where the data ends: the 0x01 that starts the
// pad, and the 0x80000000 | 0x8081 that ends the last word of the block. The
// two land at different indices because the two absorbs carry different amounts
// of data -- which is exactly why this is a pair of arrays and not one read
// twice.
const Params kFiropow = {
    /* name          */ "firopow",
    /* epoch_length  */ 1300,
    /* period_length */ 1,
    /* regs          */ 32,
    /* cache_ops     */ 11,
    /* math_ops      */ 18,
    /* rounds        */ 64,
    /* dagchange     */ 0,
    /* dag_epoch_mul */ 1,
    /* dag_full_off  */ 64,
    /* max_epoch     */ 1350,
    /* seal_seed     */ {                              // state[10] and state[18]
        0x00000001, 0, 0, 0, 0, 0, 0, 0, 0x80008081,
        0, 0, 0, 0, 0, 0,
    },
    /* seal_final    */ {                              // state[17] and state[24]
        0, 0x00000001, 0, 0, 0, 0, 0, 0, 0x80008081,
    },
};

// Telestai's node calls its copy of the array below `telestaicoin_kawpow` and
// fills it with Ravencoin's letters, lower-case 'r' included: MeraKi seals both
// keccaks exactly as KawPoW does, and the round and the epoch are what separate
// the chains. Written out again rather than shared with the row above, so a
// correction to one is not silently a correction to both.
const Params kMeraki = {
    /* name          */ "meraki",
    /* epoch_length  */ 27500,
    /* period_length */ 3,
    /* regs          */ 32,
    /* cache_ops     */ 12,
    /* math_ops      */ 5,
    /* rounds        */ 32,
    /* dagchange     */ 0,
    /* dag_epoch_mul */ 1,
    /* dag_full_off  */ 0,
    /* max_epoch     */ 80,
    /* seal_seed     */ {                              // rAVENCOINKAWPOW
        0x00000072, 0x00000041, 0x00000056, 0x00000045, 0x0000004e,
        0x00000043, 0x0000004f, 0x00000049, 0x0000004e, 0x0000004b,
        0x00000041, 0x00000057, 0x00000050, 0x0000004f, 0x00000057,
    },
    /* seal_final    */ {                              // rAVENCOIN
        0x00000072, 0x00000041, 0x00000056, 0x00000045, 0x0000004e,
        0x00000043, 0x0000004f, 0x00000049, 0x0000004e,
    },
};

const Params *find(const char *name)
{
    static const Params *const kForks[] = {
        &kKawpow, &kMeowpow, &kEvrprogpow, &kFiropow, &kMeraki,
    };

    if (!name)
        return nullptr;
    for (const Params *fork : kForks)
        if (std::strcmp(fork->name, name) == 0)
            return fork;
    return nullptr;
}

}  // namespace progpow
}  // namespace vkminer
