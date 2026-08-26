// How ProgPoW's sixteen lanes exchange a word, two ways.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The mix is 16 lanes wide and the lanes meet in exactly two places: once per
// round, where all sixteen need lane r%16's register 0 to know which DAG line
// to read, and once at the end, where the sixteen lane hashes fold into eight
// words. Everything between is per-lane arithmetic that never leaves a
// register, so this file is the whole of what one kernel costs against
// the other.
//
//   - Workgroup memory and a barrier. Every Vulkan 1.1 device has it, and the
//     software rasterizers this is differentially tested against can only run
//     it, so it is the one that has to be right.
//   - A subgroup shuffle, where the subgroup is a whole number of sixteens and
//     the device supports the operation. The value is read out of another
//     invocation's register: no barrier, no memory.
//
// Which one a device gets is a measurement. A shuffle avoids two barriers per
// round and might still lose: the barrier it avoids is between invocations
// already in lockstep, and what the round waits for is a DAG line.
//
// It cannot be a specialization constant. The shuffle declares an OpCapability
// at module scope and a device without the feature rejects the whole module for
// containing it, however unreachable the code is. So it is two modules, offered
// by Algorithm::kernels() from the feature bits and raced by the tuner.
//
// Define PROGPOW_SUBGROUP_LANES before including this for the second one. The
// includer also has to require GL_KHR_shader_subgroup_basic and
// GL_KHR_shader_subgroup_shuffle itself, since an #extension directive belongs
// at the top of a compilation unit.
//
// Include this after kLanes is declared: it is the algorithm's constant, not
// this file's.

#ifdef PROGPOW_SUBGROUP_LANES

// Which lane this invocation is, and which nonce it is helping hash, both come
// from the subgroup rather than from gl_LocalInvocationID: the mapping between
// the two is implementation-defined, so a kernel that assumed it was linear
// would exchange with whichever invocations the driver happened to put there.
//
// It does assume every subgroup is full -- a short one at the end of a
// workgroup would leave nonce indices no invocation claims, and those nonces
// would never be hashed. KernelSpec::full_subgroups is what prevents it.
uint progpow_lane()
{
    return gl_SubgroupInvocationID % kLanes;
}

uint progpow_nonce_index()
{
    uint subgroup = gl_WorkGroupID.x * gl_NumSubgroups + gl_SubgroupID;
    return subgroup * (gl_SubgroupSize / kLanes)
         + gl_SubgroupInvocationID / kLanes;
}

// One lane's word, read by all sixteen of its group. Every invocation has to
// reach this, since a shuffle reads a register out of an invocation that must
// be active -- the same rule the barrier below imposes, and the reason neither
// kernel returns early.
uint progpow_broadcast(uint value, uint from)
{
    return subgroupShuffle(value,
                           gl_SubgroupInvocationID - progpow_lane() + from);
}

// The fold at the end wants all sixteen, so the value is parked once and read
// sixteen times rather than broadcast sixteen times. Here that is a register;
// in the other spelling it is what the barriers are protecting.
uint progpow_parked;

void progpow_publish(uint value)
{
    progpow_parked = value;
}

uint progpow_published(uint from)
{
    return progpow_broadcast(progpow_parked, from);
}

#else

// One word per invocation, sized by the workgroup width -- which is a
// specialization constant, so it is exactly as large as the dispatch made it.
shared uint xchg[gl_WorkGroupSize.x];

uint progpow_lane()
{
    return gl_LocalInvocationID.x % kLanes;
}

uint progpow_nonce_index()
{
    return gl_GlobalInvocationID.x / kLanes;
}

// Two barriers, and both are load-bearing. The first says every lane is done
// reading the slot this call is about to overwrite -- without it a fast lane
// laps a slow one and reads the next round's line index. The second says the
// write has landed.
uint progpow_broadcast(uint value, uint from)
{
    barrier();
    if (progpow_lane() == from)
        xchg[gl_LocalInvocationID.x] = value;
    barrier();

    return xchg[gl_LocalInvocationID.x - progpow_lane() + from];
}

void progpow_publish(uint value)
{
    barrier();
    xchg[gl_LocalInvocationID.x] = value;
    barrier();
}

uint progpow_published(uint from)
{
    return xchg[gl_LocalInvocationID.x - progpow_lane() + from];
}

#endif
