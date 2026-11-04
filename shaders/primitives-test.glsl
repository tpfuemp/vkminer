// One primitive over one message per invocation, for primitives_test. Not used
// by the miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Each invocation owns 36 words of the buffer: a 20-word message, then the
// 16-word digest. The primitive and the message length are push constants.

#ifndef VKMINER_SHADERS_PRIMITIVES_TEST_GLSL_INCLUDED
#define VKMINER_SHADERS_PRIMITIVES_TEST_GLSL_INCLUDED

#include "shaders/common/shabal512.glsl"
#include "shaders/common/tiger192.glsl"
#include "shaders/common/whirlpool512.glsl"

layout(local_size_x_id = 0) in;

layout(std430, set = 0, binding = 0) buffer Data {
    uint data[];
};

layout(push_constant) uniform Push {
    uint count;  // invocations with a message; the rest pad the workgroup
    uint which;  // 0 Shabal-512, 1 Whirlpool, 2 Tiger
    uint words;  // 16 or 20
} push;

const uint kStride = 36u;

void main()
{
    // Before the bounds check: every invocation of the workgroup reaches the
    // barriers inside.
    whirlpool512_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);
    tiger192_table_load(gl_LocalInvocationIndex, gl_WorkGroupSize.x);

    uint i = gl_GlobalInvocationID.x;
    if (i >= push.count)
        return;

    uint base = i * kStride;
    uint msg[20];
    for (uint k = 0u; k < 20u; k++)
        msg[k] = data[base + k];

    uint h[16];
    for (uint k = 0u; k < 16u; k++)
        h[k] = 0u;

    if (push.which == 0u) {
        if (push.words == 16u)
            shabal512_hash(msg, 16u, h);
        else
            shabal512_hash(msg, 20u, h);
    } else if (push.which == 1u) {
        if (push.words == 16u)
            whirlpool512_hash(msg, 16u, h);
        else
            whirlpool512_hash(msg, 20u, h);
    } else {
        uint t[6];
        if (push.words == 16u)
            tiger192_hash(msg, 16u, t);
        else
            tiger192_hash(msg, 20u, t);
        for (uint k = 0u; k < 6u; k++)
            h[k] = t[k];
    }

    for (uint k = 0u; k < 16u; k++)
        data[base + 20u + k] = h[k];
}

#endif  // VKMINER_SHADERS_PRIMITIVES_TEST_GLSL_INCLUDED
