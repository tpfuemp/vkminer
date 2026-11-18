// Whirlpool-512 of four 64-byte messages at once, bitsliced.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state is 64 words, s[8 c + b]: bit 4 row + h is bit b of byte (row,
// column c) of message h. The S-box is logic on a column's eight planes,
// ShiftColumns a rotate of each word by 4 c, and MixRows GF(2^8) doublings
// across columns, so no table is read. Message and digest words are
// little-endian, as in whirlpool512.glsl; the tables below were generated
// from that file's T0 and round constants. Written out with literal indices:
// loops over the 64-word arrays leave the state in memory.
#ifndef VKMINER_SHADERS_COMMON_WHIRLPOOL512_X4_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_WHIRLPOOL512_X4_GLSL_INCLUDED

#extension GL_EXT_control_flow_attributes : require

// The first block's round keys from a zero chaining value, round r at
// [64 r]; the key schedule's round constants the same way; the padding block
// of a 64-byte message.
const uint kWhirlpoolX4Key1[640] = uint[640](
    0x00000000u, 0x00000000u, 0x00000000u, 0xfffffff0u, 0x0000000fu, 0xffffffffu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0xffffffffu, 0x00000000u, 0xfffffff0u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0xffffffffu, 0x00000000u, 0xffffffffu, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0xfffffff0u, 0x00000000u, 0xfffffff0u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0xffffffffu, 0x00000000u, 0xffffffffu, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0xfffffff0u, 0x0000000fu, 0xfffffff0u, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x00000000u, 0xffffffffu, 0x00000000u, 0xffffffffu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0xfffffff0u, 0x00000000u, 0xffffffffu, 0x0000000fu, 0x00000000u,
    0x00f0f00fu, 0x0ff0000fu, 0x0ff0f0f0u, 0xf0ff000fu, 0xff000f0fu, 0xf0000f0fu, 0xf00ffff0u, 0xfff0f000u,
    0x0ff000ffu, 0x00f0ff0fu, 0x00ff0ff0u, 0xff0fff0fu, 0x0ff0ff00u, 0xffffff0fu, 0x0ff0fff0u, 0xf0ffff0fu,
    0x0000f0ffu, 0x00f00000u, 0x0ff00ff0u, 0xf0f0f00fu, 0xff000000u, 0xf000ff00u, 0xf00f00f0u, 0xf00fff0fu,
    0x0f00f000u, 0x0ff000f0u, 0x0fff0ff0u, 0xf00f000fu, 0x000f000fu, 0xf0f0ffffu, 0xf00ff0ffu, 0x0000ff0fu,
    0x0f00fff0u, 0x0f00000fu, 0x0f0f0ff0u, 0xf00f000fu, 0xffff0000u, 0xf00ff00fu, 0x0f0fffffu, 0xffffff0fu,
    0x0ff000ffu, 0x00f00000u, 0x0fffff00u, 0xf0fff0f0u, 0x000f000fu, 0x000f0ff0u, 0xf00ff0ffu, 0xffffffffu,
    0x0ff0f0f0u, 0x00f00fffu, 0x00f0000fu, 0xffff00ffu, 0xff0f0f00u, 0xff0fff0fu, 0xff00f0f0u, 0x00ffffffu,
    0x0ff00ff0u, 0x000000f0u, 0x000f00ffu, 0xffff0ff0u, 0xff0f0000u, 0xfffff0ffu, 0xffff0000u, 0xf00ffff0u,
    0xf0f0ffffu, 0xf0f0000fu, 0x0f0f0000u, 0xff0000f0u, 0xfff0000fu, 0xf0f000f0u, 0xffff000fu, 0x0f00f00fu,
    0xfff0f0ffu, 0x0ffff0f0u, 0xff0f0f00u, 0xf0ff0fffu, 0x00ff00ffu, 0x0f00ff00u, 0x0ffff0f0u, 0xf0000000u,
    0xff0000ffu, 0xf000ffffu, 0x00f0f00fu, 0xfff0ff0fu, 0xf000f00fu, 0xf0ff00ffu, 0x000f0000u, 0x0000ff0fu,
    0x00f0f0ffu, 0x00ff0f0fu, 0x0ff00000u, 0x00ff000fu, 0xf00ff0ffu, 0xff0ff000u, 0xf0ff0fffu, 0xf0f0ffffu,
    0xff000ff0u, 0xff000ff0u, 0xfff000f0u, 0x0ff00ff0u, 0xf0ff000fu, 0x0fff00ffu, 0xff00f000u, 0xfffffff0u,
    0xff000ff0u, 0xf00ff0ffu, 0x0ff00fffu, 0xfff000f0u, 0xf00fff00u, 0xff0ff000u, 0x0f0000ffu, 0x0ffffff0u,
    0xff0f00f0u, 0x0000f0f0u, 0xfff0fff0u, 0xffff0f00u, 0xfff000ffu, 0xf0f00fffu, 0xff00000fu, 0x0ff00f00u,
    0xfffff0f0u, 0x0f0ff0f0u, 0x0000f000u, 0xf00f0fffu, 0xffff0fffu, 0x00f0f000u, 0x0fff00ffu, 0x0f0ffff0u,
    0x0fffff00u, 0xff000f00u, 0x0000f000u, 0x0f0000ffu, 0xff0f0f0fu, 0xff000fffu, 0x0f00fff0u, 0x0f00ff00u,
    0x0fff0f00u, 0xf000ff0fu, 0xf0f00fffu, 0x0f0f00ffu, 0xf0000fffu, 0x0000ffffu, 0xfff0f0f0u, 0x0ff0f00fu,
    0x000000f0u, 0x0ff0ffffu, 0xf0f00000u, 0xf0000f0fu, 0xffff0ff0u, 0x000f0fffu, 0xfffffff0u, 0xf0ff0fffu,
    0x0ff00f0fu, 0x00000f00u, 0xf0f00000u, 0xf0ffff00u, 0x0f00fff0u, 0x0fff0000u, 0x0fffffffu, 0x0fff0fffu,
    0xff0f0000u, 0xff00f0ffu, 0xf000f00fu, 0x0f0fffffu, 0x0fff0f0fu, 0x0f00f000u, 0xff00f0ffu, 0xf00fff0fu,
    0xf000ffffu, 0x000f00f0u, 0x000ffff0u, 0x0f0f0f00u, 0xf0f0f00fu, 0xffffff00u, 0xf00f0000u, 0xf0f00ff0u,
    0xf000f0ffu, 0xf00000f0u, 0xfffff00fu, 0x0f00f000u, 0x00f00ff0u, 0xffff0fffu, 0x0f000f0fu, 0x0f00ff00u,
    0x0ff00ff0u, 0x0f0f0fffu, 0x000fffffu, 0x000ff0f0u, 0x0f0ffff0u, 0x000ff0f0u, 0xff0f0ff0u, 0x0f00f00fu,
    0x0f00f0ffu, 0x00ff0f0fu, 0xf0ff0f0fu, 0x00f0000fu, 0xfffff000u, 0x0ff00f0fu, 0xf0000ff0u, 0xffffffffu,
    0x0ff0ff0fu, 0x0f0f0ff0u, 0x0000ffffu, 0x0fffff00u, 0xff0ff0f0u, 0xfff000ffu, 0xfffff000u, 0xf0f00000u,
    0xfff00f0fu, 0x0000f0f0u, 0x000fffffu, 0xff000f00u, 0x0fff0f00u, 0x00f0ffffu, 0xff0fff00u, 0xf000f00fu,
    0x00f0f0f0u, 0xf0f0ff00u, 0xf00f0f00u, 0x0ffff0f0u, 0xff00f000u, 0xf000f0ffu, 0x00ff0000u, 0x00fffff0u,
    0xf0000ff0u, 0xfff0fff0u, 0xff0f0f0fu, 0x000f0000u, 0x0f000f0fu, 0xf0f0fff0u, 0x00fffff0u, 0x0f00f0ffu,
    0xf000000fu, 0x00fff00fu, 0x0f0f00f0u, 0xf00ff00fu, 0xf0ff000fu, 0x00fff000u, 0xf00ffff0u, 0x0f0f00ffu,
    0xf0000fffu, 0xfffff0ffu, 0xf00ff00fu, 0xffff0f0fu, 0x00ff0ff0u, 0xfff00f00u, 0x0f0f0fffu, 0xf0000f0fu,
    0xff0ffff0u, 0x0ff00000u, 0x0fff00ffu, 0x000ff0f0u, 0xf000000fu, 0xf0f0ff00u, 0x0f000ff0u, 0x00ff0f00u,
    0x00ff00f0u, 0xf0fff00fu, 0x0ff00000u, 0x0f00f0f0u, 0xfffff0f0u, 0x000fffffu, 0x0f00ff0fu, 0xffff000fu,
    0xfffff0ffu, 0xf00f0ff0u, 0xff00f000u, 0x0ff00fffu, 0xf00f000fu, 0xff0ff0ffu, 0xf0ff000fu, 0x0f0fff0fu,
    0xf0f0f0ffu, 0xf0fff0f0u, 0xf0fff00fu, 0xfff00ff0u, 0x00f0ff0fu, 0x0ff0ff0fu, 0xff0f0ff0u, 0x0f000fffu,
    0xf00f0000u, 0x0f000ff0u, 0x0000ff00u, 0xfff00f00u, 0x0f000000u, 0x0f0ff0f0u, 0xf0f0ff0fu, 0x0f0f0fffu,
    0xf000f00fu, 0x0f0f0ff0u, 0xff0000ffu, 0xffff0f00u, 0x0fff0ff0u, 0xf0ff0f0fu, 0xf0ffff00u, 0xf00f0f00u,
    0x000f000fu, 0x00ff000fu, 0x0000ffffu, 0x0000f000u, 0xf0000f0fu, 0xf0000f0fu, 0x00000000u, 0xf00ff0f0u,
    0x0fff000fu, 0xfffff00fu, 0x0fff0ff0u, 0x0fff0f0fu, 0xf00ff0f0u, 0xf00f0000u, 0x00f00000u, 0x0ff0fff0u,
    0xff0ff0f0u, 0x0f000000u, 0xf0f00ff0u, 0xf0fff000u, 0xf0f0ff0fu, 0xfff000ffu, 0x00f00000u, 0x000f00ffu,
    0x00f00fffu, 0x00f00ff0u, 0xf000ffffu, 0xf00f0ff0u, 0x0f00ffffu, 0xfff0ffffu, 0x000ff0ffu, 0xff0ffff0u,
    0x000f0f0fu, 0x0f0f00f0u, 0x0fff0f00u, 0x000ffff0u, 0xffff0ff0u, 0xf0f0fff0u, 0x00ff0fffu, 0x00fff0f0u,
    0xf000000fu, 0x00ff0f0fu, 0xf0000000u, 0xf0ff00f0u, 0x0fff00f0u, 0x0000f0ffu, 0xf0fff00fu, 0xf0000000u,
    0xf0f00f00u, 0x0f00f00fu, 0x00ff0000u, 0xf0000f00u, 0x0ff000f0u, 0xf0000000u, 0x00fffff0u, 0x0000f0ffu,
    0x000000ffu, 0x0f0fff0fu, 0x00ff0fffu, 0xf00fff00u, 0x0000ffffu, 0xf00f0f0fu, 0xf00f00ffu, 0x000ff000u,
    0xfffff0ffu, 0xf00000f0u, 0x00fff00fu, 0x0f0f0f0fu, 0xffff0f00u, 0xfff0f000u, 0x0ffff00fu, 0x0f00ff00u,
    0xf00f0f0fu, 0xff00ffffu, 0x000ff0ffu, 0x000ff00fu, 0xf00f0f0fu, 0xff000f0fu, 0x0f00ffffu, 0x0f0fff0fu,
    0xf00fff0fu, 0x000ff00fu, 0xffff000fu, 0xff00f00fu, 0xf0000000u, 0x00ff0f0fu, 0x00000f00u, 0x0ff00000u,
    0xf0ff00ffu, 0x0ff0f00fu, 0x0f000f00u, 0xf0f00ff0u, 0xf0f000f0u, 0x0f0ff000u, 0xf000ff00u, 0xff00f0f0u,
    0x000f0f0fu, 0x0fff0f0fu, 0x00fff000u, 0xf0fff00fu, 0xff0ff000u, 0x000f000fu, 0x000f0fffu, 0x00fff000u,
    0x0f0ff00fu, 0x0f00fff0u, 0x0000fff0u, 0x0f00ff00u, 0xff0f0f0fu, 0x0f000f0fu, 0x0000f0ffu, 0xf000f0ffu,
    0x0ff0ff00u, 0xfff0ffffu, 0xff000f00u, 0xf0f00000u, 0x0f00ff00u, 0x0f0f00f0u, 0x0ff0f0f0u, 0x0ffff00fu,
    0xff000f00u, 0xff0f0f00u, 0x00f0f000u, 0xf0f0ffffu, 0xf00000f0u, 0xfff0000fu, 0x00ffffffu, 0x0f0000f0u,
    0x0f0fff00u, 0x0f0ff0f0u, 0x0ffff0ffu, 0xf00fff00u, 0x000fff00u, 0xf0f0f000u, 0x0ffff0f0u, 0x00fff00fu,
    0xfff000ffu, 0xffffff00u, 0x0f0ff00fu, 0x00f0000fu, 0xff0000f0u, 0xff0f00ffu, 0x00f00ff0u, 0x0f00ff0fu,
    0x00fff0ffu, 0xffff00f0u, 0x0f00f000u, 0xff00000fu, 0x00ff0f00u, 0x000000f0u, 0xff0ff0f0u, 0xff00f00fu,
    0x00f0f000u, 0xf0f0f0f0u, 0x00fff000u, 0xff000ff0u, 0x00ff000fu, 0xf0ff00f0u, 0x00fff00fu, 0x00000f0fu,
    0x00f00000u, 0xffffff00u, 0xf0ff00ffu, 0x0f00f00fu, 0xf0f000ffu, 0xff0f0000u, 0xf000ff00u, 0xf00f00f0u,
    0x0f0000ffu, 0x0fff0fffu, 0x00f0f0ffu, 0xff00f0f0u, 0xff0ff000u, 0x0ff00fffu, 0xf0f0f00fu, 0x00ff0000u,
    0xff0ff0f0u, 0xff00ffffu, 0x00ffff00u, 0xffff000fu, 0x000f00ffu, 0xf000000fu, 0xf00fffffu, 0xf0f0f000u,
    0xff0ff000u, 0x0f000fffu, 0x00ffff00u, 0x0000ffffu, 0x0f00ff00u, 0x000fff00u, 0x0ff00ff0u, 0xf0ff0f00u,
    0xf0f000f0u, 0x00f000ffu, 0xff0f0f00u, 0xff0fff0fu, 0x00fff00fu, 0x0ff00ff0u, 0xfffff0f0u, 0x0f000f0fu,
    0xf00ff000u, 0xff0f00f0u, 0xf0fff0ffu, 0x0fff0f0fu, 0x0ff0f0f0u, 0xf00fffffu, 0xf0ff0000u, 0xf0000ff0u,
    0x00fff00fu, 0xff0000f0u, 0x0f000f00u, 0x00f0f00fu, 0x00f0ffffu, 0xf0ff0fffu, 0xff00f00fu, 0x0f0f0fffu,
    0x0ff000f0u, 0xfff0f000u, 0x000f00f0u, 0xf000000fu, 0x000f0000u, 0xff000ff0u, 0xffffff0fu, 0x0000fff0u,
    0x0fff00ffu, 0xf00f0f00u, 0x000fffffu, 0xff00fff0u, 0xff0f000fu, 0xf00f0000u, 0xf0f00f00u, 0x000fff0fu,
    0x0ff00ff0u, 0xf0f0f0f0u, 0xff0f0f00u, 0xf0ffffffu, 0x0f0f0f00u, 0x0f000ff0u, 0xf0f0f0ffu, 0x000f0000u,
    0x0f0fff00u, 0xfff0ffffu, 0xf00f0fffu, 0x0ff0ff00u, 0xff0ff00fu, 0xff00000fu, 0xf00ffff0u, 0xffffffffu,
    0xffff00ffu, 0xffff00f0u, 0xf0ff0000u, 0x0f0f0ff0u, 0xffff0000u, 0xf00f00f0u, 0x0f0ff0f0u, 0x0ff0ff00u,
    0xf0ff00f0u, 0x0f00ff0fu, 0x0ff0ffffu, 0x00f000ffu, 0x0ffff000u, 0x0fffffffu, 0x0ffff0ffu, 0x0f00f0ffu,
    0x0fff0000u, 0xf0f00ff0u, 0x0f0ff0ffu, 0x00f0ffffu, 0x0f00ff0fu, 0x0000000fu, 0x00000f00u, 0xf00ff0ffu,
    0xf0fffff0u, 0xffff000fu, 0xf0000f00u, 0x0ff0f00fu, 0x0fff0f0fu, 0xfff0ff0fu, 0x0ff0ff00u, 0x0000f0f0u);
const uint kWhirlpoolX4Rc[640] = uint[640](
    0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x00000000u, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x0000000fu, 0x00000000u,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u, 0x0000000fu, 0x0000000fu, 0x00000000u, 0x00000000u);
const uint kWhirlpoolX4Pad[64] = uint[64](
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x0000000fu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0xf0000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u);

// Three-input logic with truth table `lut` over (a, b, c) = (0xf0, 0xcc,
// 0xaa); a literal at every call site, so it folds to one operation.
uint wpx4_lop3(uint a, uint b, uint c, uint lut)
{
    uint m0 = 0u - (lut & 1u), m1 = 0u - ((lut >> 1) & 1u);
    uint m2 = 0u - ((lut >> 2) & 1u), m3 = 0u - ((lut >> 3) & 1u);
    uint m4 = 0u - ((lut >> 4) & 1u), m5 = 0u - ((lut >> 5) & 1u);
    uint m6 = 0u - ((lut >> 6) & 1u), m7 = 0u - ((lut >> 7) & 1u);
    return (m0 & ~a & ~b & ~c) | (m1 & ~a & ~b & c) | (m2 & ~a & b & ~c)
         | (m3 & ~a & b & c) | (m4 & a & ~b & ~c) | (m5 & a & ~b & c)
         | (m6 & a & b & ~c) | (m7 & a & b & c);
}

// SubBytes, ShiftColumns and MixRows, circ(1, 1, 4, 1, 8, 5, 2, 9) as
// b_j = A_j + A_{j+1} + A_{j+3} + A_{j+5} + A_{j+7}
//     + 2 (A_{j+2} + 2 (U_{j+2} + 2 U_j)), U_j = A_{j+4} + A_{j+1},
// doubling mod 0x11d on planes. The S-box on each column, in planes: E of
// the high nibble, E^-1 of the low, R of their sum, then E and E^-1 again;
// each mini-box output picks between two functions of the other three inputs
// by the first. The caller adds the round key.
void wpx4_round(inout uint s[64])
{
    {
    uint x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[0] = g0; s[1] = g1; s[2] = g2; s[3] = g3;
    s[4] = h0; s[5] = h1; s[6] = h2; s[7] = h3;
    }
    {
    uint x0 = s[8], x1 = s[9], x2 = s[10], x3 = s[11], x4 = s[12], x5 = s[13], x6 = s[14], x7 = s[15];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[8] = g0; s[9] = g1; s[10] = g2; s[11] = g3;
    s[12] = h0; s[13] = h1; s[14] = h2; s[15] = h3;
    }
    {
    uint x0 = s[16], x1 = s[17], x2 = s[18], x3 = s[19], x4 = s[20], x5 = s[21], x6 = s[22], x7 = s[23];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[16] = g0; s[17] = g1; s[18] = g2; s[19] = g3;
    s[20] = h0; s[21] = h1; s[22] = h2; s[23] = h3;
    }
    {
    uint x0 = s[24], x1 = s[25], x2 = s[26], x3 = s[27], x4 = s[28], x5 = s[29], x6 = s[30], x7 = s[31];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[24] = g0; s[25] = g1; s[26] = g2; s[27] = g3;
    s[28] = h0; s[29] = h1; s[30] = h2; s[31] = h3;
    }
    {
    uint x0 = s[32], x1 = s[33], x2 = s[34], x3 = s[35], x4 = s[36], x5 = s[37], x6 = s[38], x7 = s[39];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[32] = g0; s[33] = g1; s[34] = g2; s[35] = g3;
    s[36] = h0; s[37] = h1; s[38] = h2; s[39] = h3;
    }
    {
    uint x0 = s[40], x1 = s[41], x2 = s[42], x3 = s[43], x4 = s[44], x5 = s[45], x6 = s[46], x7 = s[47];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[40] = g0; s[41] = g1; s[42] = g2; s[43] = g3;
    s[44] = h0; s[45] = h1; s[46] = h2; s[47] = h3;
    }
    {
    uint x0 = s[48], x1 = s[49], x2 = s[50], x3 = s[51], x4 = s[52], x5 = s[53], x6 = s[54], x7 = s[55];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[48] = g0; s[49] = g1; s[50] = g2; s[51] = g3;
    s[52] = h0; s[53] = h1; s[54] = h2; s[55] = h3;
    }
    {
    uint x0 = s[56], x1 = s[57], x2 = s[58], x3 = s[59], x4 = s[60], x5 = s[61], x6 = s[62], x7 = s[63];
    uint u0 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xf5u), wpx4_lop3(x5, x6, x7, 0x41u), x4, 0xd8u);
    uint u1 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x6au), wpx4_lop3(x5, x6, x7, 0x4du), x4, 0xd8u);
    uint u2 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0xe6u), wpx4_lop3(x5, x6, x7, 0x34u), x4, 0xd8u);
    uint u3 = wpx4_lop3(wpx4_lop3(x5, x6, x7, 0x5eu), wpx4_lop3(x5, x6, x7, 0x13u), x4, 0xd8u);
    uint l0 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x5fu), wpx4_lop3(x1, x2, x3, 0x30u), x0, 0xd8u);
    uint l1 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x0du), wpx4_lop3(x1, x2, x3, 0xd6u), x0, 0xd8u);
    uint l2 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0x71u), wpx4_lop3(x1, x2, x3, 0x9cu), x0, 0xd8u);
    uint l3 = wpx4_lop3(wpx4_lop3(x1, x2, x3, 0xb7u), wpx4_lop3(x1, x2, x3, 0x44u), x0, 0xd8u);
    uint ul0 = u0 ^ l0, ul1 = u1 ^ l1, ul2 = u2 ^ l2, ul3 = u3 ^ l3;
    uint r0 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0xd1u), wpx4_lop3(ul1, ul2, ul3, 0x5au), ul0, 0xd8u);
    uint r1 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x1fu), wpx4_lop3(ul1, ul2, ul3, 0x62u), ul0, 0xd8u);
    uint r2 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x07u), wpx4_lop3(ul1, ul2, ul3, 0x5du), ul0, 0xd8u);
    uint r3 = wpx4_lop3(wpx4_lop3(ul1, ul2, ul3, 0x74u), wpx4_lop3(ul1, ul2, ul3, 0x71u), ul0, 0xd8u);
    uint ur0 = u0 ^ r0, ur1 = u1 ^ r1, ur2 = u2 ^ r2, ur3 = u3 ^ r3;
    uint lr0 = l0 ^ r0, lr1 = l1 ^ r1, lr2 = l2 ^ r2, lr3 = l3 ^ r3;
    uint h0 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xf5u), wpx4_lop3(ur1, ur2, ur3, 0x41u), ur0, 0xd8u);
    uint h1 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x6au), wpx4_lop3(ur1, ur2, ur3, 0x4du), ur0, 0xd8u);
    uint h2 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0xe6u), wpx4_lop3(ur1, ur2, ur3, 0x34u), ur0, 0xd8u);
    uint h3 = wpx4_lop3(wpx4_lop3(ur1, ur2, ur3, 0x5eu), wpx4_lop3(ur1, ur2, ur3, 0x13u), ur0, 0xd8u);
    uint g0 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x5fu), wpx4_lop3(lr1, lr2, lr3, 0x30u), lr0, 0xd8u);
    uint g1 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x0du), wpx4_lop3(lr1, lr2, lr3, 0xd6u), lr0, 0xd8u);
    uint g2 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0x71u), wpx4_lop3(lr1, lr2, lr3, 0x9cu), lr0, 0xd8u);
    uint g3 = wpx4_lop3(wpx4_lop3(lr1, lr2, lr3, 0xb7u), wpx4_lop3(lr1, lr2, lr3, 0x44u), lr0, 0xd8u);
    s[56] = g0; s[57] = g1; s[58] = g2; s[59] = g3;
    s[60] = h0; s[61] = h1; s[62] = h2; s[63] = h3;
    }
    s[8] = (s[8] << 4) | (s[8] >> 28);
    s[9] = (s[9] << 4) | (s[9] >> 28);
    s[10] = (s[10] << 4) | (s[10] >> 28);
    s[11] = (s[11] << 4) | (s[11] >> 28);
    s[12] = (s[12] << 4) | (s[12] >> 28);
    s[13] = (s[13] << 4) | (s[13] >> 28);
    s[14] = (s[14] << 4) | (s[14] >> 28);
    s[15] = (s[15] << 4) | (s[15] >> 28);
    s[16] = (s[16] << 8) | (s[16] >> 24);
    s[17] = (s[17] << 8) | (s[17] >> 24);
    s[18] = (s[18] << 8) | (s[18] >> 24);
    s[19] = (s[19] << 8) | (s[19] >> 24);
    s[20] = (s[20] << 8) | (s[20] >> 24);
    s[21] = (s[21] << 8) | (s[21] >> 24);
    s[22] = (s[22] << 8) | (s[22] >> 24);
    s[23] = (s[23] << 8) | (s[23] >> 24);
    s[24] = (s[24] << 12) | (s[24] >> 20);
    s[25] = (s[25] << 12) | (s[25] >> 20);
    s[26] = (s[26] << 12) | (s[26] >> 20);
    s[27] = (s[27] << 12) | (s[27] >> 20);
    s[28] = (s[28] << 12) | (s[28] >> 20);
    s[29] = (s[29] << 12) | (s[29] >> 20);
    s[30] = (s[30] << 12) | (s[30] >> 20);
    s[31] = (s[31] << 12) | (s[31] >> 20);
    s[32] = (s[32] << 16) | (s[32] >> 16);
    s[33] = (s[33] << 16) | (s[33] >> 16);
    s[34] = (s[34] << 16) | (s[34] >> 16);
    s[35] = (s[35] << 16) | (s[35] >> 16);
    s[36] = (s[36] << 16) | (s[36] >> 16);
    s[37] = (s[37] << 16) | (s[37] >> 16);
    s[38] = (s[38] << 16) | (s[38] >> 16);
    s[39] = (s[39] << 16) | (s[39] >> 16);
    s[40] = (s[40] << 20) | (s[40] >> 12);
    s[41] = (s[41] << 20) | (s[41] >> 12);
    s[42] = (s[42] << 20) | (s[42] >> 12);
    s[43] = (s[43] << 20) | (s[43] >> 12);
    s[44] = (s[44] << 20) | (s[44] >> 12);
    s[45] = (s[45] << 20) | (s[45] >> 12);
    s[46] = (s[46] << 20) | (s[46] >> 12);
    s[47] = (s[47] << 20) | (s[47] >> 12);
    s[48] = (s[48] << 24) | (s[48] >> 8);
    s[49] = (s[49] << 24) | (s[49] >> 8);
    s[50] = (s[50] << 24) | (s[50] >> 8);
    s[51] = (s[51] << 24) | (s[51] >> 8);
    s[52] = (s[52] << 24) | (s[52] >> 8);
    s[53] = (s[53] << 24) | (s[53] >> 8);
    s[54] = (s[54] << 24) | (s[54] >> 8);
    s[55] = (s[55] << 24) | (s[55] >> 8);
    s[56] = (s[56] << 28) | (s[56] >> 4);
    s[57] = (s[57] << 28) | (s[57] >> 4);
    s[58] = (s[58] << 28) | (s[58] >> 4);
    s[59] = (s[59] << 28) | (s[59] >> 4);
    s[60] = (s[60] << 28) | (s[60] >> 4);
    s[61] = (s[61] << 28) | (s[61] >> 4);
    s[62] = (s[62] << 28) | (s[62] >> 4);
    s[63] = (s[63] << 28) | (s[63] >> 4);
    uint t[64];
    uint u0_0 = (s[32] ^ s[8]);
    uint u0_1 = (s[33] ^ s[9]);
    uint u0_2 = (s[34] ^ s[10]);
    uint u0_3 = (s[35] ^ s[11]);
    uint u0_4 = (s[36] ^ s[12]);
    uint u0_5 = (s[37] ^ s[13]);
    uint u0_6 = (s[38] ^ s[14]);
    uint u0_7 = (s[39] ^ s[15]);
    uint a0_0 = u0_7 ^ (s[48] ^ s[24]);
    uint a0_1 = u0_0 ^ (s[49] ^ s[25]);
    uint a0_2 = (u0_1 ^ u0_7) ^ (s[50] ^ s[26]);
    uint a0_3 = (u0_2 ^ u0_7) ^ (s[51] ^ s[27]);
    uint a0_4 = (u0_3 ^ u0_7) ^ (s[52] ^ s[28]);
    uint a0_5 = u0_4 ^ (s[53] ^ s[29]);
    uint a0_6 = u0_5 ^ (s[54] ^ s[30]);
    uint a0_7 = u0_6 ^ (s[55] ^ s[31]);
    uint c0_0 = a0_7 ^ s[16];
    uint c0_1 = a0_0 ^ s[17];
    uint c0_2 = (a0_1 ^ a0_7) ^ s[18];
    uint c0_3 = (a0_2 ^ a0_7) ^ s[19];
    uint c0_4 = (a0_3 ^ a0_7) ^ s[20];
    uint c0_5 = a0_4 ^ s[21];
    uint c0_6 = a0_5 ^ s[22];
    uint c0_7 = a0_6 ^ s[23];
    t[0] = c0_7 ^ s[0] ^ s[56] ^ s[40] ^ s[24] ^ s[8];
    t[1] = c0_0 ^ s[1] ^ s[57] ^ s[41] ^ s[25] ^ s[9];
    t[2] = (c0_1 ^ c0_7) ^ s[2] ^ s[58] ^ s[42] ^ s[26] ^ s[10];
    t[3] = (c0_2 ^ c0_7) ^ s[3] ^ s[59] ^ s[43] ^ s[27] ^ s[11];
    t[4] = (c0_3 ^ c0_7) ^ s[4] ^ s[60] ^ s[44] ^ s[28] ^ s[12];
    t[5] = c0_4 ^ s[5] ^ s[61] ^ s[45] ^ s[29] ^ s[13];
    t[6] = c0_5 ^ s[6] ^ s[62] ^ s[46] ^ s[30] ^ s[14];
    t[7] = c0_6 ^ s[7] ^ s[63] ^ s[47] ^ s[31] ^ s[15];
    uint u1_0 = (s[40] ^ s[16]);
    uint u1_1 = (s[41] ^ s[17]);
    uint u1_2 = (s[42] ^ s[18]);
    uint u1_3 = (s[43] ^ s[19]);
    uint u1_4 = (s[44] ^ s[20]);
    uint u1_5 = (s[45] ^ s[21]);
    uint u1_6 = (s[46] ^ s[22]);
    uint u1_7 = (s[47] ^ s[23]);
    uint a1_0 = u1_7 ^ (s[56] ^ s[32]);
    uint a1_1 = u1_0 ^ (s[57] ^ s[33]);
    uint a1_2 = (u1_1 ^ u1_7) ^ (s[58] ^ s[34]);
    uint a1_3 = (u1_2 ^ u1_7) ^ (s[59] ^ s[35]);
    uint a1_4 = (u1_3 ^ u1_7) ^ (s[60] ^ s[36]);
    uint a1_5 = u1_4 ^ (s[61] ^ s[37]);
    uint a1_6 = u1_5 ^ (s[62] ^ s[38]);
    uint a1_7 = u1_6 ^ (s[63] ^ s[39]);
    uint c1_0 = a1_7 ^ s[24];
    uint c1_1 = a1_0 ^ s[25];
    uint c1_2 = (a1_1 ^ a1_7) ^ s[26];
    uint c1_3 = (a1_2 ^ a1_7) ^ s[27];
    uint c1_4 = (a1_3 ^ a1_7) ^ s[28];
    uint c1_5 = a1_4 ^ s[29];
    uint c1_6 = a1_5 ^ s[30];
    uint c1_7 = a1_6 ^ s[31];
    t[8] = c1_7 ^ s[8] ^ s[0] ^ s[48] ^ s[32] ^ s[16];
    t[9] = c1_0 ^ s[9] ^ s[1] ^ s[49] ^ s[33] ^ s[17];
    t[10] = (c1_1 ^ c1_7) ^ s[10] ^ s[2] ^ s[50] ^ s[34] ^ s[18];
    t[11] = (c1_2 ^ c1_7) ^ s[11] ^ s[3] ^ s[51] ^ s[35] ^ s[19];
    t[12] = (c1_3 ^ c1_7) ^ s[12] ^ s[4] ^ s[52] ^ s[36] ^ s[20];
    t[13] = c1_4 ^ s[13] ^ s[5] ^ s[53] ^ s[37] ^ s[21];
    t[14] = c1_5 ^ s[14] ^ s[6] ^ s[54] ^ s[38] ^ s[22];
    t[15] = c1_6 ^ s[15] ^ s[7] ^ s[55] ^ s[39] ^ s[23];
    uint u2_0 = (s[48] ^ s[24]);
    uint u2_1 = (s[49] ^ s[25]);
    uint u2_2 = (s[50] ^ s[26]);
    uint u2_3 = (s[51] ^ s[27]);
    uint u2_4 = (s[52] ^ s[28]);
    uint u2_5 = (s[53] ^ s[29]);
    uint u2_6 = (s[54] ^ s[30]);
    uint u2_7 = (s[55] ^ s[31]);
    uint a2_0 = u2_7 ^ (s[0] ^ s[40]);
    uint a2_1 = u2_0 ^ (s[1] ^ s[41]);
    uint a2_2 = (u2_1 ^ u2_7) ^ (s[2] ^ s[42]);
    uint a2_3 = (u2_2 ^ u2_7) ^ (s[3] ^ s[43]);
    uint a2_4 = (u2_3 ^ u2_7) ^ (s[4] ^ s[44]);
    uint a2_5 = u2_4 ^ (s[5] ^ s[45]);
    uint a2_6 = u2_5 ^ (s[6] ^ s[46]);
    uint a2_7 = u2_6 ^ (s[7] ^ s[47]);
    uint c2_0 = a2_7 ^ s[32];
    uint c2_1 = a2_0 ^ s[33];
    uint c2_2 = (a2_1 ^ a2_7) ^ s[34];
    uint c2_3 = (a2_2 ^ a2_7) ^ s[35];
    uint c2_4 = (a2_3 ^ a2_7) ^ s[36];
    uint c2_5 = a2_4 ^ s[37];
    uint c2_6 = a2_5 ^ s[38];
    uint c2_7 = a2_6 ^ s[39];
    t[16] = c2_7 ^ s[16] ^ s[8] ^ s[56] ^ s[40] ^ s[24];
    t[17] = c2_0 ^ s[17] ^ s[9] ^ s[57] ^ s[41] ^ s[25];
    t[18] = (c2_1 ^ c2_7) ^ s[18] ^ s[10] ^ s[58] ^ s[42] ^ s[26];
    t[19] = (c2_2 ^ c2_7) ^ s[19] ^ s[11] ^ s[59] ^ s[43] ^ s[27];
    t[20] = (c2_3 ^ c2_7) ^ s[20] ^ s[12] ^ s[60] ^ s[44] ^ s[28];
    t[21] = c2_4 ^ s[21] ^ s[13] ^ s[61] ^ s[45] ^ s[29];
    t[22] = c2_5 ^ s[22] ^ s[14] ^ s[62] ^ s[46] ^ s[30];
    t[23] = c2_6 ^ s[23] ^ s[15] ^ s[63] ^ s[47] ^ s[31];
    uint u3_0 = (s[56] ^ s[32]);
    uint u3_1 = (s[57] ^ s[33]);
    uint u3_2 = (s[58] ^ s[34]);
    uint u3_3 = (s[59] ^ s[35]);
    uint u3_4 = (s[60] ^ s[36]);
    uint u3_5 = (s[61] ^ s[37]);
    uint u3_6 = (s[62] ^ s[38]);
    uint u3_7 = (s[63] ^ s[39]);
    uint a3_0 = u3_7 ^ (s[8] ^ s[48]);
    uint a3_1 = u3_0 ^ (s[9] ^ s[49]);
    uint a3_2 = (u3_1 ^ u3_7) ^ (s[10] ^ s[50]);
    uint a3_3 = (u3_2 ^ u3_7) ^ (s[11] ^ s[51]);
    uint a3_4 = (u3_3 ^ u3_7) ^ (s[12] ^ s[52]);
    uint a3_5 = u3_4 ^ (s[13] ^ s[53]);
    uint a3_6 = u3_5 ^ (s[14] ^ s[54]);
    uint a3_7 = u3_6 ^ (s[15] ^ s[55]);
    uint c3_0 = a3_7 ^ s[40];
    uint c3_1 = a3_0 ^ s[41];
    uint c3_2 = (a3_1 ^ a3_7) ^ s[42];
    uint c3_3 = (a3_2 ^ a3_7) ^ s[43];
    uint c3_4 = (a3_3 ^ a3_7) ^ s[44];
    uint c3_5 = a3_4 ^ s[45];
    uint c3_6 = a3_5 ^ s[46];
    uint c3_7 = a3_6 ^ s[47];
    t[24] = c3_7 ^ s[24] ^ s[16] ^ s[0] ^ s[48] ^ s[32];
    t[25] = c3_0 ^ s[25] ^ s[17] ^ s[1] ^ s[49] ^ s[33];
    t[26] = (c3_1 ^ c3_7) ^ s[26] ^ s[18] ^ s[2] ^ s[50] ^ s[34];
    t[27] = (c3_2 ^ c3_7) ^ s[27] ^ s[19] ^ s[3] ^ s[51] ^ s[35];
    t[28] = (c3_3 ^ c3_7) ^ s[28] ^ s[20] ^ s[4] ^ s[52] ^ s[36];
    t[29] = c3_4 ^ s[29] ^ s[21] ^ s[5] ^ s[53] ^ s[37];
    t[30] = c3_5 ^ s[30] ^ s[22] ^ s[6] ^ s[54] ^ s[38];
    t[31] = c3_6 ^ s[31] ^ s[23] ^ s[7] ^ s[55] ^ s[39];
    uint u4_0 = (s[0] ^ s[40]);
    uint u4_1 = (s[1] ^ s[41]);
    uint u4_2 = (s[2] ^ s[42]);
    uint u4_3 = (s[3] ^ s[43]);
    uint u4_4 = (s[4] ^ s[44]);
    uint u4_5 = (s[5] ^ s[45]);
    uint u4_6 = (s[6] ^ s[46]);
    uint u4_7 = (s[7] ^ s[47]);
    uint a4_0 = u4_7 ^ (s[16] ^ s[56]);
    uint a4_1 = u4_0 ^ (s[17] ^ s[57]);
    uint a4_2 = (u4_1 ^ u4_7) ^ (s[18] ^ s[58]);
    uint a4_3 = (u4_2 ^ u4_7) ^ (s[19] ^ s[59]);
    uint a4_4 = (u4_3 ^ u4_7) ^ (s[20] ^ s[60]);
    uint a4_5 = u4_4 ^ (s[21] ^ s[61]);
    uint a4_6 = u4_5 ^ (s[22] ^ s[62]);
    uint a4_7 = u4_6 ^ (s[23] ^ s[63]);
    uint c4_0 = a4_7 ^ s[48];
    uint c4_1 = a4_0 ^ s[49];
    uint c4_2 = (a4_1 ^ a4_7) ^ s[50];
    uint c4_3 = (a4_2 ^ a4_7) ^ s[51];
    uint c4_4 = (a4_3 ^ a4_7) ^ s[52];
    uint c4_5 = a4_4 ^ s[53];
    uint c4_6 = a4_5 ^ s[54];
    uint c4_7 = a4_6 ^ s[55];
    t[32] = c4_7 ^ s[32] ^ s[24] ^ s[8] ^ s[56] ^ s[40];
    t[33] = c4_0 ^ s[33] ^ s[25] ^ s[9] ^ s[57] ^ s[41];
    t[34] = (c4_1 ^ c4_7) ^ s[34] ^ s[26] ^ s[10] ^ s[58] ^ s[42];
    t[35] = (c4_2 ^ c4_7) ^ s[35] ^ s[27] ^ s[11] ^ s[59] ^ s[43];
    t[36] = (c4_3 ^ c4_7) ^ s[36] ^ s[28] ^ s[12] ^ s[60] ^ s[44];
    t[37] = c4_4 ^ s[37] ^ s[29] ^ s[13] ^ s[61] ^ s[45];
    t[38] = c4_5 ^ s[38] ^ s[30] ^ s[14] ^ s[62] ^ s[46];
    t[39] = c4_6 ^ s[39] ^ s[31] ^ s[15] ^ s[63] ^ s[47];
    uint u5_0 = (s[8] ^ s[48]);
    uint u5_1 = (s[9] ^ s[49]);
    uint u5_2 = (s[10] ^ s[50]);
    uint u5_3 = (s[11] ^ s[51]);
    uint u5_4 = (s[12] ^ s[52]);
    uint u5_5 = (s[13] ^ s[53]);
    uint u5_6 = (s[14] ^ s[54]);
    uint u5_7 = (s[15] ^ s[55]);
    uint a5_0 = u5_7 ^ (s[24] ^ s[0]);
    uint a5_1 = u5_0 ^ (s[25] ^ s[1]);
    uint a5_2 = (u5_1 ^ u5_7) ^ (s[26] ^ s[2]);
    uint a5_3 = (u5_2 ^ u5_7) ^ (s[27] ^ s[3]);
    uint a5_4 = (u5_3 ^ u5_7) ^ (s[28] ^ s[4]);
    uint a5_5 = u5_4 ^ (s[29] ^ s[5]);
    uint a5_6 = u5_5 ^ (s[30] ^ s[6]);
    uint a5_7 = u5_6 ^ (s[31] ^ s[7]);
    uint c5_0 = a5_7 ^ s[56];
    uint c5_1 = a5_0 ^ s[57];
    uint c5_2 = (a5_1 ^ a5_7) ^ s[58];
    uint c5_3 = (a5_2 ^ a5_7) ^ s[59];
    uint c5_4 = (a5_3 ^ a5_7) ^ s[60];
    uint c5_5 = a5_4 ^ s[61];
    uint c5_6 = a5_5 ^ s[62];
    uint c5_7 = a5_6 ^ s[63];
    t[40] = c5_7 ^ s[40] ^ s[32] ^ s[16] ^ s[0] ^ s[48];
    t[41] = c5_0 ^ s[41] ^ s[33] ^ s[17] ^ s[1] ^ s[49];
    t[42] = (c5_1 ^ c5_7) ^ s[42] ^ s[34] ^ s[18] ^ s[2] ^ s[50];
    t[43] = (c5_2 ^ c5_7) ^ s[43] ^ s[35] ^ s[19] ^ s[3] ^ s[51];
    t[44] = (c5_3 ^ c5_7) ^ s[44] ^ s[36] ^ s[20] ^ s[4] ^ s[52];
    t[45] = c5_4 ^ s[45] ^ s[37] ^ s[21] ^ s[5] ^ s[53];
    t[46] = c5_5 ^ s[46] ^ s[38] ^ s[22] ^ s[6] ^ s[54];
    t[47] = c5_6 ^ s[47] ^ s[39] ^ s[23] ^ s[7] ^ s[55];
    uint u6_0 = (s[16] ^ s[56]);
    uint u6_1 = (s[17] ^ s[57]);
    uint u6_2 = (s[18] ^ s[58]);
    uint u6_3 = (s[19] ^ s[59]);
    uint u6_4 = (s[20] ^ s[60]);
    uint u6_5 = (s[21] ^ s[61]);
    uint u6_6 = (s[22] ^ s[62]);
    uint u6_7 = (s[23] ^ s[63]);
    uint a6_0 = u6_7 ^ (s[32] ^ s[8]);
    uint a6_1 = u6_0 ^ (s[33] ^ s[9]);
    uint a6_2 = (u6_1 ^ u6_7) ^ (s[34] ^ s[10]);
    uint a6_3 = (u6_2 ^ u6_7) ^ (s[35] ^ s[11]);
    uint a6_4 = (u6_3 ^ u6_7) ^ (s[36] ^ s[12]);
    uint a6_5 = u6_4 ^ (s[37] ^ s[13]);
    uint a6_6 = u6_5 ^ (s[38] ^ s[14]);
    uint a6_7 = u6_6 ^ (s[39] ^ s[15]);
    uint c6_0 = a6_7 ^ s[0];
    uint c6_1 = a6_0 ^ s[1];
    uint c6_2 = (a6_1 ^ a6_7) ^ s[2];
    uint c6_3 = (a6_2 ^ a6_7) ^ s[3];
    uint c6_4 = (a6_3 ^ a6_7) ^ s[4];
    uint c6_5 = a6_4 ^ s[5];
    uint c6_6 = a6_5 ^ s[6];
    uint c6_7 = a6_6 ^ s[7];
    t[48] = c6_7 ^ s[48] ^ s[40] ^ s[24] ^ s[8] ^ s[56];
    t[49] = c6_0 ^ s[49] ^ s[41] ^ s[25] ^ s[9] ^ s[57];
    t[50] = (c6_1 ^ c6_7) ^ s[50] ^ s[42] ^ s[26] ^ s[10] ^ s[58];
    t[51] = (c6_2 ^ c6_7) ^ s[51] ^ s[43] ^ s[27] ^ s[11] ^ s[59];
    t[52] = (c6_3 ^ c6_7) ^ s[52] ^ s[44] ^ s[28] ^ s[12] ^ s[60];
    t[53] = c6_4 ^ s[53] ^ s[45] ^ s[29] ^ s[13] ^ s[61];
    t[54] = c6_5 ^ s[54] ^ s[46] ^ s[30] ^ s[14] ^ s[62];
    t[55] = c6_6 ^ s[55] ^ s[47] ^ s[31] ^ s[15] ^ s[63];
    uint u7_0 = (s[24] ^ s[0]);
    uint u7_1 = (s[25] ^ s[1]);
    uint u7_2 = (s[26] ^ s[2]);
    uint u7_3 = (s[27] ^ s[3]);
    uint u7_4 = (s[28] ^ s[4]);
    uint u7_5 = (s[29] ^ s[5]);
    uint u7_6 = (s[30] ^ s[6]);
    uint u7_7 = (s[31] ^ s[7]);
    uint a7_0 = u7_7 ^ (s[40] ^ s[16]);
    uint a7_1 = u7_0 ^ (s[41] ^ s[17]);
    uint a7_2 = (u7_1 ^ u7_7) ^ (s[42] ^ s[18]);
    uint a7_3 = (u7_2 ^ u7_7) ^ (s[43] ^ s[19]);
    uint a7_4 = (u7_3 ^ u7_7) ^ (s[44] ^ s[20]);
    uint a7_5 = u7_4 ^ (s[45] ^ s[21]);
    uint a7_6 = u7_5 ^ (s[46] ^ s[22]);
    uint a7_7 = u7_6 ^ (s[47] ^ s[23]);
    uint c7_0 = a7_7 ^ s[8];
    uint c7_1 = a7_0 ^ s[9];
    uint c7_2 = (a7_1 ^ a7_7) ^ s[10];
    uint c7_3 = (a7_2 ^ a7_7) ^ s[11];
    uint c7_4 = (a7_3 ^ a7_7) ^ s[12];
    uint c7_5 = a7_4 ^ s[13];
    uint c7_6 = a7_5 ^ s[14];
    uint c7_7 = a7_6 ^ s[15];
    t[56] = c7_7 ^ s[56] ^ s[48] ^ s[32] ^ s[16] ^ s[0];
    t[57] = c7_0 ^ s[57] ^ s[49] ^ s[33] ^ s[17] ^ s[1];
    t[58] = (c7_1 ^ c7_7) ^ s[58] ^ s[50] ^ s[34] ^ s[18] ^ s[2];
    t[59] = (c7_2 ^ c7_7) ^ s[59] ^ s[51] ^ s[35] ^ s[19] ^ s[3];
    t[60] = (c7_3 ^ c7_7) ^ s[60] ^ s[52] ^ s[36] ^ s[20] ^ s[4];
    t[61] = c7_4 ^ s[61] ^ s[53] ^ s[37] ^ s[21] ^ s[5];
    t[62] = c7_5 ^ s[62] ^ s[54] ^ s[38] ^ s[22] ^ s[6];
    t[63] = c7_6 ^ s[63] ^ s[55] ^ s[39] ^ s[23] ^ s[7];
    s = t;
}

// Byte n of a and byte n of b, as the low half of a word.
uint wpx4_pair(uint a, uint b, uint n)
{
    return ((a >> (8u * n)) & 0xffu) | (((b >> (8u * n)) & 0xffu) << 8);
}

// Whirlpool of messages h = 0..3, sixteen little-endian words each at
// m[16 h], into d the same way.
void whirlpool512_x4_hash64(uint m[64], out uint d[64])
{
    // Word k of column c, byte n: byte (row 2 n + k / 4, column c) of
    // message k % 4; then each column to planes, swapping the index bits of
    // word k and of bit b within each byte.
    uint s[64];
    s[0] = wpx4_pair(m[0], m[4], 0u) | (wpx4_pair(m[8], m[12], 0u) << 16);
    s[1] = wpx4_pair(m[16], m[20], 0u) | (wpx4_pair(m[24], m[28], 0u) << 16);
    s[2] = wpx4_pair(m[32], m[36], 0u) | (wpx4_pair(m[40], m[44], 0u) << 16);
    s[3] = wpx4_pair(m[48], m[52], 0u) | (wpx4_pair(m[56], m[60], 0u) << 16);
    s[4] = wpx4_pair(m[2], m[6], 0u) | (wpx4_pair(m[10], m[14], 0u) << 16);
    s[5] = wpx4_pair(m[18], m[22], 0u) | (wpx4_pair(m[26], m[30], 0u) << 16);
    s[6] = wpx4_pair(m[34], m[38], 0u) | (wpx4_pair(m[42], m[46], 0u) << 16);
    s[7] = wpx4_pair(m[50], m[54], 0u) | (wpx4_pair(m[58], m[62], 0u) << 16);
    s[8] = wpx4_pair(m[0], m[4], 1u) | (wpx4_pair(m[8], m[12], 1u) << 16);
    s[9] = wpx4_pair(m[16], m[20], 1u) | (wpx4_pair(m[24], m[28], 1u) << 16);
    s[10] = wpx4_pair(m[32], m[36], 1u) | (wpx4_pair(m[40], m[44], 1u) << 16);
    s[11] = wpx4_pair(m[48], m[52], 1u) | (wpx4_pair(m[56], m[60], 1u) << 16);
    s[12] = wpx4_pair(m[2], m[6], 1u) | (wpx4_pair(m[10], m[14], 1u) << 16);
    s[13] = wpx4_pair(m[18], m[22], 1u) | (wpx4_pair(m[26], m[30], 1u) << 16);
    s[14] = wpx4_pair(m[34], m[38], 1u) | (wpx4_pair(m[42], m[46], 1u) << 16);
    s[15] = wpx4_pair(m[50], m[54], 1u) | (wpx4_pair(m[58], m[62], 1u) << 16);
    s[16] = wpx4_pair(m[0], m[4], 2u) | (wpx4_pair(m[8], m[12], 2u) << 16);
    s[17] = wpx4_pair(m[16], m[20], 2u) | (wpx4_pair(m[24], m[28], 2u) << 16);
    s[18] = wpx4_pair(m[32], m[36], 2u) | (wpx4_pair(m[40], m[44], 2u) << 16);
    s[19] = wpx4_pair(m[48], m[52], 2u) | (wpx4_pair(m[56], m[60], 2u) << 16);
    s[20] = wpx4_pair(m[2], m[6], 2u) | (wpx4_pair(m[10], m[14], 2u) << 16);
    s[21] = wpx4_pair(m[18], m[22], 2u) | (wpx4_pair(m[26], m[30], 2u) << 16);
    s[22] = wpx4_pair(m[34], m[38], 2u) | (wpx4_pair(m[42], m[46], 2u) << 16);
    s[23] = wpx4_pair(m[50], m[54], 2u) | (wpx4_pair(m[58], m[62], 2u) << 16);
    s[24] = wpx4_pair(m[0], m[4], 3u) | (wpx4_pair(m[8], m[12], 3u) << 16);
    s[25] = wpx4_pair(m[16], m[20], 3u) | (wpx4_pair(m[24], m[28], 3u) << 16);
    s[26] = wpx4_pair(m[32], m[36], 3u) | (wpx4_pair(m[40], m[44], 3u) << 16);
    s[27] = wpx4_pair(m[48], m[52], 3u) | (wpx4_pair(m[56], m[60], 3u) << 16);
    s[28] = wpx4_pair(m[2], m[6], 3u) | (wpx4_pair(m[10], m[14], 3u) << 16);
    s[29] = wpx4_pair(m[18], m[22], 3u) | (wpx4_pair(m[26], m[30], 3u) << 16);
    s[30] = wpx4_pair(m[34], m[38], 3u) | (wpx4_pair(m[42], m[46], 3u) << 16);
    s[31] = wpx4_pair(m[50], m[54], 3u) | (wpx4_pair(m[58], m[62], 3u) << 16);
    s[32] = wpx4_pair(m[1], m[5], 0u) | (wpx4_pair(m[9], m[13], 0u) << 16);
    s[33] = wpx4_pair(m[17], m[21], 0u) | (wpx4_pair(m[25], m[29], 0u) << 16);
    s[34] = wpx4_pair(m[33], m[37], 0u) | (wpx4_pair(m[41], m[45], 0u) << 16);
    s[35] = wpx4_pair(m[49], m[53], 0u) | (wpx4_pair(m[57], m[61], 0u) << 16);
    s[36] = wpx4_pair(m[3], m[7], 0u) | (wpx4_pair(m[11], m[15], 0u) << 16);
    s[37] = wpx4_pair(m[19], m[23], 0u) | (wpx4_pair(m[27], m[31], 0u) << 16);
    s[38] = wpx4_pair(m[35], m[39], 0u) | (wpx4_pair(m[43], m[47], 0u) << 16);
    s[39] = wpx4_pair(m[51], m[55], 0u) | (wpx4_pair(m[59], m[63], 0u) << 16);
    s[40] = wpx4_pair(m[1], m[5], 1u) | (wpx4_pair(m[9], m[13], 1u) << 16);
    s[41] = wpx4_pair(m[17], m[21], 1u) | (wpx4_pair(m[25], m[29], 1u) << 16);
    s[42] = wpx4_pair(m[33], m[37], 1u) | (wpx4_pair(m[41], m[45], 1u) << 16);
    s[43] = wpx4_pair(m[49], m[53], 1u) | (wpx4_pair(m[57], m[61], 1u) << 16);
    s[44] = wpx4_pair(m[3], m[7], 1u) | (wpx4_pair(m[11], m[15], 1u) << 16);
    s[45] = wpx4_pair(m[19], m[23], 1u) | (wpx4_pair(m[27], m[31], 1u) << 16);
    s[46] = wpx4_pair(m[35], m[39], 1u) | (wpx4_pair(m[43], m[47], 1u) << 16);
    s[47] = wpx4_pair(m[51], m[55], 1u) | (wpx4_pair(m[59], m[63], 1u) << 16);
    s[48] = wpx4_pair(m[1], m[5], 2u) | (wpx4_pair(m[9], m[13], 2u) << 16);
    s[49] = wpx4_pair(m[17], m[21], 2u) | (wpx4_pair(m[25], m[29], 2u) << 16);
    s[50] = wpx4_pair(m[33], m[37], 2u) | (wpx4_pair(m[41], m[45], 2u) << 16);
    s[51] = wpx4_pair(m[49], m[53], 2u) | (wpx4_pair(m[57], m[61], 2u) << 16);
    s[52] = wpx4_pair(m[3], m[7], 2u) | (wpx4_pair(m[11], m[15], 2u) << 16);
    s[53] = wpx4_pair(m[19], m[23], 2u) | (wpx4_pair(m[27], m[31], 2u) << 16);
    s[54] = wpx4_pair(m[35], m[39], 2u) | (wpx4_pair(m[43], m[47], 2u) << 16);
    s[55] = wpx4_pair(m[51], m[55], 2u) | (wpx4_pair(m[59], m[63], 2u) << 16);
    s[56] = wpx4_pair(m[1], m[5], 3u) | (wpx4_pair(m[9], m[13], 3u) << 16);
    s[57] = wpx4_pair(m[17], m[21], 3u) | (wpx4_pair(m[25], m[29], 3u) << 16);
    s[58] = wpx4_pair(m[33], m[37], 3u) | (wpx4_pair(m[41], m[45], 3u) << 16);
    s[59] = wpx4_pair(m[49], m[53], 3u) | (wpx4_pair(m[57], m[61], 3u) << 16);
    s[60] = wpx4_pair(m[3], m[7], 3u) | (wpx4_pair(m[11], m[15], 3u) << 16);
    s[61] = wpx4_pair(m[19], m[23], 3u) | (wpx4_pair(m[27], m[31], 3u) << 16);
    s[62] = wpx4_pair(m[35], m[39], 3u) | (wpx4_pair(m[43], m[47], 3u) << 16);
    s[63] = wpx4_pair(m[51], m[55], 3u) | (wpx4_pair(m[59], m[63], 3u) << 16);
    {
    uint t;
    t = (s[0] ^ (s[1] << 1)) & 0xaaaaaaaau; s[0] ^= t; s[1] ^= t >> 1;
    t = (s[2] ^ (s[3] << 1)) & 0xaaaaaaaau; s[2] ^= t; s[3] ^= t >> 1;
    t = (s[4] ^ (s[5] << 1)) & 0xaaaaaaaau; s[4] ^= t; s[5] ^= t >> 1;
    t = (s[6] ^ (s[7] << 1)) & 0xaaaaaaaau; s[6] ^= t; s[7] ^= t >> 1;
    t = (s[0] ^ (s[2] << 2)) & 0xccccccccu; s[0] ^= t; s[2] ^= t >> 2;
    t = (s[1] ^ (s[3] << 2)) & 0xccccccccu; s[1] ^= t; s[3] ^= t >> 2;
    t = (s[4] ^ (s[6] << 2)) & 0xccccccccu; s[4] ^= t; s[6] ^= t >> 2;
    t = (s[5] ^ (s[7] << 2)) & 0xccccccccu; s[5] ^= t; s[7] ^= t >> 2;
    t = (s[0] ^ (s[4] << 4)) & 0xf0f0f0f0u; s[0] ^= t; s[4] ^= t >> 4;
    t = (s[1] ^ (s[5] << 4)) & 0xf0f0f0f0u; s[1] ^= t; s[5] ^= t >> 4;
    t = (s[2] ^ (s[6] << 4)) & 0xf0f0f0f0u; s[2] ^= t; s[6] ^= t >> 4;
    t = (s[3] ^ (s[7] << 4)) & 0xf0f0f0f0u; s[3] ^= t; s[7] ^= t >> 4;
    }
    {
    uint t;
    t = (s[8] ^ (s[9] << 1)) & 0xaaaaaaaau; s[8] ^= t; s[9] ^= t >> 1;
    t = (s[10] ^ (s[11] << 1)) & 0xaaaaaaaau; s[10] ^= t; s[11] ^= t >> 1;
    t = (s[12] ^ (s[13] << 1)) & 0xaaaaaaaau; s[12] ^= t; s[13] ^= t >> 1;
    t = (s[14] ^ (s[15] << 1)) & 0xaaaaaaaau; s[14] ^= t; s[15] ^= t >> 1;
    t = (s[8] ^ (s[10] << 2)) & 0xccccccccu; s[8] ^= t; s[10] ^= t >> 2;
    t = (s[9] ^ (s[11] << 2)) & 0xccccccccu; s[9] ^= t; s[11] ^= t >> 2;
    t = (s[12] ^ (s[14] << 2)) & 0xccccccccu; s[12] ^= t; s[14] ^= t >> 2;
    t = (s[13] ^ (s[15] << 2)) & 0xccccccccu; s[13] ^= t; s[15] ^= t >> 2;
    t = (s[8] ^ (s[12] << 4)) & 0xf0f0f0f0u; s[8] ^= t; s[12] ^= t >> 4;
    t = (s[9] ^ (s[13] << 4)) & 0xf0f0f0f0u; s[9] ^= t; s[13] ^= t >> 4;
    t = (s[10] ^ (s[14] << 4)) & 0xf0f0f0f0u; s[10] ^= t; s[14] ^= t >> 4;
    t = (s[11] ^ (s[15] << 4)) & 0xf0f0f0f0u; s[11] ^= t; s[15] ^= t >> 4;
    }
    {
    uint t;
    t = (s[16] ^ (s[17] << 1)) & 0xaaaaaaaau; s[16] ^= t; s[17] ^= t >> 1;
    t = (s[18] ^ (s[19] << 1)) & 0xaaaaaaaau; s[18] ^= t; s[19] ^= t >> 1;
    t = (s[20] ^ (s[21] << 1)) & 0xaaaaaaaau; s[20] ^= t; s[21] ^= t >> 1;
    t = (s[22] ^ (s[23] << 1)) & 0xaaaaaaaau; s[22] ^= t; s[23] ^= t >> 1;
    t = (s[16] ^ (s[18] << 2)) & 0xccccccccu; s[16] ^= t; s[18] ^= t >> 2;
    t = (s[17] ^ (s[19] << 2)) & 0xccccccccu; s[17] ^= t; s[19] ^= t >> 2;
    t = (s[20] ^ (s[22] << 2)) & 0xccccccccu; s[20] ^= t; s[22] ^= t >> 2;
    t = (s[21] ^ (s[23] << 2)) & 0xccccccccu; s[21] ^= t; s[23] ^= t >> 2;
    t = (s[16] ^ (s[20] << 4)) & 0xf0f0f0f0u; s[16] ^= t; s[20] ^= t >> 4;
    t = (s[17] ^ (s[21] << 4)) & 0xf0f0f0f0u; s[17] ^= t; s[21] ^= t >> 4;
    t = (s[18] ^ (s[22] << 4)) & 0xf0f0f0f0u; s[18] ^= t; s[22] ^= t >> 4;
    t = (s[19] ^ (s[23] << 4)) & 0xf0f0f0f0u; s[19] ^= t; s[23] ^= t >> 4;
    }
    {
    uint t;
    t = (s[24] ^ (s[25] << 1)) & 0xaaaaaaaau; s[24] ^= t; s[25] ^= t >> 1;
    t = (s[26] ^ (s[27] << 1)) & 0xaaaaaaaau; s[26] ^= t; s[27] ^= t >> 1;
    t = (s[28] ^ (s[29] << 1)) & 0xaaaaaaaau; s[28] ^= t; s[29] ^= t >> 1;
    t = (s[30] ^ (s[31] << 1)) & 0xaaaaaaaau; s[30] ^= t; s[31] ^= t >> 1;
    t = (s[24] ^ (s[26] << 2)) & 0xccccccccu; s[24] ^= t; s[26] ^= t >> 2;
    t = (s[25] ^ (s[27] << 2)) & 0xccccccccu; s[25] ^= t; s[27] ^= t >> 2;
    t = (s[28] ^ (s[30] << 2)) & 0xccccccccu; s[28] ^= t; s[30] ^= t >> 2;
    t = (s[29] ^ (s[31] << 2)) & 0xccccccccu; s[29] ^= t; s[31] ^= t >> 2;
    t = (s[24] ^ (s[28] << 4)) & 0xf0f0f0f0u; s[24] ^= t; s[28] ^= t >> 4;
    t = (s[25] ^ (s[29] << 4)) & 0xf0f0f0f0u; s[25] ^= t; s[29] ^= t >> 4;
    t = (s[26] ^ (s[30] << 4)) & 0xf0f0f0f0u; s[26] ^= t; s[30] ^= t >> 4;
    t = (s[27] ^ (s[31] << 4)) & 0xf0f0f0f0u; s[27] ^= t; s[31] ^= t >> 4;
    }
    {
    uint t;
    t = (s[32] ^ (s[33] << 1)) & 0xaaaaaaaau; s[32] ^= t; s[33] ^= t >> 1;
    t = (s[34] ^ (s[35] << 1)) & 0xaaaaaaaau; s[34] ^= t; s[35] ^= t >> 1;
    t = (s[36] ^ (s[37] << 1)) & 0xaaaaaaaau; s[36] ^= t; s[37] ^= t >> 1;
    t = (s[38] ^ (s[39] << 1)) & 0xaaaaaaaau; s[38] ^= t; s[39] ^= t >> 1;
    t = (s[32] ^ (s[34] << 2)) & 0xccccccccu; s[32] ^= t; s[34] ^= t >> 2;
    t = (s[33] ^ (s[35] << 2)) & 0xccccccccu; s[33] ^= t; s[35] ^= t >> 2;
    t = (s[36] ^ (s[38] << 2)) & 0xccccccccu; s[36] ^= t; s[38] ^= t >> 2;
    t = (s[37] ^ (s[39] << 2)) & 0xccccccccu; s[37] ^= t; s[39] ^= t >> 2;
    t = (s[32] ^ (s[36] << 4)) & 0xf0f0f0f0u; s[32] ^= t; s[36] ^= t >> 4;
    t = (s[33] ^ (s[37] << 4)) & 0xf0f0f0f0u; s[33] ^= t; s[37] ^= t >> 4;
    t = (s[34] ^ (s[38] << 4)) & 0xf0f0f0f0u; s[34] ^= t; s[38] ^= t >> 4;
    t = (s[35] ^ (s[39] << 4)) & 0xf0f0f0f0u; s[35] ^= t; s[39] ^= t >> 4;
    }
    {
    uint t;
    t = (s[40] ^ (s[41] << 1)) & 0xaaaaaaaau; s[40] ^= t; s[41] ^= t >> 1;
    t = (s[42] ^ (s[43] << 1)) & 0xaaaaaaaau; s[42] ^= t; s[43] ^= t >> 1;
    t = (s[44] ^ (s[45] << 1)) & 0xaaaaaaaau; s[44] ^= t; s[45] ^= t >> 1;
    t = (s[46] ^ (s[47] << 1)) & 0xaaaaaaaau; s[46] ^= t; s[47] ^= t >> 1;
    t = (s[40] ^ (s[42] << 2)) & 0xccccccccu; s[40] ^= t; s[42] ^= t >> 2;
    t = (s[41] ^ (s[43] << 2)) & 0xccccccccu; s[41] ^= t; s[43] ^= t >> 2;
    t = (s[44] ^ (s[46] << 2)) & 0xccccccccu; s[44] ^= t; s[46] ^= t >> 2;
    t = (s[45] ^ (s[47] << 2)) & 0xccccccccu; s[45] ^= t; s[47] ^= t >> 2;
    t = (s[40] ^ (s[44] << 4)) & 0xf0f0f0f0u; s[40] ^= t; s[44] ^= t >> 4;
    t = (s[41] ^ (s[45] << 4)) & 0xf0f0f0f0u; s[41] ^= t; s[45] ^= t >> 4;
    t = (s[42] ^ (s[46] << 4)) & 0xf0f0f0f0u; s[42] ^= t; s[46] ^= t >> 4;
    t = (s[43] ^ (s[47] << 4)) & 0xf0f0f0f0u; s[43] ^= t; s[47] ^= t >> 4;
    }
    {
    uint t;
    t = (s[48] ^ (s[49] << 1)) & 0xaaaaaaaau; s[48] ^= t; s[49] ^= t >> 1;
    t = (s[50] ^ (s[51] << 1)) & 0xaaaaaaaau; s[50] ^= t; s[51] ^= t >> 1;
    t = (s[52] ^ (s[53] << 1)) & 0xaaaaaaaau; s[52] ^= t; s[53] ^= t >> 1;
    t = (s[54] ^ (s[55] << 1)) & 0xaaaaaaaau; s[54] ^= t; s[55] ^= t >> 1;
    t = (s[48] ^ (s[50] << 2)) & 0xccccccccu; s[48] ^= t; s[50] ^= t >> 2;
    t = (s[49] ^ (s[51] << 2)) & 0xccccccccu; s[49] ^= t; s[51] ^= t >> 2;
    t = (s[52] ^ (s[54] << 2)) & 0xccccccccu; s[52] ^= t; s[54] ^= t >> 2;
    t = (s[53] ^ (s[55] << 2)) & 0xccccccccu; s[53] ^= t; s[55] ^= t >> 2;
    t = (s[48] ^ (s[52] << 4)) & 0xf0f0f0f0u; s[48] ^= t; s[52] ^= t >> 4;
    t = (s[49] ^ (s[53] << 4)) & 0xf0f0f0f0u; s[49] ^= t; s[53] ^= t >> 4;
    t = (s[50] ^ (s[54] << 4)) & 0xf0f0f0f0u; s[50] ^= t; s[54] ^= t >> 4;
    t = (s[51] ^ (s[55] << 4)) & 0xf0f0f0f0u; s[51] ^= t; s[55] ^= t >> 4;
    }
    {
    uint t;
    t = (s[56] ^ (s[57] << 1)) & 0xaaaaaaaau; s[56] ^= t; s[57] ^= t >> 1;
    t = (s[58] ^ (s[59] << 1)) & 0xaaaaaaaau; s[58] ^= t; s[59] ^= t >> 1;
    t = (s[60] ^ (s[61] << 1)) & 0xaaaaaaaau; s[60] ^= t; s[61] ^= t >> 1;
    t = (s[62] ^ (s[63] << 1)) & 0xaaaaaaaau; s[62] ^= t; s[63] ^= t >> 1;
    t = (s[56] ^ (s[58] << 2)) & 0xccccccccu; s[56] ^= t; s[58] ^= t >> 2;
    t = (s[57] ^ (s[59] << 2)) & 0xccccccccu; s[57] ^= t; s[59] ^= t >> 2;
    t = (s[60] ^ (s[62] << 2)) & 0xccccccccu; s[60] ^= t; s[62] ^= t >> 2;
    t = (s[61] ^ (s[63] << 2)) & 0xccccccccu; s[61] ^= t; s[63] ^= t >> 2;
    t = (s[56] ^ (s[60] << 4)) & 0xf0f0f0f0u; s[56] ^= t; s[60] ^= t >> 4;
    t = (s[57] ^ (s[61] << 4)) & 0xf0f0f0f0u; s[57] ^= t; s[61] ^= t >> 4;
    t = (s[58] ^ (s[62] << 4)) & 0xf0f0f0f0u; s[58] ^= t; s[62] ^= t >> 4;
    t = (s[59] ^ (s[63] << 4)) & 0xf0f0f0f0u; s[59] ^= t; s[63] ^= t >> 4;
    }

    // First block, from a zero chaining value: its key schedule is a table.
    uint h1[64] = s;
    [[dont_unroll]] for (uint r = 0u; r < 10u; r++) {
        wpx4_round(s);
        s[0] ^= kWhirlpoolX4Key1[64u * r + 0u];
        s[1] ^= kWhirlpoolX4Key1[64u * r + 1u];
        s[2] ^= kWhirlpoolX4Key1[64u * r + 2u];
        s[3] ^= kWhirlpoolX4Key1[64u * r + 3u];
        s[4] ^= kWhirlpoolX4Key1[64u * r + 4u];
        s[5] ^= kWhirlpoolX4Key1[64u * r + 5u];
        s[6] ^= kWhirlpoolX4Key1[64u * r + 6u];
        s[7] ^= kWhirlpoolX4Key1[64u * r + 7u];
        s[8] ^= kWhirlpoolX4Key1[64u * r + 8u];
        s[9] ^= kWhirlpoolX4Key1[64u * r + 9u];
        s[10] ^= kWhirlpoolX4Key1[64u * r + 10u];
        s[11] ^= kWhirlpoolX4Key1[64u * r + 11u];
        s[12] ^= kWhirlpoolX4Key1[64u * r + 12u];
        s[13] ^= kWhirlpoolX4Key1[64u * r + 13u];
        s[14] ^= kWhirlpoolX4Key1[64u * r + 14u];
        s[15] ^= kWhirlpoolX4Key1[64u * r + 15u];
        s[16] ^= kWhirlpoolX4Key1[64u * r + 16u];
        s[17] ^= kWhirlpoolX4Key1[64u * r + 17u];
        s[18] ^= kWhirlpoolX4Key1[64u * r + 18u];
        s[19] ^= kWhirlpoolX4Key1[64u * r + 19u];
        s[20] ^= kWhirlpoolX4Key1[64u * r + 20u];
        s[21] ^= kWhirlpoolX4Key1[64u * r + 21u];
        s[22] ^= kWhirlpoolX4Key1[64u * r + 22u];
        s[23] ^= kWhirlpoolX4Key1[64u * r + 23u];
        s[24] ^= kWhirlpoolX4Key1[64u * r + 24u];
        s[25] ^= kWhirlpoolX4Key1[64u * r + 25u];
        s[26] ^= kWhirlpoolX4Key1[64u * r + 26u];
        s[27] ^= kWhirlpoolX4Key1[64u * r + 27u];
        s[28] ^= kWhirlpoolX4Key1[64u * r + 28u];
        s[29] ^= kWhirlpoolX4Key1[64u * r + 29u];
        s[30] ^= kWhirlpoolX4Key1[64u * r + 30u];
        s[31] ^= kWhirlpoolX4Key1[64u * r + 31u];
        s[32] ^= kWhirlpoolX4Key1[64u * r + 32u];
        s[33] ^= kWhirlpoolX4Key1[64u * r + 33u];
        s[34] ^= kWhirlpoolX4Key1[64u * r + 34u];
        s[35] ^= kWhirlpoolX4Key1[64u * r + 35u];
        s[36] ^= kWhirlpoolX4Key1[64u * r + 36u];
        s[37] ^= kWhirlpoolX4Key1[64u * r + 37u];
        s[38] ^= kWhirlpoolX4Key1[64u * r + 38u];
        s[39] ^= kWhirlpoolX4Key1[64u * r + 39u];
        s[40] ^= kWhirlpoolX4Key1[64u * r + 40u];
        s[41] ^= kWhirlpoolX4Key1[64u * r + 41u];
        s[42] ^= kWhirlpoolX4Key1[64u * r + 42u];
        s[43] ^= kWhirlpoolX4Key1[64u * r + 43u];
        s[44] ^= kWhirlpoolX4Key1[64u * r + 44u];
        s[45] ^= kWhirlpoolX4Key1[64u * r + 45u];
        s[46] ^= kWhirlpoolX4Key1[64u * r + 46u];
        s[47] ^= kWhirlpoolX4Key1[64u * r + 47u];
        s[48] ^= kWhirlpoolX4Key1[64u * r + 48u];
        s[49] ^= kWhirlpoolX4Key1[64u * r + 49u];
        s[50] ^= kWhirlpoolX4Key1[64u * r + 50u];
        s[51] ^= kWhirlpoolX4Key1[64u * r + 51u];
        s[52] ^= kWhirlpoolX4Key1[64u * r + 52u];
        s[53] ^= kWhirlpoolX4Key1[64u * r + 53u];
        s[54] ^= kWhirlpoolX4Key1[64u * r + 54u];
        s[55] ^= kWhirlpoolX4Key1[64u * r + 55u];
        s[56] ^= kWhirlpoolX4Key1[64u * r + 56u];
        s[57] ^= kWhirlpoolX4Key1[64u * r + 57u];
        s[58] ^= kWhirlpoolX4Key1[64u * r + 58u];
        s[59] ^= kWhirlpoolX4Key1[64u * r + 59u];
        s[60] ^= kWhirlpoolX4Key1[64u * r + 60u];
        s[61] ^= kWhirlpoolX4Key1[64u * r + 61u];
        s[62] ^= kWhirlpoolX4Key1[64u * r + 62u];
        s[63] ^= kWhirlpoolX4Key1[64u * r + 63u];
    }
    h1[0] ^= s[0];
    h1[1] ^= s[1];
    h1[2] ^= s[2];
    h1[3] ^= s[3];
    h1[4] ^= s[4];
    h1[5] ^= s[5];
    h1[6] ^= s[6];
    h1[7] ^= s[7];
    h1[8] ^= s[8];
    h1[9] ^= s[9];
    h1[10] ^= s[10];
    h1[11] ^= s[11];
    h1[12] ^= s[12];
    h1[13] ^= s[13];
    h1[14] ^= s[14];
    h1[15] ^= s[15];
    h1[16] ^= s[16];
    h1[17] ^= s[17];
    h1[18] ^= s[18];
    h1[19] ^= s[19];
    h1[20] ^= s[20];
    h1[21] ^= s[21];
    h1[22] ^= s[22];
    h1[23] ^= s[23];
    h1[24] ^= s[24];
    h1[25] ^= s[25];
    h1[26] ^= s[26];
    h1[27] ^= s[27];
    h1[28] ^= s[28];
    h1[29] ^= s[29];
    h1[30] ^= s[30];
    h1[31] ^= s[31];
    h1[32] ^= s[32];
    h1[33] ^= s[33];
    h1[34] ^= s[34];
    h1[35] ^= s[35];
    h1[36] ^= s[36];
    h1[37] ^= s[37];
    h1[38] ^= s[38];
    h1[39] ^= s[39];
    h1[40] ^= s[40];
    h1[41] ^= s[41];
    h1[42] ^= s[42];
    h1[43] ^= s[43];
    h1[44] ^= s[44];
    h1[45] ^= s[45];
    h1[46] ^= s[46];
    h1[47] ^= s[47];
    h1[48] ^= s[48];
    h1[49] ^= s[49];
    h1[50] ^= s[50];
    h1[51] ^= s[51];
    h1[52] ^= s[52];
    h1[53] ^= s[53];
    h1[54] ^= s[54];
    h1[55] ^= s[55];
    h1[56] ^= s[56];
    h1[57] ^= s[57];
    h1[58] ^= s[58];
    h1[59] ^= s[59];
    h1[60] ^= s[60];
    h1[61] ^= s[61];
    h1[62] ^= s[62];
    h1[63] ^= s[63];

    // Second block, the padding, keyed by the first block's result.
    uint k[64] = h1;
    s[0] = h1[0] ^ kWhirlpoolX4Pad[0];
    s[1] = h1[1] ^ kWhirlpoolX4Pad[1];
    s[2] = h1[2] ^ kWhirlpoolX4Pad[2];
    s[3] = h1[3] ^ kWhirlpoolX4Pad[3];
    s[4] = h1[4] ^ kWhirlpoolX4Pad[4];
    s[5] = h1[5] ^ kWhirlpoolX4Pad[5];
    s[6] = h1[6] ^ kWhirlpoolX4Pad[6];
    s[7] = h1[7] ^ kWhirlpoolX4Pad[7];
    s[8] = h1[8] ^ kWhirlpoolX4Pad[8];
    s[9] = h1[9] ^ kWhirlpoolX4Pad[9];
    s[10] = h1[10] ^ kWhirlpoolX4Pad[10];
    s[11] = h1[11] ^ kWhirlpoolX4Pad[11];
    s[12] = h1[12] ^ kWhirlpoolX4Pad[12];
    s[13] = h1[13] ^ kWhirlpoolX4Pad[13];
    s[14] = h1[14] ^ kWhirlpoolX4Pad[14];
    s[15] = h1[15] ^ kWhirlpoolX4Pad[15];
    s[16] = h1[16] ^ kWhirlpoolX4Pad[16];
    s[17] = h1[17] ^ kWhirlpoolX4Pad[17];
    s[18] = h1[18] ^ kWhirlpoolX4Pad[18];
    s[19] = h1[19] ^ kWhirlpoolX4Pad[19];
    s[20] = h1[20] ^ kWhirlpoolX4Pad[20];
    s[21] = h1[21] ^ kWhirlpoolX4Pad[21];
    s[22] = h1[22] ^ kWhirlpoolX4Pad[22];
    s[23] = h1[23] ^ kWhirlpoolX4Pad[23];
    s[24] = h1[24] ^ kWhirlpoolX4Pad[24];
    s[25] = h1[25] ^ kWhirlpoolX4Pad[25];
    s[26] = h1[26] ^ kWhirlpoolX4Pad[26];
    s[27] = h1[27] ^ kWhirlpoolX4Pad[27];
    s[28] = h1[28] ^ kWhirlpoolX4Pad[28];
    s[29] = h1[29] ^ kWhirlpoolX4Pad[29];
    s[30] = h1[30] ^ kWhirlpoolX4Pad[30];
    s[31] = h1[31] ^ kWhirlpoolX4Pad[31];
    s[32] = h1[32] ^ kWhirlpoolX4Pad[32];
    s[33] = h1[33] ^ kWhirlpoolX4Pad[33];
    s[34] = h1[34] ^ kWhirlpoolX4Pad[34];
    s[35] = h1[35] ^ kWhirlpoolX4Pad[35];
    s[36] = h1[36] ^ kWhirlpoolX4Pad[36];
    s[37] = h1[37] ^ kWhirlpoolX4Pad[37];
    s[38] = h1[38] ^ kWhirlpoolX4Pad[38];
    s[39] = h1[39] ^ kWhirlpoolX4Pad[39];
    s[40] = h1[40] ^ kWhirlpoolX4Pad[40];
    s[41] = h1[41] ^ kWhirlpoolX4Pad[41];
    s[42] = h1[42] ^ kWhirlpoolX4Pad[42];
    s[43] = h1[43] ^ kWhirlpoolX4Pad[43];
    s[44] = h1[44] ^ kWhirlpoolX4Pad[44];
    s[45] = h1[45] ^ kWhirlpoolX4Pad[45];
    s[46] = h1[46] ^ kWhirlpoolX4Pad[46];
    s[47] = h1[47] ^ kWhirlpoolX4Pad[47];
    s[48] = h1[48] ^ kWhirlpoolX4Pad[48];
    s[49] = h1[49] ^ kWhirlpoolX4Pad[49];
    s[50] = h1[50] ^ kWhirlpoolX4Pad[50];
    s[51] = h1[51] ^ kWhirlpoolX4Pad[51];
    s[52] = h1[52] ^ kWhirlpoolX4Pad[52];
    s[53] = h1[53] ^ kWhirlpoolX4Pad[53];
    s[54] = h1[54] ^ kWhirlpoolX4Pad[54];
    s[55] = h1[55] ^ kWhirlpoolX4Pad[55];
    s[56] = h1[56] ^ kWhirlpoolX4Pad[56];
    s[57] = h1[57] ^ kWhirlpoolX4Pad[57];
    s[58] = h1[58] ^ kWhirlpoolX4Pad[58];
    s[59] = h1[59] ^ kWhirlpoolX4Pad[59];
    s[60] = h1[60] ^ kWhirlpoolX4Pad[60];
    s[61] = h1[61] ^ kWhirlpoolX4Pad[61];
    s[62] = h1[62] ^ kWhirlpoolX4Pad[62];
    s[63] = h1[63] ^ kWhirlpoolX4Pad[63];
    [[dont_unroll]] for (uint r = 0u; r < 10u; r++) {
        wpx4_round(k);
        k[0] ^= kWhirlpoolX4Rc[64u * r + 0u];
        k[1] ^= kWhirlpoolX4Rc[64u * r + 1u];
        k[2] ^= kWhirlpoolX4Rc[64u * r + 2u];
        k[3] ^= kWhirlpoolX4Rc[64u * r + 3u];
        k[4] ^= kWhirlpoolX4Rc[64u * r + 4u];
        k[5] ^= kWhirlpoolX4Rc[64u * r + 5u];
        k[6] ^= kWhirlpoolX4Rc[64u * r + 6u];
        k[7] ^= kWhirlpoolX4Rc[64u * r + 7u];
        k[8] ^= kWhirlpoolX4Rc[64u * r + 8u];
        k[9] ^= kWhirlpoolX4Rc[64u * r + 9u];
        k[10] ^= kWhirlpoolX4Rc[64u * r + 10u];
        k[11] ^= kWhirlpoolX4Rc[64u * r + 11u];
        k[12] ^= kWhirlpoolX4Rc[64u * r + 12u];
        k[13] ^= kWhirlpoolX4Rc[64u * r + 13u];
        k[14] ^= kWhirlpoolX4Rc[64u * r + 14u];
        k[15] ^= kWhirlpoolX4Rc[64u * r + 15u];
        k[16] ^= kWhirlpoolX4Rc[64u * r + 16u];
        k[17] ^= kWhirlpoolX4Rc[64u * r + 17u];
        k[18] ^= kWhirlpoolX4Rc[64u * r + 18u];
        k[19] ^= kWhirlpoolX4Rc[64u * r + 19u];
        k[20] ^= kWhirlpoolX4Rc[64u * r + 20u];
        k[21] ^= kWhirlpoolX4Rc[64u * r + 21u];
        k[22] ^= kWhirlpoolX4Rc[64u * r + 22u];
        k[23] ^= kWhirlpoolX4Rc[64u * r + 23u];
        k[24] ^= kWhirlpoolX4Rc[64u * r + 24u];
        k[25] ^= kWhirlpoolX4Rc[64u * r + 25u];
        k[26] ^= kWhirlpoolX4Rc[64u * r + 26u];
        k[27] ^= kWhirlpoolX4Rc[64u * r + 27u];
        k[28] ^= kWhirlpoolX4Rc[64u * r + 28u];
        k[29] ^= kWhirlpoolX4Rc[64u * r + 29u];
        k[30] ^= kWhirlpoolX4Rc[64u * r + 30u];
        k[31] ^= kWhirlpoolX4Rc[64u * r + 31u];
        k[32] ^= kWhirlpoolX4Rc[64u * r + 32u];
        k[33] ^= kWhirlpoolX4Rc[64u * r + 33u];
        k[34] ^= kWhirlpoolX4Rc[64u * r + 34u];
        k[35] ^= kWhirlpoolX4Rc[64u * r + 35u];
        k[36] ^= kWhirlpoolX4Rc[64u * r + 36u];
        k[37] ^= kWhirlpoolX4Rc[64u * r + 37u];
        k[38] ^= kWhirlpoolX4Rc[64u * r + 38u];
        k[39] ^= kWhirlpoolX4Rc[64u * r + 39u];
        k[40] ^= kWhirlpoolX4Rc[64u * r + 40u];
        k[41] ^= kWhirlpoolX4Rc[64u * r + 41u];
        k[42] ^= kWhirlpoolX4Rc[64u * r + 42u];
        k[43] ^= kWhirlpoolX4Rc[64u * r + 43u];
        k[44] ^= kWhirlpoolX4Rc[64u * r + 44u];
        k[45] ^= kWhirlpoolX4Rc[64u * r + 45u];
        k[46] ^= kWhirlpoolX4Rc[64u * r + 46u];
        k[47] ^= kWhirlpoolX4Rc[64u * r + 47u];
        k[48] ^= kWhirlpoolX4Rc[64u * r + 48u];
        k[49] ^= kWhirlpoolX4Rc[64u * r + 49u];
        k[50] ^= kWhirlpoolX4Rc[64u * r + 50u];
        k[51] ^= kWhirlpoolX4Rc[64u * r + 51u];
        k[52] ^= kWhirlpoolX4Rc[64u * r + 52u];
        k[53] ^= kWhirlpoolX4Rc[64u * r + 53u];
        k[54] ^= kWhirlpoolX4Rc[64u * r + 54u];
        k[55] ^= kWhirlpoolX4Rc[64u * r + 55u];
        k[56] ^= kWhirlpoolX4Rc[64u * r + 56u];
        k[57] ^= kWhirlpoolX4Rc[64u * r + 57u];
        k[58] ^= kWhirlpoolX4Rc[64u * r + 58u];
        k[59] ^= kWhirlpoolX4Rc[64u * r + 59u];
        k[60] ^= kWhirlpoolX4Rc[64u * r + 60u];
        k[61] ^= kWhirlpoolX4Rc[64u * r + 61u];
        k[62] ^= kWhirlpoolX4Rc[64u * r + 62u];
        k[63] ^= kWhirlpoolX4Rc[64u * r + 63u];
        wpx4_round(s);
        s[0] ^= k[0];
        s[1] ^= k[1];
        s[2] ^= k[2];
        s[3] ^= k[3];
        s[4] ^= k[4];
        s[5] ^= k[5];
        s[6] ^= k[6];
        s[7] ^= k[7];
        s[8] ^= k[8];
        s[9] ^= k[9];
        s[10] ^= k[10];
        s[11] ^= k[11];
        s[12] ^= k[12];
        s[13] ^= k[13];
        s[14] ^= k[14];
        s[15] ^= k[15];
        s[16] ^= k[16];
        s[17] ^= k[17];
        s[18] ^= k[18];
        s[19] ^= k[19];
        s[20] ^= k[20];
        s[21] ^= k[21];
        s[22] ^= k[22];
        s[23] ^= k[23];
        s[24] ^= k[24];
        s[25] ^= k[25];
        s[26] ^= k[26];
        s[27] ^= k[27];
        s[28] ^= k[28];
        s[29] ^= k[29];
        s[30] ^= k[30];
        s[31] ^= k[31];
        s[32] ^= k[32];
        s[33] ^= k[33];
        s[34] ^= k[34];
        s[35] ^= k[35];
        s[36] ^= k[36];
        s[37] ^= k[37];
        s[38] ^= k[38];
        s[39] ^= k[39];
        s[40] ^= k[40];
        s[41] ^= k[41];
        s[42] ^= k[42];
        s[43] ^= k[43];
        s[44] ^= k[44];
        s[45] ^= k[45];
        s[46] ^= k[46];
        s[47] ^= k[47];
        s[48] ^= k[48];
        s[49] ^= k[49];
        s[50] ^= k[50];
        s[51] ^= k[51];
        s[52] ^= k[52];
        s[53] ^= k[53];
        s[54] ^= k[54];
        s[55] ^= k[55];
        s[56] ^= k[56];
        s[57] ^= k[57];
        s[58] ^= k[58];
        s[59] ^= k[59];
        s[60] ^= k[60];
        s[61] ^= k[61];
        s[62] ^= k[62];
        s[63] ^= k[63];
    }
    s[0] ^= h1[0] ^ kWhirlpoolX4Pad[0];
    s[1] ^= h1[1] ^ kWhirlpoolX4Pad[1];
    s[2] ^= h1[2] ^ kWhirlpoolX4Pad[2];
    s[3] ^= h1[3] ^ kWhirlpoolX4Pad[3];
    s[4] ^= h1[4] ^ kWhirlpoolX4Pad[4];
    s[5] ^= h1[5] ^ kWhirlpoolX4Pad[5];
    s[6] ^= h1[6] ^ kWhirlpoolX4Pad[6];
    s[7] ^= h1[7] ^ kWhirlpoolX4Pad[7];
    s[8] ^= h1[8] ^ kWhirlpoolX4Pad[8];
    s[9] ^= h1[9] ^ kWhirlpoolX4Pad[9];
    s[10] ^= h1[10] ^ kWhirlpoolX4Pad[10];
    s[11] ^= h1[11] ^ kWhirlpoolX4Pad[11];
    s[12] ^= h1[12] ^ kWhirlpoolX4Pad[12];
    s[13] ^= h1[13] ^ kWhirlpoolX4Pad[13];
    s[14] ^= h1[14] ^ kWhirlpoolX4Pad[14];
    s[15] ^= h1[15] ^ kWhirlpoolX4Pad[15];
    s[16] ^= h1[16] ^ kWhirlpoolX4Pad[16];
    s[17] ^= h1[17] ^ kWhirlpoolX4Pad[17];
    s[18] ^= h1[18] ^ kWhirlpoolX4Pad[18];
    s[19] ^= h1[19] ^ kWhirlpoolX4Pad[19];
    s[20] ^= h1[20] ^ kWhirlpoolX4Pad[20];
    s[21] ^= h1[21] ^ kWhirlpoolX4Pad[21];
    s[22] ^= h1[22] ^ kWhirlpoolX4Pad[22];
    s[23] ^= h1[23] ^ kWhirlpoolX4Pad[23];
    s[24] ^= h1[24] ^ kWhirlpoolX4Pad[24];
    s[25] ^= h1[25] ^ kWhirlpoolX4Pad[25];
    s[26] ^= h1[26] ^ kWhirlpoolX4Pad[26];
    s[27] ^= h1[27] ^ kWhirlpoolX4Pad[27];
    s[28] ^= h1[28] ^ kWhirlpoolX4Pad[28];
    s[29] ^= h1[29] ^ kWhirlpoolX4Pad[29];
    s[30] ^= h1[30] ^ kWhirlpoolX4Pad[30];
    s[31] ^= h1[31] ^ kWhirlpoolX4Pad[31];
    s[32] ^= h1[32] ^ kWhirlpoolX4Pad[32];
    s[33] ^= h1[33] ^ kWhirlpoolX4Pad[33];
    s[34] ^= h1[34] ^ kWhirlpoolX4Pad[34];
    s[35] ^= h1[35] ^ kWhirlpoolX4Pad[35];
    s[36] ^= h1[36] ^ kWhirlpoolX4Pad[36];
    s[37] ^= h1[37] ^ kWhirlpoolX4Pad[37];
    s[38] ^= h1[38] ^ kWhirlpoolX4Pad[38];
    s[39] ^= h1[39] ^ kWhirlpoolX4Pad[39];
    s[40] ^= h1[40] ^ kWhirlpoolX4Pad[40];
    s[41] ^= h1[41] ^ kWhirlpoolX4Pad[41];
    s[42] ^= h1[42] ^ kWhirlpoolX4Pad[42];
    s[43] ^= h1[43] ^ kWhirlpoolX4Pad[43];
    s[44] ^= h1[44] ^ kWhirlpoolX4Pad[44];
    s[45] ^= h1[45] ^ kWhirlpoolX4Pad[45];
    s[46] ^= h1[46] ^ kWhirlpoolX4Pad[46];
    s[47] ^= h1[47] ^ kWhirlpoolX4Pad[47];
    s[48] ^= h1[48] ^ kWhirlpoolX4Pad[48];
    s[49] ^= h1[49] ^ kWhirlpoolX4Pad[49];
    s[50] ^= h1[50] ^ kWhirlpoolX4Pad[50];
    s[51] ^= h1[51] ^ kWhirlpoolX4Pad[51];
    s[52] ^= h1[52] ^ kWhirlpoolX4Pad[52];
    s[53] ^= h1[53] ^ kWhirlpoolX4Pad[53];
    s[54] ^= h1[54] ^ kWhirlpoolX4Pad[54];
    s[55] ^= h1[55] ^ kWhirlpoolX4Pad[55];
    s[56] ^= h1[56] ^ kWhirlpoolX4Pad[56];
    s[57] ^= h1[57] ^ kWhirlpoolX4Pad[57];
    s[58] ^= h1[58] ^ kWhirlpoolX4Pad[58];
    s[59] ^= h1[59] ^ kWhirlpoolX4Pad[59];
    s[60] ^= h1[60] ^ kWhirlpoolX4Pad[60];
    s[61] ^= h1[61] ^ kWhirlpoolX4Pad[61];
    s[62] ^= h1[62] ^ kWhirlpoolX4Pad[62];
    s[63] ^= h1[63] ^ kWhirlpoolX4Pad[63];

    // Back to bytes. Digest word w of message h: row w / 2, columns 4 (w % 2)
    // to 4 (w % 2) + 3, each in its word 4 (row % 2) + h, byte row / 2.
    {
    uint t;
    t = (s[0] ^ (s[1] << 1)) & 0xaaaaaaaau; s[0] ^= t; s[1] ^= t >> 1;
    t = (s[2] ^ (s[3] << 1)) & 0xaaaaaaaau; s[2] ^= t; s[3] ^= t >> 1;
    t = (s[4] ^ (s[5] << 1)) & 0xaaaaaaaau; s[4] ^= t; s[5] ^= t >> 1;
    t = (s[6] ^ (s[7] << 1)) & 0xaaaaaaaau; s[6] ^= t; s[7] ^= t >> 1;
    t = (s[0] ^ (s[2] << 2)) & 0xccccccccu; s[0] ^= t; s[2] ^= t >> 2;
    t = (s[1] ^ (s[3] << 2)) & 0xccccccccu; s[1] ^= t; s[3] ^= t >> 2;
    t = (s[4] ^ (s[6] << 2)) & 0xccccccccu; s[4] ^= t; s[6] ^= t >> 2;
    t = (s[5] ^ (s[7] << 2)) & 0xccccccccu; s[5] ^= t; s[7] ^= t >> 2;
    t = (s[0] ^ (s[4] << 4)) & 0xf0f0f0f0u; s[0] ^= t; s[4] ^= t >> 4;
    t = (s[1] ^ (s[5] << 4)) & 0xf0f0f0f0u; s[1] ^= t; s[5] ^= t >> 4;
    t = (s[2] ^ (s[6] << 4)) & 0xf0f0f0f0u; s[2] ^= t; s[6] ^= t >> 4;
    t = (s[3] ^ (s[7] << 4)) & 0xf0f0f0f0u; s[3] ^= t; s[7] ^= t >> 4;
    }
    {
    uint t;
    t = (s[8] ^ (s[9] << 1)) & 0xaaaaaaaau; s[8] ^= t; s[9] ^= t >> 1;
    t = (s[10] ^ (s[11] << 1)) & 0xaaaaaaaau; s[10] ^= t; s[11] ^= t >> 1;
    t = (s[12] ^ (s[13] << 1)) & 0xaaaaaaaau; s[12] ^= t; s[13] ^= t >> 1;
    t = (s[14] ^ (s[15] << 1)) & 0xaaaaaaaau; s[14] ^= t; s[15] ^= t >> 1;
    t = (s[8] ^ (s[10] << 2)) & 0xccccccccu; s[8] ^= t; s[10] ^= t >> 2;
    t = (s[9] ^ (s[11] << 2)) & 0xccccccccu; s[9] ^= t; s[11] ^= t >> 2;
    t = (s[12] ^ (s[14] << 2)) & 0xccccccccu; s[12] ^= t; s[14] ^= t >> 2;
    t = (s[13] ^ (s[15] << 2)) & 0xccccccccu; s[13] ^= t; s[15] ^= t >> 2;
    t = (s[8] ^ (s[12] << 4)) & 0xf0f0f0f0u; s[8] ^= t; s[12] ^= t >> 4;
    t = (s[9] ^ (s[13] << 4)) & 0xf0f0f0f0u; s[9] ^= t; s[13] ^= t >> 4;
    t = (s[10] ^ (s[14] << 4)) & 0xf0f0f0f0u; s[10] ^= t; s[14] ^= t >> 4;
    t = (s[11] ^ (s[15] << 4)) & 0xf0f0f0f0u; s[11] ^= t; s[15] ^= t >> 4;
    }
    {
    uint t;
    t = (s[16] ^ (s[17] << 1)) & 0xaaaaaaaau; s[16] ^= t; s[17] ^= t >> 1;
    t = (s[18] ^ (s[19] << 1)) & 0xaaaaaaaau; s[18] ^= t; s[19] ^= t >> 1;
    t = (s[20] ^ (s[21] << 1)) & 0xaaaaaaaau; s[20] ^= t; s[21] ^= t >> 1;
    t = (s[22] ^ (s[23] << 1)) & 0xaaaaaaaau; s[22] ^= t; s[23] ^= t >> 1;
    t = (s[16] ^ (s[18] << 2)) & 0xccccccccu; s[16] ^= t; s[18] ^= t >> 2;
    t = (s[17] ^ (s[19] << 2)) & 0xccccccccu; s[17] ^= t; s[19] ^= t >> 2;
    t = (s[20] ^ (s[22] << 2)) & 0xccccccccu; s[20] ^= t; s[22] ^= t >> 2;
    t = (s[21] ^ (s[23] << 2)) & 0xccccccccu; s[21] ^= t; s[23] ^= t >> 2;
    t = (s[16] ^ (s[20] << 4)) & 0xf0f0f0f0u; s[16] ^= t; s[20] ^= t >> 4;
    t = (s[17] ^ (s[21] << 4)) & 0xf0f0f0f0u; s[17] ^= t; s[21] ^= t >> 4;
    t = (s[18] ^ (s[22] << 4)) & 0xf0f0f0f0u; s[18] ^= t; s[22] ^= t >> 4;
    t = (s[19] ^ (s[23] << 4)) & 0xf0f0f0f0u; s[19] ^= t; s[23] ^= t >> 4;
    }
    {
    uint t;
    t = (s[24] ^ (s[25] << 1)) & 0xaaaaaaaau; s[24] ^= t; s[25] ^= t >> 1;
    t = (s[26] ^ (s[27] << 1)) & 0xaaaaaaaau; s[26] ^= t; s[27] ^= t >> 1;
    t = (s[28] ^ (s[29] << 1)) & 0xaaaaaaaau; s[28] ^= t; s[29] ^= t >> 1;
    t = (s[30] ^ (s[31] << 1)) & 0xaaaaaaaau; s[30] ^= t; s[31] ^= t >> 1;
    t = (s[24] ^ (s[26] << 2)) & 0xccccccccu; s[24] ^= t; s[26] ^= t >> 2;
    t = (s[25] ^ (s[27] << 2)) & 0xccccccccu; s[25] ^= t; s[27] ^= t >> 2;
    t = (s[28] ^ (s[30] << 2)) & 0xccccccccu; s[28] ^= t; s[30] ^= t >> 2;
    t = (s[29] ^ (s[31] << 2)) & 0xccccccccu; s[29] ^= t; s[31] ^= t >> 2;
    t = (s[24] ^ (s[28] << 4)) & 0xf0f0f0f0u; s[24] ^= t; s[28] ^= t >> 4;
    t = (s[25] ^ (s[29] << 4)) & 0xf0f0f0f0u; s[25] ^= t; s[29] ^= t >> 4;
    t = (s[26] ^ (s[30] << 4)) & 0xf0f0f0f0u; s[26] ^= t; s[30] ^= t >> 4;
    t = (s[27] ^ (s[31] << 4)) & 0xf0f0f0f0u; s[27] ^= t; s[31] ^= t >> 4;
    }
    {
    uint t;
    t = (s[32] ^ (s[33] << 1)) & 0xaaaaaaaau; s[32] ^= t; s[33] ^= t >> 1;
    t = (s[34] ^ (s[35] << 1)) & 0xaaaaaaaau; s[34] ^= t; s[35] ^= t >> 1;
    t = (s[36] ^ (s[37] << 1)) & 0xaaaaaaaau; s[36] ^= t; s[37] ^= t >> 1;
    t = (s[38] ^ (s[39] << 1)) & 0xaaaaaaaau; s[38] ^= t; s[39] ^= t >> 1;
    t = (s[32] ^ (s[34] << 2)) & 0xccccccccu; s[32] ^= t; s[34] ^= t >> 2;
    t = (s[33] ^ (s[35] << 2)) & 0xccccccccu; s[33] ^= t; s[35] ^= t >> 2;
    t = (s[36] ^ (s[38] << 2)) & 0xccccccccu; s[36] ^= t; s[38] ^= t >> 2;
    t = (s[37] ^ (s[39] << 2)) & 0xccccccccu; s[37] ^= t; s[39] ^= t >> 2;
    t = (s[32] ^ (s[36] << 4)) & 0xf0f0f0f0u; s[32] ^= t; s[36] ^= t >> 4;
    t = (s[33] ^ (s[37] << 4)) & 0xf0f0f0f0u; s[33] ^= t; s[37] ^= t >> 4;
    t = (s[34] ^ (s[38] << 4)) & 0xf0f0f0f0u; s[34] ^= t; s[38] ^= t >> 4;
    t = (s[35] ^ (s[39] << 4)) & 0xf0f0f0f0u; s[35] ^= t; s[39] ^= t >> 4;
    }
    {
    uint t;
    t = (s[40] ^ (s[41] << 1)) & 0xaaaaaaaau; s[40] ^= t; s[41] ^= t >> 1;
    t = (s[42] ^ (s[43] << 1)) & 0xaaaaaaaau; s[42] ^= t; s[43] ^= t >> 1;
    t = (s[44] ^ (s[45] << 1)) & 0xaaaaaaaau; s[44] ^= t; s[45] ^= t >> 1;
    t = (s[46] ^ (s[47] << 1)) & 0xaaaaaaaau; s[46] ^= t; s[47] ^= t >> 1;
    t = (s[40] ^ (s[42] << 2)) & 0xccccccccu; s[40] ^= t; s[42] ^= t >> 2;
    t = (s[41] ^ (s[43] << 2)) & 0xccccccccu; s[41] ^= t; s[43] ^= t >> 2;
    t = (s[44] ^ (s[46] << 2)) & 0xccccccccu; s[44] ^= t; s[46] ^= t >> 2;
    t = (s[45] ^ (s[47] << 2)) & 0xccccccccu; s[45] ^= t; s[47] ^= t >> 2;
    t = (s[40] ^ (s[44] << 4)) & 0xf0f0f0f0u; s[40] ^= t; s[44] ^= t >> 4;
    t = (s[41] ^ (s[45] << 4)) & 0xf0f0f0f0u; s[41] ^= t; s[45] ^= t >> 4;
    t = (s[42] ^ (s[46] << 4)) & 0xf0f0f0f0u; s[42] ^= t; s[46] ^= t >> 4;
    t = (s[43] ^ (s[47] << 4)) & 0xf0f0f0f0u; s[43] ^= t; s[47] ^= t >> 4;
    }
    {
    uint t;
    t = (s[48] ^ (s[49] << 1)) & 0xaaaaaaaau; s[48] ^= t; s[49] ^= t >> 1;
    t = (s[50] ^ (s[51] << 1)) & 0xaaaaaaaau; s[50] ^= t; s[51] ^= t >> 1;
    t = (s[52] ^ (s[53] << 1)) & 0xaaaaaaaau; s[52] ^= t; s[53] ^= t >> 1;
    t = (s[54] ^ (s[55] << 1)) & 0xaaaaaaaau; s[54] ^= t; s[55] ^= t >> 1;
    t = (s[48] ^ (s[50] << 2)) & 0xccccccccu; s[48] ^= t; s[50] ^= t >> 2;
    t = (s[49] ^ (s[51] << 2)) & 0xccccccccu; s[49] ^= t; s[51] ^= t >> 2;
    t = (s[52] ^ (s[54] << 2)) & 0xccccccccu; s[52] ^= t; s[54] ^= t >> 2;
    t = (s[53] ^ (s[55] << 2)) & 0xccccccccu; s[53] ^= t; s[55] ^= t >> 2;
    t = (s[48] ^ (s[52] << 4)) & 0xf0f0f0f0u; s[48] ^= t; s[52] ^= t >> 4;
    t = (s[49] ^ (s[53] << 4)) & 0xf0f0f0f0u; s[49] ^= t; s[53] ^= t >> 4;
    t = (s[50] ^ (s[54] << 4)) & 0xf0f0f0f0u; s[50] ^= t; s[54] ^= t >> 4;
    t = (s[51] ^ (s[55] << 4)) & 0xf0f0f0f0u; s[51] ^= t; s[55] ^= t >> 4;
    }
    {
    uint t;
    t = (s[56] ^ (s[57] << 1)) & 0xaaaaaaaau; s[56] ^= t; s[57] ^= t >> 1;
    t = (s[58] ^ (s[59] << 1)) & 0xaaaaaaaau; s[58] ^= t; s[59] ^= t >> 1;
    t = (s[60] ^ (s[61] << 1)) & 0xaaaaaaaau; s[60] ^= t; s[61] ^= t >> 1;
    t = (s[62] ^ (s[63] << 1)) & 0xaaaaaaaau; s[62] ^= t; s[63] ^= t >> 1;
    t = (s[56] ^ (s[58] << 2)) & 0xccccccccu; s[56] ^= t; s[58] ^= t >> 2;
    t = (s[57] ^ (s[59] << 2)) & 0xccccccccu; s[57] ^= t; s[59] ^= t >> 2;
    t = (s[60] ^ (s[62] << 2)) & 0xccccccccu; s[60] ^= t; s[62] ^= t >> 2;
    t = (s[61] ^ (s[63] << 2)) & 0xccccccccu; s[61] ^= t; s[63] ^= t >> 2;
    t = (s[56] ^ (s[60] << 4)) & 0xf0f0f0f0u; s[56] ^= t; s[60] ^= t >> 4;
    t = (s[57] ^ (s[61] << 4)) & 0xf0f0f0f0u; s[57] ^= t; s[61] ^= t >> 4;
    t = (s[58] ^ (s[62] << 4)) & 0xf0f0f0f0u; s[58] ^= t; s[62] ^= t >> 4;
    t = (s[59] ^ (s[63] << 4)) & 0xf0f0f0f0u; s[59] ^= t; s[63] ^= t >> 4;
    }
    d[0] = wpx4_pair(s[0], s[8], 0u) | (wpx4_pair(s[16], s[24], 0u) << 16);
    d[1] = wpx4_pair(s[32], s[40], 0u) | (wpx4_pair(s[48], s[56], 0u) << 16);
    d[2] = wpx4_pair(s[4], s[12], 0u) | (wpx4_pair(s[20], s[28], 0u) << 16);
    d[3] = wpx4_pair(s[36], s[44], 0u) | (wpx4_pair(s[52], s[60], 0u) << 16);
    d[4] = wpx4_pair(s[0], s[8], 1u) | (wpx4_pair(s[16], s[24], 1u) << 16);
    d[5] = wpx4_pair(s[32], s[40], 1u) | (wpx4_pair(s[48], s[56], 1u) << 16);
    d[6] = wpx4_pair(s[4], s[12], 1u) | (wpx4_pair(s[20], s[28], 1u) << 16);
    d[7] = wpx4_pair(s[36], s[44], 1u) | (wpx4_pair(s[52], s[60], 1u) << 16);
    d[8] = wpx4_pair(s[0], s[8], 2u) | (wpx4_pair(s[16], s[24], 2u) << 16);
    d[9] = wpx4_pair(s[32], s[40], 2u) | (wpx4_pair(s[48], s[56], 2u) << 16);
    d[10] = wpx4_pair(s[4], s[12], 2u) | (wpx4_pair(s[20], s[28], 2u) << 16);
    d[11] = wpx4_pair(s[36], s[44], 2u) | (wpx4_pair(s[52], s[60], 2u) << 16);
    d[12] = wpx4_pair(s[0], s[8], 3u) | (wpx4_pair(s[16], s[24], 3u) << 16);
    d[13] = wpx4_pair(s[32], s[40], 3u) | (wpx4_pair(s[48], s[56], 3u) << 16);
    d[14] = wpx4_pair(s[4], s[12], 3u) | (wpx4_pair(s[20], s[28], 3u) << 16);
    d[15] = wpx4_pair(s[36], s[44], 3u) | (wpx4_pair(s[52], s[60], 3u) << 16);
    d[16] = wpx4_pair(s[1], s[9], 0u) | (wpx4_pair(s[17], s[25], 0u) << 16);
    d[17] = wpx4_pair(s[33], s[41], 0u) | (wpx4_pair(s[49], s[57], 0u) << 16);
    d[18] = wpx4_pair(s[5], s[13], 0u) | (wpx4_pair(s[21], s[29], 0u) << 16);
    d[19] = wpx4_pair(s[37], s[45], 0u) | (wpx4_pair(s[53], s[61], 0u) << 16);
    d[20] = wpx4_pair(s[1], s[9], 1u) | (wpx4_pair(s[17], s[25], 1u) << 16);
    d[21] = wpx4_pair(s[33], s[41], 1u) | (wpx4_pair(s[49], s[57], 1u) << 16);
    d[22] = wpx4_pair(s[5], s[13], 1u) | (wpx4_pair(s[21], s[29], 1u) << 16);
    d[23] = wpx4_pair(s[37], s[45], 1u) | (wpx4_pair(s[53], s[61], 1u) << 16);
    d[24] = wpx4_pair(s[1], s[9], 2u) | (wpx4_pair(s[17], s[25], 2u) << 16);
    d[25] = wpx4_pair(s[33], s[41], 2u) | (wpx4_pair(s[49], s[57], 2u) << 16);
    d[26] = wpx4_pair(s[5], s[13], 2u) | (wpx4_pair(s[21], s[29], 2u) << 16);
    d[27] = wpx4_pair(s[37], s[45], 2u) | (wpx4_pair(s[53], s[61], 2u) << 16);
    d[28] = wpx4_pair(s[1], s[9], 3u) | (wpx4_pair(s[17], s[25], 3u) << 16);
    d[29] = wpx4_pair(s[33], s[41], 3u) | (wpx4_pair(s[49], s[57], 3u) << 16);
    d[30] = wpx4_pair(s[5], s[13], 3u) | (wpx4_pair(s[21], s[29], 3u) << 16);
    d[31] = wpx4_pair(s[37], s[45], 3u) | (wpx4_pair(s[53], s[61], 3u) << 16);
    d[32] = wpx4_pair(s[2], s[10], 0u) | (wpx4_pair(s[18], s[26], 0u) << 16);
    d[33] = wpx4_pair(s[34], s[42], 0u) | (wpx4_pair(s[50], s[58], 0u) << 16);
    d[34] = wpx4_pair(s[6], s[14], 0u) | (wpx4_pair(s[22], s[30], 0u) << 16);
    d[35] = wpx4_pair(s[38], s[46], 0u) | (wpx4_pair(s[54], s[62], 0u) << 16);
    d[36] = wpx4_pair(s[2], s[10], 1u) | (wpx4_pair(s[18], s[26], 1u) << 16);
    d[37] = wpx4_pair(s[34], s[42], 1u) | (wpx4_pair(s[50], s[58], 1u) << 16);
    d[38] = wpx4_pair(s[6], s[14], 1u) | (wpx4_pair(s[22], s[30], 1u) << 16);
    d[39] = wpx4_pair(s[38], s[46], 1u) | (wpx4_pair(s[54], s[62], 1u) << 16);
    d[40] = wpx4_pair(s[2], s[10], 2u) | (wpx4_pair(s[18], s[26], 2u) << 16);
    d[41] = wpx4_pair(s[34], s[42], 2u) | (wpx4_pair(s[50], s[58], 2u) << 16);
    d[42] = wpx4_pair(s[6], s[14], 2u) | (wpx4_pair(s[22], s[30], 2u) << 16);
    d[43] = wpx4_pair(s[38], s[46], 2u) | (wpx4_pair(s[54], s[62], 2u) << 16);
    d[44] = wpx4_pair(s[2], s[10], 3u) | (wpx4_pair(s[18], s[26], 3u) << 16);
    d[45] = wpx4_pair(s[34], s[42], 3u) | (wpx4_pair(s[50], s[58], 3u) << 16);
    d[46] = wpx4_pair(s[6], s[14], 3u) | (wpx4_pair(s[22], s[30], 3u) << 16);
    d[47] = wpx4_pair(s[38], s[46], 3u) | (wpx4_pair(s[54], s[62], 3u) << 16);
    d[48] = wpx4_pair(s[3], s[11], 0u) | (wpx4_pair(s[19], s[27], 0u) << 16);
    d[49] = wpx4_pair(s[35], s[43], 0u) | (wpx4_pair(s[51], s[59], 0u) << 16);
    d[50] = wpx4_pair(s[7], s[15], 0u) | (wpx4_pair(s[23], s[31], 0u) << 16);
    d[51] = wpx4_pair(s[39], s[47], 0u) | (wpx4_pair(s[55], s[63], 0u) << 16);
    d[52] = wpx4_pair(s[3], s[11], 1u) | (wpx4_pair(s[19], s[27], 1u) << 16);
    d[53] = wpx4_pair(s[35], s[43], 1u) | (wpx4_pair(s[51], s[59], 1u) << 16);
    d[54] = wpx4_pair(s[7], s[15], 1u) | (wpx4_pair(s[23], s[31], 1u) << 16);
    d[55] = wpx4_pair(s[39], s[47], 1u) | (wpx4_pair(s[55], s[63], 1u) << 16);
    d[56] = wpx4_pair(s[3], s[11], 2u) | (wpx4_pair(s[19], s[27], 2u) << 16);
    d[57] = wpx4_pair(s[35], s[43], 2u) | (wpx4_pair(s[51], s[59], 2u) << 16);
    d[58] = wpx4_pair(s[7], s[15], 2u) | (wpx4_pair(s[23], s[31], 2u) << 16);
    d[59] = wpx4_pair(s[39], s[47], 2u) | (wpx4_pair(s[55], s[63], 2u) << 16);
    d[60] = wpx4_pair(s[3], s[11], 3u) | (wpx4_pair(s[19], s[27], 3u) << 16);
    d[61] = wpx4_pair(s[35], s[43], 3u) | (wpx4_pair(s[51], s[59], 3u) << 16);
    d[62] = wpx4_pair(s[7], s[15], 3u) | (wpx4_pair(s[23], s[31], 3u) << 16);
    d[63] = wpx4_pair(s[39], s[47], 3u) | (wpx4_pair(s[55], s[63], 3u) << 16);
}

#endif  // VKMINER_SHADERS_COMMON_WHIRLPOOL512_X4_GLSL_INCLUDED
