// The shared table, in as many bindings as the device made it take.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A table an algorithm hashes against -- a DAG, at the size that matters -- is
// built once and read by every dispatch. On the cards here a shader can address
// four gigabytes of one buffer and the table is simply that buffer; on a
// software rasterizer, and on parts that report the Vulkan minimum, one binding
// reaches 128 MiB and a gigabyte of table has to arrive in pieces.
//
// Which of those it is, is a property of the device rather than the algorithm.
// The shader declares the most pieces it will ever accept and the backend uses
// as few as the device allows, filling the spare descriptors with a repeat of
// the last real one: a descriptor a shader declares and nobody wrote is not
// unused, it is a pointer at whatever the driver left there.
//
// A chain of compares rather than an array indexed by the piece number. The
// array is descriptor indexing, which is Vulkan 1.2, and the index here is
// computed from the data and differs between the lanes of a subgroup -- exactly
// the case the baseline does not allow. The chain costs nothing where the count
// is one, since the count is a specialization constant and it all folds away.

#ifndef VKMINER_SHADERS_COMMON_SHARED_TABLE_GLSL_INCLUDED
#define VKMINER_SHADERS_COMMON_SHARED_TABLE_GLSL_INCLUDED

// Which binding the pieces start at. The shader defines it before including
// this, because what comes before them -- the candidate buffer, a scratchpad --
// is the shader's own business.
#ifndef SHARED_TABLE_BINDING
#error "define SHARED_TABLE_BINDING before including shared_table.glsl"
#endif

// How many of those bindings hold anything, and how many 32-bit words are in
// one of them. Specialization constants, so the driver folds everything below
// into a single load when there is one piece.
layout(constant_id = 2) const uint kSharedChunks     = 1u;
layout(constant_id = 3) const uint kSharedChunkWords = 0u;

// A macro rather than sixteen hand-written declarations: the only difference
// between them is a number, and a mistyped one is a shader reading the wrong
// piece. The count must match kMaxSharedChunks in backends/backend.h.
//
// Declared as quads, not words, so that a caller wanting four consecutive words
// gets them in one load. A caller wanting one indexes the component inside the
// access chain below and the driver emits the same scalar load as before. There
// is no second binding viewing the same memory as words: a block is a binding,
// and the piece count is already all this shader is allowed.
//
// std430 gives a uvec4 array a 16-byte stride and no padding, so both views are
// the same bytes in the same order. The cost is an invariant -- a piece must be
// a whole number of quads, or its last words fall off the end of `quad[]`. The
// backend checks it where the pieces are sized; see shared_state.cpp.
#define VKMINER_SHARED_CHUNK(n)                                               \
    layout(std430, set = 0, binding = SHARED_TABLE_BINDING + n)               \
        readonly buffer SharedChunk##n { uvec4 quad[]; } shared_chunk##n

VKMINER_SHARED_CHUNK(0);
VKMINER_SHARED_CHUNK(1);
VKMINER_SHARED_CHUNK(2);
VKMINER_SHARED_CHUNK(3);
VKMINER_SHARED_CHUNK(4);
VKMINER_SHARED_CHUNK(5);
VKMINER_SHARED_CHUNK(6);
VKMINER_SHARED_CHUNK(7);
VKMINER_SHARED_CHUNK(8);
VKMINER_SHARED_CHUNK(9);
VKMINER_SHARED_CHUNK(10);
VKMINER_SHARED_CHUNK(11);
VKMINER_SHARED_CHUNK(12);
VKMINER_SHARED_CHUNK(13);
VKMINER_SHARED_CHUNK(14);
VKMINER_SHARED_CHUNK(15);

// Word `index` of the table, wherever it happens to live. The index is into the
// whole table and always was: how it is held is decided after the algorithm was
// written, and nothing above this line should be able to tell.
uint shared_word(uint index)
{
    if (kSharedChunks == 1u)
        return shared_chunk0.quad[index >> 2u][index & 3u];

    // A power of two, so both of these are a shift and a mask.
    uint piece = index / kSharedChunkWords;
    uint at    = index % kSharedChunkWords;
    uint of    = at & 3u;
    at >>= 2u;

    if (piece == 0u)  return shared_chunk0.quad[at][of];
    if (piece == 1u)  return shared_chunk1.quad[at][of];
    if (piece == 2u)  return shared_chunk2.quad[at][of];
    if (piece == 3u)  return shared_chunk3.quad[at][of];
    if (piece == 4u)  return shared_chunk4.quad[at][of];
    if (piece == 5u)  return shared_chunk5.quad[at][of];
    if (piece == 6u)  return shared_chunk6.quad[at][of];
    if (piece == 7u)  return shared_chunk7.quad[at][of];
    if (piece == 8u)  return shared_chunk8.quad[at][of];
    if (piece == 9u)  return shared_chunk9.quad[at][of];
    if (piece == 10u) return shared_chunk10.quad[at][of];
    if (piece == 11u) return shared_chunk11.quad[at][of];
    if (piece == 12u) return shared_chunk12.quad[at][of];
    if (piece == 13u) return shared_chunk13.quad[at][of];
    if (piece == 14u) return shared_chunk14.quad[at][of];
    return shared_chunk15.quad[at][of];
}

// The four words starting at `index`, in one load. `index` must be a multiple
// of four: a quad sits where the table's alignment puts it, not where a caller
// starts reading, and a run straddling two is two loads however it is spelled.
// A caller that cannot promise a multiple of four wants shared_word() four
// times, which is what this replaced.
//
// A straddle across a piece boundary is ruled out one level up: a piece is a
// whole number of quads, so a quad is never split between two bindings.
uvec4 shared_quad(uint index)
{
    if (kSharedChunks == 1u)
        return shared_chunk0.quad[index >> 2u];

    uint piece = index / kSharedChunkWords;
    uint at    = (index % kSharedChunkWords) >> 2u;

    if (piece == 0u)  return shared_chunk0.quad[at];
    if (piece == 1u)  return shared_chunk1.quad[at];
    if (piece == 2u)  return shared_chunk2.quad[at];
    if (piece == 3u)  return shared_chunk3.quad[at];
    if (piece == 4u)  return shared_chunk4.quad[at];
    if (piece == 5u)  return shared_chunk5.quad[at];
    if (piece == 6u)  return shared_chunk6.quad[at];
    if (piece == 7u)  return shared_chunk7.quad[at];
    if (piece == 8u)  return shared_chunk8.quad[at];
    if (piece == 9u)  return shared_chunk9.quad[at];
    if (piece == 10u) return shared_chunk10.quad[at];
    if (piece == 11u) return shared_chunk11.quad[at];
    if (piece == 12u) return shared_chunk12.quad[at];
    if (piece == 13u) return shared_chunk13.quad[at];
    if (piece == 14u) return shared_chunk14.quad[at];
    return shared_chunk15.quad[at];
}

#endif  // VKMINER_SHADERS_COMMON_SHARED_TABLE_GLSL_INCLUDED
