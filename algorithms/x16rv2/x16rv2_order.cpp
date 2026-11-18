// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "algorithms/x16rv2/x16rv2_order.h"

namespace vkminer {
namespace x16rv2 {

namespace {

// Byte b of the previous block's hash as it sits in the header: wire bytes 4
// to 35, so header words 1 to 8, each of which be32enc() writes most
// significant byte first.
unsigned prevhash_byte(const uint32_t *header, unsigned b)
{
    return (header[1 + b / 4] >> (24 - 8 * (b % 4))) & 0xff;
}

}  // namespace

// Positions 0 and 1 are byte 7's high and low nibbles, 2 and 3 byte 6's, and
// so on down to byte 0.
uint64_t order_of(const uint32_t *header)
{
    uint64_t order = 0;
    for (unsigned i = 0; i < kStages; i++) {
        const unsigned byte = prevhash_byte(header, 7 - i / 2);
        const unsigned stage = i % 2 == 0 ? byte >> 4 : byte & 0xf;
        order |= static_cast<uint64_t>(stage) << (4 * i);
    }
    return order;
}

unsigned passes(uint64_t order)
{
    unsigned n = kStages;
    for (unsigned i = 0; i < kStages; i++)
        n += tiger_first(stage_at(order, i));
    return n;
}

const char *stage_name(unsigned stage)
{
    static const char *const names[kStages] = {
        "blake", "bmw512", "groestl", "jh512", "keccak", "skein",
        "luffa", "cube", "shavite", "simd", "echo", "hamsi",
        "fugue", "shabal", "whirlpool", "sha512",
    };
    return stage < kStages ? names[stage] : "?";
}

void order_string(uint64_t order, char *out)
{
    static const char digits[] = "0123456789ABCDEF";
    for (unsigned i = 0; i < kStages; i++)
        out[i] = digits[stage_at(order, i)];
    out[kStages] = '\0';
}

bool parse_order(const char *text, uint64_t *order)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < kStages; i++) {
        const char c = text[i];
        unsigned d;
        if (c >= '0' && c <= '9')
            d = static_cast<unsigned>(c - '0');
        else if (c >= 'A' && c <= 'F')
            d = static_cast<unsigned>(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f')
            d = static_cast<unsigned>(c - 'a' + 10);
        else
            return false;
        v |= static_cast<uint64_t>(d) << (4 * i);
    }
    if (text[kStages] != '\0')
        return false;
    *order = v;
    return true;
}

void set_order(uint32_t *header, uint64_t order)
{
    for (unsigned b = 0; b < 8; b++) {
        // Byte b holds positions 14 - 2b (high nibble) and 15 - 2b (low).
        const unsigned hi = stage_at(order, 14 - 2 * b);
        const unsigned lo = stage_at(order, 15 - 2 * b);
        const unsigned shift = 24 - 8 * (b % 4);
        uint32_t &w = header[1 + b / 4];
        w = (w & ~(0xffu << shift)) | (((hi << 4) | lo) << shift);
    }
}

}  // namespace x16rv2
}  // namespace vkminer
