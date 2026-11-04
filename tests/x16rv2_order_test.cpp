// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// x16rv2's stage order, with no hashing: a wrong order hashes as cleanly as a
// right one, so no digest can test it.
//
// 1. ccminer's getAlgoString over fifteen previous-block prefixes.
// 2. The last sixteen hex digits of the printed previous-block hash, so the
//    byte reversal is the code under test's.
// 3. Each of the 64 order bits moves exactly its position; no other header
//    bit moves anything.
// 4. The pass count: sixteen stages plus a Tiger per Keccak, Luffa, SHA-512.

#include "algorithms/x16rv2/x16rv2_order.h"

#include <cstdio>
#include <cstring>

using namespace vkminer::x16rv2;

namespace {

int failures = 0;

void expect_order(const char *what, uint64_t order, const char *want)
{
    char got[17];
    order_string(order, got);
    if (std::strcmp(got, want) != 0) {
        std::printf("FAIL: %s\n  want %s\n  got  %s\n", what, want, got);
        failures++;
    }
}

// Header words 1 and 2 as ccminer's pdata holds them, which is the miner's
// spelling too, and what getAlgoString printed for them.
struct CcminerVector {
    uint32_t word1, word2;
    const char *order;
};

const CcminerVector kCcminer[] = {
    { 0xefcdab89, 0x67452301, "0123456789ABCDEF" },
    { 0x00000000, 0x00000000, "0000000000000000" },
    { 0xffffffff, 0xffffffff, "FFFFFFFFFFFFFFFF" },
    { 0x5a3d4d43, 0xa6fbc764, "64C7FBA6434D3D5A" },
    { 0x25079fe4, 0x546cccd5, "D5CC6C54E49F0725" },
    { 0x563b0b93, 0xfe544cf8, "F84C54FE930B3B56" },
    { 0x1301479f, 0x90292bb1, "B12B29909F470113" },
    { 0x301eb078, 0x92b3cb75, "75CBB39278B01E30" },
    { 0x781bbd2c, 0x6a9504bd, "BD04956A2CBD1B78" },
    { 0xb53eb735, 0x14e09a29, "299AE01435B73EB5" },
    { 0xf06df973, 0x831b1e3f, "3F1E1B8373F96DF0" },
    { 0x447958c8, 0x7789fdb7, "B7FD8977C8587944" },
    { 0x0bd08a96, 0x16064c19, "194C0616968AD00B" },
    { 0xe8c74fed, 0x9a2ce27e, "7EE22C9AED4FC7E8" },
    { 0x7a50f9e1, 0x0706f802, "02F80607E1F9507A" },
};

// Previous-block hashes as an explorer prints them. Invented: what is tested
// is the reading, and a real hash would only be a longer string.
const char *const kPrinted[] = {
    "000000000000000000000000000000000000000000000000fedcba9876543210",
    "0000000000000a1f3c5d0000000000000000000000000000444444444b6f4f06",
    "7b2e4a0c1d3f59e68a9cb0d2f4e61738a5c7e9fb1d3f5072849ab6cde0f21436",
};

unsigned hex_digit(char c)
{
    return c <= '9' ? static_cast<unsigned>(c - '0')
                    : static_cast<unsigned>(c - 'a' + 10);
}

// Wire bytes 4..35 are the hash in its own byte order, which is the printed
// one reversed; header words are those bytes read big-endian.
void header_from_printed(const char *printed, uint32_t header[20])
{
    unsigned char wire[80];
    std::memset(wire, 0, sizeof wire);
    for (unsigned i = 0; i < 32; i++)
        wire[4 + 31 - i] = static_cast<unsigned char>(
            hex_digit(printed[2 * i]) << 4 | hex_digit(printed[2 * i + 1]));
    for (unsigned w = 0; w < 20; w++)
        header[w] = static_cast<uint32_t>(wire[4 * w]) << 24
                  | static_cast<uint32_t>(wire[4 * w + 1]) << 16
                  | static_cast<uint32_t>(wire[4 * w + 2]) << 8
                  | wire[4 * w + 3];
}

void upper(const char *in, char *out)
{
    for (; *in; in++, out++)
        *out = *in >= 'a' ? static_cast<char>(*in - 'a' + 'A') : *in;
    *out = '\0';
}

}  // namespace

int main()
{
    // 1. ccminer's vectors.
    for (const CcminerVector &v : kCcminer) {
        uint32_t header[20] = {};
        header[1] = v.word1;
        header[2] = v.word2;
        char what[64];
        std::snprintf(what, sizeof what, "ccminer's order for %08x %08x",
                      v.word1, v.word2);
        expect_order(what, order_of(header), v.order);
    }

    // 2. The last sixteen printed digits.
    for (const char *printed : kPrinted) {
        if (std::strlen(printed) != 64) {
            std::printf("FAIL: %s is not a printed hash\n", printed);
            failures++;
            continue;
        }
        uint32_t header[20];
        header_from_printed(printed, header);
        char want[17];
        upper(printed + 48, want);
        char what[96];
        std::snprintf(what, sizeof what, "the tail of %s", printed);
        expect_order(what, order_of(header), want);
    }

    // 3. One bit at a time. Prevhash byte b, bit k, sits at wire byte 4 + b,
    //    so header word 1 + b / 4, and names position 2 (7 - b) for the high
    //    nibble or the one after it for the low.
    uint32_t base[20];
    for (unsigned w = 0; w < 20; w++)
        base[w] = 0x9e3779b9u * (w + 1);
    const uint64_t base_order = order_of(base);

    unsigned moved_right = 0;
    for (unsigned w = 0; w < 20; w++)
        for (unsigned bit = 0; bit < 32; bit++) {
            uint32_t header[20];
            std::memcpy(header, base, sizeof header);
            header[w] ^= 1u << bit;
            const uint64_t diff = order_of(header) ^ base_order;

            const unsigned wire_byte = 4 * w + 3 - bit / 8;
            if (wire_byte < 4 || wire_byte > 11) {
                if (diff) {
                    std::printf("FAIL: header word %u bit %u is outside the "
                                "previous hash's first 8 bytes and moved the "
                                "order\n", w, bit);
                    failures++;
                }
                continue;
            }

            const unsigned b = wire_byte - 4;
            const unsigned k = bit % 8;
            const unsigned position = 2 * (7 - b) + (k < 4 ? 1 : 0);
            const uint64_t want = static_cast<uint64_t>(1) << (4 * position + k % 4);
            if (diff != want) {
                std::printf("FAIL: header word %u bit %u should flip bit %u of "
                            "position %u alone\n", w, bit, k % 4, position);
                failures++;
            } else {
                moved_right++;
            }
        }
    if (moved_right != 64) {
        std::printf("FAIL: %u of the 64 order bits moved as they should\n",
                    moved_right);
        failures++;
    }

    // 4. Passes, with the orders that pin each end.
    struct PassCase {
        uint32_t word1, word2;
        unsigned passes;
    };
    static const PassCase kPasses[] = {
        { 0x00000000, 0x00000000, 16 },  // sixteen BLAKEs
        { 0xefcdab89, 0x67452301, 19 },  // the identity: 4, 6 and F once each
        { 0x44444444, 0x44444444, 32 },  // sixteen Keccaks, each after a Tiger
        { 0x666f6f66, 0x46f44f64, 32 },  // only 4, 6 and F, mixed
        { 0x55555555, 0x55555555, 16 },  // Skein, which Tiger never precedes
    };
    for (const PassCase &c : kPasses) {
        uint32_t header[20] = {};
        header[1] = c.word1;
        header[2] = c.word2;
        const uint64_t order = order_of(header);
        if (passes(order) != c.passes) {
            char s[17];
            order_string(order, s);
            std::printf("FAIL: order %s costs %u passes, not %u\n", s,
                        passes(order), c.passes);
            failures++;
        }
    }

    if (std::strcmp(stage_name(kKeccak), "keccak") != 0
        || std::strcmp(stage_name(kSha512), "sha512") != 0) {
        std::printf("FAIL: stage names are out of step with the numbering\n");
        failures++;
    }

    if (!failures)
        std::printf("ok   %u ccminer orders, %u printed hashes, 64 order bits "
                    "and 576 others, %u pass counts\n",
                    static_cast<unsigned>(sizeof kCcminer / sizeof kCcminer[0]),
                    static_cast<unsigned>(sizeof kPrinted / sizeof kPrinted[0]),
                    static_cast<unsigned>(sizeof kPasses / sizeof kPasses[0]));
    return failures ? 1 : 0;
}
