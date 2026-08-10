// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VKMINER_ALGORITHMS_SCRYPT_SCRYPT_H__
#define VKMINER_ALGORITHMS_SCRYPT_SCRYPT_H__

#include "algorithms/algorithm.h"

#include <cstddef>
#include <memory>

namespace vkminer {

// scrypt as RFC 7914 defines it, for arbitrary parameters. Exposed rather than
// kept private to the algorithm because the RFC publishes vectors for parameters
// no coin mines at, and those vectors are the only published anchor this
// algorithm has: Litecoin's scrypt digest appears on no explorer.
//
// `n` must be a power of two greater than one. Allocates internally -- ROMix
// needs 128 * r * n bytes and nothing here pretends otherwise.
void scrypt(const unsigned char *password, size_t password_len,
            const unsigned char *salt, size_t salt_len,
            uint32_t n, uint32_t r, uint32_t p,
            unsigned char *out, size_t out_len);

// PBKDF2-HMAC-SHA256, which scrypt uses at both ends. Exposed for the same
// reason: RFC 6070's vectors are for HMAC-SHA1, but a wrong PBKDF2 here would
// show up only as a wrong scrypt, and the test can separate them.
void pbkdf2_sha256(const unsigned char *password, size_t password_len,
                   const unsigned char *salt, size_t salt_len,
                   uint32_t iterations, unsigned char *out, size_t out_len);

// Bytes of scratchpad one hash needs at the mined parameters: 128 * r * n, so
// 128 KiB at N=1024, r=1. Public because it is the number that decides how many
// invocations fit in a device's memory, and that decision is not the
// algorithm's to make alone.
constexpr uint64_t kScryptScratchBytes = 128ull * 1 * 1024;

std::unique_ptr<Algorithm> make_scrypt();

}  // namespace vkminer

#endif  // VKMINER_ALGORITHMS_SCRYPT_SCRYPT_H__
