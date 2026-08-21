// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "self_test.h"

#include "algorithms/registry.h"

#include <vector>

extern "C" {
#include "core/miner.h"
}

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace vkminer {
namespace {

// Nonces either side of the published one. The device is asked for a range
// rather than the single right answer so that a kernel which ignores
// nonce_start, or hashes the wrong invocation index, produces the wrong nonce
// instead of the right one by construction.
constexpr uint32_t kBefore = 100;
constexpr uint32_t kSpan = 256;

// Room for more than the one candidate that can legitimately turn up, so that
// a kernel emitting several is seen doing it rather than truncated to look
// correct.
constexpr int kMaxSolutions = 16;

std::string hex(const unsigned char *bytes, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out.push_back(digits[bytes[i] >> 4]);
        out.push_back(digits[bytes[i] & 15]);
    }
    return out;
}

// The header as struct work carries it: one host-order word per big-endian read
// of the wire. The same conversion the miner makes on the way in, and the nonce
// word is zeroed because it is supplied separately -- a reference or a kernel
// that reads the nonce out of the header instead is then wrong here rather than
// right by accident.
void header_words(const Algorithm &algo, const KnownAnswer &answer,
                  std::vector<uint32_t> *out)
{
    const size_t words = algo.header_bytes() / 4;
    out->assign(words, 0);
    for (size_t i = 0; i < words; i++)
        (*out)[i] = be32dec(answer.header + i * 4);
    if (algo.nonce_word() < words)
        (*out)[algo.nonce_word()] = 0;
}

// The scalar reference against the published digest. If this fails nothing
// else is worth running: the reference is what every candidate off a device is
// re-checked against, so a wrong one would launder wrong hashes into shares.
bool check_reference(const Algorithm &algo, const KnownAnswer &answer)
{
    std::vector<uint32_t> header;
    header_words(algo, answer, &header);

    uint32_t got[8];
    algo.hash(header.data(), answer.nonce, got);

    if (std::memcmp(got, answer.digest, sizeof got) == 0)
        return true;

    applog(LOG_ERR, "Self-test: the %s reference hashes %s wrongly",
           algo.name(), answer.label);
    applog(LOG_ERR, "  expected %s", hex(answer.digest, 32).c_str());
    applog(LOG_ERR, "  got      %s",
           hex(reinterpret_cast<const unsigned char *>(got), 32).c_str());
    return false;
}

// Digests as the target comparison reads them: eight words, most significant
// last.
bool digest_below(const uint32_t *a, const uint32_t *b)
{
    for (int i = 7; i >= 0; i--)
        if (a[i] != b[i])
            return a[i] < b[i];
    return false;
}

// The nonce in a range whose digest the reference says is smallest, and that
// digest. Taken as a target it admits exactly one nonce of the range, by
// construction rather than by luck -- which is the property the device pass
// below rests on.
//
// The published digest has that property only for a vector that is a mined
// block, where every neighbour would have to clear sixty-four leading zero bits
// to join it. ProgPoW publishes hashes of chosen inputs rather than solutions,
// so its digests are ordinary 256-bit numbers and most of a range meets one.
// That is why the range's target is asked of the reference and only the
// published nonce is checked against the published digest.
struct Smallest {
    uint64_t nonce;
    uint32_t digest[8];
    bool alone;      // no other nonce in the range hashes to the same value
};

// Once per vector, however many kernels ask. The tuner calls in here for every
// candidate it races, from more than one thread, and for KawPoW one sweep is
// 256 hashes against a dataset built an item at a time.
const Smallest &smallest_in_range(const Algorithm &algo,
                                  const KnownAnswer &answer, uint64_t start)
{
    static std::mutex lock;
    static std::map<const KnownAnswer *, Smallest> cache;

    std::lock_guard<std::mutex> held(lock);

    const std::map<const KnownAnswer *, Smallest>::iterator it =
        cache.find(&answer);
    if (it != cache.end())
        return it->second;

    std::vector<uint32_t> header;
    header_words(algo, answer, &header);

    Smallest best;
    best.nonce = start;
    best.alone = true;
    algo.hash(header.data(), start, best.digest);

    for (uint32_t i = 1; i < kSpan; i++) {
        uint32_t got[8];
        algo.hash(header.data(), start + i, got);

        if (digest_below(got, best.digest)) {
            best.nonce = start + i;
            std::memcpy(best.digest, got, sizeof best.digest);
            best.alone = true;
        } else if (std::memcmp(got, best.digest, sizeof best.digest) == 0) {
            best.alone = false;
        }
    }

    return cache.insert(std::make_pair(&answer, best)).first->second;
}

// One dispatch whose target exactly one nonce of it meets, and the check that
// the device says so and says the right digest with it.
bool one_solution(Kernel &kernel, const char *device, const char *label,
                  const char *what, const std::vector<uint32_t> &header,
                  const uint32_t target[8], uint64_t start, uint32_t count,
                  uint64_t nonce, const uint32_t digest[8])
{
    if (!kernel.dispatch(header.data(), target, start, count)) {
        applog(LOG_ERR, "Self-test: %s refused a dispatch of %u nonces",
               device, count);
        return false;
    }

    Solution found[kMaxSolutions];
    const int n = kernel.collect(found, kMaxSolutions);
    if (n < 0) {
        applog(LOG_ERR, "Self-test: %s failed while hashing %s", device, label);
        return false;
    }
    if (n != 1) {
        applog(LOG_ERR, "Self-test: %s found %d nonces meeting %s, and exactly "
                        "one does", device, n, what);
        for (int i = 0; i < n; i++)
            applog(LOG_ERR, "  nonce %s", nonce_hex(found[i].nonce).c_str());
        return false;
    }
    if (found[0].nonce != nonce) {
        applog(LOG_ERR, "Self-test: %s met %s with nonce %s, and the answer is "
                        "%s", device, what, nonce_hex(found[0].nonce).c_str(),
               nonce_hex(nonce).c_str());
        return false;
    }
    if (std::memcmp(found[0].hash, digest, sizeof found[0].hash) != 0) {
        applog(LOG_ERR, "Self-test: %s found the right nonce for %s and "
                        "reported the wrong digest", device, label);
        applog(LOG_ERR, "  expected %s",
               hex(reinterpret_cast<const unsigned char *>(digest),
                   32).c_str());
        applog(LOG_ERR, "  got      %s",
               hex(reinterpret_cast<const unsigned char *>(found[0].hash),
                   32).c_str());
        return false;
    }

    return true;
}

}  // namespace

// The same vector through a kernel, in two dispatches that fail differently.
//
// The first is the published point alone: one nonce, the published digest as
// the target. It is what ties this device to a number somebody else computed,
// and a kernel that ignores nonce_start fails it by hashing nonce zero.
//
// The second is the range around it, at the target the reference says only one
// of those nonces meets. That is where a kernel which hashes the wrong
// invocation index -- right on a dispatch of one, wrong on a dispatch of many
// -- stops agreeing.
bool kernel_reproduces(Kernel &kernel, const Algorithm &algo,
                       const KnownAnswer &answer, const char *device)
{
    std::vector<uint32_t> header;
    header_words(algo, answer, &header);

    uint32_t published[8];
    std::memcpy(published, answer.digest, sizeof published);

    // A vector for an algorithm with shared device state names a state of its
    // own -- an old epoch, for a header published years ago -- so this is where
    // it gets built. Nothing for the algorithms without it, and the one line
    // covers both callers: the self-test and the tuner's check of each
    // candidate it races.
    if (!kernel.prepare_state(algo.state_key(header.data()))) {
        applog(LOG_ERR, "Self-test: %s could not prepare the state %s needs",
               device, answer.label);
        return false;
    }

    // And the program the vector's header names, for a kernel that is compiled
    // per program. A known answer is a known answer for one of them, and a
    // shader built with the wrong one hashes wrongly on purpose.
    if (!kernel.prepare_program(algo.program_key(header.data()))) {
        applog(LOG_ERR, "Self-test: %s could not build the kernel %s needs",
               device, answer.label);
        return false;
    }

    if (!one_solution(kernel, device, answer.label, "its own published hash",
                      header, published, answer.nonce, 1, answer.nonce,
                      published))
        return false;

    // Not below zero for a vector whose nonce is one of the first hundred: the
    // range still contains it, and a range that had wrapped instead would be a
    // dispatch of 2^64 nonces asked for by accident.
    const uint64_t start = answer.nonce > kBefore ? answer.nonce - kBefore : 0;

    const Smallest &best = smallest_in_range(algo, answer, start);
    if (!best.alone) {
        applog(LOG_ERR, "Self-test: two nonces around %s hash alike, so there "
                        "is no target only one of them meets", answer.label);
        return false;
    }

    return one_solution(kernel, device, answer.label,
                        "the smallest hash in its range", header, best.digest,
                        start, kSpan, best.nonce, best.digest);
}

bool self_test(ComputeBackend &backend, const std::vector<int> &device_indices,
               const char *algo_name)
{
    std::unique_ptr<Algorithm> algo = create_algorithm(algo_name);
    if (!algo) {
        applog(LOG_ERR, "Self-test: no algorithm called '%s'", algo_name);
        return false;
    }

    const KnownAnswer *answers = nullptr;
    const size_t count = algo->known_answers(&answers);
    if (!count) {
        applog(LOG_ERR, "Self-test: '%s' carries no known-answer vectors, so "
                        "this build cannot show that it hashes correctly",
               algo->name());
        return false;
    }

    // Counts are printed as unsigned rather than with %zu, because mingw's
    // printf does not accept it and this binary is built for Windows.
    const unsigned n = static_cast<unsigned>(count);

    for (size_t i = 0; i < count; i++)
        if (!check_reference(*algo, answers[i]))
            return false;

    applog(LOG_INFO, "Self-test: the %s reference reproduces %u published "
                     "hash(es)", algo->name(), n);

    const std::vector<DeviceInfo> &devices = backend.devices();

    for (const int index : device_indices) {
        if (index < 0 || index >= static_cast<int>(devices.size())) {
            applog(LOG_ERR, "Self-test: there is no device %d", index);
            return false;
        }
        const DeviceInfo &info = devices[index];

        std::unique_ptr<Kernel> kernel =
            backend.create_kernel(index, algo->kernel(info));
        if (!kernel) {
            applog(LOG_ERR, "Self-test: '%s' would not build for device %d",
                   algo->name(), index);
            return false;
        }

        const std::string device = "device " + std::to_string(index)
                                 + " (" + info.name + ")";

        for (size_t i = 0; i < count; i++)
            if (!kernel_reproduces(*kernel, *algo, answers[i], device.c_str()))
                return false;

        applog(LOG_INFO, "Self-test: %s reproduces %u published hash(es)",
               device.c_str(), n);
    }

    return true;
}

}  // namespace vkminer
