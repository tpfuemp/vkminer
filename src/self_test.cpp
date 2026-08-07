// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "self_test.h"

#include "algorithms/registry.h"

#include <vector>

extern "C" {
#include "core/miner.h"
}

#include <cstring>
#include <memory>
#include <string>

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

}  // namespace

// The same vector through a kernel. The target is the published digest itself,
// which the network's hash <= target rule means exactly that nonce meets: the
// neighbours in the range would each have to clear a target with sixty-four
// leading zero bits to join it, so one candidate is the answer and any other
// number is a bug.
bool kernel_reproduces(Kernel &kernel, const Algorithm &algo,
                       const KnownAnswer &answer, const char *device)
{
    std::vector<uint32_t> header;
    header_words(algo, answer, &header);

    uint32_t target[8];
    std::memcpy(target, answer.digest, sizeof target);

    const uint32_t start = answer.nonce - kBefore;

    if (!kernel.dispatch(header.data(), target, start, kSpan)) {
        applog(LOG_ERR, "Self-test: %s refused a dispatch of %u nonces",
               device, kSpan);
        return false;
    }

    Solution found[kMaxSolutions];
    const int n = kernel.collect(found, kMaxSolutions);
    if (n < 0) {
        applog(LOG_ERR, "Self-test: %s failed while hashing %s", device,
               answer.label);
        return false;
    }
    if (n != 1) {
        applog(LOG_ERR, "Self-test: %s found %d nonces meeting %s's own hash, "
                        "and exactly one does", device, n, answer.label);
        for (int i = 0; i < n; i++)
            applog(LOG_ERR, "  nonce %08x", found[i].nonce);
        return false;
    }
    if (found[0].nonce != answer.nonce) {
        applog(LOG_ERR, "Self-test: %s solved %s with nonce %08x, and the "
                        "answer is %08x", device, answer.label, found[0].nonce,
               answer.nonce);
        return false;
    }
    if (std::memcmp(found[0].hash, answer.digest, sizeof found[0].hash) != 0) {
        applog(LOG_ERR, "Self-test: %s found the right nonce for %s and "
                        "reported the wrong digest", device, answer.label);
        applog(LOG_ERR, "  expected %s", hex(answer.digest, 32).c_str());
        applog(LOG_ERR, "  got      %s",
               hex(reinterpret_cast<const unsigned char *>(found[0].hash),
                   32).c_str());
        return false;
    }

    return true;
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
