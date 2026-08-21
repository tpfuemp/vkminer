// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "replay.h"

#include "algorithms/registry.h"
#include "backends/backend.h"
#include "scheduler/candidate_log.h"

extern "C" {
#include "core/miner.h"
}

#include <cstring>
#include <memory>

namespace vkminer {
namespace {

void log_hash(const char *label, const uint32_t hash[8])
{
    // Most significant word first, which is the order the target comparison
    // reads and the order the deciding word ends up leftmost in.
    char text[70];
    for (int i = 0; i < 8; i++)
        snprintf(text + i * 8, sizeof text - i * 8, "%08x", hash[7 - i]);
    applog2(LOG_INFO, "%-8s %s", label, text);
}

// One capture through one device. `agreed` counts the ones that came back the
// way the host says they should, which is the interesting number when a bug has
// been fixed and the file is being used to prove it.
void replay_one(Kernel &kernel, const Algorithm &algo,
                const CapturedCandidate &bad, int device, int *agreed,
                int *reproduced)
{
    uint32_t host_hash[8];
    const bool host_says = algo.verify(bad.header, bad.nonce, bad.target,
                                       host_hash);

    // A capture is a header from some past job, and for an algorithm with
    // shared state that header names the state it was hashed under. Replaying
    // it against whatever the device is holding now would answer a different
    // question from the one the file was written to ask.
    if (!kernel.prepare_state(algo.state_key(bad.header))) {
        applog(LOG_ERR, "Device %d could not prepare the state nonce %s was "
                        "captured under", device, nonce_hex(bad.nonce).c_str());
        return;
    }

    // The same for the program that header ran, which for KawPoW changes every
    // three blocks: a capture from an hour ago replayed under this period's
    // program would disagree with the host for a reason that is not a bug.
    if (!kernel.prepare_program(algo.program_key(bad.header))) {
        applog(LOG_ERR, "Device %d could not build the kernel nonce %s was "
                        "captured under", device, nonce_hex(bad.nonce).c_str());
        return;
    }

    if (!kernel.dispatch(bad.header, bad.target, bad.nonce, 1)) {
        applog(LOG_ERR, "Device %d refused a dispatch of one nonce", device);
        return;
    }

    Solution got[4];
    const int n = kernel.collect(got, 4);
    if (n < 0) {
        applog(LOG_ERR, "Device %d failed while replaying nonce %s", device,
               nonce_hex(bad.nonce).c_str());
        return;
    }

    const bool device_says = n > 0 && got[0].nonce == bad.nonce;

    // The device reporting a nonce the host rejects is the fault that was
    // captured; the device reporting it again is the fault reproducing.
    if (device_says != host_says) {
        applog(LOG_ERR, "Device %d, nonce %s: the device %s it meets the "
                        "target and the host %s -- the fault reproduces",
               device, nonce_hex(bad.nonce).c_str(),
               device_says ? "says" : "does not say",
               host_says ? "agrees" : "does not");
        (*reproduced)++;
        return;
    }

    if (device_says && std::memcmp(got[0].hash, host_hash, sizeof host_hash)) {
        applog(LOG_ERR, "Device %d, nonce %s: both agree it is a share and "
                        "they compute different digests -- the fault reproduces",
               device, nonce_hex(bad.nonce).c_str());
        log_hash("device", got[0].hash);
        log_hash("host", host_hash);
        (*reproduced)++;
        return;
    }

    // Not a pass for the kernel, only for this input on this device today. Said
    // that way round on purpose: the capture was taken under a full dispatch and
    // this is one invocation, so a race does not have to show here.
    applog(LOG_INFO, "Device %d, nonce %s: device and host agree now", device,
           nonce_hex(bad.nonce).c_str());
    if (std::memcmp(bad.device_hash, bad.host_hash, sizeof bad.host_hash))
        log_hash("captured", bad.device_hash);
    (*agreed)++;
}

}  // namespace

bool replay_captures(ComputeBackend &backend, const std::vector<int> &devices,
                     const char *algo_name, const std::string &path)
{
    std::vector<CapturedCandidate> captures;
    if (!read_captures(path, &captures))
        return false;

    std::unique_ptr<Algorithm> algo = create_algorithm(algo_name);
    if (!algo) {
        applog(LOG_ERR, "--replay: no algorithm called '%s'", algo_name);
        return false;
    }

    applog(LOG_NOTICE, "Replaying %u capture(s) from %s",
           static_cast<unsigned>(captures.size()), path.c_str());

    int agreed = 0, reproduced = 0;

    for (const int index : devices) {
        const DeviceInfo &info = backend.devices()[static_cast<size_t>(index)];

        KernelSpec spec = algo->kernel(info);
        if (!spec.spirv || !spec.spirv_words) {
            applog(LOG_WARNING, "Device %d (%s) has no %s shader to replay on",
                   index, info.name.c_str(), algo_name);
            continue;
        }

        // Deliberately not tuned. A capture is evidence about a kernel, and the
        // point of replaying it is to run the same shader again, not the one a
        // sweep has since decided this device prefers.
        std::unique_ptr<Kernel> kernel = backend.create_kernel(index, spec);
        if (!kernel) {
            applog(LOG_ERR, "Device %d (%s): no kernel for %s", index,
                   info.name.c_str(), algo_name);
            continue;
        }

        // Every capture on every selected device, not only on the device that
        // recorded it: a nonce one GPU gets wrong and another gets right is the
        // most useful thing this can find, and it costs a dispatch to look.
        for (const CapturedCandidate &bad : captures)
            replay_one(*kernel, *algo, bad, index, &agreed, &reproduced);
    }

    if (reproduced)
        applog(LOG_ERR, "%d of %d replayed candidate(s) still disagree",
               reproduced, agreed + reproduced);
    else
        applog(LOG_NOTICE, "All %d replayed candidate(s) agree with the host "
                           "now. A fault that only appears under load will not "
                           "show here -- one invocation is not occupancy.",
               agreed);

    return reproduced == 0;
}

}  // namespace vkminer
