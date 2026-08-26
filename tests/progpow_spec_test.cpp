// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Every other KawPoW kernel against the interpreter, and all of them against
// the host.
//
// progpow_test showed that the interpreter hashes correctly. This file is about
// the kernels that are faster than it: the one whose rounds are compiled into
// the pipeline rather than read out of a buffer, one pipeline per period, and
// the one that additionally exchanges between lanes through subgroup shuffles
// instead of shared memory. It asks the algorithm what those are rather than
// naming them, so a kernel added later is tested by having been offered.
//
// Everything that could go wrong with them goes wrong quietly: a specialization
// constant declared at the wrong ID is a valid program that is not this
// period's, reordered operations produce digests that look exactly like
// digests, a shuffle reaching the wrong invocation mixes two nonces and both
// still look random, and a pipeline never rebuilt at a period boundary keeps
// mining the previous program at full speed.
//
// So there are four comparisons here, each catching a different one:
//
//   - the kernel against the scalar reference, word by word, which is the only
//     oracle not itself under test;
//   - the kernel against the interpreter on the same nonces, so a disagreement
//     points at the difference between the two files rather than at KawPoW;
//   - the same nonces either side of a period boundary, which have to stop
//     agreeing -- the height is not hashed, so unchanged digests can only mean
//     a stale program;
//   - and, under --wide, the kernel against the interpreter over a range wide
//     enough to be called coverage, with the host left out so that the range
//     can be: a host oracle that walks a DAG per nonce keeps it to dozens.
//
// The DAG is built on the host and uploaded, for the reason progpow_test gives:
// a disagreement should have one cause.

#include "algorithms/algorithm.h"
#include "algorithms/progpow/progpow.h"
#include "algorithms/progpow/progpow_program.h"
#include "backends/vulkan/vulkan_backend.h"
#include "backends/vulkan/vulkan_common.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and the option parser reach for and no more.
extern "C" {
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
struct thr_info *thr_info = nullptr;
double *thr_hashrates = nullptr;
struct work_restart *work_restart = nullptr;
int work_thr_id = 0;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
}

namespace {

// The epoch, and how much of its DAG to upload: the same small host-built table
// progpow_test uses, and for the same reasons.
constexpr uint32_t kEpoch = 0;
constexpr uint64_t kLines = 8192;

// Nonces per dispatch, all of which come back as candidates because the target
// is wide open.
constexpr uint32_t kBatch = 16;

// Nonces per period, unless argv[1] says otherwise. Lower than progpow_test's
// count because every one of them is hashed twice on the host -- once per
// period -- and the host is much the slower half.
constexpr uint32_t kDefaultNonces = 64;

// Nonces for the wide comparison, unless --wide says otherwise. Off by default
// because it is a second run of everything.
//
// The host oracle is what holds the count above down to dozens: one host KawPoW
// hash walks a DAG, so a range wide enough to be worth calling coverage would
// take longer than anyone waits. Two kernels compared against each other have
// no such cost -- both halves are the device -- and what that buys is the one
// thing the small count cannot: enough distinct mixes to reach the parts of a
// program a few dozen nonces never select.
//
// It is a weaker check than the one above, and deliberately so. Two kernels
// agreeing says only that they agree; if the shared body they are both built
// from is wrong, they will agree about that too. So this runs beside the host
// comparison rather than instead of it, and its job is the narrow one of
// catching a change that makes one kernel diverge from the other.
constexpr uint32_t kDefaultWide = 0;

// The period the run starts in. Arbitrary, and fixed so that a failure is
// reproducible; what matters is that the next one follows it, because that is
// the key the backend will have been building ahead.
constexpr uint64_t kPeriod = 1249;

// Which fork's constants the kernels are built from -- see the same declaration
// in progpow_test.cpp for why it is a command-line argument. Here it decides one
// thing more: how many blocks a period lasts, and so where the boundary these
// kernels are rebuilt at falls.
const vkminer::progpow::Params *fork_params = &vkminer::progpow::kKawpow;

int failures = 0;

// A nonce is a 64-bit quantity here and is printed as one, so the format string
// has to be checked against the printf that will read it rather than against
// the C library's default one.
#if defined(__MINGW_PRINTF_FORMAT)
#define KAWPOW_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#elif defined(__GNUC__)
#define KAWPOW_PRINTF_FORMAT printf
#endif

void fail(const char *fmt, ...)
#if defined(KAWPOW_PRINTF_FORMAT)
    __attribute__((format(KAWPOW_PRINTF_FORMAT, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    std::printf("FAIL ");
    std::vprintf(fmt, args);
    std::printf("\n");
    va_end(args);
    failures++;
}

// A header as struct work carries one for this algorithm: the 32-byte header
// hash, then the block height. The hash is the same at both heights this
// test uses, deliberately -- the height is not hashed, so the program is then
// the only thing that differs between the two halves of the run.
std::vector<uint32_t> header_for(uint64_t height)
{
    static const uint32_t kHash[8] = {
        0x11c1a3d4u, 0x1f2e3d4cu, 0x5b6a7988u, 0xc0ffee00u,
        0x0badf00du, 0xdeadbeefu, 0x13579bdfu, 0x2468ace0u,
    };
    std::vector<uint32_t> header(kHash, kHash + 8);
    header.push_back(static_cast<uint32_t>(height));
    return header;
}

// Every candidate, whatever it hashed to.
const uint32_t kOpen[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
};

struct Digest {
    uint32_t word[8];
};

// A range of nonces through one kernel, in nonce order. The kernel returns them
// in whatever order the device finished them, so this puts them back: the whole
// point is to compare position for position against another kernel's.
bool digests_of(vkminer::Kernel &kernel, const std::vector<uint32_t> &header,
                uint64_t first, uint32_t nonces, const char *label,
                std::vector<Digest> *out)
{
    out->assign(nonces, Digest());
    std::vector<bool> seen(nonces, false);

    for (uint32_t done = 0; done < nonces; done += kBatch) {
        const uint32_t count = std::min(kBatch, nonces - done);
        const uint64_t base = first + done;

        if (!kernel.dispatch(header.data(), kOpen, base, count)) {
            fail("%s: the kernel refused a dispatch at %s", label,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        vkminer::Solution got[vkminer::kMaxCandidates];
        const int n = kernel.collect(got, vkminer::kMaxCandidates);
        if (n != static_cast<int>(count)) {
            fail("%s: %d of %u nonces came back at %s", label, n, count,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        for (int i = 0; i < n; i++) {
            const uint64_t nonce = got[i].nonce;
            if (nonce < base || nonce >= base + count) {
                fail("%s: nonce %s is outside the %u dispatched from %s", label,
                     vkminer::nonce_hex(nonce).c_str(), count,
                     vkminer::nonce_hex(base).c_str());
                return false;
            }
            const size_t at = static_cast<size_t>(nonce - first);
            std::memcpy((*out)[at].word, got[i].hash, sizeof (*out)[at].word);
            seen[at] = true;
        }
    }

    for (uint32_t i = 0; i < nonces; i++)
        if (!seen[i]) {
            fail("%s: nonce %s never came back", label,
                 vkminer::nonce_hex(first + i).c_str());
            return false;
        }

    return true;
}

// One period, the kernel under test and the control, against the host and
// against each other. `first` is the nonce the range starts at; the digests are
// handed back so the caller can compare periods.
bool period_agrees(vkminer::Kernel &spec, vkminer::Kernel &interp,
                   const vkminer::Algorithm &algo,
                   const std::vector<uint32_t> &header, uint64_t first,
                   uint32_t nonces, const char *label,
                   std::vector<Digest> *out)
{
    const uint64_t key = algo.program_key(header.data());
    if (!spec.prepare_program(key) || !interp.prepare_program(key)) {
        fail("%s: could not build a kernel for period %llu", label,
             static_cast<unsigned long long>(key));
        return false;
    }

    std::vector<Digest> other;
    if (!digests_of(spec, header, first, nonces, label, out))
        return false;
    if (!digests_of(interp, header, first, nonces, label, &other))
        return false;

    for (uint32_t i = 0; i < nonces; i++) {
        const uint64_t nonce = first + i;

        uint32_t expect[8];
        algo.hash(header.data(), nonce, expect);

        for (uint32_t w = 0; w < 8; w++) {
            if ((*out)[i].word[w] != expect[w]) {
                fail("%s: nonce %s word %u came back 0x%08x, and the host says "
                     "0x%08x", label, vkminer::nonce_hex(nonce).c_str(), w,
                     (*out)[i].word[w], expect[w]);
                return false;
            }
            if ((*out)[i].word[w] != other[i].word[w]) {
                fail("%s: nonce %s word %u is 0x%08x here and 0x%08x "
                     "interpreted", label, vkminer::nonce_hex(nonce).c_str(), w,
                     (*out)[i].word[w], other[i].word[w]);
                return false;
            }
        }
    }

    return true;
}

// The candidate against the control over a range wide enough to be called
// coverage, with the host left out of it. Same period, same header, position
// for position.
//
// Progress is printed because this is the one phase that runs long enough for a
// silent test to look like a hung one.
bool wide_agrees(vkminer::Kernel &spec, vkminer::Kernel &interp,
                 const std::vector<uint32_t> &header, uint32_t nonces,
                 const char *variant)
{
    // In chunks, so that a disagreement is reported after seconds rather than
    // after the whole range, and so that two ranges of digests rather than the
    // whole run are in memory at once.
    constexpr uint32_t kChunk = 4096;

    std::vector<Digest> mine, theirs;
    for (uint32_t done = 0; done < nonces; done += kChunk) {
        const uint32_t count = std::min(kChunk, nonces - done);

        if (!digests_of(spec, header, done, count, variant, &mine))
            return false;
        if (!digests_of(interp, header, done, count, "interp", &theirs))
            return false;

        for (uint32_t i = 0; i < count; i++)
            for (uint32_t w = 0; w < 8; w++)
                if (mine[i].word[w] != theirs[i].word[w]) {
                    fail("wide: nonce %s word %u is 0x%08x from '%s' and "
                         "0x%08x interpreted",
                         vkminer::nonce_hex(done + i).c_str(), w,
                         mine[i].word[w], variant, theirs[i].word[w]);
                    return false;
                }

        std::printf("     %u of %u agree\r", done + count, nonces);
        std::fflush(stdout);
    }

    std::printf("\rok   %u nonces agree with the interpreter, digest for "
                "digest    \n", nonces);
    return true;
}

// The control, and everything to be checked against it. The control is found by
// the name the algorithm gives it rather than by position -- which kernel
// kernels() offers first is a guess about which is faster, and this test is
// about none of that -- and everything else offered is a candidate, whether
// this file has heard of it or not.
//
// A device that is offered only the interpreter is not a failure: the
// shuffle kernel needs a subgroup of sixteen and the software rasterizers this
// runs on have four or eight. It is a failure to find no control, and it is a
// failure to find nothing at all to compare, because that is what a build with
// the modules missing looks like too.
bool specs_for(const vkminer::Algorithm &algo, const vkminer::DeviceInfo &info,
               vkminer::KernelSpec *interp,
               std::vector<vkminer::KernelSpec> *candidates)
{
    vkminer::KernelSpec offered[4];
    const size_t count = algo.kernels(info, offered, 4);

    bool have_interp = false;
    for (size_t i = 0; i < count; i++) {
        if (!offered[i].variant)
            continue;
        if (!std::strcmp(offered[i].variant, "interp")) {
            *interp = offered[i];
            have_interp = true;
        } else {
            candidates->push_back(offered[i]);
        }
    }

    if (!have_interp) {
        fail("the kawpow interpreter, which is the control, is not in this "
             "build");
        return false;
    }
    if (candidates->empty()) {
        fail("%s was offered nothing but the interpreter, so there is nothing "
             "to compare it against", info.name.c_str());
        return false;
    }
    return true;
}

// One candidate kernel, end to end: it agrees with the host and with the
// interpreter in one period, again in the next, and the two periods disagree.
bool check_kernel(vkminer::VulkanBackend &backend,
                  const vkminer::DeviceInfo &info,
                  const vkminer::Algorithm &algo, vkminer::Kernel &interp,
                  const vkminer::KernelSpec &desc, uint32_t nonces,
                  uint32_t wide)
{
    std::printf("\n   kernel '%s'\n", desc.variant);

    if (desc.program_constants
        && desc.program_constants != vkminer::progpow::kProgramWords + 1) {
        fail("'%s' wants %u constants and the program is %u words", desc.variant,
             desc.program_constants, vkminer::progpow::kProgramWords);
        return false;
    }

    std::unique_ptr<vkminer::Kernel> spec =
        backend.create_kernel(info.index, desc);
    if (!spec) {
        fail("could not create '%s' wanting %llu KiB of DAG", desc.variant,
             static_cast<unsigned long long>(desc.shared_bytes >> 10));
        return false;
    }

    const std::vector<uint32_t> low = header_for(kPeriod * fork_params->period_length);
    const std::vector<uint32_t> high =
        header_for((kPeriod + 1) * fork_params->period_length);

    if (!spec->prepare_state(algo.state_key(low.data()))) {
        fail("could not upload the DAG for '%s'", desc.variant);
        return false;
    }

    // ---- what a kernel does before it has a program
    //
    // Nothing, and it says so. The program is part of the pipeline, so there is
    // no pipeline to dispatch yet; a kernel that quietly ran anyway would be
    // hashing with the defaults the shader declares, which is a program nobody
    // chose. This deliberately provokes an error line into the log.
    if (desc.program_constants) {
        std::printf("     (the refusal below is the check, not a failure)\n");
        if (spec->dispatch(low.data(), kOpen, 0, kBatch)) {
            fail("'%s' dispatched before its program was built", desc.variant);
            return false;
        }
    }

    // ---- the first period
    std::vector<Digest> before;
    if (!period_agrees(*spec, interp, algo, low, 0, nonces, "first period",
                       &before))
        return false;
    std::printf("ok   %u nonces at period %llu, both matching the host\n",
                nonces, static_cast<unsigned long long>(kPeriod));

    // ---- and the next one
    //
    // The same nonces and the same header hash. Only the program is different,
    // so this is the whole of what a period boundary means to a kernel.
    std::vector<Digest> after;
    if (!period_agrees(*spec, interp, algo, high, 0, nonces, "second period",
                       &after))
        return false;
    std::printf("ok   %u nonces at period %llu, after the boundary\n", nonces,
                static_cast<unsigned long long>(kPeriod + 1));

    // ---- and they have to disagree with each other
    //
    // A pipeline that was never rebuilt returns exactly what it returned
    // before. One nonce colliding across two programs would be a 2^-256
    // coincidence; every nonce colliding is a stale program.
    for (uint32_t i = 0; i < nonces; i++)
        if (!std::memcmp(before[i].word, after[i].word, sizeof before[i].word)) {
            fail("nonce %s hashes the same in both periods, so '%s' did not "
                 "change program", vkminer::nonce_hex(i).c_str(), desc.variant);
            return false;
        }
    std::printf("ok   every digest changed with the period\n");

    if (!desc.program_constants)
        return wide ? wide_agrees(*spec, interp, high, wide, desc.variant)
                    : true;

    // ---- and the next program was built before it was asked for
    //
    // Which is what keeps a period boundary from being a stall: the backend was
    // told the next key when it took this one, and built it on a background
    // thread while the device was still mining the current one. Counted rather
    // than timed -- NVIDIA keeps a compiled-shader cache on disk, so a second
    // run of this test would time a period boundary at nearly zero whether
    // anything was built ahead or not.
    const vkminer::Kernel::ProgramStats stats = spec->program_stats();
    if (stats.builds < 2 || !stats.ahead) {
        fail("%llu pipelines were built for '%s' and %llu of them were ready "
             "before they were asked for",
             static_cast<unsigned long long>(stats.builds), desc.variant,
             static_cast<unsigned long long>(stats.ahead));
        return false;
    }
    std::printf("ok   %llu pipelines built, %llu of them ahead of the period "
                "that needed them\n",
                static_cast<unsigned long long>(stats.builds),
                static_cast<unsigned long long>(stats.ahead));

    // Last, because it is much the longest phase and everything above is worth
    // knowing before waiting for it. On the program the kernel already holds,
    // so this adds no pipeline to the count just checked.
    if (wide && !wide_agrees(*spec, interp, high, wide, desc.variant))
        return false;

    return true;
}

bool run_device(vkminer::VulkanBackend &backend, const vkminer::DeviceInfo &info,
                uint32_t nonces, uint32_t wide)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::make_progpow_host_dag(*fork_params, kEpoch, kLines);

    vkminer::KernelSpec interp_desc;
    std::vector<vkminer::KernelSpec> candidates;
    if (!specs_for(*algo, info, &interp_desc, &candidates))
        return false;

    // Which is worth printing: a device whose subgroup is not a whole number of
    // sixteens is offered one kernel fewer, and that is the difference between
    // a run that checked the shuffles and a run that could not.
    std::printf("     subgroup %u, %zu kernel(s) against the interpreter\n",
                info.subgroup_size, candidates.size());

    // The control, built once and handed to each candidate in turn. One
    // interpreter for all of them because it is the same answers either way,
    // and a second upload of the DAG per candidate is minutes of nothing.
    std::unique_ptr<vkminer::Kernel> interp =
        backend.create_kernel(info.index, interp_desc);
    if (!interp) {
        fail("could not create the interpreter wanting %llu KiB of DAG",
             static_cast<unsigned long long>(interp_desc.shared_bytes >> 10));
        return false;
    }

    const std::vector<uint32_t> low = header_for(kPeriod * fork_params->period_length);
    if (!interp->prepare_state(algo->state_key(low.data()))) {
        fail("could not upload the DAG");
        return false;
    }

    // Every candidate is run even after one fails. Which kernels a device
    // gets is a device's own business, and a run that stopped at the first
    // would report the shuffle kernel's problems only on the machines where the
    // specialized one is already right.
    bool ok = true;
    for (const vkminer::KernelSpec &desc : candidates)
        ok = check_kernel(backend, info, *algo, *interp, desc, nonces, wide)
             && ok;

    return ok;
}

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    uint32_t nonces = kDefaultNonces;
    uint32_t wide = kDefaultWide;
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--wide") && i + 1 < argc) {
            const long asked = std::strtol(argv[++i], nullptr, 10);
            if (asked < 0) {
                std::printf("usage: %s [nonces] [--wide nonces] [--fork name]\n",
                            argv[0]);
                return 2;
            }
            wide = static_cast<uint32_t>(asked);
            continue;
        }

        if (!std::strcmp(argv[i], "--fork") && i + 1 < argc) {
            fork_params = vkminer::progpow::find(argv[++i]);
            if (!fork_params) {
                std::printf("usage: %s [nonces] [--wide nonces] [--fork name]\n",
                            argv[0]);
                return 2;
            }
            continue;
        }

        const long asked = std::strtol(argv[i], nullptr, 10);
        if (asked <= 0) {
            std::printf("usage: %s [nonces] [--wide nonces] [--fork name]\n",
                        argv[0]);
            return 2;
        }
        nonces = static_cast<uint32_t>(asked);
    }

    std::printf("-- %s: %u regs, %u cache and %u math operations a round, a "
                "program every %u block(s)\n", fork_params->name,
                fork_params->regs, fork_params->cache_ops,
                fork_params->math_ops, fork_params->period_length);

    // Worth their cost for the barriers, as in progpow_test, and for one thing
    // more that is this file's own: pipelines are created and destroyed while
    // the device is working, from a thread that is not this one.
    opt_vk_validate = true;

    vkminer::VulkanBackend backend;
    if (!backend.init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    for (const vkminer::DeviceInfo &info : backend.devices())
        run_device(backend, info, nonces, wide);

    if (vkminer::vk_validation_errors) {
        std::printf("\nFAIL the validation layers reported %u error(s)\n",
                    vkminer::vk_validation_errors);
        failures++;
    } else if (vkminer::vk_validation_enabled) {
        std::printf("\nok   no validation errors\n");
    } else {
        std::printf("\nWARNING the validation layers are not installed, so "
                    "this run proved only that the numbers came back right\n");
    }

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
