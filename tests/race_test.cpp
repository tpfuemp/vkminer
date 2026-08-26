// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The race check: the same dispatch, run over and over, at the size the miner
// runs it at. Every repetition must return the same candidates.
//
// A known-answer test cannot find a race: one run is self-consistent. The
// differential test is stronger but sees each nonce once, so a race firing on
// one invocation in a million is a wrong answer it happens not to have asked
// for. Repetition under occupancy pressure does find one -- identical input,
// full-size dispatches, several in flight -- because any variation in the
// output is a race by definition. And it needs no validation layers and no
// profiler, so it runs on every device this miner reaches.
//
// Two things about it are deliberate and easy to undo by accident:
//
//   The dispatch is full sized. A race is a function of occupancy, and a test-
//   sized batch is the one shape guaranteed not to have any -- so the batch
//   comes from the kernel's own preferred_batch(), after enough warm-up
//   dispatches for it to have settled where mining would leave it.
//
//   The target is chosen from that batch size rather than fixed, so that a few
//   candidates come back per dispatch on a fast GPU and on a software
//   rasterizer alike. A run that returned nothing would compare nothing and
//   pass, which is the failure this file must not have.

#include "algorithms/kawpow/kawpow.h"
#include "algorithms/registry.h"
#include "backends/backend.h"
#include "backends/vulkan/vulkan_common.h"

extern "C" {
#include "core/miner.h"
}

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

// The inherited C expects the miner to own these. A test is not the miner, so
// it owns the ones applog and fulltest reach for and no more.
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

int failures = 0;

void fail(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
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

// Dispatches to run before the batch size is read. The kernel aims each
// dispatch at a fixed wall time and corrects from what it measures, sitting out
// a queue's worth of completions after every change -- so it needs more than a
// couple of them to arrive anywhere, and reading the size too early would
// measure the initial guess instead of this device.
constexpr int kWarmup = 24;

// Candidates a dispatch should average. Well under the result buffer's
// capacity, because a dispatch that overflowed it would return a truncated set
// and the comparison below would report the truncation as a race.
constexpr double kWantCandidates = 6.;

// How many candidates to ask for in one collect(), larger than the buffer holds
// so that a truncation shows up as missing nonces rather than as this test
// quietly asking for fewer.
constexpr int kMaxSolutions = 256;

// Where the range starts. Not zero, and it crosses 0x80000000 partway through a
// large batch, which is where a kernel treating the nonce as signed breaks.
constexpr uint64_t kNonceBase = 0x7fff0000u;

// Nonces every kernel of an algorithm is asked for, once each, and compared
// against each other rather than against the host.
//
// The differential test is the gate on a shader edit and its bar is a hundred
// thousand nonces, which for most algorithms the host reference meets in a few
// seconds. For one whose reference walks a gigabyte of table per hash it is
// hours, and that is exactly the algorithm with more than one kernel to compare.
// Two kernels are not the host -- agreeing with each other is weaker than
// agreeing with the reference, since a mistake in the body they share is
// invisible here -- but they are two different spellings of the lane exchange,
// the loads and the loop, and a hundred thousand nonces of them costs two
// dispatches. The small host-checked vector is what says the shared body is
// right; this is what says an edit to one kernel did not change what it answers.
constexpr uint32_t kCrossNonces = 100000;

// Block 125552's header, as it went over the wire. A real header rather than a
// pattern, so the words the shader schedules are the shape of the thing it will
// be given in earnest.
const unsigned char kHeader[80] = {
    0x01, 0x00, 0x00, 0x00,
    0x81, 0xcd, 0x02, 0xab, 0x7e, 0x56, 0x9e, 0x8b,
    0xcd, 0x93, 0x17, 0xe2, 0xfe, 0x99, 0xf2, 0xde,
    0x44, 0xd4, 0x9a, 0xb2, 0xb8, 0x85, 0x1b, 0xa4,
    0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe3, 0x20, 0xb6, 0xc2, 0xff, 0xfc, 0x8d, 0x75,
    0x04, 0x23, 0xdb, 0x8b, 0x1e, 0xb9, 0x42, 0xae,
    0x71, 0x0e, 0x95, 0x1e, 0xd7, 0x97, 0xf7, 0xaf,
    0xfc, 0x88, 0x92, 0xb0, 0xf1, 0xfc, 0x12, 0x2b,
    0xc7, 0xf5, 0xd7, 0x4d,
    0xf2, 0xb9, 0x44, 0x1a,
    0x42, 0xa1, 0x46, 0x95,
};

// A target this batch size meets about kWantCandidates times. The digest words
// a hash produces are uniform, so the fraction of nonces that meet a target
// whose top word is T is (T+1)/2^32, and the lower words are left at all ones
// so the comparison is decided in the top word.
void target_for(uint32_t batch, uint32_t out[8])
{
    for (int i = 0; i < 7; i++)
        out[i] = 0xffffffffu;

    const double top = kWantCandidates * 4294967296. / static_cast<double>(batch);
    out[7] = top >= 4294967295. ? 0xfffffffeu : static_cast<uint32_t>(top);
}

struct Candidate {
    uint64_t nonce;
    uint32_t hash[8];
};

// What one dispatch returned, in an order that does not depend on which
// invocation reached the counter first. Sorting is not papering over anything:
// nothing in the miner depends on the emission order, and a duplicate survives
// a sort and is caught by the comparison.
std::vector<Candidate> sorted_results(const vkminer::Solution *got, int n)
{
    std::vector<Candidate> out;
    out.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; i++) {
        Candidate c;
        c.nonce = got[i].nonce;
        std::memcpy(c.hash, got[i].hash, sizeof c.hash);
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(), [](const Candidate &a, const Candidate &b) {
        return a.nonce < b.nonce;
    });
    return out;
}

// Every candidate has to be a real one. Cheap -- there are a handful of them
// against millions of nonces -- and it is what keeps a device that returns the
// same wrong answer every time from passing a test about repeatability.
bool all_real(const vkminer::Algorithm &algo, const uint32_t *header,
              const uint32_t *target, uint64_t base, uint32_t batch,
              const std::vector<Candidate> &got, const char *what)
{
    for (const Candidate &c : got) {
        // Asked for first, valid second. A nonce outside the range still hashes
        // to a real share and would pass every check below it, so without this
        // the only evidence of a kernel reaching past the end of its dispatch
        // is a candidate count that looks a little generous.
        if (c.nonce - base >= batch) {
            fail("%s returned nonce 0x%s, which is outside the "
                 "%u nonces from 0x%s it was given", what,
                 vkminer::nonce_hex(c.nonce).c_str(), batch,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        uint32_t hash[8];
        if (!algo.verify(header, c.nonce, target, hash)) {
            fail("%s returned nonce 0x%s, which does not meet the "
                 "target", what, vkminer::nonce_hex(c.nonce).c_str());
            return false;
        }
        if (std::memcmp(hash, c.hash, sizeof hash) != 0) {
            fail("%s returned a digest for nonce 0x%s that the "
                 "host does not compute", what,
                 vkminer::nonce_hex(c.nonce).c_str());
            return false;
        }
    }
    return true;
}

// Which nonces one set has and the other does not, in order. Shared by the two
// comparisons below, because a disagreement is read the same way whichever axis
// it is on: what was lost, and what appeared.
void print_difference(const std::vector<Candidate> &first,
                      const std::vector<Candidate> &got)
{
    size_t i = 0, j = 0;
    while (i < first.size() || j < got.size()) {
        if (j >= got.size() || (i < first.size()
                                && first[i].nonce < got[j].nonce)) {
            std::printf("  lost      nonce 0x%s\n",
                        vkminer::nonce_hex(first[i].nonce).c_str());
            i++;
        } else if (i >= first.size() || got[j].nonce < first[i].nonce) {
            std::printf("  appeared  nonce 0x%s\n",
                        vkminer::nonce_hex(got[j].nonce).c_str());
            j++;
        } else {
            i++;
            j++;
        }
    }
}

// The comparison this file exists for. `first` is what the first repetition
// returned and is the answer every later one has to match.
bool same_results(const std::vector<Candidate> &first,
                  const std::vector<Candidate> &got, int repetition)
{
    if (first.size() != got.size()) {
        fail("repetition %d returned %u candidate(s) and the first returned "
             "%u, over the same nonces and the same header -- that is a race",
             repetition, static_cast<unsigned>(got.size()),
             static_cast<unsigned>(first.size()));

        print_difference(first, got);
        return false;
    }

    for (size_t i = 0; i < got.size(); i++) {
        if (got[i].nonce != first[i].nonce) {
            fail("repetition %d returned nonce 0x%s where the first returned "
                 "0x%s -- that is a race", repetition,
                 vkminer::nonce_hex(got[i].nonce).c_str(),
                 vkminer::nonce_hex(first[i].nonce).c_str());
            return false;
        }
        if (std::memcmp(got[i].hash, first[i].hash, sizeof got[i].hash) != 0) {
            fail("repetition %d hashed nonce 0x%s differently from the first "
                 "-- that is a race", repetition,
                 vkminer::nonce_hex(got[i].nonce).c_str());
            return false;
        }
    }
    return true;
}

// The same comparison across kernels instead of across repetitions. Every
// difference means one of the two is wrong, and which one it is takes the host
// to say -- but that there is one at all is the thing worth knowing before a
// shader edit ships, and it is knowable at a hundred thousand nonces.
bool same_kernels(const char *first_name, const std::vector<Candidate> &first,
                  const char *name, const std::vector<Candidate> &got)
{
    if (first.size() != got.size()) {
        fail("kernel '%s' found %u candidate(s) and '%s' found %u, over the "
             "same nonces and the same header", name,
             static_cast<unsigned>(got.size()), first_name,
             static_cast<unsigned>(first.size()));
        print_difference(first, got);
        return false;
    }

    for (size_t i = 0; i < got.size(); i++) {
        if (got[i].nonce != first[i].nonce) {
            fail("kernel '%s' found nonce 0x%s where '%s' found 0x%s", name,
                 vkminer::nonce_hex(got[i].nonce).c_str(), first_name,
                 vkminer::nonce_hex(first[i].nonce).c_str());
            return false;
        }
        if (std::memcmp(got[i].hash, first[i].hash, sizeof got[i].hash) != 0) {
            fail("kernel '%s' hashed nonce 0x%s differently from '%s'", name,
                 vkminer::nonce_hex(got[i].nonce).c_str(), first_name);
            return false;
        }
    }
    return true;
}

// Enough dispatches for the kernel's batch size to stop moving. Their results
// are thrown away -- what is wanted here is the size, not the answers.
//
// The target is recomputed for every one of them rather than fixed, because the
// batch size is what is moving: the first dispatch is the initial guess and the
// last can be a hundred times larger, and a target chosen for the first would
// have the last returning candidates by the hundred, overflowing the result
// buffer and filling the log with capacity warnings. Those warnings are real --
// the kernel is right to print them -- which is exactly why this must not
// manufacture them, or the ones that mean something get read as noise.
void warm_up(vkminer::Kernel &kernel, const uint32_t *header)
{
    const uint32_t depth = std::max<uint32_t>(1, kernel.queue_depth());
    uint32_t inflight = 0;

    for (int i = 0; i < kWarmup; i++) {
        const uint32_t batch = kernel.preferred_batch();
        uint32_t target[8];
        target_for(batch, target);

        if (!kernel.dispatch(header, target, kNonceBase, batch))
            break;
        inflight++;
        if (inflight < depth)
            continue;

        vkminer::Solution got[kMaxSolutions];
        if (kernel.collect(got, kMaxSolutions) < 0)
            break;
        inflight--;
    }

    while (inflight--) {
        vkminer::Solution got[kMaxSolutions];
        if (kernel.collect(got, kMaxSolutions) < 0)
            break;
    }
}

// kCrossNonces from the same base, in whatever pieces this kernel is willing to
// take them in. The pieces are the kernel's own dispatch size and so differ
// between kernels; the nonces do not, and they are what is being compared.
//
// Cut into pieces at all because that size is what the kernel can finish inside
// its timeout, and this many of a 16-lane hash is a minute of a software
// rasterizer -- one dispatch of them would be refused. One at a time because
// what is wanted here is the answer and not the rate.
bool cross_pass(vkminer::Kernel &kernel, const vkminer::Algorithm &algo,
                const uint32_t *header, const uint32_t *target,
                const char *name, std::vector<Candidate> *out)
{
    out->clear();
    uint32_t done = 0;
    while (done < kCrossNonces) {
        const uint32_t chunk =
            std::min(kCrossNonces - done, kernel.preferred_batch());
        const uint64_t base = kNonceBase + done;

        if (!kernel.dispatch(header, target, base, chunk)) {
            fail("kernel '%s' refused %u nonces from 0x%s", name, chunk,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        vkminer::Solution got[kMaxSolutions];
        const int n = kernel.collect(got, kMaxSolutions);
        if (n < 0) {
            fail("kernel '%s' failed on %u nonces from 0x%s", name, chunk,
                 vkminer::nonce_hex(base).c_str());
            return false;
        }

        const std::vector<Candidate> piece = sorted_results(got, n);
        if (!all_real(algo, header, target, base, chunk, piece, name))
            return false;
        out->insert(out->end(), piece.begin(), piece.end());
        done += chunk;
    }

    // Two kernels that both found nothing agree perfectly, and that is the one
    // way the comparison can pass without having compared anything.
    if (out->empty()) {
        fail("kernel '%s' found no candidate in %u nonces -- the target is "
             "meant to be met about %.0f times", name, kCrossNonces,
             kWantCandidates);
        return false;
    }

    // Each piece arrives sorted and the pieces are in ascending order, so the
    // whole is sorted already -- said rather than assumed, since the comparison
    // is elementwise.
    return true;
}

// One kernel of one algorithm on one device, repeated.
bool run_kernel(vkminer::ComputeBackend &backend, const vkminer::DeviceInfo &info,
                const vkminer::Algorithm &algo,
                const vkminer::KernelSpec &spec, int repetitions,
                std::vector<Candidate> *cross)
{
    if (!spec.spirv || !spec.spirv_words) {
        std::printf("SKIP %s has no shader for this device\n", algo.name());
        return true;
    }

    std::unique_ptr<vkminer::Kernel> kernel =
        backend.create_kernel(info.index, spec);
    if (!kernel) {
        fail("could not build %s for this device", algo.name());
        return false;
    }

    // struct work's spelling of the header: one host-order word per big-endian
    // read of the wire, which is the conversion the miner makes on the way in.
    uint32_t header[20];
    for (size_t i = 0; i < 20; i++)
        header[i] = be32dec(kHeader + i * 4);

    // Once, not per dispatch: every dispatch below is the same header, which is
    // the whole point of the file, so the table and the program are the same
    // ones throughout and the miner would skip the upload too. No-ops for an
    // algorithm that needs neither. This can be slow -- a device-generated DAG
    // is a gigabyte written by a kernel -- so it is said before it starts.
    std::printf("     preparing the kernel for this header\n");
    std::fflush(stdout);
    if (!kernel->prepare_state(algo.state_key(header)) ||
        !kernel->prepare_program(algo.program_key(header))) {
        fail("the kernel could not prepare itself for this header");
        return false;
    }

    warm_up(*kernel, header);

    // Read once and used for every repetition. It must not be re-read inside
    // the loop: a dispatch that changed size partway through would make the
    // repetitions different dispatches, and this file would then be comparing
    // two answers to two questions.
    const uint32_t batch = kernel->preferred_batch();
    const uint32_t depth = std::max<uint32_t>(1, kernel->queue_depth());

    uint32_t target[8];
    target_for(batch, target);

    std::printf("     %u nonces from 0x%s, target %08x, %d repetition(s), "
                "%u in flight\n", batch, vkminer::nonce_hex(kNonceBase).c_str(),
                target[7], repetitions, depth);

    // Identical dispatches, as many outstanding at once as the device will
    // take. Several copies of one dispatch in flight together is the state the
    // miner spends its life in and the one a cross-dispatch mix-up needs: each
    // has its own result buffer and descriptor set, and a kernel that confused
    // two of them would still return real hashes of real nonces.
    std::vector<Candidate> first;
    int submitted = 0;
    int collected = 0;
    uint32_t inflight = 0;

    while (collected < repetitions) {
        while (submitted < repetitions && inflight < depth) {
            if (!kernel->dispatch(header, target, kNonceBase, batch)) {
                fail("dispatch of %u nonces was refused with %u in flight",
                     batch, inflight);
                return false;
            }
            submitted++;
            inflight++;
        }

        vkminer::Solution got[kMaxSolutions];
        const int n = kernel->collect(got, kMaxSolutions);
        if (n < 0) {
            fail("the device failed on repetition %d", collected);
            return false;
        }
        inflight--;

        const std::vector<Candidate> results = sorted_results(got, n);
        char what[32];
        std::snprintf(what, sizeof what, "repetition %d", collected);
        if (!all_real(algo, header, target, kNonceBase, batch, results, what))
            return false;

        if (collected == 0)
            first = results;
        else if (!same_results(first, results, collected))
            return false;
        collected++;
    }

    // A device that returns nothing returns the same nothing every time, and
    // this whole file would pass on it. That is the one way a repetition test
    // can be vacuous, so it is a failure rather than a pass.
    if (first.empty()) {
        fail("no candidates at all in %d dispatch(es) of %u nonces -- the "
             "target above is meant to be met about %.0f times per dispatch",
             collected, batch, kWantCandidates);
        return false;
    }

    std::printf("ok   %d repetition(s), %u candidate(s) each, identical\n",
                collected, static_cast<unsigned>(first.size()));

    // The nonces the caller compares between kernels. A different target from
    // the one above, because it covers a different number of nonces and a
    // target chosen for one would return either nothing or hundreds from the
    // other.
    if (cross) {
        const char *name = spec.variant && spec.variant[0] ? spec.variant : "";
        uint32_t cross_target[8];
        target_for(kCrossNonces, cross_target);
        if (!cross_pass(*kernel, algo, header, cross_target, name, cross))
            return false;
        std::printf("     %u nonces from 0x%s, target %08x, %u candidate(s)\n",
                    kCrossNonces, vkminer::nonce_hex(kNonceBase).c_str(),
                    cross_target[7], static_cast<unsigned>(cross->size()));
    }
    return true;
}

// Kernels one algorithm may offer for one device, the tuner's own bound.
constexpr size_t kMaxVariants = 4;

// Every kernel the device could run, not the one kernel() opens with.
//
// A race is a property of a kernel and not of an algorithm, and the ones an
// algorithm offers can differ in exactly the machinery a race lives in: KawPoW
// exchanges registers between its sixteen invocations through a workgroup array
// in two of its kernels and through subgroup shuffles in the third, and the
// third is the one the tuner picks to mine with on this card. Testing the
// default would leave that one unrepeated.
bool run_device(vkminer::ComputeBackend &backend, const vkminer::DeviceInfo &info,
                const vkminer::Algorithm &algo, int repetitions)
{
    std::printf("\n-- device %d: %s [%s]\n", info.index, info.name.c_str(),
                vkminer::device_kind_name(info.kind));

    vkminer::KernelSpec variants[kMaxVariants];
    const size_t count = algo.kernels(info, variants, kMaxVariants);
    if (!count) {
        std::printf("SKIP %s has no shader for this device\n", algo.name());
        return true;
    }

    bool ok = true;
    std::vector<Candidate> first;
    const char *first_name = nullptr;

    for (size_t i = 0; i < count; i++) {
        // Named only where there is a choice, so the single-kernel algorithms
        // keep the output they have always had -- and where there is no choice
        // there is nothing to compare against either.
        std::vector<Candidate> cross;
        if (count > 1 && variants[i].variant)
            std::printf("\n   kernel '%s'\n", variants[i].variant);
        if (!run_kernel(backend, info, algo, variants[i], repetitions,
                        count > 1 ? &cross : nullptr)) {
            ok = false;
            continue;   // it has nothing to be compared against
        }
        if (cross.empty())
            continue;   // no shader for this device, so no answers from it

        const char *name = variants[i].variant ? variants[i].variant : "";
        if (!first_name) {
            first = std::move(cross);
            first_name = name;
        } else if (same_kernels(first_name, first, name, cross)) {
            std::printf("ok   kernel '%s' and '%s' agree on all %u candidate(s) "
                        "in %u nonces\n", first_name, name,
                        static_cast<unsigned>(first.size()), kCrossNonces);
        } else {
            ok = false;
        }
    }
    return ok;
}

void usage(const char *program)
{
    std::printf("usage: %s [algo] [repetitions] [queue-depth] [--device-dag]\n",
                program);
}

// KawPoW's table, and the choice between the two of them.
//
// The default is a short one the host builds and uploads, as the other KawPoW
// device tests use: the registry's algorithm generates a gigabyte on the device
// under test, which is seconds on a GPU and out of reach on the software
// rasterizer some machines here have nothing but.
//
// It is not the same experiment. Sixteen invocations cooperating on one nonce
// is unchanged -- the lane exchanges, the workgroup array and the loop are what
// they always were -- but two megabytes of table stays in cache, so a race that
// needs the latency of a real DRAM read to open a window will not open one.
// --device-dag is that experiment, and it is worth running by hand on a card
// that can build the table before a memory-path change is believed.
constexpr uint64_t kKawpowLines = 8192;
constexpr uint32_t kKawpowEpoch = 0;   // the header below states height 0

}  // namespace

int main(int argc, char *argv[])
{
    pthread_mutex_init(&applog_lock, nullptr);

    bool device_dag = false;
    std::vector<const char *> positional;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--device-dag") == 0)
            device_dag = true;
        else
            positional.push_back(argv[i]);
    }

    const char *name = !positional.empty() ? positional[0] : "sha256d";
    int repetitions = 8;
    if (positional.size() > 1) {
        const long n = std::strtol(positional[1], nullptr, 0);
        if (n < 2) {
            // One repetition compares nothing. Refused rather than accepted as
            // a fast run, because a test that cannot fail is worse than one
            // that is not run.
            usage(argv[0]);
            return 2;
        }
        repetitions = static_cast<int>(n);
    }

    if (positional.size() > 2) {
        const long n = std::strtol(positional[2], nullptr, 0);
        if (n < 1 || n > 16) {
            usage(argv[0]);
            return 2;
        }
        opt_queue_depth = static_cast<int>(n);
    }

    const bool kawpow = std::strcmp(name, "kawpow") == 0;
    std::unique_ptr<vkminer::Algorithm> algo =
        kawpow && !device_dag
            ? vkminer::make_progpow_host_dag(vkminer::kawpow::kKawpow, kKawpowEpoch, kKawpowLines)
            : vkminer::create_algorithm(name);
    if (!algo) {
        std::printf("FAIL no algorithm called '%s'\n", name);
        return 1;
    }
    if (kawpow)
        std::printf("%s: against %s\n", name,
                    device_dag ? "the whole of the epoch's DAG, generated on "
                                 "the device"
                               : "a short host-built table -- see --device-dag");

    // Deliberately without the validation layers, which diff_test runs under.
    // They serialize a good deal of what a driver would otherwise overlap, and
    // this is the one test whose subject is what happens when work overlaps.
    std::unique_ptr<vkminer::ComputeBackend> backend =
        vkminer::make_vulkan_backend();
    if (!backend || !backend->init()) {
        std::printf("SKIP no Vulkan device available\n");
        return 77;  // ctest's convention for a test that could not run
    }

    std::printf("%s: the same full-size dispatch %d times per device\n", name,
                repetitions);

    for (const vkminer::DeviceInfo &info : backend->devices())
        run_device(*backend, info, *algo, repetitions);

    if (failures)
        std::printf("\n%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
