// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the other stratum. Its sibling, stratum_header_kat,
// covers the dialect every algorithm here but one speaks: a coinbase in two
// halves, a merkle branch, and eighty bytes for the miner to assemble. This
// covers the dialect where none of that exists -- the pool sends the hash of a
// header it built itself, plus the block height, and the miner's whole
// contribution is a 64-bit nonce whose top two bytes the pool keeps.
//
// Nothing here needs a device, and that is the point: everything the miner can
// get wrong about a KawPoW pool is on this side of the first dispatch. A wrong
// nonce prefix, a target read at the wrong end, a height dropped on the floor,
// or the mix hash left out of the submit are each a session of rejected shares
// with a perfectly correct kernel underneath.
//
// The vector is ProgPoW 0.9.4's published block 99, wrapped in the notify a
// pool would have sent for it. That is what makes this more than a round trip
// through the miner's own code: the header this job assembles into has to hash
// to a number the algorithm's authors published, and the mix hash the submit
// carries has to be theirs as well.
//
// The last check is the one this file exists for. A mining.set_target
// arriving before a job must not change how the job is read. The sibling CUDA
// port took that method as evidence about which dialect the pool spoke and
// rewired its notify parser from inside the handler -- correct against every
// pool that never sends it, and wrong against the ones that do.

#include "algorithms/progpow/progpow.h"
#include "algorithms/registry.h"

extern "C" {
#include "core/miner.h"
}

#include <cstdio>
#include <cstring>
#include <memory>

// The inherited C expects the miner to own these.
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

void fail(const char *what)
{
    std::printf("FAIL: %s\n", what);
    failures++;
}

// ProgPoW 0.9.4's own block 99: the header hash a pool would send, the nonce it
// was solved with, and the mix and final hashes the fork publishes for that
// pair. Verbatim from the same table tests/progpow_kat.cpp reads.
const char kHeaderHash[] =
    "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d";
const char kMixHash[] =
    "fa706860e5e0e830d5d1d7157e5bea7f5f8a350c7c8612ac1d1fcf2974d64244";
const char kFinalHash[] =
    "aa85340690f2e907054324a5021937910e15edfd1ef1577231843e7d32ec3a61";

constexpr uint64_t kNonce = UINT64_C(0x3917afab);
constexpr int kHeight = 99;

// Epoch 0's seed hash is thirty-two zero bytes. The miner does not use it --
// the height already says which epoch this is -- but it is a field of the
// notify and a parser that mistook it for the header hash would mine a job of
// zeros without complaining.
const char kSeedHash[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

// What a pool pushes with mining.set_target: a whole 256-bit share target,
// most significant byte first.
const char kStandingTarget[] =
    "000000ffff000000000000000000000000000000000000000000000000000000";

// And a tighter one carried by the job itself, which is how most ProgPoW pools
// state a share target. A job that names one must be mined at that and not at
// whatever was standing.
const char kJobTarget[] =
    "0000003fff000000000000000000000000000000000000000000000000000000";

void print_bytes(const char *label, const unsigned char *bytes, size_t n)
{
    std::printf("  %-9s ", label);
    for (size_t i = 0; i < n; i++)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}

// A 64-character big-endian hex string in work->target's layout: most
// significant word last. The same conversion stratum.c makes, written again
// here so that the test does not check the parser against itself.
void target_words(const char *hex, uint32_t out[8])
{
    unsigned char raw[32];
    hex2bin(raw, hex, 32);
    for (int i = 0; i < 8; i++)
        out[7 - i] = be32dec(raw + i * 4);
}

// One line as it arrives from the socket. Returns what the handler made of it,
// because half these cases are about a line being refused.
bool feed(struct stratum_ctx *sctx, const char *line)
{
    return stratum_handle_method(sctx, line);
}

char *target_line(char *buf, size_t n, const char *target)
{
    std::snprintf(buf, n,
                  "{\"id\":null,\"method\":\"mining.set_target\","
                  "\"params\":[\"%s\"]}", target);
    return buf;
}

char *notify_line(char *buf, size_t n, const char *job_id, const char *target)
{
    std::snprintf(buf, n,
                  "{\"id\":null,\"method\":\"mining.notify\",\"params\":"
                  "[\"%s\",\"%s\",\"%s\",\"%s\",true,%d,\"1d00ffff\"]}",
                  job_id, kHeaderHash, kSeedHash, target, kHeight);
    return buf;
}

}  // namespace

int main()
{
    pthread_mutex_init(&applog_lock, nullptr);
    pthread_mutex_init(&stats_lock, nullptr);
    have_stratum = true;

    std::unique_ptr<vkminer::Algorithm> algo =
        vkminer::create_algorithm("kawpow");
    if (!algo) {
        std::printf("FAIL: the registry has no 'kawpow'\n");
        return 1;
    }

    // Exactly what main.cpp does with the algorithm before the first packet.
    // Taking these from the algorithm rather than stating them is the whole
    // mechanism under test: the dialect is decided by what is being mined, not
    // by what turns up on the wire.
    if (algo->stratum_dialect() != vkminer::StratumDialect::kProgPow)
        fail("kawpow does not ask for the ProgPoW stratum");
    opt_stratum_dialect = STRATUM_PROGPOW;
    opt_nonce_bits = algo->nonce_bits();

    if (opt_nonce_bits != 48)
        fail("kawpow no longer leaves a two-byte nonce prefix to the pool");

    struct stratum_ctx sctx;
    std::memset(&sctx, 0, sizeof sctx);
    pthread_mutex_init(&sctx.work_lock, nullptr);

    char line[512];

    // ------------------------------------------------ the nonce prefix
    //
    // Two bytes, which is what 48 bits of nonce leaves room for. The reply to
    // mining.subscribe carries the same string in the same shape, and this is
    // the one that can be delivered without a socket.
    if (!feed(&sctx, "{\"id\":null,\"method\":\"mining.set_extranonce\","
                     "\"params\":[\"8007\"]}"))
        fail("the pool's two-byte nonce prefix was refused");

    if (sctx.xnonce1_size != 2 || !sctx.xnonce1 ||
        sctx.xnonce1[0] != 0x80 || sctx.xnonce1[1] != 0x07)
        fail("the nonce prefix did not arrive as the two bytes the pool sent");

    // There is no coinbase in this dialect, so there is nothing to roll. Every
    // reader of this field takes zero as "the pool gave the miner none", and
    // the worker's extranonce2 path is switched off by exactly this.
    if (sctx.xnonce2_size != 0)
        fail("a ProgPoW subscription left the miner an extranonce2 to roll");

    // A pool that keeps some other width would have this miner submitting
    // nonces outside its own prefix -- every share rejected, and no other
    // symptom. It is refused rather than accommodated, and the refusal must
    // not damage what was already agreed.
    if (feed(&sctx, "{\"id\":null,\"method\":\"mining.set_extranonce\","
                    "\"params\":[\"8007e1bb\"]}"))
        fail("a four-byte nonce prefix was accepted against a 48-bit nonce");
    if (sctx.xnonce1_size != 2 || sctx.xnonce1[0] != 0x80)
        fail("the refused prefix overwrote the one the miner was mining with");

    // ------------------------------------------------ target, then job
    //
    // In that order deliberately. This is the sequence the sibling port got
    // wrong: the set_target arrives first, and the notify after it has to be
    // read as the dialect the algorithm named and not as the one the method
    // suggested.
    if (!feed(&sctx, target_line(line, sizeof line, kStandingTarget)))
        fail("mining.set_target was refused");

    uint32_t standing[8];
    target_words(kStandingTarget, standing);
    if (!sctx.have_next_target ||
        std::memcmp(sctx.next_target, standing, sizeof standing) != 0)
        fail("the standing target was not kept as the pool stated it");

    // A job that states no target of its own falls back to the standing one.
    // That is a legitimate way for a pool to run, and it is the only thing
    // set_target is for here.
    if (!feed(&sctx, notify_line(line, sizeof line, "bf0", "")))
        fail("a job with no target of its own was refused after a set_target");

    struct work work;
    std::memset(&work, 0, sizeof work);
    progpow_gen_work(&sctx, &work);

    unsigned char header[32];
    hex2bin(header, kHeaderHash, 32);
    for (int i = 0; i < 8; i++)
        if (work.data[i] != be32dec(header + i * 4))
            fail("the header hash did not reach the work in one piece");

    // The only channel through which the epoch and the period reach the
    // algorithm. A job whose height was dropped mines the wrong dataset with
    // the wrong program and cannot be told from a broken kernel.
    if (work.data[8] != static_cast<uint32_t>(kHeight))
        fail("the block height did not reach the work");

    if (std::memcmp(work.target, standing, sizeof standing) != 0)
        fail("the job did not fall back to the standing target");

    // The pool's two bytes at the top of the 64-bit nonce, and the other 48
    // bits left for the workers to divide.
    if (work.nonce_base != UINT64_C(0x8007000000000000))
        fail("the pool's prefix did not land at the top of the nonce");

    // ------------------------------------------------ the job's own target
    if (!feed(&sctx, notify_line(line, sizeof line, "bf1", kJobTarget)))
        fail("a job stating its own target was refused");

    struct work job_work;
    std::memset(&job_work, 0, sizeof job_work);
    progpow_gen_work(&sctx, &job_work);

    uint32_t stated[8];
    target_words(kJobTarget, stated);
    if (std::memcmp(job_work.target, stated, sizeof stated) != 0)
        fail("a job's own target lost to the one set before it");

    // ------------------------------------------------ the published hash
    //
    // What ties all of the above to something outside this tree. The words the
    // notify assembled are the words the algorithm hashes, and at the vector's
    // nonce they have to produce the vector's hash.
    unsigned char digest[32];
    hex2bin(digest, kFinalHash, 32);
    for (int i = 0; i < 16; i++) {   // the byte reversal hash() writes it in
        const unsigned char t = digest[i];
        digest[i] = digest[31 - i];
        digest[31 - i] = t;
    }

    uint32_t got[8];
    algo->hash(job_work.data, kNonce, got);
    if (std::memcmp(got, digest, sizeof digest) != 0) {
        fail("the job this notify assembled does not hash to the published "
             "answer for it");
        print_bytes("expected", digest, 32);
        print_bytes("got", reinterpret_cast<const unsigned char *>(got), 32);
    }

    // The other half of a ProgPoW share, and the half a Bitcoin-dialect miner
    // has no field for. The pool re-checks the share from the header, the nonce
    // and these 32 bytes in one keccak; a wrong mix is a rejected share whose
    // digest was perfectly correct.
    unsigned char mix[32];
    unsigned char want_mix[32];
    hex2bin(want_mix, kMixHash, 32);
    if (!algo->submit_mix(job_work.data, kNonce, mix))
        fail("the algorithm would not produce a mix hash for the share");
    else if (std::memcmp(mix, want_mix, sizeof want_mix) != 0) {
        fail("the mix hash is not the published one");
        print_bytes("expected", want_mix, 32);
        print_bytes("got", mix, 32);
    }

    // ------------------------------------------------ the seed hash
    //
    // The one notify field no algorithm reads. What it is worth is that the
    // pool has stated which epoch it thinks this height is in, so a miner whose
    // epoch length differs can find that out from the job instead of from a
    // session of rejected shares. main.cpp installs the check; here it is
    // installed the same way and asked about the same job twice, under two
    // forks whose epochs are 7500 and 1300 blocks long.
    unsigned char zeros[32];
    std::memset(zeros, 0, sizeof zeros);
    if (std::memcmp(sctx.job.seed_hash, zeros, sizeof zeros) != 0)
        fail("epoch 0's seed hash did not reach the job as the pool sent it");

    char kawpow_name[] = "kawpow";
    char firopow_name[] = "firopow";
    opt_algo = kawpow_name;
    progpow_seed_hash_agrees = progpow_seed_hash_check;

    if (!progpow_seed_hash_agrees(kHeight, sctx.job.seed_hash))
        fail("the pool's seed hash for epoch 0 was read as some other epoch");

    // Block 1300 is still epoch 0 for one of these forks and epoch 1 for the
    // other, which is the disagreement this exists to catch -- and the reason
    // it is not enough to check that the seed parses.
    if (!progpow_seed_hash_agrees(1300, sctx.job.seed_hash))
        fail("kawpow's epoch 0 no longer reaches block 1300");
    opt_algo = firopow_name;
    if (progpow_seed_hash_agrees(1300, sctx.job.seed_hash))
        fail("a fork with 1300-block epochs agreed to epoch 0's seed hash at "
             "block 1300");
    opt_algo = kawpow_name;

    // ------------------------------------------------ the submit
    //
    // The nonce is the whole 64 bits, big-endian, and its first four hex digits
    // are the pool's prefix -- which is the first thing a pool checks and the
    // cheapest thing to get wrong. This vector's nonce belongs to the prefix
    // 0000, so that is the subscription it is submitted under.
    if (!feed(&sctx, "{\"id\":null,\"method\":\"mining.set_extranonce\","
                     "\"params\":[\"0000\"]}"))
        fail("a zero nonce prefix was refused");

    std::memset(&job_work, 0, sizeof job_work);
    progpow_gen_work(&sctx, &job_work);
    if (job_work.nonce_base != 0)
        fail("a zero prefix did not leave the whole nonce to the miner");

    char job_id[] = "bf1";
    job_work.job_id = job_id;
    job_work.nonce = job_work.nonce_base | kNonce;
    job_work.submit_id = 7;
    std::memcpy(job_work.mixhash, mix, sizeof mix);
    job_work.have_mixhash = true;

    rpc_user = strdup("worker.rig");

    char req[JSON_BUF_LEN];
    progpow_build_stratum_request(req, &job_work);

    char want[JSON_BUF_LEN];
    std::snprintf(want, sizeof want,
                  "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\","
                  " \"0x%016llx\", \"0x%s\", \"0x%s\"], \"id\":%u}",
                  rpc_user, job_id, (unsigned long long)job_work.nonce,
                  kHeaderHash, kMixHash, job_work.submit_id);

    if (std::strcmp(req, want) != 0) {
        fail("the submit is not the five fields a ProgPoW pool reads");
        std::printf("  expected %s\n", want);
        std::printf("  got      %s\n", req);
    }

    job_work.job_id = nullptr;

    // ------------------------------------------------ the gate
    //
    // A set_target does not decide a dialect. Read as one, the miner would take
    // the seven parameters below as a Bitcoin job and mine a header built from
    // a header hash and a seed hash -- which is why this asserts the notify is
    // *refused* rather than merely parsed differently. The job the miner is
    // already on must survive it untouched.
    opt_stratum_dialect = STRATUM_BITCOIN;

    if (!feed(&sctx, target_line(line, sizeof line, kStandingTarget)))
        fail("mining.set_target was refused in the Bitcoin dialect");

    if (feed(&sctx, notify_line(line, sizeof line, "bf2", kJobTarget)))
        fail("a set_target rewired the notify parser");
    if (!sctx.job.job_id || std::strcmp(sctx.job.job_id, "bf1") != 0)
        fail("the refused job replaced the one the miner was mining");

    opt_stratum_dialect = STRATUM_PROGPOW;
    if (!feed(&sctx, notify_line(line, sizeof line, "bf2", kJobTarget)))
        fail("the same job was refused with the dialect the algorithm names");

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    std::printf("stratum: a ProgPoW notify becomes a job that hashes to its "
                "published answer, submits as five fields, and is read the "
                "same way whether or not a set_target came first\n");
    return 0;
}
