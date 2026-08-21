// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for the ProgPoW host reference, on the host alone.
//
// The only test in the KawPoW family that needs no GPU: the vendored CPU
// reference against the fork's own published vectors. Every ProgPoW kernel is
// differentially tested against that reference, so a misunderstanding here
// would be inherited by the test meant to catch it.
//
// The code under test is not first-party, which makes this more necessary
// rather than less: what it establishes is that the copy in this tree, built by
// this toolchain, computes what the network agrees with. The failure would
// otherwise surface as a shader that disagrees with its own reference.
//
// Three things are checked, and they fail in different directions:
//
//   - the thirteen official hashes, mix and final. A wrong ProgPoW.
//   - the dataset sizes against the published table. A right ProgPoW over the
//     wrong amount of memory -- which the vectors above would also catch, but
//     only for the five epochs they happen to cover.
//   - the constants that make this KawPoW rather than Ethash's ProgPoW, chiefly
//     the 7500-block epoch: cheap to state, expensive to discover from a wrong
//     hash.

#include <ethash/ethash.hpp>
#include <ethash/progpow.hpp>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

int failures = 0;

// The sibling tests here spell this `format(printf, ...)` and cast their
// arguments down to `unsigned` to stay inside what mingw's printf checker
// accepts. That is not available to this one: a dataset size is 274 GB at the
// end of the published table, so it has to be printed as a 64-bit number and
// the format string has to be checked against the printf that will read it.
// mingw names that one, and everywhere else it is the only one there is.
#if defined(__MINGW_PRINTF_FORMAT)
#define KAT_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#elif defined(__GNUC__)
#define KAT_PRINTF_FORMAT printf
#endif

void fail(const char *fmt, ...)
#if defined(KAT_PRINTF_FORMAT)
    __attribute__((format(KAT_PRINTF_FORMAT, 1, 2)))
#endif
    ;

void fail(const char *fmt, ...)
{
    va_list ap;

    std::printf("FAIL: ");
    va_start(ap, fmt);
    std::vprintf(fmt, ap);
    va_end(ap);
    std::printf("\n");
    failures++;
}

// One published case. Verbatim from cpp-kawpow's
// test/unittests/progpow_test_vectors.hpp, which is where the network's own
// implementations take them from; the block numbers put them in epochs 0, 3, 4,
// 7 and 22, so five different light caches are exercised rather than one.
struct Vector {
    int block;
    const char *header_hash;
    const char *nonce;
    const char *mix_hash;
    const char *final_hash;
};

const Vector kVectors[] = {
    {0, "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000",
     "6e97b47b134fda0c7888802988e1a373affeb28bcd813b6e9a0fc669c935d03a",
     "e601a7257a70dc48fccc97a7330d704d776047623b92883d77111fb36870f3d1"},
    {49, "63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b",
     "0000000007073c07",
     "d36f7e815ee09e74eceb9c96993a3d681edf2bf0921fc7bb710364042db99777",
     "e7ced124598fd2500a55ad9f9f48e3569327fe50493c77a4ac9799b96efb9463"},
    {50, "9e7248f20914913a73d80a70174c331b1d34f260535ac3631d770e656b5dd922",
     "00000000076e482e",
     "d6dc634ae837e2785b347648ea515e25e5d8821ae0b95e1c2a9c2d497e0dcfbd",
     "ab0ad7ef8d8ee317dd12d10310aceed7321d34fb263791c2de5776a6658d177e"},
    {99, "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d",
     "000000003917afab",
     "fa706860e5e0e830d5d1d7157e5bea7f5f8a350c7c8612ac1d1fcf2974d64244",
     "aa85340690f2e907054324a5021937910e15edfd1ef1577231843e7d32ec3a61"},
    {29950, "ac7b55e801511b77e11d52e9599206101550144525b5679f2dab19386f23dcce",
     "005d409dbc23a62a",
     "5359807b77a74878269c3a3044df8618a576ce8dc52e1c48d927d4a60e7c6b79",
     "022019e5408683f7f8326b4e46b42864a3a069f17b6151e434fcaedecaadd918"},
    {29999, "e43d7e0bdc8a4a3f6e291a5ed790b9fa1a0948a2b9e33c844888690847de19f5",
     "005db5fa4c2a3d03",
     "d15de3f9bfedd9b6d0f498273eb3b437115bdc8326c96c6457ac06deb5c9f389",
     "4e93630b81198752f876b24380999189b7b9366c08222ac05e4237b87114f305"},
    {30000, "d34519f72c97cae8892c277776259db3320820cb5279a299d0ef1e155e5c6454",
     "005db8607994ff30",
     "de0348b69bf91dfe2c3d3dba6f0132e9048a5284e57b8d9d20adc5f3dc0d3236",
     "c7953d848cda6e304f77b4c6d735645c8e8508a5e74c9e9814ef37b19087cd6c"},
    {30049, "8b6ce5da0b06d18db7bd8492d9e5717f8b53e7e098d9fef7886d58a6e913ef64",
     "005e2e215a8ca2e7",
     "975c6a9decc89cba7ace69338d4de8510d9619aef42b1d35d0bef7e0ce0614a9",
     "c262d8055e288d04b951a844bfca8ba529f5b4d652b408e3942727d7dd90957a"},
    {30050, "c2c46173481b9ced61123d2e293b42ede5a1b323210eb2a684df0874ffe09047",
     "005e30899481055e",
     "362f2fabdb9699d3634b6499703f939f378ee4eac803396c2b0ed0fe1d154972",
     "4cd7e6e79e0b63d42b2b06716a919ccc7834077ec727a9ea94edcdaff2fefab8"},
    {30099, "ea42197eb2ba79c63cb5e655b8b1f612c5f08aae1a49ff236795a3516d87bc71",
     "005ea6aef136f88b",
     "b1196457261bd05ccb387a8ff3fd02687bf496bd7943d89419465289669e27aa",
     "39d1ebfa783b61a6fa8e9747d0f9f134efae5cfba284a2c80e8deabae6b98676"},
    {59950, "49e15ba4bf501ce8fe8876101c808e24c69a859be15de554bf85dbc095491bd6",
     "02ebe0503bd7b1da",
     "df3dbb1669fd35dbb0ae96bbea2d498f0c6992cbddd092aeace42dd933505f95",
     "b8984cf4021c4433f753654848d721f33a0792b4417241f0cf7c7c2db011a54a"},
    {59999, "f5c50ba5c0d6210ddb16250ec3efda178de857b2b1703d8d5403bd0f848e19cf",
     "02edb6275bd221e3",
     "5017df70e97ca35638cf439cdbe54f30383d335e18eb4a74d6e166736f1038fa",
     "4cf1fa62f25b577ac822a6a28d55f8b7e3ae7fe983abd868ae00927e68c41016"},
    {170915, "5b3e8dfa1aafd3924a51f33e2d672d8dae32fa528d8b1d378d6e4db0ec5d665d",
     "0000000044975727",
     "efb29147484c434f1cc59629da90fd0343e3b047407ecd36e9ad973bd51bbac5",
     "e7e6bb3b2f9acd3864bc86f72f87237eaf475633ef650c726ac80eb0adf116b6"},
};

// Epoch sizes, from the published data-size table the Ethash family has always
// been specified against (ethereum/wiki, Ethash#data-sizes) by way of the same
// table in cpp-kawpow's own tests. The epochs are a spread rather than a run:
// each is an independent product of the prime search that picks the item
// counts, and an off-by-one in that search shows up at some epochs and not at
// others.
//
// 350 and 412 are here for a reason particular to this project: a dataset
// crosses 4 GiB between them, and this backend's storage bindings do not. Every
// epoch a real chain is at today needs the dataset split across several of them.
struct EpochSize {
    int epoch;
    uint64_t light_cache;
    uint64_t full_dataset;
};

const EpochSize kEpochSizes[] = {
    {0, 16776896, 1073739904},
    {14, 18611392, 1191180416},
    {56, 24116672, 1543503488},
    {158, 37486528, 2399139968},
    {272, 52427968, 3355440512},
    {350, 62651584, 4009751168},
    {412, 70778816, 4529846144},
    {530, 86244416, 5519703424},
    {1093, 160038464, 10242489472},
    {2047, 285081536, 18245220736},
    {32639, 4294836032, 274869514624},
};

// Strict, because every hex string in this file is a transcribed constant: a
// vector with a digit dropped would otherwise become a shorter number and fail
// as a wrong hash rather than as a wrong vector.
bool parse_hash(const char *hex, ethash::hash256 *out)
{
    if (std::strlen(hex) != 64)
        return false;

    for (int i = 0; i < 32; i++) {
        unsigned byte = 0;
        for (int half = 0; half < 2; half++) {
            const char c = hex[i * 2 + half];
            unsigned digit;
            if (c >= '0' && c <= '9')
                digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = static_cast<unsigned>(c - 'a') + 10;
            else
                return false;
            byte = byte * 16 + digit;
        }
        out->bytes[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

bool parse_nonce(const char *hex, uint64_t *out)
{
    if (std::strlen(hex) != 16)
        return false;

    uint64_t value = 0;
    for (int i = 0; i < 16; i++) {
        const char c = hex[i];
        if (c >= '0' && c <= '9')
            value = value * 16 + static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            value = value * 16 + static_cast<uint64_t>(c - 'a') + 10;
        else
            return false;
    }
    *out = value;
    return true;
}

std::string to_hex(const ethash::hash256 &hash)
{
    char text[65];
    for (int i = 0; i < 32; i++)
        std::snprintf(text + i * 2, 3, "%02x", hash.bytes[i]);
    return std::string(text, 64);
}

// The light cache for one epoch, kept across the vectors that share it. Building
// it is the slow part -- tens of MiB of keccak -- and the vectors are in block
// order, so one context serves every case in its epoch.
class EpochCache {
public:
    const ethash::epoch_context *get(int epoch)
    {
        if (epoch != epoch_ || !context_) {
            context_ = ethash::create_epoch_context(epoch);
            epoch_ = epoch;
        }
        return context_.get();
    }

private:
    int epoch_ = -1;
    ethash::epoch_context_ptr context_{nullptr, nullptr};
};

// One published case: both halves of the answer, because a miner submits both.
// The final hash is what the share is judged by and the mix hash is what the
// pool re-verifies it with, so a kernel right about one and wrong about the
// other produces rejected shares and no local evidence at all.
void check_vector(EpochCache &cache, const Vector &vector)
{
    ethash::hash256 header;
    ethash::hash256 unused;
    uint64_t nonce = 0;
    // The two expected hashes are parsed and then not used: the comparison
    // below is on hex text, and this is what says a transcribed constant is 64
    // hex digits rather than 63. Without it a dropped digit fails as a wrong
    // hash, which sends the reader to the algorithm instead of to the vector.
    if (!parse_hash(vector.header_hash, &header) ||
        !parse_hash(vector.mix_hash, &unused) ||
        !parse_hash(vector.final_hash, &unused) ||
        !parse_nonce(vector.nonce, &nonce)) {
        fail("block %d: the vector itself does not parse", vector.block);
        return;
    }

    const ethash::epoch_context *context =
        cache.get(ethash::get_epoch_number(vector.block));
    if (!context) {
        fail("block %d: no epoch context -- out of memory?", vector.block);
        return;
    }

    const ethash::result got =
        progpow::hash(*context, vector.block, header, nonce);

    const std::string mix = to_hex(got.mix_hash);
    const std::string final_hash = to_hex(got.final_hash);

    if (mix != vector.mix_hash) {
        fail("block %d: mix hash", vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.mix_hash,
                    mix.c_str());
    }
    if (final_hash != vector.final_hash) {
        fail("block %d: final hash", vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.final_hash,
                    final_hash.c_str());
    }
}

// A hash that cannot be made to fail is not a test. Two perturbations, one per
// input the hash has: a bit of the header, and the nonce. Each must move the
// answer -- a reference that ignored either would reproduce every vector above
// for the wrong reason, and no vector can show it.
void check_negative(EpochCache &cache)
{
    const Vector &vector = kVectors[0];

    ethash::hash256 header;
    uint64_t nonce = 0;
    if (!parse_hash(vector.header_hash, &header) ||
        !parse_nonce(vector.nonce, &nonce)) {
        fail("the negative test's own vector does not parse");
        return;
    }

    const ethash::epoch_context *context =
        cache.get(ethash::get_epoch_number(vector.block));
    if (!context)
        return;   // check_vector has already said so

    ethash::hash256 flipped = header;
    flipped.bytes[0] ^= 0x01;
    const ethash::result moved =
        progpow::hash(*context, vector.block, flipped, nonce);
    if (to_hex(moved.final_hash) == vector.final_hash)
        fail("one bit of the header changed nothing -- the reference does not "
             "read the header, and every vector above passed vacuously");

    const ethash::result next =
        progpow::hash(*context, vector.block, header, nonce + 1);
    if (to_hex(next.final_hash) == vector.final_hash)
        fail("the next nonce hashed to the same digest -- the reference does "
             "not read the nonce");
}

// How much memory an epoch asks for, which decides what hardware can mine this
// at all and how many bindings the dataset needs. Checked separately from the
// hashes because the vectors reach five epochs and this reaches the sizes a
// chain in production actually uses.
void check_sizes()
{
    for (const EpochSize &size : kEpochSizes) {
        const int light_items =
            ethash::calculate_light_cache_num_items(size.epoch);
        const uint64_t light_bytes = ethash::get_light_cache_size(light_items);
        if (light_bytes != size.light_cache)
            fail("epoch %d: light cache is %llu bytes, published as %llu",
                 size.epoch, static_cast<unsigned long long>(light_bytes),
                 static_cast<unsigned long long>(size.light_cache));

        const int full_items =
            ethash::calculate_full_dataset_num_items(size.epoch);
        const uint64_t full_bytes = ethash::get_full_dataset_size(full_items);
        if (full_bytes != size.full_dataset)
            fail("epoch %d: dataset is %llu bytes, published as %llu",
                 size.epoch, static_cast<unsigned long long>(full_bytes),
                 static_cast<unsigned long long>(size.full_dataset));
    }
}

// The parameters, stated rather than discovered. Every one of them is a number
// a device kernel will have to agree with, and each has an Ethash or ProgPoW
// value that differs from KawPoW's -- the epoch length above all, which is 7500
// here and 30000 in the algorithm this forked from. A build that picked up the
// wrong upstream would fail the vectors, but it would fail them as "the hash is
// wrong" rather than as "this is not KawPoW".
void check_constants()
{
    if (ethash::epoch_length != 7500)
        fail("the epoch is %d blocks, and KawPoW's is 7500 -- this is not the "
             "KawPoW fork of ethash", ethash::epoch_length);
    if (ethash::light_cache_item_size != 64)
        fail("light cache items are %d bytes, not 64",
             ethash::light_cache_item_size);
    if (ethash::full_dataset_item_size != 128)
        fail("dataset items are %d bytes, not 128",
             ethash::full_dataset_item_size);
    if (ethash::num_dataset_accesses != 64)
        fail("%d dataset accesses per hash, not 64",
             ethash::num_dataset_accesses);

    if (std::strcmp(progpow::revision, "0.9.4") != 0)
        fail("the ProgPoW revision is %s, and KawPoW is 0.9.4",
             progpow::revision);
    if (progpow::period_length != 3)
        fail("the program changes every %d blocks, not 3",
             progpow::period_length);
    if (progpow::num_lanes != 16)
        fail("%zu lanes per nonce, not 16", progpow::num_lanes);
    if (progpow::num_regs != 32)
        fail("%u registers per lane, not 32", progpow::num_regs);
    if (progpow::l1_cache_size != 16 * 1024)
        fail("the on-chip cache is %zu bytes, not 16 KiB",
             progpow::l1_cache_size);
}

}  // namespace

int main()
{
    check_constants();
    check_sizes();

    EpochCache cache;
    for (const Vector &vector : kVectors)
        check_vector(cache, vector);
    check_negative(cache);

    if (failures) {
        std::printf("\n%d check(s) failed\n", failures);
        return 1;
    }

    const size_t vectors = sizeof kVectors / sizeof kVectors[0];
    const size_t sizes = sizeof kEpochSizes / sizeof kEpochSizes[0];
    std::printf("progpow: %zu official vectors reproduce their mix and final "
                "hash, %zu epochs match the published sizes, and a perturbed "
                "header or nonce changes the answer\n", vectors, sizes);
    return 0;
}
