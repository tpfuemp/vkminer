// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The ProgPoW forks against whatever vectors were published for them, on the
// host.
//
// Of the four, only Firo published any: 55 solved blocks, mix hash and final
// hash, from height 1 to 545,860. Spanning ten epochs and four consecutive
// blocks, they pin the whole of its row -- and check_each_constant_matters()
// argues that from the other side, hashing one vector with each constant
// replaced by another fork's and requiring every answer to differ.
//
// The other three have no such table, so their evidence is the arithmetic
// their own nodes state -- check_evrmore_arithmetic, check_meowcoin_arithmetic
// and check_telestai_arithmetic -- together with shares their pools accepted,
// see check_share.

#include "algorithms/progpow/progpow_dag.h"
#include "algorithms/progpow/progpow_hash.h"
#include "algorithms/progpow/progpow_params.h"
#include "algorithms/progpow/progpow_program.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

namespace pp = vkminer::progpow;

int failures = 0;

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

// ---------------------------------------------------------------- byte order

uint32_t le32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

// ------------------------------------------------------- the dataset it reads

// Four of the setup pass's 64-byte items make one 256-byte line: the kernel
// that generates the DAG counts in items, the kernel that hashes it counts in
// lines, and this is where the two are reconciled.
constexpr uint32_t kItemsPerLine = pp::kLineWords / pp::kItemWords;

// The dataset computed from the light cache an item at a time, which is the
// only way to have epoch 419's anywhere near a host. The miner's own
// dataset_item, deliberately: it is where the seed epoch and the size the DAG
// is taken modulo come apart, and those are two of the constants under test.
class ReferenceLines final : public pp::DagLines {
public:
    explicit ReferenceLines(const pp::Epochs &epochs) : epochs_(epochs) {}

    bool line(uint64_t index, uint32_t out[pp::kLineWords]) const override
    {
        for (uint32_t i = 0; i < kItemsPerLine; i++)
            if (!pp::dataset_item(epochs_, index * kItemsPerLine + i,
                                  out + i * pp::kItemWords))
                return false;
        return true;
    }

private:
    pp::Epochs epochs_;
};

// One block, start to finish, through the interpreter the miner uses. False
// only if the dataset could not be produced, which is a small machine and not a
// wrong answer.
bool hash_block(const pp::Params &fork, uint64_t block,
                const uint8_t header[32], uint64_t nonce, uint8_t mix_out[32],
                uint8_t final_out[32])
{
    const pp::Epochs epochs = pp::epochs_of(fork, block);

    // The 16 KiB the cache operations read is the first 16 KiB of the DAG, so
    // it is the first 256 items and not a separate table.
    uint32_t l1[pp::kL1Words];
    for (uint32_t i = 0; i < pp::kL1Words / pp::kItemWords; i++)
        if (!pp::dataset_item(epochs, i, l1 + i * pp::kItemWords))
            return false;

    uint32_t words[8];
    for (uint32_t i = 0; i < 8; i++)
        words[i] = le32(header + i * 4);

    pp::Program program;
    pp::build_program(fork, pp::period_of(fork, block), &program);

    const ReferenceLines lines(epochs);
    const uint64_t dag_lines = pp::dag_items(epochs.full) / kItemsPerLine;

    pp::Hash out;
    if (!pp::hash(fork, program, l1, dag_lines, lines, words, nonce, &out))
        return false;

    for (uint32_t i = 0; i < 8; i++) {
        put_le32(mix_out + i * 4, out.mix[i]);
        put_le32(final_out + i * 4, out.digest[i]);
    }
    return true;
}

// --------------------------------------------------------------- the vectors

// One published block. Verbatim from firoorg/firo's
// src/crypto/progpow/firopow_test_vectors.hpp; the boundary each case also
// states is dropped, because what is checked here is the hash and not whether
// the block was hard enough.
struct Vector {
    int block;
    const char *header_hash;
    const char *nonce;
    const char *mix_hash;
    const char *final_hash;
};

// In block order, which is also light-cache order: ten epochs, each built once
// and thrown away when the next arrives.
const Vector kFiropow[] = {
    {1, "2d794e900dcad779e658de9078d9a88eee87d75f7b09a8fdd270d3a8e76650c7",
     "85f22c9b3cd2f123",
     "cfab3766331d6c4e6913e6688a71e4c26b7f36c1581cdbec0f5b19db8956eb50",
     "00017c7de1fa499314f9e3dd3537546982073624f7d478592cf28a6d13929f2d"},
    {2, "312d5670db5cb352e232d372df400c050b4966f0f75a358422cd66d49ddac706",
     "85f22c9d3cd3018d",
     "43c12507b86cbf4530217c9d2552b476d02e813d939c0af415f4deb6442c9880",
     "0000b9689069f0b245f795683b3dd8c7ac6db3042aaa7c4f41c9d9aa457ce38f"},
    {3, "e24e712050309ba90ed700b3f398cd86d4b1f1c3512fd4868160e7b46b163b71",
     "85f22c9d3cd3174e",
     "40a97d9bc76f9fafba88d282f37c64f4b83b12a10c884ac44da603e3a1d3c954",
     "0000f005e9038845ec66c43a16dccc231139c7bbe4233b9ff0ac83e23358e039"},
    {4, "f8ae4c2ddaf46743ebac31d9cb9297ce4899770f0571ebe8b054c33df4f12f99",
     "85f22c9a3cd2ecee",
     "5cb1a5886a18720d8c0cd7cc880dec917308d454f01afb3429bdf279a4f119f4",
     "0000342886ef7663e625e7fd448efafaf3407031b99aa3ad99cea817f9731a91"},
    {1299, "e0724517229995bb72bf516a385716627dec523f622c79660a1d27426ca8ad23",
     "dec25421bac291d6",
     "8cff2cf5ae77dff90485a55d1f5a14cc2f0ad0a5dbd129971b8e45a25e01737b",
     "00021f431adcff9f70154985b469758d7fa97fb0adc33d2f58f856fe19817b4a"},
    {1300, "1fc36bd5d1bff8d134e24a997cfa43cbb2a0b956379bdc0c8df444f2553f6b7d",
     "dec25420bac29b01",
     "5f8fe6069efb88d9af861999973b3523295d3b1ec7e8423c965f33b3d12b20b1",
     "000038a1804eb3976346bf84e679884d56122e113c3b4a301f6180a246644262"},
    {1301, "ecbd807e58edaf0fb3ee7c167a7c2728b31cd6a8fd23219afdc5f7be3161c8eb",
     "dec25420bac292d8",
     "30ba0ee0916d403d71cfa78e7fbebca7c31e2e829e977dd18848cb0f22ec5dbf",
     "00018b40127c8e24ef958d9867b543aec015bb8eb10f77844b49b7451c48bb12"},
    {1302, "4cb46ab5c76d0f86e09d71947ec4d403cb95c8f70a335ae2163cfed2ee06bd05",
     "dec2541fbac299b5",
     "01e3ecf528e4f3b40203bfd9651857fa4440b93d5ac5d0c6f7d8d8ccc202014d",
     "00022678ddd120a3454bc894c139badb5933ae76c5b2c4c2dae2d6c54224ffcf"},
    {1303, "0b4410741b34f040065633185af718248093dc66ae9430fbfb69ef023acbf145",
     "dec2541fbac2a4e9",
     "e1e26b162b92599f1c88ef7952b7d265013b7f8e928fe3ff5b051b7c3e6b2a30",
     "0002b72cba06b7f872af443a826d5409f4d7c9b24ae052324dba403e4d4a8bfa"},
    {12999, "0f26f1349755c816aa69090f228f37404c543a717b5d2a060d31000d0ec89140",
     "10d0835770ff398f",
     "d46f166b0ca83df5c1cda3104b496ebe234d55da1bfb0fa8a630b18bdaa6a504",
     "0001146b5363e81238e48541cc49fb3cfc27d833126e7b49ad60d7a2facc9bda"},
    {13000, "794688e6167995f4891124d488365df76becfd2fc47c5c8337c9a545801d8e60",
     "10d0835970ff1254",
     "653b09240717ddc1d251e75cd24b5fb35d7890a08be6e2ac6b97105f0ff5b27d",
     "000131b06b06be7a9bd653065f21e0a2a6e46996849f9f8daa996df35e1a9f0e"},
    {13001, "49aac6ff085524ac8e5f62f3d83cf538b8ba1c1ef985c4836a0db732d82f5501",
     "10d0835970ff0be0",
     "e0a4114afde4f73720f821c033a03783ab4eba3868cd4075fab9c64ccb9961da",
     "0000ea1289598f14ed43f3a9a6bb3aeadf44f4352df307abac2fa7f4b3f9fbe1"},
    {13002, "e6e3cdbbc6998b2b006906f7b13c0638f43c8dcd1b47e4db75df15b19cc06089",
     "10d0835770ff05fa",
     "68f23dd01fba47c9c4ed8e314512bc5108a858ba990fbd5aece5eb50d5593be8",
     "00005d7d46632a52e2a232a1ff2c8af11a4a64933ac923c2610535b70275d16e"},
    {13003, "eba5065ece50fbe0df889b80b5429b1138ddbce0c880fc98fc41db27c16acc52",
     "10d0835a70ff13e7",
     "717f4970843d90af5672bef264b14fda176f5114b71bd2903c0d330d2ea64a5c",
     "00010f49654b470b6568bdce805d13b333f99691b3477b652c5d0c96b31d7fef"},
    {13004, "5f4d66eedfabeecdb0840b3a94f670b0aa1637567628a979677b944d53d66350",
     "10d0835870ff14cc",
     "9c64f92a4a87e2355e05ed307ce3c68ecafa33b78c4a058922a549202a96f832",
     "0001d2e8ea914a696f9cacafd7c6996d0d06b86ff1f00ae97d8947d70bfe5176"},
    {13005, "1a75e51b3c24968ff80af1458872bc2bf7fbd6b7a68663d815299369d1d2b49f",
     "10d0835970ff0928",
     "384428101d1394a2943672077d8edf771e2ddb4b412a97cd4cd3c8497d800285",
     "0000a463b128e65c08cc4c668b8d35d1740ec0ed5a18344305d7fe939d81e4f4"},
    {13006, "7072ca2d6172ae53aed24ec54db19c38f2682b1f3365276237ea1bfb3e2adcfc",
     "10d0835870ff9174",
     "19892a71a2e2de646e80571e287f9a1f2561b7bf30f99052dd9080bc12287a32",
     "0000d79a1627cc9d8d1f55dd93dc03badfebbdda82dc12df073d40ff7cb344b4"},
    {13007, "94c6060f7843dca66edcdd1f752f32c1b9fbf9a523780222ced9748688fba511",
     "10d0835770ff0291",
     "26ff0482fd2d2984cd2a43c3ebf6ed043c5f20df87cabafcce0f880a84674718",
     "000154031e70c22bd074023d9f2d15d9609a172c77c6693acbb5ded8842c5db6"},
    {13008, "f962572c9663cd7986c2560449afa3595d10a290525caf060c65dcef56422659",
     "10d0835870ff4802",
     "ad9bba3d9baa53cf832d25d3afe85c68c3e0baa796c0450e79e17cff8e921cf7",
     "0000e4891befecbff65859f0aef391b70771acc4196afa30c4ca53ce03bf0dd1"},
    {13009, "17a943d97e7a157eed35d0a63a1c72a8d364d95b491706eedd7a22da2adceab4",
     "10d0835a70ff28f5",
     "19263eb69773ba960ed7fddd64e6802101db5e5445ee848e3765cb577fafa13a",
     "00001c83042832b92722b4049c591a17ee2fef150ccbe2c1e256f5c22cb4df2e"},
    {13010, "8c3715e03eb354ccbf9cd846c97e7b88b0f1d11dfa7efb2c8472dc9885b72856",
     "10d0835a70ff0934",
     "0652be5c9c43fd63923cca59dd614e90bbc672c20b493a98c6abbe8ff5f588f8",
     "0000bb57589af1269c7c65c30d957e47417139cc735610ee6a8191ffc9219f15"},
    {13011, "d227eae293a153735775b2cc3622636bdd3aa5da061734bc1659893a7ae35f57",
     "10d0835870ff21f9",
     "6632515805e6416845e8c2b139f2d3b59c0e24acfeec46e154a42b584253f714",
     "00009c64ce1d8970f17495ba376eded9958f5dd29e2460ef67dfc1fc613387f0"},
    {13012, "431b7cc510b0c16040406006f617833caf00191910763470dfd5af0fd2da2607",
     "10d0835970ff09e1",
     "a86156101ca1260fcf4ce609529b871b8eb14035e9bb2b0cd09ac30a53c304c8",
     "00000184b4f8e57b0fb8147e83275d5f12784e137b45e98c5dbca6bdffd2174b"},
    {48650, "b1e6202f07ef291b18497c8210639f246d43299c27d1354bb959430b20cebf12",
     "f63c144f8f7a580c",
     "419d0df63ea7576a3ee8ca2bc226edc193b50caa086aa51b772b59ef805e7cc5",
     "00004a35ac80a9ccca61baed18a7df446b56b4c7816b928d6c530e2212cb426c"},
    {48651, "d1175e6a053cd3f346f3c51c144055c869198f5f52531ab8f93a039fee2dd6fb",
     "f63c14528f7d6a63",
     "ef010595bbd8ed93718a006f33789751a86897a45bbdfc3dd759c7825ae3f4e1",
     "000042e351bf4f2bd4029a124f71495c520f1450ceba60d4e10b6b8df203598c"},
    {48652, "ccef7f9c32178c6cc602472decbf4e7fd94e040170083d5f12021b2b3d71f104",
     "f63c144f8f7a5e25",
     "126f97c6f53f3122e735f7e7bfbadce009c189a4719d3528f58c875af0c4f995",
     "0000208614e2c5f10af77ed5dd4a39eb18d65142bd8494a948691924424d7bcd"},
    {48653, "2c128024a0274ec45f773fa878e0f9efc309ebc4864e63346931fb0a80ec9f1e",
     "f63c14518f7a9067",
     "6d64d93fa9bdd7f3d1a0dd9a18d32293bc665f196017284e4a2fdb7a24e1a2f4",
     "000045e2e42b17acd3b394c3b13e68ac466366d96f3f859fcda479cf038e3aa5"},
    {48654, "e735c300f9475fbb068e10a6a5525af6ed23a9d722b824560376de5f63a57616",
     "f63c14508f7c08ca",
     "db395ee0366eac32d6e9abe6fc4fbcd3a1010263ae0c6a1a3e17a217b22c23d3",
     "000014d06665181b73056cca8426f9c396f7c4e3f5556b17289c0c3079f730ac"},
    {48655, "bf0a109b79b2e989590e7a12acccc4d79016e0d95ed73f15170dfc446917552d",
     "f63c144f8f7a760d",
     "b3285062764170d185f90e79ae315821eb97e556e99761078a07028da478710e",
     "000020d490bc8079daeb3454c0546272382cdc8539e5927b73e3681ee53c0494"},
    {48656, "0033058cb7a6b4b4a31ac1f5755573a542fa121e2aec6b4b8053ffeb5d25d5cf",
     "f63c14518f7cf884",
     "f31c21fa4fa526d8cd61648b75abd7bcad95fbb6abdb552897838a0d699b8aac",
     "0000114f87c0ab69515ddcc536c2800ffb9000d3d6e92a80f1f4528dc97feb62"},
    {48657, "70517a1e542e8706d22b47f7350dd0940edeec87b15cf8f47fd4f39d38946d5f",
     "f63c144f8f7a6b4d",
     "501ffa55559d938660ddff613bb0ecf46f253b45530d3bde7eb4a2fb6cf2d154",
     "0000465f1a28272e53680cfd4c9962ee6cfed960580cf82afb981fa75ab391e6"},
    {48658, "0de3db810d0384a17fbdca43c8153fe56b6253e2d83d167c93a562ab6ed9d552",
     "f63c144f8f7a5219",
     "a41d1e701aa411e56ea8d519be9a49f302ddbcb29969ecf235c751167f0fce22",
     "0000345f4413afee14d84ba3b155f0b39d841cf3c75cd961e06a5dbedab52478"},
    {48659, "15a8044fb91d7e51a71a0e4192b7a348b27d23742343dfa3f26fd3b1fda53309",
     "f63c14528f7a8441",
     "1357cb9ed8339cf39f3293298aa85f9fe6d25b8f0706a74c34d9c25db5253f77",
     "00000f68bb4cad82f2e113ef54278b7601b9553c764e21b5f7121d8656e6d151"},
    {48660, "5053fcbea728d7c4c3ba2e8ddced295aed66a7a79921b6d3740589accf75bcbe",
     "f63c14508f7a8541",
     "6153328c35d1118f48b5ef4e52e9b7ebebe45e03f8a540ac6c15cd1efff66964",
     "00004710ef9f5f7b1ecaec1f75453a8240ca3b5c8af5b379c1417881d9baf890"},
    {48661, "0abf147cc465d649f6a2369f43fc48b40ff8c5c2bbf4d11b7539114169dbbc2c",
     "f63c144f8f7a5152",
     "2984861e2add6efa0fd7fff989eca7d8d636626de0accc467aef4a391d57859b",
     "0000402da9d2e2576c559032944a4631ce45f02710147987072262ddcc95b2b6"},
    {96587, "80b9cd8b67db95fdb900affece4d7d2c14ddec9b901be0d6e42b89fc7819c693",
     "6fec0853f96eb6f3",
     "3a9608a1f415a76a98eb4fbcb2285db14d3e9d411aacb6a89525432b1b228132",
     "00001e5086d2148fec8df3097580efb2672786bca9fe7dba04cd111f21cd42de"},
    {96588, "f6737c8737818d6d69078554279f55576102ca182290d263395eb2b7ca3df5f4",
     "6fec0855f96a97e5",
     "bb6ecae5ae70526d0f35888c11f34cc0095db347e80fe4f2b544efe93aa82db8",
     "000002dc8b7d376e2ab354af218d96cb29c6869098cd22aeefd3ef3fea0489d8"},
    {96589, "15fff750c0be3b1154b84adf42402ccd068c82c3103ea4e72ea100b49e3b51fe",
     "6fec0854f96d1416",
     "542db538572570227f3bdcec56c45788b83da23eeea3cd1edae5ec62df6761cf",
     "00000b981f0a57e10cbd39096fb27341f21dbb568861bca06efdf6619b563b13"},
    {96590, "0231f310fb1a0cfd63f363802ae3f0a90c50b3b879d8cedb243efc1446d0d6b2",
     "6fec0856f969dd81",
     "a91de8ff0849aed667d4e11f610e3fdc4612ea7d8fe6c58e902eaf95c978bf54",
     "000016f6ebb36334946238e06d484b8ed8ff50477729eb28c4c294a9e8218f97"},
    {96591, "c5cf3e468cf1987809c7ec07a0d54abead5e843c35cb1fd9088b35b55f4a1d28",
     "6fec0856f96c094a",
     "37aa1832f41ccb16ca3956148034bcfe6c55fcc41fe835bdca99e1ca41a0bda5",
     "000008bdb0253bbdef6d0c29b8b840ecd955b4f096fcca1f251ba3060b1b1853"},
    {138524, "c3245ec955bd49ce5994a800f6c14db5c17fcc6ccc490f77847bbb7381f4f779",
     "3ddce1e1713d2952",
     "962c9ff57906f6b13e4cbd6d9dd5d0ace43dc69013b49370301cd02a9c90ef11",
     "0000003bcd31ed7c2341af79941419da4475593cd4eadfeb2c7f1392f36fc1f1"},
    {138525, "a4b15a6aa6a61b36b53a4fcba5d0f91deda619a1b639c41e3e796de66d0ece97",
     "3ddce1e471397224",
     "0d92269db895547d47c307219aee739267998c7115c510bb94e50ce75eb6b642",
     "000005ffdbc2df46b9967115692827e5701a0953d8dfb33375a0e2e7665e8c01"},
    {265000, "5a085fb8be7e0f10cbeb45a1deda25abfef270e12a203c7dfb020aac0723fa7c",
     "f3e95657f2470e38",
     "b5500ea9243f46c0ec2a2293dd5c5b49d299395635597597405f3a87225b472f",
     "00010c328e59ca58ad0fa9c7f0d266c3dc6cfa83e77bb44e92eb9aa2f377abb6"},
    {265001, "6071af1007725ee11f28b1f010a1ac0cafbda917947e9737592197f0808290af",
     "f3e95655f247313c",
     "b5a71090dc07218d392a56cbc55c08b9b616d53a0cdc1c166ae1f91ea39c2a6c",
     "0001269e4b345375261bb78a19a513f536a12e5882c1a7d1152cc8c2df7e8011"},
    {265002, "2ebef575a00ff895cbec8774cf670e2514c05ec1eb0609e740a8522813cad487",
     "f3e95657f2472f25",
     "47d8c49c60cd88ea187fcf2eee162b0506606e937a01953f65de54ff4358b2bc",
     "0000b4760f61f4a37e9a9eb01407b5846c3d27a09dc6b5e7bcfd5c1357f040f4"},
    {265003, "91b662e2355d7fd83dc847575aa47e321c852bd4105792a85e76f7e5f44e3c90",
     "f3e95658f2474f6b",
     "94ab3bf6300ae2b2d336f1ec0e6bc482a9736e4740b2bc11bd950be131e7a4fe",
     "00013b8edb98563fa532445437d2f1e25ca7c8cff3fbc28104fe9cfa1567ef5b"},
    {400000, "df8208e69e7c8eac0121fc6a9377ae0790079352714fbffdb3c4ec13f1bfc884",
     "32ec0f0a8878e9c1",
     "65fd5ae460458787790c5c3f07676d9ebde9209625b4069b1f54f8d6ae12c668",
     "0000d009a21a524e53b49b4776a269549e88b86a90afca329b8f2e7ae70e3776"},
    {400001, "b98bcec3991c33a1211d49360cd90c0906652240a56668530bde843e9cfd1703",
     "32ec0f0b88790fbe",
     "c5e943a63ffe8f68eba2b1dcc9fcea7044c5b76c0cd4654ea84ce455f2cd5642",
     "00006e2a6f617b6de63500382092988d292283d42cb437ade47c1f20f11f0998"},
    {400002, "e220a0c62442740ad95b1b941b054226d720543b3dcdbfae99a72c9ebe71709d",
     "32ec0f0a8878ee2e",
     "d497b31427a5ab4f90fea12b46374be01c4fa9a72e8c2e9e39352ee3167f680a",
     "0001601a6d05af98a48453e8320a5aa408fd0a79ad2a6e8d630128406614ca9d"},
    {400003, "1ac721ef41f48e58d1357f9e1ac588eecf59e4620c5cf1e360e888171b7f6f97",
     "32ec0f0988792f53",
     "10184e6c54293704d07d836334c924eb3aee47fd28a2afe68f5cff1e7ee0ece2",
     "00006a95e279f56df10a9aff98dceb141b83615050dcc1de0a7a9a5daa27f5e2"},
    {545856, "4741563174fb16f3abf2ca9b593e7f2cca7d5363cce3cb6b1792a9fc97b6848a",
     "844c83fe15de8d05",
     "a0fee97a41a7bd84a7e2d75a9cac1dd66f0b3ace888f029e2102d14d5f64b09d",
     "0000305bf56700d0c304b91a57b6564eaa7815926fdaf89e5133fa29e4300ab0"},
    {545857, "c09cb3f75345751eb84e35a71712123d7f0c8e2edbb980be29034a1aadda0725",
     "844c83fd15dea41f",
     "46e2dc0f08e4ffbc8cc8a0355676c2e62d9922ec41a3aa27cc1d6948acca543c",
     "00001cac52c8dafcb697b0fa6257b81891242ec0f89910c15d57629ec31b69c8"},
    {545858, "802730918e3776de37b0b03e5f9e1ebd5c7376097e64578a7702a647214432b3",
     "844c83fd15de3317",
     "66d917802bf756031404d6947e4b389db703af51df2b72dc7806e339a0e51961",
     "00001d63aff2cee40464b7ea580cbc44ae2842a961dfd78f4084ab99179beb30"},
    {545859, "c09e4a8e697fb29447a5301b4c716182a267020b131a0f4137c1841e4c6fc8a2",
     "844c83fc15de0838",
     "768f7232065b7d6ae6e2db50b88b8bb8ec5df6dc9dee45ed95850586c60904f3",
     "0000486174a163e26818c06f6069ee8e16ff66dd26f3e3bcf7bf3c964f999590"},
    {545860, "421ecabe666b8a4b3c5d9f899a15115f1fc8e2644468459c9f200d2dd10c204c",
     "844c83fd15ddbc98",
     "19b62e800a00b6ad8208eb53baeebe9d5e96018ccc7df2ebe35cac463984ea4b",
     "0000368b42a54273789090266c5093f660642e728031448cc6b21b1ca7ebcbb7"},
};

// Strict, for the reason its siblings are: a constant transcribed with a digit
// dropped must fail as a bad vector and not as a bad hash.
bool parse_hash(const char *hex, uint8_t out[32])
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
        out[i] = static_cast<uint8_t>(byte);
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

std::string to_hex(const uint8_t hash[32])
{
    char text[65];
    for (int i = 0; i < 32; i++)
        std::snprintf(text + i * 2, 3, "%02x", hash[i]);
    return std::string(text, 64);
}

void check_vector(const pp::Params &fork, const Vector &vector)
{
    uint8_t header[32];
    uint8_t unused[32];
    uint64_t nonce = 0;
    if (!parse_hash(vector.header_hash, header) ||
        !parse_hash(vector.mix_hash, unused) ||
        !parse_hash(vector.final_hash, unused) ||
        !parse_nonce(vector.nonce, &nonce)) {
        fail("%s block %d: the vector itself does not parse", fork.name,
             vector.block);
        return;
    }

    uint8_t mix[32];
    uint8_t final_hash[32];
    if (!hash_block(fork, static_cast<uint64_t>(vector.block), header, nonce,
                    mix, final_hash)) {
        fail("%s block %d: no dataset -- out of memory?", fork.name,
             vector.block);
        return;
    }

    if (to_hex(mix) != vector.mix_hash) {
        fail("%s block %d: mix hash", fork.name, vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.mix_hash,
                    to_hex(mix).c_str());
    }
    if (to_hex(final_hash) != vector.final_hash) {
        fail("%s block %d: final hash", fork.name, vector.block);
        std::printf("  expected  %s\n  got       %s\n", vector.final_hash,
                    to_hex(final_hash).c_str());
    }
}

// ------------------------------------------------ and that they carry weight

// Every entry of the fork's row, one at a time, replaced by another fork's
// value -- and the answer required to move, so that the table above is
// evidence about Firo rather than about ProgPoW.
//
// Block 13000 because it is where all of these separate: epoch 10 at 1300
// blocks and epoch 1 at 7500, period 13000 at one block and 4333 at three.
// Block 1 would agree with itself under half of them.
void check_each_constant_matters()
{
    const Vector *at = nullptr;
    for (const Vector &v : kFiropow)
        if (v.block == 13000)
            at = &v;
    if (!at) {
        fail("the vector this check is written around is gone");
        return;
    }

    uint8_t header[32];
    uint64_t nonce = 0;
    if (!parse_hash(at->header_hash, header) ||
        !parse_nonce(at->nonce, &nonce)) {
        fail("block 13000: the vector itself does not parse");
        return;
    }

    struct Tweak {
        const char *what;
        pp::Params params;
    };

    Tweak tweaks[] = {
        { "epoch_length",  pp::kFiropow },
        { "period_length", pp::kFiropow },
        { "dag_full_off",  pp::kFiropow },
        { "regs",          pp::kFiropow },
        { "cache_ops",     pp::kFiropow },
        { "math_ops",      pp::kFiropow },
        { "the seal",      pp::kFiropow },
    };

    tweaks[0].params.epoch_length  = pp::kKawpow.epoch_length;
    tweaks[1].params.period_length = pp::kKawpow.period_length;
    tweaks[2].params.dag_full_off  = pp::kKawpow.dag_full_off;
    tweaks[3].params.regs          = pp::kMeowpow.regs;
    tweaks[4].params.cache_ops     = pp::kMeowpow.cache_ops;
    tweaks[5].params.math_ops      = pp::kMeowpow.math_ops;
    std::memcpy(tweaks[6].params.seal_seed, pp::kKawpow.seal_seed,
                sizeof tweaks[6].params.seal_seed);
    std::memcpy(tweaks[6].params.seal_final, pp::kKawpow.seal_final,
                sizeof tweaks[6].params.seal_final);

    for (const Tweak &tweak : tweaks) {
        uint8_t mix[32];
        uint8_t final_hash[32];
        if (!hash_block(tweak.params, 13000, header, nonce, mix, final_hash)) {
            fail("block 13000 with %s changed: no dataset", tweak.what);
            continue;
        }
        if (to_hex(final_hash) == at->final_hash)
            fail("block 13000 reproduces with %s taken from another fork, so "
                 "the vectors above do not test it", tweak.what);
    }
}

// ------------------------------------------------ Evrmore, which published none
//
// The file Evrmore's node ships as a vector table holds the vectors it
// inherited, which its own seal cannot reproduce. What it does state is two
// sizes: an epoch of 12000 blocks, and a dataset starting at three gigabytes
// rather than one. The second is what dag_full_off = 256 is for, an epoch
// being 8 MiB. Both checked as sizes, because those are Evrmore's numbers and
// the offset is only this implementation's way of reaching them.
void check_evrmore_arithmetic()
{
    constexpr uint64_t kGiB = UINT64_C(1) << 30;

    // The epoch boundary, from both sides.
    if (pp::epochs_of(pp::kEvrprogpow, 11999).seed != 0 ||
        pp::epochs_of(pp::kEvrprogpow, 12000).seed != 1 ||
        pp::epochs_of(pp::kEvrprogpow, 24000).seed != 2)
        fail("evrprogpow: an epoch is not 12000 blocks long");

    // And that the offset moved the dataset without moving the seed. A fork
    // that offset both would build a correctly sized table out of the wrong
    // epoch's bytes, which has no symptom short of a rejected share.
    const pp::Epochs at12000 = pp::epochs_of(pp::kEvrprogpow, 12000);
    if (at12000.light != 1 || at12000.full != 257)
        fail("evrprogpow: the dataset and the seed did not come apart by 256 "
             "epochs exactly");

    // Evrmore's full_dataset_init_size, from the outside: the largest prime
    // number of items that fits, so just under the round number and never over.
    const uint64_t evr = pp::dag_bytes(pp::epochs_of(pp::kEvrprogpow, 0).full);
    if (evr > 3 * kGiB || evr < 3 * kGiB - (1 << 20))
        fail("evrprogpow: epoch 0's dataset is %llu bytes, which is not the "
             "three gigabytes Evrmore starts at",
             static_cast<unsigned long long>(evr));

    // The same measurement on the fork that did not move it, so that the one
    // above is a statement about Evrmore rather than about this arithmetic.
    const uint64_t rvn = pp::dag_bytes(pp::epochs_of(pp::kKawpow, 0).full);
    if (rvn > kGiB || rvn < kGiB - (1 << 20))
        fail("kawpow: epoch 0's dataset is %llu bytes, which is not the one "
             "gigabyte ProgPoW starts at",
             static_cast<unsigned long long>(rvn));
}

// ----------------------------------------- Meowcoin, which published none either
//
// Meowcoin left the epoch at 7500 blocks and scaled the dataset instead: from
// epoch 110 its node sizes both the light cache and the DAG at four times the
// epoch, to put the table past four gigabytes, while going on seeding the cache
// from the real epoch. That is the one place in this family where the size and
// the seed come apart, and getting it wrong builds a cache of exactly the right
// length out of another epoch's bytes -- no size out of place, every item
// derived from it wrong.
//
// So the seed is checked as well as the sizes. It cannot be read back out of a
// cache, since ethash mixes every item three times over the whole array, but it
// can be checked from the two sides that are available: a cache built the other
// way has to differ from this one, and the seed hash a pool sends with a job is
// somebody else's statement of which epoch seeds it.
void check_meowcoin_arithmetic()
{
    constexpr uint64_t kGiB = UINT64_C(1) << 30;

    // The block where the multiplier turns on, from both sides -- which also
    // pins the epoch at 7500 blocks, since that is what puts it here.
    const pp::Epochs before = pp::epochs_of(pp::kMeowpow, 110 * 7500 - 1);
    const pp::Epochs after  = pp::epochs_of(pp::kMeowpow, 110 * 7500);
    if (before.seed != 109 || before.light != 109 || before.full != 109)
        fail("meowpow: epoch 109 is not built at its own size");
    if (after.seed != 110 || after.light != 440 || after.full != 440)
        fail("meowpow: at epoch 110 the dataset is not four times the epoch, or "
             "the seed moved with it");

    // The size that scaling is for, in the node's own words: past four
    // gigabytes, from a last unscaled epoch that is nowhere near it.
    if (pp::dag_bytes(after.full) <= 4 * kGiB ||
        pp::dag_bytes(before.full) >= 2 * kGiB)
        fail("meowpow: the scaled dataset is %llu bytes and the one before it "
             "%llu, which is not the step over four gigabytes Meowcoin scales "
             "for",
             static_cast<unsigned long long>(pp::dag_bytes(after.full)),
             static_cast<unsigned long long>(pp::dag_bytes(before.full)));

    // And the half of it that has no symptom, as two caches of exactly the same
    // length: the one this fork builds, and the one a reading that let the
    // scaled epoch through to everything would build. They have to differ.
    uint8_t mine[pp::kItemBytes];
    uint8_t edge[pp::kItemBytes];
    uint8_t naive[pp::kItemBytes];

    // Both reads of the fork's own cache before the other one replaces it: one
    // cache is kept at a time and these are 71 MiB each to build.
    //
    // The second read is the count from the far end -- the last item of the
    // scaled epoch's cache is there and one item past it is not. That is the
    // number the seeding failure would have kept while spoiling every byte
    // behind it, which is why both halves are checked and not just one.
    const uint64_t bytes = pp::light_cache_bytes(after.light);
    if (!pp::light_cache(after, 0, mine, sizeof mine)) {
        fail("meowpow: no light cache -- out of memory?");
        return;
    }
    if (!pp::light_cache(after, bytes - pp::kItemBytes, edge, sizeof edge) ||
        pp::light_cache(after, bytes, edge, sizeof edge))
        fail("meowpow: the light cache does not hold exactly the scaled "
             "epoch's items");

    const pp::Epochs all_scaled = {after.light, after.light, after.full};
    if (!pp::light_cache(all_scaled, 0, naive, sizeof naive)) {
        fail("meowpow: no light cache -- out of memory?");
        return;
    }

    if (std::memcmp(mine, naive, sizeof mine) == 0)
        fail("meowpow: the light cache is seeded from the epoch it was scaled "
             "to, so every item of it belongs to another epoch");

    // The other side, which is not this code hashing twice: the seed hash a
    // pool sent with the jobs the shares below were found on, verbatim off the
    // wire. A Stratum job for this family carries the epoch's seed beside the
    // height, and for height 2047808 that pool sent the seed of epoch 273 --
    // the real epoch, not the epoch 1092 the dataset for that job is sized at.
    static const char kJobSeedHash[] =
        "276c49b87b1e9bb22100a267913eb21aea33179b251004d15a468e328d7bbb76";

    uint8_t seed[32];
    pp::epoch_seed(pp::epochs_of(pp::kMeowpow, 2047808).seed, seed);
    if (to_hex(seed) != kJobSeedHash) {
        fail("meowpow: the seed for the epoch of block 2047808 is not the one a "
             "pool sent with that job");
        std::printf("  pool      %s\n  got       %s\n", kJobSeedHash,
                    to_hex(seed).c_str());
    }
}

// ---------------------------------------- Telestai, which published none either
//
// Telestai sizes its dataset exactly as Ravencoin does and seals both keccaks
// with Ravencoin's array, typo and all, so no byte count separates the two
// chains. What separates them is the round -- twelve cache reads, five
// arithmetic operations, half the rounds -- and a 27500-block epoch.
//
// The round is what a share tests, below. The epoch can be tested before one
// and against somebody else, a Stratum job for this family carrying the seed
// hash beside the height.
void check_telestai_arithmetic()
{
    // The boundary from both sides, and the height the shares below were found
    // at -- which is the one the seed hash is about.
    if (pp::epochs_of(pp::kMeraki, 27499).seed != 0 ||
        pp::epochs_of(pp::kMeraki, 27500).seed != 1 ||
        pp::epochs_of(pp::kMeraki, 1075797).seed != 39)
        fail("meraki: an epoch is not 27500 blocks long");

    // And that all three of the epoch numbers are the one epoch. This fork's
    // row is the identity sizing, so a dataset built off anything but its own
    // epoch is this table having grown an offset it does not have.
    const pp::Epochs at = pp::epochs_of(pp::kMeraki, 1075797);
    if (at.light != at.seed || at.full != at.seed)
        fail("meraki: the dataset and the seed do not share an epoch");

    static const char kJobSeedHash[] =
        "39238891c3ff3084a1264284ac4e2bb99f55430db15300f26f5c55eca8edd3c7";

    uint8_t seed[32];
    pp::epoch_seed(at.seed, seed);
    if (to_hex(seed) != kJobSeedHash) {
        fail("meraki: the seed for the epoch of block 1075797 is not the one a "
             "pool sent with that job");
        std::printf("  pool      %s\n  got       %s\n", kJobSeedHash,
                    to_hex(seed).c_str());
    }
}

// ------------------------------------------ and a share the network accepted

// What stands in for a vector table when nobody wrote one: shares this miner
// submitted and a pool accepted on 2026-08-25, frozen off the wire.
//
// The oracle is the acceptance. A pool re-runs the fork over the header hash
// and nonce it handed out and takes the share only if the mix is the one
// claimed and the final hash is under that job's target, so `result: true` is
// another implementation stating both about these bytes. Weaker than a solved
// block, which a reader could look up in an explorer, and still a second
// opinion rather than this one again.
struct Share {
    uint64_t block;
    const char *header_hash;
    const char *nonce;
    const char *mix_hash;      // as submitted, and accepted
    const char *share_target;  // what the job set, which the final hash is under
};

// Two consecutive blocks: two headers over one epoch and one program. The epoch
// is 166, so these were found against the dataset sized at epoch 422 -- 4399
// MiB, this row's offset met on a live chain rather than in the arithmetic.
const Share kEvrprogpowShares[] = {
    {1993180,
     "db00407def0a70b88d97ad6d8f718664b9c50f95becb70d62559647f2244eb31",
     "904200000382252d",
     "3b1705f91c100496b753d1eb399cba5f26bc962568ff5143f0b73dce69eb296c",
     "0000000ffff00000000000000000000000000000000000000000000000000000"},
    {1993181,
     "ecef8b658bcd158e4e693e1e88ba1ccbecb4663f6044b7f2bda17161bec46165",
     "904200000f72c67d",
     "327939ad02113e6407cc2c50545adb91d089150732837eab7d2ff27aef4a1334",
     "0000000ffff00000000000000000000000000000000000000000000000000000"},
};

// The same for Meowcoin: two blocks two apart, again one epoch and one program.
// The epoch is 273, so the table these were found against is the one sized at
// epoch 1092 -- the scaling checked above meeting a live chain.
const Share kMeowpowShares[] = {
    {2047808,
     "f69bce17825cb7576f8d5884d1a35609c1d47c0535aae78cf07413dee1c55e08",
     "ae9a0000081d6a6d",
     "26654561e4de53f9992e49f3f665ad141ada59111beca3099f0bc74832547208",
     "0000000ffff00000000000000000000000000000000000000000000000000000"},
    {2047810,
     "8cfbceeb1db79801b2fb3064bc6f69361e86b297c4c738941719ebfdc5f22041",
     "ae9a000001db4001",
     "169d5680486f439031dd521f3ff3686143c3e4b0d3370d7c35a29f8355d847c3",
     "0000000ffff00000000000000000000000000000000000000000000000000000"},
};

// Telestai's pair, and the one taken from two periods rather than one: at three
// blocks to a program these are two programs over the one epoch, which costs
// nothing because the light cache is the expensive part and epoch 39 holds
// both. That epoch's own dataset, 1336 MiB -- the identity sizing on a live
// chain.
const Share kMerakiShares[] = {
    {1075795,
     "023c523bc160c1bacd44fffb30f9d9ede71a7b8b51091dcba5cab324446125fb",
     "d42f000033410cbc",
     "3e921c5174b1c79e587b15f6600fd38cf7b7680d7375c978b0935fcec32fed70",
     "00000003fffc0000000000000000000000000000000000000000000000000000"},
    {1075797,
     "fdc2515d149d7c7d67cdc15bda81db08f57a4c52680f77dcbe629b58e2b3fafc",
     "d42f0000006c0ef4",
     "e29adb76d7b690c3568802a7743bafdb3cc325d808adefd38ee6aed7425e505d",
     "00000003fffc0000000000000000000000000000000000000000000000000000"},
};

void check_share(const pp::Params &fork, const Share &share)
{
    uint8_t header[32];
    uint8_t unused[32];
    uint64_t nonce = 0;
    if (!parse_hash(share.header_hash, header) ||
        !parse_hash(share.mix_hash, unused) ||
        !parse_hash(share.share_target, unused) ||
        !parse_nonce(share.nonce, &nonce)) {
        fail("%s block %llu: the share itself does not parse", fork.name,
             static_cast<unsigned long long>(share.block));
        return;
    }

    uint8_t mix[32];
    uint8_t final_hash[32];
    if (!hash_block(fork, share.block, header, nonce, mix, final_hash)) {
        fail("%s block %llu: no dataset -- out of memory?", fork.name,
             static_cast<unsigned long long>(share.block));
        return;
    }

    if (to_hex(mix) != share.mix_hash) {
        fail("%s block %llu: mix hash", fork.name,
             static_cast<unsigned long long>(share.block));
        std::printf("  accepted  %s\n  got       %s\n", share.mix_hash,
                    to_hex(mix).c_str());
    }

    // Both are 64 lowercase hex digits of a big-endian number, so the string
    // order is the numeric one. The pool's own comparison, made again here.
    if (to_hex(final_hash) >= std::string(share.share_target)) {
        fail("%s block %llu: the final hash is not under the target the share "
             "was taken at", fork.name,
             static_cast<unsigned long long>(share.block));
        std::printf("  target    %s\n  got       %s\n", share.share_target,
                    to_hex(final_hash).c_str());
    }
}

// The forks an entry can be borrowed from, in the order they are tried. Not
// alphabetical: swapping an epoch length or a multiplier moves the hash onto
// another epoch's light cache, which at these sizes is tens of seconds of
// keccak, so the nearest disagreement is also the cheapest one.
const pp::Params *const kDonors[] = {
    &pp::kKawpow, &pp::kEvrprogpow, &pp::kFiropow, &pp::kMeowpow, &pp::kMeraki,
};

// The first fork that disagrees with this one about `field`, or null if none
// does. Searched rather than named: these five rows share most of their values,
// so a donor picked by hand can lend back a number the fork already has, and
// the tweak then hashes the same row twice and passes without testing anything.
template <class T>
const pp::Params *donor_of(const pp::Params &fork, T pp::Params::*field)
{
    for (const pp::Params *donor : kDonors)
        if (fork.*field != donor->*field)
            return donor;
    return nullptr;
}

// Whether two rows send a block to the same dataset -- all three epoch numbers,
// because two of them can move without the third.
bool same_dataset(const pp::Params &a, const pp::Params &b, uint64_t block)
{
    const pp::Epochs x = pp::epochs_of(a, block);
    const pp::Epochs y = pp::epochs_of(b, block);
    return x.seed == y.seed && x.light == y.light && x.full == y.full;
}

// And the same argument the published table gets: the share hashed again with
// one entry of the fork's row replaced each time, and the mix required to move.
// A share that re-derives under KawPoW's constants would say nothing about the
// fork it was found on -- which is the trap EvrProgPow sets, since it shares
// every number with KawPoW except the two it moved.
void check_share_constants_matter(const pp::Params &fork, const Share &share)
{
    uint8_t header[32];
    uint64_t nonce = 0;
    if (!parse_hash(share.header_hash, header) ||
        !parse_nonce(share.nonce, &nonce))
        return;  // check_share has already reported it

    // The multiplier is a pair -- the epoch it starts at and the factor -- so a
    // member pointer cannot lend it and it has to move as one, or the tweak
    // hashes a fifth fork's sizing rather than somebody's.
    //
    // Lending it whole is not enough either: Meowcoin's pair does nothing below
    // epoch 110, so a share under that re-derives unmoved and the substitution
    // passes while testing nothing. So the donor is chosen by what it does to
    // this block's dataset, and failing that its factor is asked from the epoch
    // the share is on -- still somebody's factor, put where it can be read.
    const pp::Params *scaling = nullptr;
    pp::Params scaled = fork;
    for (const pp::Params *donor : kDonors) {
        pp::Params trial = fork;
        trial.dagchange_epoch = donor->dagchange_epoch;
        trial.dag_epoch_mul   = donor->dag_epoch_mul;
        if (!same_dataset(fork, trial, share.block)) {
            scaling = donor;
            scaled  = trial;
            break;
        }
    }
    for (const pp::Params *donor : kDonors) {
        if (scaling)
            break;
        if (donor->dag_epoch_mul == fork.dag_epoch_mul)
            continue;
        pp::Params trial = fork;
        trial.dagchange_epoch = pp::epochs_of(fork, share.block).seed;
        trial.dag_epoch_mul   = donor->dag_epoch_mul;
        if (!same_dataset(fork, trial, share.block)) {
            scaling = donor;
            scaled  = trial;
        }
    }

    const pp::Params *seal = nullptr;
    for (const pp::Params *donor : kDonors)
        if (std::memcmp(donor->seal_seed, fork.seal_seed,
                        sizeof fork.seal_seed) != 0) {
            seal = donor;
            break;
        }

    struct Tweak {
        const char *what;
        const pp::Params *donor;
        pp::Params params;
    };

    // In this order because the last three are the expensive ones: everything
    // above them changes the round and hashes against the cache already in
    // hand, and each of those three sends the test to another epoch.
    Tweak tweaks[] = {
        { "regs",          donor_of(fork, &pp::Params::regs),          fork },
        { "rounds",        donor_of(fork, &pp::Params::rounds),        fork },
        { "cache_ops",     donor_of(fork, &pp::Params::cache_ops),     fork },
        { "math_ops",      donor_of(fork, &pp::Params::math_ops),      fork },
        { "period_length", donor_of(fork, &pp::Params::period_length), fork },
        { "the seal",      seal,                                       fork },
        { "dag_full_off",  donor_of(fork, &pp::Params::dag_full_off),  fork },
        { "epoch_length",  donor_of(fork, &pp::Params::epoch_length),  fork },
        { "the dataset multiplier", scaling,                           fork },
    };

    for (const Tweak &tweak : tweaks)
        if (!tweak.donor) {
            fail("no other fork disagrees with %s about %s, so a substitution "
                 "cannot test it", fork.name, tweak.what);
            return;
        }

    tweaks[0].params.regs          = tweaks[0].donor->regs;
    tweaks[1].params.rounds        = tweaks[1].donor->rounds;
    tweaks[2].params.cache_ops     = tweaks[2].donor->cache_ops;
    tweaks[3].params.math_ops      = tweaks[3].donor->math_ops;
    tweaks[4].params.period_length = tweaks[4].donor->period_length;
    std::memcpy(tweaks[5].params.seal_seed, tweaks[5].donor->seal_seed,
                sizeof fork.seal_seed);
    std::memcpy(tweaks[5].params.seal_final, tweaks[5].donor->seal_final,
                sizeof fork.seal_final);
    tweaks[6].params.dag_full_off    = tweaks[6].donor->dag_full_off;
    tweaks[7].params.epoch_length    = tweaks[7].donor->epoch_length;
    tweaks[8].params                 = scaled;

    for (const Tweak &tweak : tweaks) {
        uint8_t mix[32];
        uint8_t final_hash[32];
        if (!hash_block(tweak.params, share.block, header, nonce, mix,
                        final_hash)) {
            fail("the %s share with %s changed: no dataset", fork.name,
                 tweak.what);
            continue;
        }
        if (to_hex(mix) == share.mix_hash)
            fail("the accepted %s share re-derives with %s taken from %s, so it "
                 "does not test it", fork.name, tweak.what, tweak.donor->name);
    }
}

// The four forks and what this file has to say about each, so that the count
// printed at the end is a claim and not a number. A fork whose row is empty is
// reported as such rather than silently skipped.
struct Fork {
    const pp::Params *params;
    const Vector *vectors;
    size_t count;
};

const Fork kForks[] = {
    { &pp::kFiropow,    kFiropow, sizeof kFiropow / sizeof kFiropow[0] },
    { &pp::kEvrprogpow, nullptr,  0 },
    { &pp::kMeowpow,    nullptr,  0 },
    { &pp::kMeraki,     nullptr,  0 },
};

}  // namespace

int main()
{
    size_t checked = 0;
    for (const Fork &fork : kForks) {
        if (!fork.count) {
            std::printf("%s: no published vectors; its evidence is a live "
                        "share\n", fork.params->name);
            continue;
        }
        for (size_t i = 0; i < fork.count; i++)
            check_vector(*fork.params, fork.vectors[i]);
        checked += fork.count;
    }

    check_each_constant_matters();
    check_evrmore_arithmetic();
    check_meowcoin_arithmetic();
    check_telestai_arithmetic();

    // A fork at a time, and its substitutions before the next fork's shares:
    // one light cache is kept, and these two are on epochs a hundred apart.
    const size_t evr = sizeof kEvrprogpowShares / sizeof kEvrprogpowShares[0];
    for (size_t i = 0; i < evr; i++)
        check_share(pp::kEvrprogpow, kEvrprogpowShares[i]);

    // Once, not per share: each pair sits in one epoch under one program, so
    // what the second would add is the same eight hashes again.
    check_share_constants_matter(pp::kEvrprogpow, kEvrprogpowShares[0]);

    const size_t mewc = sizeof kMeowpowShares / sizeof kMeowpowShares[0];
    for (size_t i = 0; i < mewc; i++)
        check_share(pp::kMeowpow, kMeowpowShares[i]);

    check_share_constants_matter(pp::kMeowpow, kMeowpowShares[0]);

    const size_t tls = sizeof kMerakiShares / sizeof kMerakiShares[0];
    for (size_t i = 0; i < tls; i++)
        check_share(pp::kMeraki, kMerakiShares[i]);

    check_share_constants_matter(pp::kMeraki, kMerakiShares[0]);

    if (failures) {
        std::printf("%d failure(s)\n", failures);
        return 1;
    }

    std::printf("firopow: %zu published blocks reproduce, and every constant "
                "the table gives it changes one of them\n", checked);
    std::printf("evrprogpow: no published blocks, but its epoch length and "
                "dataset size are the ones Evrmore states, and %zu accepted "
                "share(s) re-derive\n", evr);
    std::printf("meowpow: no published blocks, but its dataset is scaled and "
                "seeded the way Meowcoin's node does it, and %zu accepted "
                "share(s) re-derive\n", mewc);
    std::printf("meraki: no published blocks, but its epoch is the one a pool's "
                "seed hash names, and %zu accepted share(s) re-derive\n", tls);
    return 0;
}
