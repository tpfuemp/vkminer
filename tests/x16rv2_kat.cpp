// vkminer -- a Vulkan compute cryptocurrency miner.
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Known-answer test for x16rv2's host side. Shabal-512, Whirlpool and Tiger
// against the designers' published digests and against sph over the bytes
// 0, 1, 2, ... at lengths covering every padding case; then the whole chain
// one position at a time against sph's states for one real block.

#include <cstddef>
#include <cstdio>
#include <cstring>

extern "C" {
#include "core/blake512.h"
#include "core/bmw512.h"
#include "core/cubehash512.h"
#include "core/echo512.h"
#include "core/fugue512.h"
#include "core/groestl512.h"
#include "core/hamsi512.h"
#include "core/jh512.h"
#include "core/keccak512.h"
#include "core/luffa512.h"
#include "core/sha512.h"
#include "core/shavite512.h"
#include "core/simd512.h"
#include "core/skein512.h"
#include "core/shabal512.h"
#include "core/tiger192.h"
#include "core/whirlpool512.h"
}

namespace {

int failures = 0;

typedef void (*HashFn)(void *, const void *, size_t);

struct Vector {
    const char *name;
    HashFn fn;
    size_t len;
    const char *digest;
};

// The published ones, over the string "abc" except where the length is 0.
const Vector kPublished[] = {
    { "Shabal-512", shabal512_full, 0,
      "fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19cc"
      "ffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6" },
    { "Whirlpool", whirlpool512_full, 3,
      "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
      "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5" },
    { "Tiger", tiger192_full, 0,
      "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3" },
    { "Tiger", tiger192_full, 3,
      "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93" },
};

// sph's, over the bytes 0, 1, 2, ...
const Vector kSph[] = {
    { "Shabal-512", shabal512_full, 0,
      "fc2d5dff5d70b7f6b1f8c2fcc8c1f9fe9934e54257eded0cf2b539a2ef0a19cc"
      "ffa84f8d9fa135e4bd3c09f590f3a927ebd603ac29eb729e6f2a9af031ad8dc6" },
    { "Shabal-512", shabal512_full, 1,
      "8703886b4251eccd6861da6ef21b4c9aa5a00793475056e05473c839ec8c7441"
      "a645d6b4eb4a876b12d3fa84963283d46de289c599801bd46b29daee6642f2b1" },
    { "Shabal-512", shabal512_full, 3,
      "1212f6e374c12a395b581fe3a2b040ba0ed3e7897c85976cc87a56f7df47868f"
      "30f61bb31bcd1e1ae6306a8215c32dd01080952657e9db6110ea1d01c914b4e9" },
    { "Shabal-512", shabal512_full, 4,
      "f01893dfb43fe6ce46ece6b874c541b8f951f56aeb66fd651705c25448ad24ec"
      "3604a0ab1ec3c775cc14b4e9c3ef9b0362ab9e30d5f2cd1744876b45308b4834" },
    { "Shabal-512", shabal512_full, 7,
      "633f3899fbbefc94ee4dea0ce9a1d3e1f10edd92ee63edb7851d35eebb29eb1d"
      "2ce11c5588f8954cf085fca32ce10d55854ff96c24ba3363cc8a7a01026f2d58" },
    { "Shabal-512", shabal512_full, 8,
      "6db67eac386a339482895cba5ef955311f812b3e36174617d171d7ca04a8ba9d"
      "11ef30fb67c885153d60dcfd4c7de16dddd962c3fec8b10fd567b822143bcc1c" },
    { "Shabal-512", shabal512_full, 55,
      "ba4dc867f09ca9ef217a417938a746f96c737b5a47beb6b5d428748d6b673cf5"
      "95dd513a282674cf0f6e260d36ce012c4a69a305bdcde477a866bb5f72b5561c" },
    { "Shabal-512", shabal512_full, 56,
      "57d16d6368d2d61f0233fb947d3c6e2d2adc44dd93457c993d8db8a0befd3d47"
      "a482f02c88d8692e63b520514d3bbeb24c5ec0ac6855afde26fc86f006f4c83c" },
    { "Shabal-512", shabal512_full, 63,
      "10e2b34aa75dea094e41e354ec1055c0158e7ecfcd9880af98deaa115e9bd8fc"
      "44e29b9330f4d5c98e96f32b3a0e2b0cc998a4c7264a8c47d6799c6f1f974155" },
    { "Shabal-512", shabal512_full, 64,
      "2ee4a74633348e70cd572fe237051e662869fe7ee5f160e2a2007f15139936fc"
      "f4c6315e4c930fc7bd6d8679d9915d9fdb0f248827455e053f7002ce5fdbc8da" },
    { "Shabal-512", shabal512_full, 80,
      "e699d85850c827c1a7a01296e19a11362a58c9e154e09f15d44b39612c3d237f"
      "44d973328f5a0b835f00ef9dfb0b0042854f37c597dc89637a7b9dfa55a332b8" },
    { "Shabal-512", shabal512_full, 120,
      "1b63a9fea330682f56275a761709db939d6b32760f996797dc1b113c05f2c6d8"
      "743e9899cf6b46e51db9b37c55b01d26330dcb7fc00bc6f391837a1240b9f3fa" },
    { "Shabal-512", shabal512_full, 128,
      "c7d7b09c8932e632aff1f7bc77df03f149a3578d126ad58de1db612e85777bc3"
      "ed068ae3279ddb51d6d7b7f814eb837078cce18fadd264391b1530602a5628ed" },
    { "Shabal-512", shabal512_full, 144,
      "5c36e349f92ac0432cc344f0dec4dd426f5de5aa410bd7c749d14b6937b0c7fc"
      "4bc8ec212891618732fa86779f0462b2447e6f10abb286cef810050a37b1f7be" },
    { "Shabal-512", shabal512_full, 200,
      "25a90093eea977ea9e210f1538ee2d30a05ab5596a7e727fbbe7decf6d63cc66"
      "258dd1e6f1b5b224acfdb4b516c2efe8159982789505db03b69741e5e4468fe0" },
    { "Whirlpool", whirlpool512_full, 0,
      "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
      "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3" },
    { "Whirlpool", whirlpool512_full, 1,
      "4d9444c212955963d425a410176fccfb74161e6839692b4c11fde2ed6eb559ef"
      "e0560c39a7b61d5a8bcabd6817a3135af80f342a4942ccaae745abddfb6afed0" },
    { "Whirlpool", whirlpool512_full, 3,
      "7314e8035788304e57e68ac9ea89544ace6d2379035697d91b98b64b105130dc"
      "814b67a4b46b4df6c103016b8f7c7403e0b943f0291ed6909e2219b6e18e89d8" },
    { "Whirlpool", whirlpool512_full, 4,
      "a6c01d8cb93a5cec17a9bdd270b24c8ee78686caffc454f253d9b8dad5398e52"
      "304cd57f30f2111be78fd98338dd3a41fd8a45124c940c4a59f270100dd6cb6f" },
    { "Whirlpool", whirlpool512_full, 7,
      "052a7c4ec5ad200b6b8131f30e97a9a5da44899e1c6c31bbe078058630d5e208"
      "fd6f2f51a796f814f8ad048d759f8dce442c405d96d6e1b1a197ad908b366e98" },
    { "Whirlpool", whirlpool512_full, 8,
      "219b01987262c597603dbc495792f2423e24a4bcd38825a74cee8ed91d559352"
      "96d80e73db43a78fdd6119233a31da5940c6e335eb22600729478a20f61a56dd" },
    { "Whirlpool", whirlpool512_full, 55,
      "a385fe66f8c852638f5be44503b680298ebbf27dbd9f20b1a0447215c0e2c107"
      "8926002113a71c78148d5019fb22c8132dd05356c78a1a8d8e4eec5a6442dba9" },
    { "Whirlpool", whirlpool512_full, 56,
      "218336585a419e9877cb63387c5e759fc93f0fe1a7ba717b8be9b2302393e0d1"
      "4def2f749d138692d0a0296f1c792b567f40037dd2b8787f1f47ff363cf34f37" },
    { "Whirlpool", whirlpool512_full, 63,
      "37bf321f66ace827b66ecaa651ccfcad30ab627e717aa4fe441279c4fa48555c"
      "b7784b0af25a73b86375be71a1e3fddec661e0eb8115e0bb2b9a7ff81dc75df9" },
    { "Whirlpool", whirlpool512_full, 64,
      "5c3c6f524c8ae1e7a4f76b84977b1560e78eb568e2fd8d72699ad79186481bd4"
      "2b53ab39a0b741d9c098a4ecb01f3eccf3844cf1b73a9355ee5d496a2a1fb5b3" },
    { "Whirlpool", whirlpool512_full, 80,
      "db1067879f014ef676471d950a81da073d676de52e85f67890c8471fe6144078"
      "daf940cb6f9f097bedb8fac94c737c5b8a3b4217cff4a56dc349b2ae845ab25b" },
    { "Whirlpool", whirlpool512_full, 120,
      "47386df4d41775737bc4e52d7cb2efc11ba335a5d59597b5deb3dd0a35032461"
      "f5db4779d48bd6f3a10c5503ac563c790235e6f54ea79ceadb6a56afcce890df" },
    { "Whirlpool", whirlpool512_full, 128,
      "803a3b37c89e84fbbec75bee3d00dd728ffc4246b5a5e989dc8dc2cd0f793796"
      "6ab78c79e1d4648ee6eb40f3d70491cb46b8ab42e155672e2ab8374fcf70dd79" },
    { "Whirlpool", whirlpool512_full, 144,
      "f7a763793358e48a81a8f56d943e85827b5cd2727d9fe88205f625f281fcc92c"
      "b158cd4b86d1a0641cd077f50899ef8048dc7fee232d8e253a82fa861e9dc131" },
    { "Whirlpool", whirlpool512_full, 200,
      "50cc69782191cb4bda8975391ee7307ba29911d617cc162286864ed40e1e426c"
      "90861ff3b48ad8ab966891ef4862441f8747ccbf4d38a0959a13bb9bece698d6" },
    { "Tiger", tiger192_full, 0,
      "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3" },
    { "Tiger", tiger192_full, 1,
      "5d9ed00a030e638bdb753a6a24fb900e5a63b8e73e6c25b6" },
    { "Tiger", tiger192_full, 3,
      "ab7fb8d21ce3d8d9bb5f1af1f2fa0d3c277906160db8d226" },
    { "Tiger", tiger192_full, 4,
      "fe2e9d43f74b199d91b9291d73ccfca0bea5f068fba244ff" },
    { "Tiger", tiger192_full, 7,
      "4056ddbf82ae74ab56720deaf079aca2f076ed046d044de5" },
    { "Tiger", tiger192_full, 8,
      "801fb9be1a9ac7337a81345b3845e4e7c13af1fbadb73723" },
    { "Tiger", tiger192_full, 55,
      "2d48ee2bf85de234754becf3c6f5b0e62988b5bf24aea5bb" },
    { "Tiger", tiger192_full, 56,
      "0d17702ddca078ed1cc51b95df29ea1053ce97f69395c613" },
    { "Tiger", tiger192_full, 63,
      "d401f9b13d39c24477c0ae6971c705c63c067f29508c29c9" },
    { "Tiger", tiger192_full, 64,
      "212df89c57155270344accb19027b0b26b104fa0fbbe0fe4" },
    { "Tiger", tiger192_full, 80,
      "00278b4e5690e729ec7118b5bf63c9d1eb1268960893ca75" },
    { "Tiger", tiger192_full, 120,
      "c20ad90db0b8bee0335d069259991060969eec9f939e4ca7" },
    { "Tiger", tiger192_full, 128,
      "34fa7c74ee67c1f92c0be1cfd4b2f46a14ffb999604925f6" },
    { "Tiger", tiger192_full, 144,
      "0019a004a45a1375a9ae197803ada79398854d4f9ff9a765" },
    { "Tiger", tiger192_full, 200,
      "687e2237754be9fc84489c01769f2a4358b41adf036b82e4" },
};

// Ravencoin block 1000108, order 5F334EB6B226BAB4 (five Tigers, repeated
// stages): the wire header, then sph's state after each position, Tiger
// included in the stage it precedes. Each position starts from sph's previous
// state, so a wrong stage fails only at its own position.
const char kChainHeader[] =
    "00000032b4ba26b2b64e335f3f9990e82e73243372b0f6d5a472bb8d29540000"
    "00000000950032a66e6f421aa6d5bc5728e173a8614a3646a9cf9e49fa1068a9"
    "bd858270c8afe85da035711ac40d119a";

const char *const kChainStates[16] = {
    // 0: 5
    "4993df899bf7d98b3adcc7bd8aff8c7dc2971acaee79dda5ce6f5a35009dbc4d"
    "ce95b890ddb2f53e3309aefb19e750a5ae7cc007c0211febb34af369996fbd20",
    // 1: F
    "be91b9de912349874e51211a6eef02aaf701ccea53f97578e59d698e0e0b0f0f"
    "af4148bb40fa4e87b8951b210116a248912e48682119c4abe599975e4a157282",
    // 2: 3
    "351827680f013c3287421e0607f7a25eb97eaf48aee7c3958124d9522a57d509"
    "ea9d18f725f3ef303881edadc8a8351bb0d726bb341725e5bcae417698f69005",
    // 3: 3
    "4a67746b162d3c123798d990459d69959b9e40f4fa4b9b07fc29d6168eb1a6c8"
    "8824bb0cf08d2ef02cb6f712529251765fd81bb1bd1e9cfa7c8534b0eada26e1",
    // 4: 4
    "4cf595f9b390da77f2a1d01c922f0478e2a6106f169504be176312f2c9a5b147"
    "7f135f4b88a76f3c4dcf14758ae409bc3f425b4c6c4c4fb2a088b92f4c118fa8",
    // 5: E
    "4c1568bdb2292ff0d10a723dcb821cf1424221e0893bd58eda2270a25bc78e8b"
    "1de64b8a41be89f882664aae9b9ed401d83d12ed6df0f77acf396ef1a60a7dbd",
    // 6: B
    "bbf74e5bc38f641deb035b0adbb63e728e1bbdcaa26616071eccc884d997c100"
    "d7127b21738314a10394d4396401525ba8c560235105ba548f09c0fb74dfe6b6",
    // 7: 6
    "1fda775ea24c38e3097ab24a1eb637de62951cc64cf376702bdcc0339059203d"
    "517542aa7fa96df0c789e771559da701474cf3fc0ad888211589fc5153434e71",
    // 8: B
    "4e5c9e54aee6edad4c32f0dbb38159505481dc1bf67e426204e842d868e60b06"
    "003fc77d62df1e6f4bf29bb9cedf1eac054f0ad8fbeb113045d615e8d01f6373",
    // 9: 2
    "6e70a12924acc8e2efb22a67d6d017ee0387d6b772309d7b6efa9efc51929e64"
    "11774de5dcc8cff806827fd617d391ff557d9ad71198597dfe4cf9382ea58302",
    // 10: 2
    "5ca37d76378580fe19d8ceb3745b821c3f986cc7d256752d9ab863fe4fbf37fd"
    "2cd5c32e28c537dd2f4386ec062d96a3eed5a178b5ba514d1b4e9e074207f80e",
    // 11: 6
    "3f41017874cd7c130a94901fd3ba3a827f62f967abca75ea2e5df1d8a6cecfe5"
    "4aa24f968c4f2f580ae580eee1997a78c94c1abf41da4e33c53a8018d155522f",
    // 12: B
    "8fd96fad3a6e53a613108abdbca682c20798bab3e58c425d971ddfe6b60cdb11"
    "59e06d5a38fe5161070ed60025827c086a4060f99691d7fc260a38278e923d97",
    // 13: A
    "fed8d9c8e53fde165edd2a18d4a7fb9cd0b9aaaef346466fbcb728d5c15428af"
    "610b45054c66e28abe2c6665494138563c0d62705ee28ba51bb1b381f186f73b",
    // 14: B
    "be0c3ee83e32794eddc4af6f168dbb46249d37aa69371344b316c21754dd073e"
    "a655f01cdd62da503f78c7b831bb99ae64eb6c73bca1d5cf9b0181deca629f61",
    // 15: 4
    "025f09657b2cb4120337ae2ca504bdde29094996afe997dc1647000000000000"
    "42f0715b8acd66f080b121c0fdceacb01927ce8e933c7fd93646e2aa5188f0db",
};

bool check(const Vector &v, const unsigned char *msg)
{
    const size_t bytes = std::strlen(v.digest) / 2;
    unsigned char got[64];
    v.fn(got, msg, v.len);

    char hex[129];
    for (size_t i = 0; i < bytes; i++)
        std::snprintf(hex + 2 * i, 3, "%02x", got[i]);

    if (std::strcmp(hex, v.digest) == 0)
        return true;

    std::printf("FAIL: %s of %u bytes\n  want %s\n  got  %s\n", v.name,
                static_cast<unsigned>(v.len), v.digest, hex);
    failures++;
    return false;
}

void from_hex(const char *hex, unsigned char *out, size_t bytes)
{
    for (size_t i = 0; i < bytes; i++) {
        unsigned v = 0;
        std::sscanf(hex + 2 * i, "%2x", &v);
        out[i] = static_cast<unsigned char>(v);
    }
}

// The sixteen in the order the nibbles name them.
const HashFn kStageFns[16] = {
    blake512_full,    bmw512_full,     groestl512_full,  jh512_full,
    keccak512_full,   skein512_full,   luffa512_full,    cubehash512_full,
    shavite512_full,  simd512_full,    echo512_full,     hamsi512_full,
    fugue512_full,    shabal512_full,  whirlpool512_full, sha512_full,
};

// Position i of the chain from sph's state before it; true if it lands on
// sph's state after it. The order is read here from the header's own bytes,
// 11 down to 4 and high nibble first, not through x16rv2_order.h.
bool check_chain_position(unsigned i)
{
    unsigned char header[80];
    from_hex(kChainHeader, header, sizeof header);
    const unsigned char byte = header[4 + 7 - i / 2];
    const unsigned stage = i % 2 == 0 ? byte >> 4 : byte & 0xf;

    unsigned char in[80];
    size_t len = 80;
    if (i == 0) {
        std::memcpy(in, header, sizeof header);
    } else {
        from_hex(kChainStates[i - 1], in, 64);
        len = 64;
    }
    if (stage == 4 || stage == 6 || stage == 15) {
        unsigned char t[24];
        tiger192_full(t, in, len);
        std::memset(in, 0, 64);
        std::memcpy(in, t, sizeof t);
        len = 64;
    }
    unsigned char got[64];
    kStageFns[stage](got, in, len);

    unsigned char want[64];
    from_hex(kChainStates[i], want, sizeof want);
    if (std::memcmp(got, want, sizeof want) == 0)
        return true;

    char hex[129];
    for (size_t k = 0; k < sizeof got; k++)
        std::snprintf(hex + 2 * k, 3, "%02x", got[k]);
    std::printf("FAIL: chain position %u, stage %X\n  want %s\n  got  %s\n", i,
                stage, kChainStates[i], hex);
    failures++;
    return false;
}

}  // namespace

int main()
{
    const unsigned char *abc = reinterpret_cast<const unsigned char *>("abc");
    unsigned char counting[256];
    for (size_t i = 0; i < sizeof counting; i++)
        counting[i] = static_cast<unsigned char>(i);

    size_t passed = 0, total = 0;
    for (const Vector &v : kPublished) {
        total++;
        passed += check(v, abc);
    }
    for (const Vector &v : kSph) {
        total++;
        passed += check(v, counting);
    }
    for (unsigned i = 0; i < 16; i++) {
        total++;
        passed += check_chain_position(i);
    }

    std::printf("%u of %u vectors\n", static_cast<unsigned>(passed),
                static_cast<unsigned>(total));
    return failures ? 1 : 0;
}
