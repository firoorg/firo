#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/mint_transaction.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    const spark::Params* params;
    params = spark::Params::get_default();
    const size_t t = fdp.ConsumeIntegral<uint8_t>();

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    std::vector<spark::MintedCoinData> outputs;

    for (size_t i = 0; i < t; i++) {
        spark::MintedCoinData output;
        output.address = spark::Address(incoming_view_key, fdp.ConsumeIntegral<uint64_t>());
        output.v = fdp.ConsumeIntegral<int>();
        output.memo = fdp.ConsumeBytesAsString(len);
        outputs.emplace_back(output);
    }

    spark::MintTransaction mint(params, outputs, fdp.ConsumeBytes<unsigned char>(spark::SCALAR_ENCODING));
    assert(mint.verify());

    
    return 0;

}