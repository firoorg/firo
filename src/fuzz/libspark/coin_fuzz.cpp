#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/coin.h"
// #include "../../test/test_bitcoin.h"

#include <cassert>

const std::size_t SCALAR_ENCODING = 32;
const char COIN_TYPE_MINT = 0;
const char COIN_TYPE_SPEND = 1;


extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    // Scalar temp = fsp.GetScalar();
    Scalar temp;
    temp.randomize();

    std::vector<unsigned char> result;
    result.resize(SCALAR_ENCODING);
    temp.serialize(result.data());

    const spark::Params* params;
    params = spark::Params::get_default();

    const uint64_t i = len;

    // it will be better to choose s different way to generate the value
    const uint64_t v = std::rand();
    const std::string memo = fdp.ConsumeBytesAsString(len);

    // Generate keys
    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    // Generate address
    spark::Address address(incoming_view_key, i);

    // Generate coin
    // Scalar k = fsp.GetScalar();
    Scalar k;
    k.randomize();

    spark::Coin coin = spark::Coin (
        params,
        COIN_TYPE_MINT,
        k,
        address,
        v,
        memo,
        result
    );

    // Identify coin
    spark::IdentifiedCoinData i_data = coin.identify(incoming_view_key);
    assert(i_data.i == i);
    assert(i_data.d == address.get_d());
    assert(i_data.v == v);
    assert(i_data.memo == memo);

    // Recover coin
    spark::RecoveredCoinData r_data = coin.recover(full_view_key, i_data);
    assert(params->get_F()*(spark::SparkUtils::hash_ser(k, coin.serial_context) + spark::SparkUtils::hash_Q2(incoming_view_key.get_s1(), i) + full_view_key.get_s2()) + full_view_key.get_D() == params->get_F()*r_data.s + full_view_key.get_D());

    assert(r_data.T * r_data.s + full_view_key.get_D() == params->get_U());

    

}