#include "../fuzzing_utilities.h"
#include "../FuzzedDataProvider.h"
#include "../../libspark/spend_transaction.h"
#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
    FuzzedDataProvider fdp(buf, len);
    FuzzedSecp256k1Object fsp(&fdp);

    const spark::Params* params;
    params = spark::Params::get_default();
    const std::string memo = fdp.ConsumeBytesAsString(len);

    spark::SpendKey spend_key(params);
    spark::FullViewKey full_view_key(spend_key);
    spark::IncomingViewKey incoming_view_key(full_view_key);

    spark::Address address(incoming_view_key, fdp.ConsumeIntegral<uint64_t>());

    size_t N = (size_t) pow(params->get_n_grootle(), params->get_m_grootle());

    bool exception_thrown = false;
    if (memo.size() > params->get_memo_bytes()) {
        try{
            Scalar k;
            k.randomize();
            uint64_t v = rand();
            spark::Coin(params, spark::COIN_TYPE_MINT, k, address, v, memo, fdp.ConsumeBytes<unsigned char>(spark::SCALAR_ENCODING));
        } catch(const std::exception& ) {
            exception_thrown = true;
        }
        assert(exception_thrown);
        return 0;
    }

    std::vector<spark::Coin> in_coins;
    for (size_t i = 0; i < N; i ++) {
        secp_primitives::Scalar k = fsp.GetScalar();

        uint64_t v = fdp.ConsumeIntegral<uint64_t>();

        in_coins.emplace_back(spark::Coin(params, spark::COIN_TYPE_MINT, k, address, v, memo, fdp.ConsumeBytes<unsigned char>(spark::SCALAR_ENCODING)));
    }

    uint64_t f = 0;

    std::vector<uint8_t> spend_indices = fdp.ConsumeBytes<uint8_t>(len);
    if (spend_indices.size() < len) {
        for (int i = spend_indices.size(); i < len; i++) {
            spend_indices.push_back(std::rand());
        }
    }
    std::vector<spark::InputCoinData> spend_coin_data;
    std::unordered_map<uint64_t, spark::CoverSetData> cover_set_data;
    const size_t w = spend_indices.size();
    for (size_t u = 0; u < w; u++) {
        spark::IdentifiedCoinData identified_coin_data = in_coins[spend_indices[u]].identify(incoming_view_key);
        spark::RecoveredCoinData recovered_coin_data = in_coins[spend_indices[u]].recover(full_view_key, identified_coin_data);

        spend_coin_data.emplace_back();
        uint64_t cover_set_id = fdp.ConsumeIntegral<uint64_t>();
        spend_coin_data.back().cover_set_id = cover_set_id;

        spark::CoverSetData set_data;
        set_data.cover_set = in_coins;
        set_data.cover_set_representation = fdp.ConsumeBytes<unsigned char>(spark::SCALAR_ENCODING);
        cover_set_data[cover_set_id] = set_data;
        spend_coin_data.back().index = spend_indices[u];
        spend_coin_data.back().k = identified_coin_data.k;
        spend_coin_data.back().s = recovered_coin_data.s;
        spend_coin_data.back().T = recovered_coin_data.T;
        spend_coin_data.back().v = identified_coin_data.v;

        f += identified_coin_data.v;
    }

    const size_t t = fdp.ConsumeIntegral<uint8_t>();
    std::vector<spark::OutputCoinData> out_coin_data;
    for (size_t j = 0; j < t; j++) {
        out_coin_data.emplace_back();
        out_coin_data.back().address = address;
        out_coin_data.back().v = fdp.ConsumeIntegral<int>();
        out_coin_data.back().memo = memo;

        f -= out_coin_data.back().v;
    }

    uint64_t fee_test = f;
    for (size_t j = 0; j < t; j++) {
        fee_test += out_coin_data[j].v;
    }

    for (size_t j = 0; j < t; j++) {
        fee_test -= spend_coin_data[j].v;
    }
    assert(fee_test == 0);

    spark::SpendTransaction transaction(params, full_view_key, spend_key, spend_coin_data, cover_set_data, f, 0, out_coin_data);

    transaction.setCoverSets(cover_set_data);
    std::unordered_map<uint64_t, std::vector<spark::Coin>> cover_sets;
    for (const auto set_data: cover_set_data) {
        cover_sets[set_data.first] = set_data.second.cover_set;
    }
    assert(spark::SpendTransaction::verify(transaction, cover_sets));

    
    return 0;

}