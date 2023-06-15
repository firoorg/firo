#include "../spend_transaction.h"
#include <iostream>
#include <boost/test/unit_test.hpp>
#include "../../test/test_bitcoin.h"
namespace spark {

// Generate a random char vector from a random scalar
static std::vector<unsigned char> random_char_vector() {
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(SCALAR_ENCODING);
    temp.serialize(result.data());

    return result;
}

void run_test(const std::size_t n_grootle, const std::size_t m_grootle, const std::size_t batch_size) {
    // Parameters
    const Params *params;
    params = new Params(32, 16, n_grootle, m_grootle);

    const std::string memo = "Spam and eggs"; // arbitrary memo

    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);
    // Generate address
    Address address(incoming_view_key, 12345);

    std::size_t N = (std::size_t) pow(params->get_n_grootle(), params->get_m_grootle());
    std::cout<<"n "<<n_grootle<<" m "<<m_grootle<<" N "<<N<<" batch size "<<batch_size<<std::endl;

    // Mint some coins to the address
     std::vector<Coin> in_coins;
    for (std::size_t i = 0; i < N; i++) {
        Scalar k;
        k.randomize();

        uint64_t v = 123 + i; // arbitrary value

        in_coins.emplace_back(Coin(
                params,
                COIN_TYPE_MINT,
                k,
                address,
                v,
                memo,
                random_char_vector()
        ));
    }

    // Track values so we can set the fee to make the transaction balance
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    uint64_t cover_set_id = 31415;
    CoverSetData setData;
    setData.cover_set = in_coins;
    setData.cover_set_representation = random_char_vector();
    cover_set_data[cover_set_id] = setData;

    auto t1 = std::chrono::high_resolution_clock::now();

    std::vector<SpendTransaction> transactions;
    for (size_t i = 0; i < batch_size; i++) {
        uint64_t f = 0;
        // Choose coins to spend, recover them, and prepare them for spending
        std::vector<std::size_t> spend_indices = { 1+i, 3+i };
        std::vector<InputCoinData> spend_coin_data;
        const std::size_t w = spend_indices.size();
        for (std::size_t u = 0; u < w; u++) {
            IdentifiedCoinData identified_coin_data = in_coins[spend_indices[u]].identify(incoming_view_key);
            RecoveredCoinData recovered_coin_data = in_coins[spend_indices[u]].recover(full_view_key, identified_coin_data);

            spend_coin_data.emplace_back();

            spend_coin_data.back().cover_set_id = cover_set_id;

            spend_coin_data.back().index = spend_indices[u];
            spend_coin_data.back().k = identified_coin_data.k;
            spend_coin_data.back().s = recovered_coin_data.s;
            spend_coin_data.back().T = recovered_coin_data.T;
            spend_coin_data.back().v = identified_coin_data.v;

            f += identified_coin_data.v;
        }

        // Generate new output coins and compute the fee
        const std::size_t t = 2;
        std::vector<OutputCoinData> out_coin_data;
        for (std::size_t j = 0; j < t; j++) {
            out_coin_data.emplace_back();
            out_coin_data.back().address = address;
            out_coin_data.back().v = 12 + j; // arbitrary value
            out_coin_data.back().memo = memo;

            f -= out_coin_data.back().v;
        }

        // Assert the fee is correct
        uint64_t fee_test = f;
        for (std::size_t j = 0; j < t; j++) {
            fee_test += out_coin_data[j].v;
        }
        for (std::size_t u = 0; u < w; u++) {
            fee_test -= spend_coin_data[u].v;
        }
        if (fee_test != 0) {
            throw std::runtime_error("Bad fee assertion");
        }

        // Generate spend transaction
        SpendTransaction transaction(
                params,
                full_view_key,
                spend_key,
                spend_coin_data,
                cover_set_data,
                f,
                0,
                out_coin_data
        );

        transaction.setCoverSets(cover_set_data);
        transactions.push_back(transaction);
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    std::cout << "Creation time "
              << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count()
              << " milliseconds";
    std::cout << " Single tx Creation time "
              << std::chrono::duration_cast<std::chrono::milliseconds>((t2-t1)/batch_size).count()
              << " milliseconds\n";

    std::vector<uint8_t> vch;
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << transactions[0];
    vch.assign(serialized.begin(), serialized.end());
    std::cout << "Spark spend size "<<vch.size()<<" byte "<<std::endl;

    // Verify
    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    for (const auto set_data : cover_set_data)
        cover_sets[set_data.first] = set_data.second.cover_set;

    t1 = std::chrono::high_resolution_clock::now();

    std::cout<<"Verify "<<(SpendTransaction::verify(params, transactions, cover_sets) ? "true" : "false")<<std::endl;

    t2 = std::chrono::high_resolution_clock::now();
    std::cout << "Verify time "
              << std::chrono::duration_cast<std::chrono::milliseconds>(t2-t1).count()
              << " milliseconds";
    delete params;

    std::cout<<std::endl<<std::endl<<std::endl;
}

BOOST_FIXTURE_TEST_SUITE(spark_test_performance, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_performance)
{
    run_test(2, 6, 1); //64
    run_test(2, 7, 1); //128
    run_test(4, 4, 1); //256
    run_test(8, 5, 1); //32768
    run_test(8, 5, 10); //32768
    run_test(8, 5, 25); //32768
    run_test(8, 5, 50); //32768
    run_test(8, 5, 100); //32768
    run_test(16, 4, 1); //65536
    run_test(16, 4, 110); //65536
    run_test(16, 4, 25); //65536
    run_test(16, 4, 50); //65536
    run_test(16, 4, 100); //65536
}

BOOST_AUTO_TEST_SUITE_END()

}