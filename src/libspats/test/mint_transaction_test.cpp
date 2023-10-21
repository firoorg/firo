#include "../mint_transaction.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>
#include <random>

namespace spats {

using namespace secp_primitives;

void hexDump(const std::string& data) {
    for (size_t i = 0; i < data.length(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;  // Restore output format to decimal
}

// Generate a random char vector from a random scalar
static std::vector<unsigned char> random_char_vector() {
    Scalar temp;
    temp.randomize();
    std::vector<unsigned char> result;
    result.resize(SCALAR_ENCODING);
    temp.serialize(result.data());

    return result;
}

static uint64_t random_uint(uint64_t min,uint64_t max){
    std::random_device rd; // Used to seed the random number generator
    std::mt19937 gen(rd()); // Mersenne Twister pseudo-random generator

    // std::numeric_limits<uint64_t>::max()
    std::uniform_int_distribution<uint64_t> distribution(min, max);

    return distribution(gen);
}

BOOST_FIXTURE_TEST_SUITE(spats_mint_transaction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_verify_identifier_zero)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    const std::size_t t = 4; // number of coins to generate
    
    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    std::vector<MintedCoinData> outputs;

    uint64_t iota = 0;

    // a == 0, v == 1
    uint64_t a = 0;
    uint64_t v = 1;

    // Generate addresses and coins
    for (std::size_t j = 0; j < t; j++) {
        MintedCoinData output;
        output.address = Address(incoming_view_key, 12345 + j);
        output.a = a;
        output.iota = iota;
        output.v = v;
        output.memo = "Spam and eggs";

        outputs.emplace_back(output);
    }

    // a == 0, v != 1
    outputs[1].a = 0;
    outputs[1].v = random_uint(2,10000);

    // a != 0, v == 1
    outputs[2].a = random_uint(1,10000);
    outputs[2].v = 1;

    // a != 0, v != 1
    outputs[3].a = random_uint(1,10000);
    outputs[3].v = random_uint(2,10000);

    for (std::size_t j = 0; j < t; j++) {
        std::cout<<"a: "<<outputs[j].a<<", "<<"v: "<<outputs[j].v<<std::endl;
    }
    // Generate mint transaction
    MintTransaction mint(
        params,
        outputs,
        random_char_vector()
    );
    // Verify
    BOOST_CHECK(mint.verify());
}

BOOST_AUTO_TEST_CASE(generate_verify_identifier_not_zero)
{
    // Parameters
    const Params* params;
    params = Params::get_default();
    const std::size_t t = 4; // number of coins to generate
    
    // Generate keys
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);

    std::vector<std::vector<MintedCoinData>> outputs;

    uint64_t iota = random_uint(1,10000);

    std::vector<uint64_t> vec_a = { 0,0,random_uint(1,10000),random_uint(1,10000)};
    std::vector<uint64_t> vec_v = { 1,random_uint(2,10000),1,random_uint(2,10000)};

    // a == 0, v == 1 (abort)
    // a == 0, v != 1 (abort)
    // a != 0, v == 1
    // a != 0, v != 1 (abort)

    // Generate addresses and coins
    for (std::size_t j = 0; j < t; j++) {
        MintedCoinData output;
        output.address = Address(incoming_view_key, 12345 + j);
        output.a = vec_a[j];
        output.iota = iota;
        output.v = vec_v[j];
        output.memo = "Spam and eggs";
        outputs.push_back({output});
    }

    for (std::size_t j = 0; j < t; j++) {
        // Generate mint transaction ()
        try {
            MintTransaction mint(params, outputs[j], random_char_vector());
            if(outputs[j][0].a == 0 || outputs[j][0].v != 1){
                BOOST_FAIL("Expected an exception but none was thrown");
            }
        } catch (const std::exception& e) {
            BOOST_CHECK(true);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

}
