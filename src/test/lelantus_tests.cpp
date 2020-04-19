#include "../lelantus.h"

#include "test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

BOOST_FIXTURE_TEST_SUITE(lelantus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(schnorr_proof)
{
    auto params = Params::get_default();

    PrivateCoin coin(params, 1);

    std::vector<unsigned char> serializedSchnorrProof;
    GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    auto commitment = coin.getPublicCoin();
    SchnorrProof<Scalar, GroupElement> proof;
    proof.deserialize(serializedSchnorrProof.data());

    BOOST_CHECK(VerifyMintSchnorrProof(1, commitment.getValue(), proof));
}

BOOST_AUTO_TEST_SUITE_END()

};