#include <test/test_bitcoin.h>
#include <chainparams.h>
#include <boost/test/unit_test.hpp>

struct ChainParamsTestingSetup : public TestingSetup
{
    ChainParamsTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
    }
};

BOOST_FIXTURE_TEST_SUITE(Regtest, ChainParamsTestingSetup)

BOOST_AUTO_TEST_CASE(regtest_chainparams_verification)
{
    CBlock genesis = Params(CBaseChainParams::REGTEST).GenesisBlock();
    auto const & consensus = Params(CBaseChainParams::REGTEST).GetConsensus();

//        std::cout << "zcoin regtest genesisBlock hash: " << consensus.hashGenesisBlock.ToString() << std::endl;
//        std::cout << "zcoin regtest hashMerkleRoot hash: " << genesis.hashMerkleRoot.ToString() << std::endl;

    BOOST_CHECK(consensus.hashGenesisBlock == uint256S("0x3a84562b4f3837ee2550fe0ecb35c5e65f8c0d929c60b8c876d5712117161ed6"));
    BOOST_CHECK(genesis.hashMerkleRoot == uint256S("0x25b361d60bc7a66b311e72389bf5d9add911c735102bcb6425f63aceeff5b7b8"));

    BOOST_CHECK(genesis.nNonce == 3);

    BOOST_CHECK(CheckProofOfWork(genesis.GetHash(), genesis.nBits, consensus));
}

BOOST_AUTO_TEST_SUITE_END()
