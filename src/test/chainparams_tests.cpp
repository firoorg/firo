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

    BOOST_CHECK(consensus.hashGenesisBlock == uint256S("0xee98d9dc0da1f3378edeeed1edcaf7d657952257d4700d594eb7c08ac1d6fa9a"));
    BOOST_CHECK(genesis.hashMerkleRoot == uint256S("0x25b361d60bc7a66b311e72389bf5d9add911c735102bcb6425f63aceeff5b7b8"));

    BOOST_CHECK(genesis.nNonce == 3);

    BOOST_CHECK(CheckProofOfWork(genesis.GetHash(), genesis.nBits, consensus));
}

BOOST_AUTO_TEST_SUITE_END()
