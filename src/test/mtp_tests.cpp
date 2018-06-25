#include "crypto/MerkleTreeProof/mtp.h"
#include "test/test_bitcoin.h"
#include <iostream>
#include <boost/test/unit_test.hpp>

using namespace std;

struct MtpTestingSetup : public TestingSetup
{
    MtpTestingSetup() : TestingSetup(CBaseChainParams::REGTEST, "1")
    {
        std::cout << "XXX MtpTestingSetup::MtpTestingSetup()" << std::endl;
    }
};

BOOST_FIXTURE_TEST_SUITE(mtp_tests, MtpTestingSetup)

BOOST_AUTO_TEST_CASE(mtp_test1)
{
    std::cout << "XXX mtp_test1" << std::endl;
    BOOST_CHECK_MESSAGE(false, "XXX boost check");
}

BOOST_AUTO_TEST_SUITE_END()
