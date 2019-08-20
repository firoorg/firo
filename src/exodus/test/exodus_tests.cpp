#include "../exodus.h"
#include "../rules.h"
#include "../sp.h"

#include "base58.h"
#include "chainparams.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>

using namespace exodus;

BOOST_FIXTURE_TEST_SUITE(exodus_exodus_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(exodus_address_mainnet)
{
    BOOST_CHECK(CBitcoinAddress("ZzzcQkPmXomcTcSVGsDHsGBCvxg67joaj5") ==
                ExodusAddress());
}

BOOST_AUTO_TEST_CASE(exodus_address_testnet)
{
    SelectParams(CBaseChainParams::TESTNET);

    BOOST_CHECK(CBitcoinAddress("TTFL4sPFHP22Dzqbw9mPQJEjdG7Wf1ajjZ") ==
                ExodusAddress());

    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(exodus_address_regtest)
{
    SelectParams(CBaseChainParams::REGTEST);

    BOOST_CHECK(CBitcoinAddress("TTFL4sPFHP22Dzqbw9mPQJEjdG7Wf1ajjZ") ==
                ExodusAddress());

    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(exodus_mints_overflow)
{
    _my_sps = new CMPSPInfo(pathTemp / "MP_spinfo_test", false);

    CMPSPInfo::Entry sp;
    sp.denominations = {MAX_INT_8_BYTES};
    auto property = _my_sps->putSP(0, sp); // non-standard

    std::vector<uint8_t> denoms = {0, 0};
    BOOST_CHECK_EXCEPTION(
        SumDenominationsValue(property, denoms.begin(), denoms.end()),
        std::overflow_error,
        [](std::overflow_error const &e) -> bool {
            return std::string("summation of mints is overflow") == e.what();
        }
    );
}

BOOST_AUTO_TEST_SUITE_END()
