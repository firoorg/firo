#include "../exodus.h"
#include "../rules.h"
#include "../sp.h"

#include "base58.h"
#include "chainparams.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <limits>

using namespace elysium;

BOOST_FIXTURE_TEST_SUITE(exodus_exodus_tests, TestingSetup)

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
