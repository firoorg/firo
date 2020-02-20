#include "exodus/notifications.h"
#include "exodus/version.h"

#include "util.h"
#include "test/test_bitcoin.h"
#include "tinyformat.h"

#include <boost/test/unit_test.hpp>

#include <stdint.h>
#include <map>
#include <string>
#include <vector>

using namespace exodus;

// Is only temporarily modified and restored after each test
extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;

BOOST_FIXTURE_TEST_SUITE(exodus_alert_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(alert_positive_authorization)
{
    // Confirm authorized sources for mainnet
    BOOST_CHECK(CheckAlertAuthorization("48UM25xTXCxPRwnv36YjjJNaAK4whKR8Rd"));  // Poramin Insom   <poramin@zcoin.io>
}

BOOST_AUTO_TEST_CASE(alert_unauthorized_source)
{
    // Confirm unauthorized sources are not accepted
    BOOST_CHECK(!CheckAlertAuthorization("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"));
}

BOOST_AUTO_TEST_CASE(alert_manual_sources)
{
    std::map<std::string, std::string> mapArgsOriginal = mapArgs;
    std::map<std::string, std::vector<std::string> > mapMultiArgsOriginal = mapMultiArgs;

    mapArgs["-elysiumalertallowsender"] = "";
    mapArgs["-elysiumalertignoresender"] = "";

    // Add 1JwSSu as allowed source for alerts
    mapMultiArgs["-elysiumalertallowsender"].push_back("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T");
    BOOST_CHECK(CheckAlertAuthorization("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"));

    // Then ignore some sources explicitly
    mapMultiArgs["-elysiumalertignoresender"].push_back("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T");
    mapMultiArgs["-elysiumalertignoresender"].push_back("16oDZYCspsczfgKXVj3xyvsxH21NpEj94F");
    BOOST_CHECK(CheckAlertAuthorization("48UM25xTXCxPRwnv36YjjJNaAK4whKR8Rd")); // should still be authorized
    BOOST_CHECK(!CheckAlertAuthorization("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"));
    BOOST_CHECK(!CheckAlertAuthorization("16oDZYCspsczfgKXVj3xyvsxH21NpEj94F"));

    mapMultiArgs = mapMultiArgsOriginal;
    mapArgs = mapArgsOriginal;
}

BOOST_AUTO_TEST_CASE(alert_authorize_any_source)
{
    std::map<std::string, std::string> mapArgsOriginal = mapArgs;
    std::map<std::string, std::vector<std::string> > mapMultiArgsOriginal = mapMultiArgs;

    mapArgs["-elysiumalertallowsender"] = "";

    // Allow any source (e.g. for tests!)
    mapMultiArgs["-elysiumalertallowsender"].push_back("any");
    BOOST_CHECK(CheckAlertAuthorization("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"));
    BOOST_CHECK(CheckAlertAuthorization("137uFtQ5EgMsreg4FVvL3xuhjkYGToVPqs"));
    BOOST_CHECK(CheckAlertAuthorization("16oDZYCspsczfgKXVj3xyvsxH21NpEj94F"));

    mapMultiArgs = mapMultiArgsOriginal;
    mapArgs = mapArgsOriginal;
}

BOOST_AUTO_TEST_SUITE_END()
