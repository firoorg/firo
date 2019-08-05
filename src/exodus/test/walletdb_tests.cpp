#include <boost/test/unit_test.hpp>

#include "../../test/test_bitcoin.h"
#include "../walletdb.h"

class ExodusWalletDBTestingSetup : public TestingSetup
{
public:
    ExodusWalletDBTestingSetup(): TestingSetup() {}
};

BOOST_FIXTURE_TEST_SUITE(exodus_walletdb_tests, ExodusWalletDBTestingSetup)

BOOST_AUTO_TEST_CASE(getid)
{
    exodus::SigmaEntry entry;
    exodus::SigmaPrivateKey priv;
    priv.Generate();

    exodus::SigmaPublicKey pub(priv);

    entry.privateKey = priv;
    entry.propertyId = 1;
    entry.denomination = 2;

    auto id = entry.GetId();

    BOOST_CHECK(id.publicKey == pub);
    BOOST_CHECK(id.propertyId == 1);
    BOOST_CHECK(id.denomination == 2);
}

BOOST_AUTO_TEST_SUITE_END()