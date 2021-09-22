#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "test/test_bitcoin.h"
#include "script/standard.h"

#include <boost/test/unit_test.hpp>

struct ProgpowTestingSetup : public TestChain100Setup
{
    CKey coinbaseKey;
    CScript coinbaseScript;

    ProgpowTestingSetup() : TestChain100Setup()
    {
        coinbaseKey.MakeNewKey(true);
        coinbaseScript = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
    }
};


BOOST_FIXTURE_TEST_SUITE(progpow_tests, ProgpowTestingSetup)

BOOST_AUTO_TEST_CASE(transition)
{
    Consensus::Params &mutableParams = const_cast<Consensus::Params&>(Params().GetConsensus());
    Consensus::Params originalParams = mutableParams;

    mutableParams.nPPSwitchTime = INT_MAX;

    CBlock regularBlock = CreateAndProcessBlock({}, coinbaseKey);
    BOOST_ASSERT(!regularBlock.IsProgPow());

    mutableParams.nPPSwitchTime = (uint32_t)(chainActive.Tip()->GetMedianTimePast()+10);
    SetMockTime(mutableParams.nPPSwitchTime+1);

    int oldHeight = chainActive.Height();
    CBlock ppBlock = CreateAndProcessBlock({}, coinbaseKey);
    BOOST_ASSERT(chainActive.Height() == oldHeight+1);
    BOOST_ASSERT(ppBlock.IsProgPow());

    // Try to add regular block after PP one. Should throw an exception
    SetMockTime(mutableParams.nPPSwitchTime-1);    
    try {
        CreateBlock({}, coinbaseKey);
        BOOST_ASSERT(false);
    }
    catch (std::runtime_error &err) {
        BOOST_ASSERT(std::string(err.what()).find("bad-blk-progpow-state") != std::string::npos);
    }
    SetMockTime(0);

    mutableParams = originalParams;
}

BOOST_AUTO_TEST_SUITE_END()