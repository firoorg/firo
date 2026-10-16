// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "llmq/quorums_instantsend.h"
#include "test/test_bitcoin.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{
struct CInstantSendManagerTestAccess
{
    static bool CheckCanLock(CInstantSendManager& manager, const COutPoint& outpoint)
    {
        return manager.CheckCanLock(outpoint, false, uint256(), nullptr, Params().GetConsensus());
    }
};

BOOST_FIXTURE_TEST_SUITE(quorums_instantsend_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(stem_parent_is_not_treated_as_mined)
{
    CMutableTransaction parent;
    parent.vin.resize(1);
    parent.vin[0].scriptSig = CScript() << OP_11;
    parent.vout.resize(1);
    parent.vout[0].nValue = 1;
    parent.vout[0].scriptPubKey = CScript() << OP_TRUE;

    txpools.clear();
    TestMemPoolEntryHelper entry;
    txpools.getStemTxPool().addUnchecked(parent.GetHash(), entry.FromTx(parent));

    BOOST_REQUIRE(!mempool.exists(parent.GetHash()));
    BOOST_REQUIRE(txpools.getStemTxPool().exists(parent.GetHash()));
    BOOST_CHECK(!CInstantSendManagerTestAccess::CheckCanLock(
        *quorumInstantSendManager, COutPoint(parent.GetHash(), 0)));

    txpools.clear();
}

BOOST_AUTO_TEST_SUITE_END()
}
