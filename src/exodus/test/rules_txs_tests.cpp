#include "exodus/exodus.h"
#include "exodus/rules.h"

#include "test/test_bitcoin.h"

#include <stdint.h>
#include <limits>

#include <boost/test/unit_test.hpp>

using namespace exodus;

BOOST_FIXTURE_TEST_SUITE(exodus_rules_txs_tests, BasicTestingSetup)

const int MAX_BLOCK = std::numeric_limits<int>::max();
const int MAX_VERSION = std::numeric_limits<uint16_t>::max();

BOOST_AUTO_TEST_CASE(simple_send_restrictions)
{
    int EXODUS_SEND_BLOCK = ConsensusParams().EXODUS_SEND_BLOCK;

    BOOST_CHECK(!IsTransactionTypeAllowed(0,                EXODUS_PROPERTY_XZC,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(EXODUS_SEND_BLOCK,   EXODUS_PROPERTY_XZC,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        EXODUS_PROPERTY_XZC,  EXODUS_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(0,                EXODUS_PROPERTY_EXODUS,  EXODUS_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(EXODUS_SEND_BLOCK-1, EXODUS_PROPERTY_EXODUS,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        EXODUS_PROPERTY_EXODUS,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V1));
    BOOST_CHECK(!IsTransactionTypeAllowed(EXODUS_SEND_BLOCK,   EXODUS_PROPERTY_TEXODUS, EXODUS_TYPE_SIMPLE_SEND, MAX_VERSION));
    BOOST_CHECK(!IsTransactionTypeAllowed(MAX_BLOCK,        EXODUS_PROPERTY_TEXODUS, EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V1));

    BOOST_CHECK(IsTransactionTypeAllowed(EXODUS_SEND_BLOCK,    EXODUS_PROPERTY_EXODUS,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(MAX_BLOCK,         EXODUS_PROPERTY_EXODUS,  EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(0,                 EXODUS_PROPERTY_TEXODUS, EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
    BOOST_CHECK(IsTransactionTypeAllowed(MAX_BLOCK,         EXODUS_PROPERTY_TEXODUS, EXODUS_TYPE_SIMPLE_SEND, MP_TX_PKT_V0));
}


BOOST_AUTO_TEST_SUITE_END()
