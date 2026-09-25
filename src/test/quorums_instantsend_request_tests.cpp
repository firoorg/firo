// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbwrapper.h"
#include "llmq/quorums_instantsend.h"
#include "net.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

namespace llmq
{

struct CInstantSendRequestTestAccess {
    static void AskNodesForLockedTx(CInstantSendManager& manager, const uint256& txid)
    {
        manager.AskNodesForLockedTx(txid);
    }
};

} // namespace llmq

namespace
{

struct InstantSendRequestSetup : BasicTestingSetup {
    CDBWrapper db;
    llmq::CInstantSendManager manager;
    std::vector<std::unique_ptr<CNode> > nodes;

    InstantSendRequestSetup() : db(boost::filesystem::temp_directory_path() / boost::filesystem::unique_path(), 1 << 20, true, false),
                                manager(db)
    {
        g_connman = std::make_unique<CConnman>(0x1337, 0x1337);
    }

    ~InstantSendRequestSetup()
    {
        LOCK(g_connman->cs_vNodes);
        g_connman->vNodes.clear();
    }

    void AddNode(bool masternode, bool knowsTx, const uint256& txid)
    {
        auto node = std::make_unique<CNode>(nodes.size(), NODE_NETWORK, 0, INVALID_SOCKET, CAddress(), 0, 0);
        node->fZnode = masternode;
        node->fSuccessfullyConnected = true;
        if (knowsTx) {
            LOCK(node->cs_inventory);
            node->filterInventoryKnown.insert(txid);
        }
        {
            LOCK(g_connman->cs_vNodes);
            g_connman->vNodes.emplace_back(node.get());
        }
        nodes.emplace_back(std::move(node));
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(quorums_instantsend_request_tests, InstantSendRequestSetup)

BOOST_AUTO_TEST_CASE(asks_at_most_four_peers_and_prefers_masternodes)
{
    uint256 txid;
    txid.SetHex("01");

    AddNode(false, true, txid);
    AddNode(false, true, txid);
    AddNode(false, true, txid);
    AddNode(true, true, txid);
    AddNode(true, false, txid);
    AddNode(true, true, txid);
    AddNode(true, true, txid);
    AddNode(false, true, txid);

    llmq::CInstantSendRequestTestAccess::AskNodesForLockedTx(manager, txid);

    const std::vector<bool> expected{true, false, false, true, false, true, true, false};
    for (size_t i = 0; i < nodes.size(); ++i) {
        LOCK(nodes[i]->cs_inventory);
        BOOST_CHECK_EQUAL(nodes[i]->setAskFor.count(txid), expected[i] ? 1 : 0);
        BOOST_CHECK_EQUAL(nodes[i]->GetRefCount(), 0);
    }
    g_connman->RemoveAskFor(txid);
}

BOOST_AUTO_TEST_SUITE_END()
