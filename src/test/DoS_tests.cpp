// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for denial-of-service detection/prevention code

#include "chainparams.h"
#include "keystore.h"
#include "net.h"
#include "net_processing.h"
#include "pow.h"
#include "script/sign.h"
#include "serialize.h"
#include "util.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <algorithm>
#include <stdint.h>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

// Tests these internal-to-net_processing.cpp methods:
extern bool AddOrphanTx(const CTransactionRef& tx, NodeId peer);
extern void EraseOrphansFor(NodeId peer);
extern unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);
struct COrphanTx {
    CTransactionRef tx;
    NodeId fromPeer;
    int64_t nTimeExpire;
};
extern std::map<uint256, COrphanTx> mapOrphanTransactions;

CService ip(uint32_t i)
{
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

static NodeId id = 0;

BOOST_FIXTURE_TEST_SUITE(DoS_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(DoS_banning)
{
    std::atomic<bool> interruptDummy(false);

    connman->ClearBanned();
    CAddress addr1(ip(0xa0b0c001), NODE_NONE);
    CNode dummyNode1(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr1, 0, 0, "", true);
    dummyNode1.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&dummyNode1, *connman);
    dummyNode1.nVersion = 1;
    dummyNode1.fSuccessfullyConnected = true;
    Misbehaving(dummyNode1.GetId(), 100); // Should get discouraged
    SendMessages(&dummyNode1, *connman, interruptDummy);
    banmap_t banmap;
    connman->GetBanned(banmap);
    BOOST_CHECK(banmap.empty());
    BOOST_CHECK(connman->IsDiscouraged(addr1));
    BOOST_CHECK(!connman->IsDiscouraged(ip(0xa0b0c001 | 0x0000ff00))); // Different IP, not discouraged
    BOOST_CHECK(!connman->IsBanned(addr1));

    CAddress addr2(ip(0xa0b0c002), NODE_NONE);
    CNode dummyNode2(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr2, 1, 1, "", true);
    dummyNode2.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&dummyNode2, *connman);
    dummyNode2.nVersion = 1;
    dummyNode2.fSuccessfullyConnected = true;
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(&dummyNode2, *connman, interruptDummy);
    BOOST_CHECK(!connman->IsDiscouraged(addr2)); // 2 not discouraged yet...
    BOOST_CHECK(connman->IsDiscouraged(addr1));  // ... but 1 still should be
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(&dummyNode2, *connman, interruptDummy);
    BOOST_CHECK(connman->IsDiscouraged(addr2));
    connman->GetBanned(banmap);
    BOOST_CHECK(banmap.empty());
}

BOOST_AUTO_TEST_CASE(DoS_discouragement_disconnects_address)
{
    std::atomic<bool> interruptDummy(false);

    connman->ClearBanned();
    CAddress addr(ip(0xa0b0c001), NODE_NONE);
    CAddress sameAddr(CService(addr, Params().GetDefaultPort() + 1), NODE_NONE);
    CAddress otherAddr(ip(0xa0b0c002), NODE_NONE);
    CNode offender(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr, 2, 2, "", true);
    CNode sameAddressPeer(id++, NODE_NETWORK, 0, INVALID_SOCKET, sameAddr, 3, 3, "", true);
    CNode otherPeer(id++, NODE_NETWORK, 0, INVALID_SOCKET, otherAddr, 4, 4, "", true);

    offender.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&offender, *connman);
    offender.nVersion = 1;
    offender.fSuccessfullyConnected = true;

    {
        LOCK(connman->cs_vNodes);
        BOOST_REQUIRE(connman->vNodes.empty());
        connman->vNodes.push_back(&offender);
        connman->vNodes.push_back(&sameAddressPeer);
        connman->vNodes.push_back(&otherPeer);
    }

    Misbehaving(offender.GetId(), 100);
    SendMessages(&offender, *connman, interruptDummy);

    BOOST_CHECK(offender.fDisconnect);
    BOOST_CHECK(sameAddressPeer.fDisconnect);
    BOOST_CHECK(!otherPeer.fDisconnect);
    BOOST_CHECK(connman->IsDiscouraged(addr));
    BOOST_CHECK(!connman->IsDiscouraged(otherAddr));
    BOOST_CHECK(!connman->IsBanned(addr));
    banmap_t banmap;
    connman->GetBanned(banmap);
    BOOST_CHECK(banmap.empty());

    {
        LOCK(connman->cs_vNodes);
        for (CNode* node : {&offender, &sameAddressPeer, &otherPeer}) {
            connman->vNodes.erase(std::remove(connman->vNodes.begin(), connman->vNodes.end(), node), connman->vNodes.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(DoS_discouragement_disconnects_non_ip_address)
{
    std::atomic<bool> interruptDummy(false);

    connman->ClearBanned();
    const std::string onionAddresses[] = {
        "6hzph5hv6337r6p2.onion",
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    };

    for (const std::string& onionString : onionAddresses) {
        CNetAddr onion;
        BOOST_REQUIRE(onion.SetSpecial(onionString));
        CAddress addr(CService(onion, Params().GetDefaultPort()), NODE_NONE);
        CAddress sameAddr(CService(onion, Params().GetDefaultPort() + 1), NODE_NONE);
        CAddress otherAddr(ip(0xa0b0c002), NODE_NONE);
        CNode offender(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr, 5, 5, "", false);
        CNode sameAddressPeer(id++, NODE_NETWORK, 0, INVALID_SOCKET, sameAddr, 6, 6, "", false);
        CNode otherPeer(id++, NODE_NETWORK, 0, INVALID_SOCKET, otherAddr, 7, 7, "", false);

        offender.SetSendVersion(PROTOCOL_VERSION);
        GetNodeSignals().InitializeNode(&offender, *connman);
        offender.nVersion = 1;
        offender.fSuccessfullyConnected = true;

        {
            LOCK(connman->cs_vNodes);
            BOOST_REQUIRE(connman->vNodes.empty());
            connman->vNodes.push_back(&offender);
            connman->vNodes.push_back(&sameAddressPeer);
            connman->vNodes.push_back(&otherPeer);
        }

        Misbehaving(offender.GetId(), 100);
        SendMessages(&offender, *connman, interruptDummy);

        BOOST_CHECK(offender.fDisconnect);
        BOOST_CHECK(sameAddressPeer.fDisconnect);
        BOOST_CHECK(!otherPeer.fDisconnect);
        BOOST_CHECK(connman->IsDiscouraged(onion));
        BOOST_CHECK(!connman->IsBanned(onion));

        {
            LOCK(connman->cs_vNodes);
            for (CNode* node : {&offender, &sameAddressPeer, &otherPeer}) {
                connman->vNodes.erase(std::remove(connman->vNodes.begin(), connman->vNodes.end(), node), connman->vNodes.end());
            }
        }
    }

    CAddress invalidAddr;
    BOOST_REQUIRE(!invalidAddr.IsValid());
    CNode invalidPeer(id++, NODE_NETWORK, 0, INVALID_SOCKET, invalidAddr, 8, 8, "unresolved.example", false);
    invalidPeer.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&invalidPeer, *connman);
    invalidPeer.nVersion = 1;
    invalidPeer.fSuccessfullyConnected = true;

    {
        LOCK(connman->cs_vNodes);
        BOOST_REQUIRE(connman->vNodes.empty());
        connman->vNodes.push_back(&invalidPeer);
    }

    Misbehaving(invalidPeer.GetId(), 100);
    SendMessages(&invalidPeer, *connman, interruptDummy);
    BOOST_CHECK(invalidPeer.fDisconnect);

    {
        LOCK(connman->cs_vNodes);
        connman->vNodes.erase(std::remove(connman->vNodes.begin(), connman->vNodes.end(), &invalidPeer), connman->vNodes.end());
    }
}

BOOST_AUTO_TEST_CASE(DoS_banscore)
{
    std::atomic<bool> interruptDummy(false);

    connman->ClearBanned();
    ForceSetArg("-banscore", "111"); // because 11 is my favorite number
    CAddress addr1(ip(0xa0b0c001), NODE_NONE);
    CNode dummyNode1(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr1, 3, 1, "", true);
    dummyNode1.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&dummyNode1, *connman);
    dummyNode1.nVersion = 1;
    dummyNode1.fSuccessfullyConnected = true;
    Misbehaving(dummyNode1.GetId(), 100);
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(!connman->IsDiscouraged(addr1));
    Misbehaving(dummyNode1.GetId(), 10);
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(!connman->IsDiscouraged(addr1));
    Misbehaving(dummyNode1.GetId(), 1);
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(connman->IsDiscouraged(addr1));
    BOOST_CHECK(!connman->IsBanned(addr1));
    ForceSetArg("-banscore", std::to_string(DEFAULT_BANSCORE_THRESHOLD));
}

BOOST_AUTO_TEST_CASE(DoS_discouragement_does_not_expire_by_time)
{
    std::atomic<bool> interruptDummy(false);

    connman->ClearBanned();
    int64_t nStartTime = GetTime();
    SetMockTime(nStartTime); // Overrides future calls to GetTime()

    CAddress addr(ip(0xa0b0c001), NODE_NONE);
    CNode dummyNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr, 4, 4, "", true);
    dummyNode.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&dummyNode, *connman);
    dummyNode.nVersion = 1;
    dummyNode.fSuccessfullyConnected = true;

    Misbehaving(dummyNode.GetId(), 100);
    SendMessages(&dummyNode, *connman, interruptDummy);
    BOOST_CHECK(connman->IsDiscouraged(addr));
    BOOST_CHECK(!connman->IsBanned(addr));

    SetMockTime(nStartTime+60*60);
    BOOST_CHECK(connman->IsDiscouraged(addr));

    SetMockTime(nStartTime + 60 * 60 * 24 + 1);
    BOOST_CHECK(connman->IsDiscouraged(addr));
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(DoS_manual_bantime)
{
    connman->ClearBanned();
    int64_t nStartTime = GetTime();
    SetMockTime(nStartTime);

    CAddress addr(ip(0xa0b0c001), NODE_NONE);
    connman->Ban(addr, BanReasonManuallyAdded);
    BOOST_CHECK(connman->IsBanned(addr));

    banmap_t banmap;
    connman->GetBanned(banmap);
    BOOST_REQUIRE_EQUAL(banmap.size(), 1U);
    BOOST_CHECK_EQUAL(banmap.begin()->second.banReason, BanReasonManuallyAdded);

    SetMockTime(nStartTime+60*60*24+1);
    BOOST_CHECK(!connman->IsBanned(addr));
    SetMockTime(0);
}

CTransactionRef RandomOrphan()
{
    std::map<uint256, COrphanTx>::iterator it;
    it = mapOrphanTransactions.lower_bound(GetRandHash());
    if (it == mapOrphanTransactions.end())
        it = mapOrphanTransactions.begin();
    return it->second.tx;
}

BOOST_AUTO_TEST_CASE(DoS_mapOrphans)
{
    CKey key;
    key.MakeNewKey(true);
    CBasicKeyStore keystore;
    keystore.AddKey(key);

    // 50 orphan transactions:
    for (int i = 0; i < 50; i++)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = GetRandHash();
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

        AddOrphanTx(MakeTransactionRef(tx), i);
    }

    // ... and 50 that depend on other orphans:
    for (int i = 0; i < 50; i++)
    {
        CTransactionRef txPrev = RandomOrphan();

        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].prevout.hash = txPrev->GetHash();
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL);

        AddOrphanTx(MakeTransactionRef(tx), i);
    }

    // This really-big orphan should be ignored:
    for (int i = 0; i < 10; i++)
    {
        CTransactionRef txPrev = RandomOrphan();

        CMutableTransaction tx;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1*CENT;
        tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
        tx.vin.resize(2777);
        for (unsigned int j = 0; j < tx.vin.size(); j++)
        {
            tx.vin[j].prevout.n = j;
            tx.vin[j].prevout.hash = txPrev->GetHash();
        }
        SignSignature(keystore, *txPrev, tx, 0, SIGHASH_ALL);
        // Re-use same signature for other inputs
        // (they don't have to be valid for this test)
        for (unsigned int j = 1; j < tx.vin.size(); j++)
            tx.vin[j].scriptSig = tx.vin[0].scriptSig;

        BOOST_CHECK(!AddOrphanTx(MakeTransactionRef(tx), i));
    }

    // Test EraseOrphansFor:
    for (NodeId i = 0; i < 3; i++)
    {
        size_t sizeBefore = mapOrphanTransactions.size();
        EraseOrphansFor(i);
        BOOST_CHECK(mapOrphanTransactions.size() < sizeBefore);
    }

    // Test LimitOrphanTxSize() function:
    LimitOrphanTxSize(40);
    BOOST_CHECK(mapOrphanTransactions.size() <= 40);
    LimitOrphanTxSize(10);
    BOOST_CHECK(mapOrphanTransactions.size() <= 10);
    LimitOrphanTxSize(0);
    BOOST_CHECK(mapOrphanTransactions.empty());
}

BOOST_AUTO_TEST_SUITE_END()
