// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for denial-of-service detection/prevention code

#include "arith_uint256.h"
#include "blockencodings.h"
#include "chainparams.h"
#include "hash.h"
#include "keystore.h"
#include "net.h"
#include "net_processing.h"
#include "netmessagemaker.h"
#include "pow.h"
#include "script/sign.h"
#include "serialize.h"
#include "util.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <limits>
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

struct BlockTxnTestingSetup : public TestChain100Setup {
    BlockTxnTestingSetup() : TestChain100Setup(1) {}
};

template <typename Payload>
static void QueueNetMessage(CNode& node, const char* command, const Payload& value)
{
    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << value;

    CMessageHeader header(Params().MessageStart(), command, payload.size());
    const uint256 payloadHash = Hash(payload.begin(), payload.end());
    memcpy(header.pchChecksum, payloadHash.begin(), CMessageHeader::CHECKSUM_SIZE);

    CDataStream serializedHeader(SER_NETWORK, PROTOCOL_VERSION);
    serializedHeader << header;

    LOCK(node.cs_vProcessMsg);
    node.vProcessMsg.emplace_back(Params().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
    CNetMessage& message = node.vProcessMsg.back();
    BOOST_REQUIRE_EQUAL(
        static_cast<size_t>(message.readHeader(serializedHeader.data(), serializedHeader.size())),
        serializedHeader.size());
    BOOST_REQUIRE_EQUAL(
        static_cast<size_t>(message.readData(payload.data(), payload.size())),
        payload.size());
    message.nTime = GetTimeMicros();
    node.nProcessQueueSize += payload.size() + CMessageHeader::HEADER_SIZE;
}

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
    Misbehaving(dummyNode1.GetId(), 100); // Should get banned
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(connman->IsBanned(addr1));
    BOOST_CHECK(!connman->IsBanned(ip(0xa0b0c001|0x0000ff00))); // Different IP, not banned

    CAddress addr2(ip(0xa0b0c002), NODE_NONE);
    CNode dummyNode2(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr2, 1, 1, "", true);
    dummyNode2.SetSendVersion(PROTOCOL_VERSION);
    GetNodeSignals().InitializeNode(&dummyNode2, *connman);
    dummyNode2.nVersion = 1;
    dummyNode2.fSuccessfullyConnected = true;
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(&dummyNode2, *connman, interruptDummy);
    BOOST_CHECK(!connman->IsBanned(addr2)); // 2 not banned yet...
    BOOST_CHECK(connman->IsBanned(addr1));  // ... but 1 still should be
    Misbehaving(dummyNode2.GetId(), 50);
    SendMessages(&dummyNode2, *connman, interruptDummy);
    BOOST_CHECK(connman->IsBanned(addr2));
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
    BOOST_CHECK(!connman->IsBanned(addr1));
    Misbehaving(dummyNode1.GetId(), 10);
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(!connman->IsBanned(addr1));
    Misbehaving(dummyNode1.GetId(), 1);
    SendMessages(&dummyNode1, *connman, interruptDummy);
    BOOST_CHECK(connman->IsBanned(addr1));
    ForceSetArg("-banscore", std::to_string(DEFAULT_BANSCORE_THRESHOLD));
}

BOOST_AUTO_TEST_CASE(DoS_bantime)
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
    BOOST_CHECK(connman->IsBanned(addr));

    SetMockTime(nStartTime+60*60);
    BOOST_CHECK(connman->IsBanned(addr));

    SetMockTime(nStartTime+60*60*24+1);
    BOOST_CHECK(!connman->IsBanned(addr));
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

BOOST_AUTO_TEST_CASE(inv_getheaders_coalesced)
{
    std::atomic<bool> interruptDummy(false);
    PeerLogicValidation peerLogic(connman);

    CAddress addr(ip(0xa0b0c003), NODE_NONE);
    CNode dummyNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, addr, 0, 0, "", true);
    dummyNode.SetSendVersion(PROTOCOL_VERSION);
    dummyNode.SetRecvVersion(PROTOCOL_VERSION);
    dummyNode.nVersion = PROTOCOL_VERSION;
    dummyNode.fSuccessfullyConnected = true;
    GetNodeSignals().InitializeNode(&dummyNode, *connman);

    struct NodeStateCleanup {
        explicit NodeStateCleanup(NodeId nodeId) : nodeId(nodeId) {}

        ~NodeStateCleanup()
        {
            bool updateConnectionTime = false;
            GetNodeSignals().FinalizeNode(nodeId, updateConnectionTime);
        }

        NodeId nodeId;
    } nodeStateCleanup(dummyNode.GetId());

    const uint256 firstBlock = uint256S("01");
    const uint256 secondBlock = uint256S("02");
    const uint256 txHash = uint256S("04");
    const uint256 dandelionTxHash = uint256S("05");
    std::vector<CInv> inventory{
        CInv(MSG_BLOCK, firstBlock),
        CInv(MSG_TX, txHash),
        CInv(MSG_BLOCK, secondBlock),
        CInv(MSG_DANDELION_TX, dandelionTxHash),
    };
    inventory.reserve(MAX_INV_SZ);

    uint256 finalBlock;
    for (uint32_t value = 100; inventory.size() < MAX_INV_SZ - 1; ++value) {
        finalBlock = ArithToUint256(value);
        inventory.emplace_back(MSG_BLOCK, finalBlock);
    }
    inventory.emplace_back(MSG_BLOCK, Params().GenesisBlock().GetHash());
    BOOST_REQUIRE_EQUAL(inventory.size(), MAX_INV_SZ);

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << inventory;
    CMessageHeader header(Params().MessageStart(), NetMsgType::INV, payload.size());
    const uint256 payloadHash = Hash(payload.begin(), payload.end());
    memcpy(header.pchChecksum, payloadHash.begin(), CMessageHeader::CHECKSUM_SIZE);

    CDataStream serializedHeader(SER_NETWORK, PROTOCOL_VERSION);
    serializedHeader << header;
    {
        LOCK(dummyNode.cs_vProcessMsg);
        dummyNode.vProcessMsg.emplace_back(Params().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
        CNetMessage& message = dummyNode.vProcessMsg.back();
        BOOST_REQUIRE_EQUAL(
            static_cast<size_t>(message.readHeader(serializedHeader.data(), serializedHeader.size())),
            serializedHeader.size());
        BOOST_REQUIRE_EQUAL(
            static_cast<size_t>(message.readData(payload.data(), payload.size())),
            payload.size());
        message.nTime = GetTimeMicros();
        dummyNode.nProcessQueueSize += payload.size() + CMessageHeader::HEADER_SIZE;
    }

    BOOST_CHECK(!ProcessMessages(&dummyNode, *connman, interruptDummy));
    BOOST_CHECK(!dummyNode.fDisconnect);
    BOOST_CHECK(dummyNode.vProcessMsg.empty());

    const CSerializedNetMsg expected = CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), finalBlock);
    const size_t expectedQueuedBytes = CMessageHeader::HEADER_SIZE + expected.data.size();
    const size_t vulnerableQueuedBytes = (MAX_INV_SZ - 3) * expectedQueuedBytes;
    BOOST_CHECK_LT(expectedQueuedBytes, DEFAULT_MAXSENDBUFFER * 1000);
    BOOST_CHECK_GT(vulnerableQueuedBytes, DEFAULT_MAXSENDBUFFER * 1000);

    CNodeStats stats;
    dummyNode.copyStats(stats);
    const auto getHeadersBytes = stats.mapSendBytesPerMsgCmd.find(NetMsgType::GETHEADERS);
    BOOST_REQUIRE(getHeadersBytes != stats.mapSendBytesPerMsgCmd.end());
    BOOST_CHECK_EQUAL(getHeadersBytes->second, expectedQueuedBytes);

    {
        LOCK(dummyNode.cs_vSend);
        BOOST_CHECK_EQUAL(dummyNode.nSendSize, expectedQueuedBytes);
        BOOST_CHECK_EQUAL(dummyNode.vSendMsg.size(), 2U);
        BOOST_REQUIRE_GE(dummyNode.vSendMsg.size(), 2U);

        CDataStream sentHeader(
            dummyNode.vSendMsg[dummyNode.vSendMsg.size() - 2],
            SER_NETWORK,
            PROTOCOL_VERSION);
        CMessageHeader parsedHeader(Params().MessageStart());
        sentHeader >> parsedHeader;
        BOOST_CHECK_EQUAL(parsedHeader.GetCommand(), NetMsgType::GETHEADERS);
        BOOST_CHECK_EQUAL(parsedHeader.nMessageSize, expected.data.size());

        CDataStream sentPayload(dummyNode.vSendMsg.back(), SER_NETWORK, PROTOCOL_VERSION);
        CBlockLocator locator;
        uint256 stopHash;
        sentPayload >> locator >> stopHash;
        BOOST_CHECK(!locator.IsNull());
        BOOST_CHECK(stopHash == finalBlock);
        BOOST_CHECK(sentPayload.empty());
    }

    {
        LOCK(dummyNode.cs_inventory);
        BOOST_CHECK(dummyNode.filterInventoryKnown.contains(txHash));
        BOOST_CHECK(dummyNode.filterDandelionInventoryKnown.contains(dandelionTxHash));
    }
}

BOOST_FIXTURE_TEST_CASE(blocktxn_repeated_response, BlockTxnTestingSetup)
{
    std::atomic<bool> interruptDummy(false);
    PeerLogicValidation peerLogic(connman);

    CAddress ownerAddress(ip(0xa0b0c004), NODE_NONE);
    CNode ownerNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, ownerAddress, 0, 0, "", true);
    ownerNode.SetSendVersion(PROTOCOL_VERSION);
    ownerNode.SetRecvVersion(PROTOCOL_VERSION);
    ownerNode.nVersion = PROTOCOL_VERSION;
    ownerNode.fSuccessfullyConnected = true;
    GetNodeSignals().InitializeNode(&ownerNode, *connman);

    CAddress nonOwnerAddress(ip(0xa0b0c005), NODE_NONE);
    CNode nonOwnerNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, nonOwnerAddress, 1, 1, "", true);
    nonOwnerNode.SetSendVersion(PROTOCOL_VERSION);
    nonOwnerNode.SetRecvVersion(PROTOCOL_VERSION);
    nonOwnerNode.nVersion = PROTOCOL_VERSION;
    nonOwnerNode.fSuccessfullyConnected = true;
    GetNodeSignals().InitializeNode(&nonOwnerNode, *connman);

    struct NodeStateCleanup {
        NodeStateCleanup(NodeId ownerId, NodeId nonOwnerId) : ownerId(ownerId), nonOwnerId(nonOwnerId) {}

        ~NodeStateCleanup()
        {
            bool updateConnectionTime = false;
            GetNodeSignals().FinalizeNode(nonOwnerId, updateConnectionTime);
            GetNodeSignals().FinalizeNode(ownerId, updateConnectionTime);
        }

        NodeId ownerId;
        NodeId nonOwnerId;
    } nodeStateCleanup(ownerNode.GetId(), nonOwnerNode.GetId());

    const auto processMessage = [&](CNode& node, bool expectDisconnect = false) {
        // TestingSetup constructs but does not start connman, leaving its synthetic send limit at zero.
        node.fPauseSend = false;
        BOOST_CHECK(!ProcessMessages(&node, *connman, interruptDummy));
        BOOST_CHECK(node.vProcessMsg.empty());
        BOOST_CHECK(node.fDisconnect == expectDisconnect);
    };

    int initialHeight;
    {
        LOCK(cs_main);
        initialHeight = chainActive.Height();
    }

    CBlock validBlock = CreateBlock({}, coinbaseKey);
    CBlockHeaderAndShortTxIDs validCompactBlock(validBlock, false);
    QueueNetMessage(ownerNode, NetMsgType::CMPCTBLOCK, validCompactBlock);
    processMessage(ownerNode);

    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainActive.Tip());
        BOOST_CHECK_EQUAL(chainActive.Height(), initialHeight + 1);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == validBlock.GetHash());
    }

    CNodeStateStats ownerState;
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_CHECK(ownerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 0);

    CMutableTransaction expectedTransaction;
    expectedTransaction.vin.resize(1);
    expectedTransaction.vin[0].prevout = COutPoint(GetRandHash(), 0);
    expectedTransaction.vin[0].scriptSig << OP_1;
    expectedTransaction.vout.resize(1);
    expectedTransaction.vout[0].nValue = 1;
    expectedTransaction.vout[0].scriptPubKey << OP_TRUE;

    CBlock attackBlock = CreateBlock({expectedTransaction}, coinbaseKey);
    BOOST_REQUIRE_EQUAL(attackBlock.vtx.size(), 2U);
    CBlockHeaderAndShortTxIDs attackCompactBlock(attackBlock, false);
    QueueNetMessage(ownerNode, NetMsgType::CMPCTBLOCK, attackCompactBlock);
    processMessage(ownerNode);

    {
        LOCK(ownerNode.cs_vSend);
        BOOST_REQUIRE_GE(ownerNode.vSendMsg.size(), 2U);

        CDataStream sentHeader(
            ownerNode.vSendMsg[ownerNode.vSendMsg.size() - 2],
            SER_NETWORK,
            PROTOCOL_VERSION);
        CMessageHeader parsedHeader(Params().MessageStart());
        sentHeader >> parsedHeader;
        BOOST_CHECK_EQUAL(parsedHeader.GetCommand(), NetMsgType::GETBLOCKTXN);

        CDataStream sentPayload(ownerNode.vSendMsg.back(), SER_NETWORK, PROTOCOL_VERSION);
        BlockTransactionsRequest request;
        sentPayload >> request;
        BOOST_CHECK(request.blockhash == attackBlock.GetHash());
        BOOST_REQUIRE_EQUAL(request.indexes.size(), 1U);
        BOOST_CHECK_EQUAL(request.indexes[0], 1U);
        BOOST_CHECK(sentPayload.empty());
    }

    ownerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_REQUIRE_EQUAL(ownerState.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(ownerState.vHeightInFlight[0], initialHeight + 2);
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 0);

    CMutableTransaction wrongTransaction(expectedTransaction);
    ++wrongTransaction.nLockTime;
    BlockTransactions mismatchedResponse;
    mismatchedResponse.blockhash = attackBlock.GetHash();
    mismatchedResponse.txn.push_back(MakeTransactionRef(wrongTransaction));

    QueueNetMessage(ownerNode, NetMsgType::BLOCKTXN, mismatchedResponse);
    processMessage(ownerNode);

    {
        LOCK(ownerNode.cs_vSend);
        BOOST_REQUIRE_GE(ownerNode.vSendMsg.size(), 2U);

        CDataStream sentHeader(
            ownerNode.vSendMsg[ownerNode.vSendMsg.size() - 2],
            SER_NETWORK,
            PROTOCOL_VERSION);
        CMessageHeader parsedHeader(Params().MessageStart());
        sentHeader >> parsedHeader;
        BOOST_CHECK_EQUAL(parsedHeader.GetCommand(), NetMsgType::GETDATA);

        CDataStream sentPayload(ownerNode.vSendMsg.back(), SER_NETWORK, PROTOCOL_VERSION);
        std::vector<CInv> requests;
        sentPayload >> requests;
        BOOST_REQUIRE_EQUAL(requests.size(), 1U);
        BOOST_CHECK(requests[0].hash == attackBlock.GetHash());
        BOOST_CHECK(sentPayload.empty());
    }

    ownerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_REQUIRE_EQUAL(ownerState.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(ownerState.vHeightInFlight[0], initialHeight + 2);
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 0);

    QueueNetMessage(nonOwnerNode, NetMsgType::BLOCKTXN, mismatchedResponse);
    processMessage(nonOwnerNode);

    ownerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_REQUIRE_EQUAL(ownerState.vHeightInFlight.size(), 1U);
    BOOST_CHECK_EQUAL(ownerState.vHeightInFlight[0], initialHeight + 2);
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 0);

    CNodeStateStats nonOwnerState;
    BOOST_REQUIRE(GetNodeStateStats(nonOwnerNode.GetId(), nonOwnerState));
    BOOST_CHECK(nonOwnerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(nonOwnerState.nMisbehavior, 0);

    QueueNetMessage(ownerNode, NetMsgType::BLOCKTXN, mismatchedResponse);
    processMessage(ownerNode, true);

    ownerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_CHECK(ownerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 100);

    nonOwnerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(nonOwnerNode.GetId(), nonOwnerState));
    BOOST_CHECK(nonOwnerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(nonOwnerState.nMisbehavior, 0);

    QueueNetMessage(nonOwnerNode, NetMsgType::BLOCKTXN, mismatchedResponse);
    processMessage(nonOwnerNode);

    ownerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(ownerNode.GetId(), ownerState));
    BOOST_CHECK(ownerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(ownerState.nMisbehavior, 100);

    nonOwnerState = CNodeStateStats();
    BOOST_REQUIRE(GetNodeStateStats(nonOwnerNode.GetId(), nonOwnerState));
    BOOST_CHECK(nonOwnerState.vHeightInFlight.empty());
    BOOST_CHECK_EQUAL(nonOwnerState.nMisbehavior, 0);

    {
        LOCK(cs_main);
        BOOST_REQUIRE(chainActive.Tip());
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == validBlock.GetHash());
    }
}

BOOST_AUTO_TEST_CASE(inv_queue_adaptive_drain)
{
    std::atomic<bool> interruptDummy(false);
    PeerLogicValidation peerLogic(connman);

    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(0), 35U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(999), 35U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(1000), 40U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(2000), 45U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(192999), 995U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(193000), 1000U);
    BOOST_CHECK_EQUAL(GetInventoryBroadcastMax(std::numeric_limits<size_t>::max()), 1000U);

    CAddress peerAddress(ip(0xa0b0c006), NODE_NONE);
    CNode peerNode(id++, NODE_NETWORK, 0, INVALID_SOCKET, peerAddress, 0, 0, "", true);
    peerNode.SetSendVersion(PROTOCOL_VERSION);
    peerNode.SetRecvVersion(PROTOCOL_VERSION);
    peerNode.nVersion = PROTOCOL_VERSION;
    peerNode.fWhitelisted = true;
    peerNode.fSuccessfullyConnected = true;
    {
        LOCK(peerNode.cs_filter);
        peerNode.fRelayTxes = true;
    }
    GetNodeSignals().InitializeNode(&peerNode, *connman);

    struct NodeStateCleanup {
        explicit NodeStateCleanup(NodeId nodeId) : nodeId(nodeId) {}

        ~NodeStateCleanup()
        {
            bool updateConnectionTime = false;
            GetNodeSignals().FinalizeNode(nodeId, updateConnectionTime);
        }

        NodeId nodeId;
    } nodeStateCleanup(peerNode.GetId());

    BOOST_REQUIRE_EQUAL(mempool.size(), 0U);

    CMutableTransaction parent;
    parent.vin.resize(1);
    parent.vin[0].prevout = COutPoint(ArithToUint256(1), 0);
    parent.vin[0].scriptSig << OP_1;
    parent.vout.resize(1);
    parent.vout[0].nValue = 1;
    parent.vout[0].scriptPubKey << OP_TRUE;

    TestMemPoolEntryHelper parentEntry;
    const uint256 parentHash = parent.GetHash();
    BOOST_REQUIRE(mempool.addUnchecked(parentHash, parentEntry.Fee(1000).FromTx(parent)));

    CMutableTransaction child;
    child.vin.resize(1);
    child.vin[0].prevout = COutPoint(parentHash, 0);
    child.vin[0].scriptSig << OP_1;
    child.vout.resize(1);
    child.vout[0].nValue = 1;
    child.vout[0].scriptPubKey << OP_TRUE;

    CTxMemPool::setEntries childAncestors;
    const auto parentIt = mempool.mapTx.find(parentHash);
    BOOST_REQUIRE(parentIt != mempool.mapTx.end());
    childAncestors.insert(parentIt);

    TestMemPoolEntryHelper childEntry;
    const uint256 childHash = child.GetHash();
    BOOST_REQUIRE(mempool.addUnchecked(
        childHash,
        childEntry.Fee(1000000).FromTx(child, &mempool),
        childAncestors));

    std::vector<uint256> liveHashes{parentHash, childHash};
    for (uint32_t tag = 2; liveHashes.size() < 50; ++tag) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(ArithToUint256(1000 + tag), 0);
        tx.vin[0].scriptSig << OP_1;
        tx.vout.resize(1);
        tx.vout[0].nValue = 1;
        tx.vout[0].scriptPubKey << OP_TRUE;
        tx.nLockTime = tag;

        TestMemPoolEntryHelper entry;
        const uint256 hash = tx.GetHash();
        BOOST_REQUIRE(mempool.addUnchecked(hash, entry.Fee((tag + 1) * 1000).FromTx(tx)));
        liveHashes.push_back(hash);
    }
    BOOST_REQUIRE_EQUAL(mempool.size(), 50U);

    std::vector<uint256> missingHashes;
    missingHashes.reserve(2000);
    for (uint32_t value = 100000; missingHashes.size() < 2000; ++value) {
        const uint256 hash = ArithToUint256(value);
        if (!mempool.exists(hash))
            missingHashes.push_back(hash);
    }

    const uint256& forcedHighFeeHash = liveHashes.back();
    const uint256& lowFeeHash = liveHashes[2];
    const uint256& missingHash = missingHashes.front();
    BOOST_CHECK(mempool.CompareDepthAndScore(missingHash, forcedHighFeeHash));
    BOOST_CHECK(!mempool.CompareDepthAndScore(forcedHighFeeHash, missingHash));
    BOOST_CHECK(mempool.CompareDepthAndScore(forcedHighFeeHash, lowFeeHash));
    BOOST_CHECK(!mempool.CompareDepthAndScore(lowFeeHash, forcedHighFeeHash));
    BOOST_CHECK(mempool.CompareDepthAndScore(parentHash, childHash));
    BOOST_CHECK(!mempool.CompareDepthAndScore(childHash, parentHash));

    for (const uint256& hash : missingHashes)
        peerNode.PushInventory(CInv(MSG_TX, hash));
    for (size_t i = 0; i + 1 < liveHashes.size(); ++i)
        peerNode.PushInventory(CInv(MSG_TX, liveHashes[i]));

    const CInv forcedInventory(MSG_TX, forcedHighFeeHash);
    peerNode.AddInventoryKnown(forcedInventory);
    peerNode.PushInventory(forcedInventory, true);

    {
        LOCK(peerNode.cs_inventory);
        BOOST_REQUIRE_EQUAL(peerNode.setInventoryTxToSend.size(), 2050U);
        BOOST_REQUIRE_EQUAL(peerNode.setInventoryForcedToSend.size(), 1U);
    }

    BOOST_CHECK(SendMessages(&peerNode, *connman, interruptDummy));

    size_t invMessageCount = 0;
    std::vector<CInv> sentInventory;
    {
        LOCK(peerNode.cs_vSend);
        size_t position = 0;
        while (position < peerNode.vSendMsg.size()) {
            CDataStream sentHeader(peerNode.vSendMsg[position++], SER_NETWORK, PROTOCOL_VERSION);
            CMessageHeader parsedHeader(Params().MessageStart());
            sentHeader >> parsedHeader;
            BOOST_CHECK(sentHeader.empty());

            if (parsedHeader.nMessageSize == 0)
                continue;

            BOOST_REQUIRE_LT(position, peerNode.vSendMsg.size());
            CDataStream sentPayload(peerNode.vSendMsg[position++], SER_NETWORK, PROTOCOL_VERSION);
            if (parsedHeader.GetCommand() != NetMsgType::INV)
                continue;

            std::vector<CInv> inventory;
            sentPayload >> inventory;
            BOOST_CHECK(sentPayload.empty());
            sentInventory.insert(sentInventory.end(), inventory.begin(), inventory.end());
            ++invMessageCount;
        }
    }

    BOOST_CHECK_EQUAL(invMessageCount, 1U);
    BOOST_CHECK_EQUAL(sentInventory.size(), 45U);

    std::set<uint256> sentHashes;
    for (const CInv& inv : sentInventory) {
        BOOST_CHECK_EQUAL(inv.type, MSG_TX);
        sentHashes.insert(inv.hash);
    }
    BOOST_CHECK_EQUAL(sentHashes.size(), sentInventory.size());
    BOOST_CHECK(sentHashes.count(forcedHighFeeHash) == 1);
    BOOST_CHECK(sentHashes.count(childHash) == 0);

    size_t remainingMissing = 0;
    bool allRemainingTransactionsAreLive = true;
    {
        LOCK(peerNode.cs_inventory);
        BOOST_CHECK_EQUAL(peerNode.setInventoryTxToSend.size(), 5U);
        BOOST_CHECK(peerNode.setInventoryForcedToSend.empty());
        for (const uint256& hash : missingHashes)
            remainingMissing += peerNode.setInventoryTxToSend.count(hash);
        for (const uint256& hash : peerNode.setInventoryTxToSend)
            allRemainingTransactionsAreLive &= mempool.exists(hash);
    }
    BOOST_CHECK_EQUAL(remainingMissing, 0U);
    BOOST_CHECK(allRemainingTransactionsAreLive);

    CNodeStateStats peerState;
    BOOST_REQUIRE(GetNodeStateStats(peerNode.GetId(), peerState));
    BOOST_CHECK_EQUAL(peerState.nMisbehavior, 0);
    BOOST_CHECK(!peerNode.fDisconnect);
}

BOOST_AUTO_TEST_SUITE_END()
