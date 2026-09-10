// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbwrapper.h"
#include "llmq/quorums_instantsend.h"
#include "net.h"
#include "test/test_bitcoin.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace llmq
{

struct CInstantSendManagerTestAccess {
    static bool PreVerify(CInstantSendManager& manager, const CInstantSendLock& islock, bool& ban)
    {
        return manager.PreVerifyInstantSendLock(1, islock, ban);
    }

    static void ProcessMessage(CInstantSendManager& manager, CNode& peer, const CInstantSendLock& islock, CConnman& connman)
    {
        manager.ProcessMessageInstantSendLock(&peer, islock, connman);
    }

    static size_t PendingCount(CInstantSendManager& manager)
    {
        LOCK(manager.cs);
        return manager.pendingInstantSendLocks.size();
    }

    static void ProcessPending(CInstantSendManager& manager)
    {
        manager.ProcessPendingInstantSendLocks();
    }

    static void ProcessPending(CInstantSendManager& manager, NodeId nodeId, const CInstantSendLock& islock)
    {
        std::unordered_map<uint256, std::pair<NodeId, CInstantSendLock>, StaticSaltedHasher> pending;
        pending.emplace(::SerializeHash(islock), std::make_pair(nodeId, islock));
        manager.ProcessPendingInstantSendLocks(0, pending, false);
    }
};

} // namespace llmq

namespace
{

uint256 HashFromNonce(size_t nonce)
{
    return uint256S(strprintf("%064x", static_cast<unsigned int>(nonce)));
}

llmq::CInstantSendLock MakeInstantSendLock(size_t nonce)
{
    llmq::CInstantSendLock islock;
    islock.txid = HashFromNonce(nonce + 1);
    islock.inputs.emplace_back(HashFromNonce(1), static_cast<uint32_t>(nonce));
    return islock;
}

struct InstantSendSetup : BasicTestingSetup {
    CDBWrapper db;
    llmq::CSigningManager signingManager;
    llmq::CInstantSendManager manager;
    CNode peer;
    llmq::CSigningManager* previousSigningManager;
    bool previousTxIndex;

    InstantSendSetup() : db(boost::filesystem::temp_directory_path() / boost::filesystem::unique_path(), 1 << 20, true, false),
                         signingManager(db, true),
                         manager(db),
                         peer(1, NODE_NETWORK, 0, INVALID_SOCKET, CAddress(), 0, 0, "", true),
                         previousSigningManager(llmq::quorumSigningManager),
                         previousTxIndex(fTxIndex)
    {
        llmq::quorumSigningManager = &signingManager;
        fTxIndex = false;
        g_connman = std::make_unique<CConnman>(0x1337, 0x1337);
    }

    ~InstantSendSetup()
    {
        llmq::quorumSigningManager = previousSigningManager;
        fTxIndex = previousTxIndex;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(quorums_instantsend_tests, InstantSendSetup)

BOOST_AUTO_TEST_CASE(input_limit_is_protocol_derived)
{
    llmq::CInstantSendLock islock;
    islock.txid = HashFromNonce(1);
    islock.inputs.reserve(llmq::CInstantSendLock::MAX_INPUTS + 1);

    BOOST_CHECK_EQUAL(llmq::CInstantSendLock::MAX_INPUTS, MAX_BLOCK_BASE_SIZE / 41);
    for (size_t i = 0; i < llmq::CInstantSendLock::MAX_INPUTS - 1; ++i) {
        islock.inputs.emplace_back(HashFromNonce(i + 1), 0);
    }

    bool ban = false;
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::PreVerify(manager, islock, ban));
    BOOST_CHECK(!ban);

    islock.inputs.emplace_back(HashFromNonce(llmq::CInstantSendLock::MAX_INPUTS), 0);
    BOOST_CHECK(llmq::CInstantSendManagerTestAccess::PreVerify(manager, islock, ban));
    BOOST_CHECK(!ban);

    islock.inputs.emplace_back(HashFromNonce(llmq::CInstantSendLock::MAX_INPUTS + 1), 0);
    BOOST_CHECK(!llmq::CInstantSendManagerTestAccess::PreVerify(manager, islock, ban));
    BOOST_CHECK(ban);
}

BOOST_AUTO_TEST_CASE(pending_queue_and_processing_are_bounded)
{
    constexpr size_t maxPending{1024};
    constexpr size_t maxPerPass{32};

    for (size_t i = 0; i < maxPending - 1; ++i) {
        const auto islock = MakeInstantSendLock(i);
        llmq::CInstantSendManagerTestAccess::ProcessMessage(manager, peer, islock, *g_connman);
    }
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending - 1);

    auto islock = MakeInstantSendLock(maxPending - 1);
    llmq::CInstantSendManagerTestAccess::ProcessMessage(manager, peer, islock, *g_connman);
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending);

    islock = MakeInstantSendLock(maxPending);
    llmq::CInstantSendManagerTestAccess::ProcessMessage(manager, peer, islock, *g_connman);
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending);

    llmq::CInstantSendManagerTestAccess::ProcessPending(manager);
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending - maxPerPass);

    for (size_t i = maxPending; i < maxPending + maxPerPass; ++i) {
        islock = MakeInstantSendLock(i);
        llmq::CInstantSendManagerTestAccess::ProcessMessage(manager, peer, islock, *g_connman);
    }
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending);

    islock = MakeInstantSendLock(maxPending + maxPerPass);
    llmq::CInstantSendManagerTestAccess::ProcessMessage(manager, peer, islock, *g_connman);
    BOOST_CHECK_EQUAL(llmq::CInstantSendManagerTestAccess::PendingCount(manager), maxPending);
}

BOOST_AUTO_TEST_CASE(recovered_signature_shortcut_requires_exact_signature)
{
    auto islock = MakeInstantSendLock(1);
    CBLSSecretKey recoveredKey;
    recoveredKey.MakeNewKey();
    islock.sig.Set(recoveredKey.Sign(HashFromNonce(100)));

    const auto llmqType = Params().GetConsensus().llmqForInstantSend;
    llmq::CRecoveredSig recoveredSig;
    recoveredSig.llmqType = llmqType;
    recoveredSig.quorumHash = HashFromNonce(101);
    recoveredSig.id = islock.GetRequestId();
    recoveredSig.msgHash = islock.txid;
    recoveredSig.sig = islock.sig;
    recoveredSig.UpdateHash();

    llmq::CRecoveredSigsDb recoveredSigsDb(db);
    recoveredSigsDb.WriteRecoveredSig(recoveredSig);

    const auto islockHash = ::SerializeHash(islock);
    llmq::CInstantSendManagerTestAccess::ProcessPending(manager, peer.GetId(), islock);
    BOOST_CHECK_EQUAL(manager.GetInstantSendLockCount(), 1);

    llmq::CInstantSendLock storedLock;
    BOOST_CHECK(db.Read(std::make_tuple(std::string("is_i"), islockHash), storedLock));

    auto alteredIslock = islock;
    CBLSSecretKey alteredKey;
    alteredKey.MakeNewKey();
    alteredIslock.sig.Set(alteredKey.Sign(HashFromNonce(102)));
    const auto alteredIslockHash = ::SerializeHash(alteredIslock);
    BOOST_REQUIRE(islockHash != alteredIslockHash);

    llmq::CInstantSendManagerTestAccess::ProcessPending(manager, peer.GetId(), alteredIslock);
    BOOST_CHECK_EQUAL(manager.GetInstantSendLockCount(), 1);
    BOOST_CHECK(!db.Read(std::make_tuple(std::string("is_i"), alteredIslockHash), storedLock));
}

BOOST_AUTO_TEST_SUITE_END()
