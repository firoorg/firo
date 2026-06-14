// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "script/interpreter.h"
#include "script/standard.h"
#include "script/sign.h"
#include "validation.h"
#include "base58.h"
#include "netbase.h"
#include "messagesigner.h"
#include "keystore.h"
#include "validationinterface.h"

#include "dsnotificationinterface.h"
#include "evo/specialtx.h"
#include "evo/providertx.h"
#include "evo/deterministicmns.h"

#include <atomic>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

static const CBitcoinAddress payoutAddress  ("TTJW6FsYqLbSiF3ZUwMXRghgQuXK7XTodR");
//static const std::string payoutKey          ("cV3qrPWzDcnhzRMV4MqtTH4LhNPqPo26ZntGvfJhc8nqCi8Ae5xR");

typedef std::map<COutPoint, std::pair<int, CAmount>> SimpleUTXOMap;

static SimpleUTXOMap BuildSimpleUtxoMap(const std::vector<CTransaction>& txs)
{
    SimpleUTXOMap utxos;
    FIRO_UNUSED CAmount balance = 0;
    for (size_t i = 0; i < txs.size(); i++) {
        auto& tx = txs[i];
        size_t const znode_output = tx.vout.size() > 6 ? FindZnodeOutput(tx) : 0;
        for (size_t j = 0; j < tx.vout.size(); j++) {
            if(j == 0 || j == znode_output) {
                balance += tx.vout[j].nValue;
                utxos.emplace(COutPoint(tx.GetHash(), j), std::make_pair((int)i + 1, tx.vout[j].nValue));
            }
        }
    }
    return utxos;
}

static std::vector<COutPoint> SelectUTXOs(SimpleUTXOMap& utoxs, CAmount amount, CAmount& changeRet)
{
    changeRet = 0;

    std::vector<COutPoint> selectedUtxos;
    CAmount selectedAmount = 0;
    while (!utoxs.empty()) {
        bool found = false;
        for (auto it = utoxs.begin(); it != utoxs.end(); ++it) {
            if (chainActive.Height() - it->second.first < 101) {
                continue;
            }

            found = true;
            selectedAmount += it->second.second;
            selectedUtxos.emplace_back(it->first);
            utoxs.erase(it);
            break;
        }
        BOOST_ASSERT(found);
        if (selectedAmount >= amount) {
            changeRet = selectedAmount - amount;
            break;
        }
    }

    return selectedUtxos;
}

static void FundTransaction(CMutableTransaction& tx, SimpleUTXOMap& utoxs, const CScript& scriptPayout, CAmount amount, const CKey& coinbaseKey)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    CAmount change;
    auto inputs = SelectUTXOs(utoxs, amount, change);
    for (size_t i = 0; i < inputs.size(); i++) {
        tx.vin.emplace_back(CTxIn(inputs[i]));
    }
    tx.vout.emplace_back(CTxOut(amount, scriptPayout));
    if (change != 0) {
        tx.vout.emplace_back(CTxOut(change, scriptPayout));
    }
}

static void SignTransaction(CMutableTransaction& tx, const CKey& coinbaseKey)
{
    CBasicKeyStore tempKeystore;
    tempKeystore.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());

    for (size_t i = 0; i < tx.vin.size(); i++) {
        CTransactionRef txFrom;
        uint256 hashBlock;
        BOOST_ASSERT(GetTransaction(tx.vin[i].prevout.hash, txFrom, Params().GetConsensus(), hashBlock));
        bool result = SignSignature(tempKeystore, *txFrom, tx, i, SIGHASH_ALL);
        if(!result)
            std::cerr << i << std::endl;
    }
}

static CMutableTransaction CreateProRegTx(SimpleUTXOMap& utxos, int port, const CScript& scriptPayout, const CKey& coinbaseKey, CKey& ownerKeyRet, CBLSSecretKey& operatorKeyRet)
{
    ownerKeyRet.MakeNewKey(true);
    operatorKeyRet.MakeNewKey();

    CAmount change;
    auto inputs = SelectUTXOs(utxos, 1000 * COIN, change);

    CProRegTx proTx;
    proTx.collateralOutpoint.n = 0;
    proTx.addr = LookupNumeric("1.1.1.1", port);
    proTx.keyIDOwner = ownerKeyRet.GetPubKey().GetID();
    proTx.pubKeyOperator = operatorKeyRet.GetPublicKey();
    proTx.keyIDVoting = ownerKeyRet.GetPubKey().GetID();
    proTx.scriptPayout = scriptPayout;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_REGISTER;
    FundTransaction(tx, utxos, scriptPayout, 1000 * COIN, coinbaseKey);
    proTx.inputsHash = CalcTxInputsHash(tx);
    SetTxPayload(tx, proTx);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpServTx(SimpleUTXOMap& utxos, const uint256& proTxHash, const CBLSSecretKey& operatorKey, int port, const CScript& scriptOperatorPayout, const CKey& coinbaseKey)
{
    CAmount change;
    auto inputs = SelectUTXOs(utxos, 1 * COIN, change);

    CProUpServTx proTx;
    proTx.proTxHash = proTxHash;
    proTx.addr = LookupNumeric("1.1.1.1", port);
    proTx.scriptOperatorPayout = scriptOperatorPayout;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_UPDATE_SERVICE;
    FundTransaction(tx, utxos, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()), 1 * COIN, coinbaseKey);
    proTx.inputsHash = CalcTxInputsHash(tx);
    proTx.sig = operatorKey.Sign(::SerializeHash(proTx));
    SetTxPayload(tx, proTx);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpRegTx(SimpleUTXOMap& utxos, const uint256& proTxHash, const CKey& mnKey, const CBLSPublicKey& pubKeyOperator, const CKeyID& keyIDVoting, const CScript& scriptPayout, const CKey& coinbaseKey)
{
    CAmount change;
    auto inputs = SelectUTXOs(utxos, 1 * COIN, change);

    CProUpRegTx proTx;
    proTx.proTxHash = proTxHash;
    proTx.pubKeyOperator = pubKeyOperator;
    proTx.keyIDVoting = keyIDVoting;
    proTx.scriptPayout = scriptPayout;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_UPDATE_REGISTRAR;
    FundTransaction(tx, utxos, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()), 1 * COIN, coinbaseKey);
    proTx.inputsHash = CalcTxInputsHash(tx);
    CHashSigner::SignHash(::SerializeHash(proTx), mnKey, proTx.vchSig);
    SetTxPayload(tx, proTx);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpRevTx(SimpleUTXOMap& utxos, const uint256& proTxHash, const CBLSSecretKey& operatorKey, const CKey& coinbaseKey)
{
    CAmount change;
    auto inputs = SelectUTXOs(utxos, 1 * COIN, change);

    CProUpRevTx proTx;
    proTx.proTxHash = proTxHash;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_UPDATE_REVOKE;
    FundTransaction(tx, utxos, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()), 1 * COIN, coinbaseKey);
    proTx.inputsHash = CalcTxInputsHash(tx);
    proTx.sig = operatorKey.Sign(::SerializeHash(proTx));
    SetTxPayload(tx, proTx);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static CScript GenerateRandomAddress()
{
    CKey key;
    key.MakeNewKey(false);
    return GetScriptForDestination(key.GetPubKey().GetID());
}

static CScript GetCoinbaseKeyScript(const CKey& coinbaseKey)
{
    return GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
}

static CMutableTransaction CreateCollateralSpendTx(const COutPoint& collateralOutpoint, const CScript& scriptPayout, const CKey& coinbaseKey)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(CTxIn(collateralOutpoint));
    tx.vout.emplace_back(CTxOut(999 * COIN, scriptPayout));
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static void ProcessBlockAndUpdateMNManager(TestChain100Setup& setup, const std::vector<CMutableTransaction>& txns, const CKey& coinbaseKey)
{
    bool processed = false;
    setup.CreateAndProcessBlock(txns, coinbaseKey, &processed);
    BOOST_REQUIRE(processed);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
}

static void InvalidateBlockAndUpdateMNManager(const uint256& blockHash)
{
    CValidationState state;
    LOCK(cs_main);

    auto it = mapBlockIndex.find(blockHash);
    BOOST_REQUIRE(it != mapBlockIndex.end());
    BOOST_REQUIRE(InvalidateBlock(state, Params(), it->second));
    BOOST_REQUIRE(state.IsValid());
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
}

static void InvalidateBlockUsingValidationSignals(const uint256& blockHash)
{
    CValidationState state;
    LOCK(cs_main);

    auto it = mapBlockIndex.find(blockHash);
    BOOST_REQUIRE(it != mapBlockIndex.end());
    BOOST_REQUIRE(InvalidateBlock(state, Params(), it->second));
    BOOST_REQUIRE(state.IsValid());
}

class DeterministicMNManagerTipSignalBridge : public CValidationInterface
{
protected:
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex*, bool) override
    {
        deterministicMNManager->UpdatedBlockTip(pindexNew);
    }
};

class ExposedDSNotificationInterface : public CDSNotificationInterface
{
public:
    using CDSNotificationInterface::CDSNotificationInterface;

    void UpdatedBlockTipForTest(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
    {
        CDSNotificationInterface::UpdatedBlockTip(pindexNew, pindexFork, fInitialDownload);
    }
};

class ScopedValidationInterfaceRegistration
{
public:
    explicit ScopedValidationInterfaceRegistration(CValidationInterface& validationInterface) :
        validationInterface(validationInterface)
    {
        RegisterValidationInterface(&validationInterface);
    }

    ~ScopedValidationInterfaceRegistration()
    {
        UnregisterValidationInterface(&validationInterface);
    }

private:
    CValidationInterface& validationInterface;
};

static std::vector<uint256> RegisterDeterministicMNs(TestChain100Setup& setup, SimpleUTXOMap& utxos, size_t count, int& port, const CScript& payoutScript)
{
    std::vector<uint256> dmnHashes;
    dmnHashes.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        CKey ownerKey;
        CBLSSecretKey operatorKey;
        auto tx = CreateProRegTx(utxos, port++, payoutScript, setup.coinbaseKey, ownerKey, operatorKey);
        auto proTxHash = tx.GetHash();
        ProcessBlockAndUpdateMNManager(setup, {tx}, setup.coinbaseKey);

        BOOST_REQUIRE(deterministicMNManager->GetListAtChainTip().HasMN(proTxHash));
        dmnHashes.emplace_back(proTxHash);
    }

    return dmnHashes;
}

static void AssertTipMNSet(const std::vector<uint256>& expectedDmnHashes)
{
    auto mnList = deterministicMNManager->GetListAtChainTip();
    BOOST_REQUIRE_EQUAL(mnList.GetAllMNsCount(), expectedDmnHashes.size());
    for (const auto& proTxHash : expectedDmnHashes) {
        BOOST_CHECK(mnList.HasMN(proTxHash));
    }
}

static CDeterministicMNCPtr FindPayoutDmn(const CBlock& block)
{
    auto dmnList = deterministicMNManager->GetListAtChainTip();

    for (const auto& txout : block.vtx[0]->vout) {
        CDeterministicMNCPtr found;
        dmnList.ForEachMN(true, [&](const CDeterministicMNCPtr& dmn) {
            if (found == nullptr && txout.scriptPubKey == dmn->pdmnState->scriptPayout) {
                found = dmn;
            }
        });
        if (found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

BOOST_AUTO_TEST_SUITE(evo_dip3_activation_tests)

BOOST_FIXTURE_TEST_CASE(dip3_activation, TestChainDIP3BeforeActivationSetup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CKey ownerKey;
    CBLSSecretKey operatorKey;
    auto tx = CreateProRegTx(utxos, 1, GetScriptForDestination(payoutAddress.Get()), coinbaseKey, ownerKey, operatorKey);
    std::vector<CMutableTransaction> txns = {tx};

    int nHeight = chainActive.Height();

    // We start one block before DIP3 activation, so mining a block with a DIP3 transaction should fail
    auto block = std::make_shared<CBlock>(CreateBlock(txns, coinbaseKey));
    BOOST_ASSERT(block->vtx.size() == 2);
    ProcessNewBlock(Params(), block, true, nullptr);
    BOOST_ASSERT(chainActive.Height() == nHeight);
    BOOST_ASSERT(block->GetHash() != chainActive.Tip()->GetBlockHash());
    BOOST_ASSERT(!deterministicMNManager->GetListAtChainTip().HasMN(tx.GetHash()));

    // This block should activate DIP3
    CreateAndProcessBlock({}, coinbaseKey);
    LOCK(cs_main);
    BOOST_ASSERT(chainActive.Height() == nHeight + 1);

    // Mining a block with a DIP3 transaction should succeed now
    block = std::make_shared<CBlock>(CreateBlock(txns, coinbaseKey));
    ProcessNewBlock(Params(), block, true, nullptr);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

    BOOST_ASSERT(chainActive.Height() == nHeight + 2);
    BOOST_ASSERT(block->GetHash() == chainActive.Tip()->GetBlockHash());
    BOOST_ASSERT(deterministicMNManager->GetListAtChainTip().HasMN(tx.GetHash()));
}

BOOST_FIXTURE_TEST_CASE(dip3_protx, TestChainDIP3Setup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);

    int nHeight = chainActive.Height();
    int port = 1;

    std::vector<uint256> dmnHashes;
    std::map<uint256, CKey> ownerKeys;
    std::map<uint256, CBLSSecretKey> operatorKeys;

    // register one MN per block
    for (size_t i = 0; i < 6; i++) {
        CKey ownerKey;
        CBLSSecretKey operatorKey;
        auto tx = CreateProRegTx(utxos, port++, GenerateRandomAddress(), coinbaseKey, ownerKey, operatorKey);
        dmnHashes.emplace_back(tx.GetHash());
        ownerKeys.emplace(tx.GetHash(), ownerKey);
        operatorKeys.emplace(tx.GetHash(), operatorKey);
        CreateAndProcessBlock({tx}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

        LOCK(cs_main);
        BOOST_ASSERT(chainActive.Height() == nHeight + 1);
        BOOST_ASSERT(deterministicMNManager->GetListAtChainTip().HasMN(tx.GetHash()));

        nHeight++;
    }

    int DIP0003EnforcementHeightBackup = Params().GetConsensus().DIP0003EnforcementHeight;
    const_cast<Consensus::Params&>(Params().GetConsensus()).DIP0003EnforcementHeight = chainActive.Height() + 1;
    CreateAndProcessBlock({}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    nHeight++;

    // check MN reward payments
    for (size_t i = 0; i < 20; i++) {
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();

        CBlock block = CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
        BOOST_ASSERT(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        BOOST_ASSERT(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }

    // register multiple MNs per block
    for (size_t i = 0; i < 3; i++) {
        std::vector<CMutableTransaction> txns;
        for (size_t j = 0; j < 3; j++) {
            CKey ownerKey;
            CBLSSecretKey operatorKey;
            auto tx = CreateProRegTx(utxos, port++, GenerateRandomAddress(), coinbaseKey, ownerKey, operatorKey);
            dmnHashes.emplace_back(tx.GetHash());
            ownerKeys.emplace(tx.GetHash(), ownerKey);
            operatorKeys.emplace(tx.GetHash(), operatorKey);
            txns.emplace_back(tx);
        }
        bool pbr = false;
        CreateAndProcessBlock(txns, coinbaseKey, &pbr);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

        BOOST_ASSERT(pbr);
        LOCK(cs_main);
        BOOST_ASSERT(chainActive.Height() == nHeight + 1);

        for (size_t j = 0; j < 3; j++) {
            BOOST_ASSERT(deterministicMNManager->GetListAtChainTip().HasMN(txns[j].GetHash()));
        }

        nHeight++;
    }

    // test ProUpServTx
    auto tx = CreateProUpServTx(utxos, dmnHashes[0], operatorKeys[dmnHashes[0]], 1000, CScript(), coinbaseKey);
    CreateAndProcessBlock({tx}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    BOOST_ASSERT(chainActive.Height() == nHeight + 1);
    nHeight++;

    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    BOOST_ASSERT(dmn != nullptr && dmn->pdmnState->addr.GetPort() == 1000);

    // test ProUpRevTx
    tx = CreateProUpRevTx(utxos, dmnHashes[0], operatorKeys[dmnHashes[0]], coinbaseKey);
    CreateAndProcessBlock({tx}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    BOOST_ASSERT(chainActive.Height() == nHeight + 1);
    nHeight++;

    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    BOOST_ASSERT(dmn != nullptr && dmn->pdmnState->nPoSeBanHeight == nHeight);

    // test that the revoked MN does not get paid anymore
    for (size_t i = 0; i < 20; i++) {
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();
        BOOST_ASSERT(dmnExpectedPayee->proTxHash != dmnHashes[0]);

        CBlock block = CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
        BOOST_ASSERT(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        BOOST_ASSERT(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }

    // test reviving the MN
    CBLSSecretKey newOperatorKey;
    newOperatorKey.MakeNewKey();
    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    tx = CreateProUpRegTx(utxos, dmnHashes[0], ownerKeys[dmnHashes[0]], newOperatorKey.GetPublicKey(), ownerKeys[dmnHashes[0]].GetPubKey().GetID(), dmn->pdmnState->scriptPayout, coinbaseKey);
    CreateAndProcessBlock({tx}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    BOOST_ASSERT(chainActive.Height() == nHeight + 1);
    nHeight++;

    tx = CreateProUpServTx(utxos, dmnHashes[0], newOperatorKey, 100, CScript(), coinbaseKey);
    CreateAndProcessBlock({tx}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    BOOST_ASSERT(chainActive.Height() == nHeight + 1);
    nHeight++;

    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    BOOST_ASSERT(dmn != nullptr && dmn->pdmnState->addr.GetPort() == 100);
    BOOST_ASSERT(dmn != nullptr && dmn->pdmnState->nPoSeBanHeight == -1);

    // test that the revived MN gets payments again
    bool foundRevived = false;
    for (size_t i = 0; i < 20; i++) {
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();
        if (dmnExpectedPayee->proTxHash == dmnHashes[0]) {
            foundRevived = true;
        }

        CBlock block = CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
        BOOST_ASSERT(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        BOOST_ASSERT(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }
    BOOST_ASSERT(foundRevived);

    const_cast<Consensus::Params&>(Params().GetConsensus()).DIP0003EnforcementHeight = DIP0003EnforcementHeightBackup;
}

BOOST_FIXTURE_TEST_CASE(dip3_invalidate_restores_single_collateral_spend_immediately, TestChainDIP3Setup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 10000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 3, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[0], 0), payoutScript, coinbaseKey);
    ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);

    std::vector<uint256> afterSpend{dmnHashes.begin() + 1, dmnHashes.end()};
    AssertTipMNSet(afterSpend);

    auto removedTipHash = chainActive.Tip()->GetBlockHash();
    InvalidateBlockAndUpdateMNManager(removedTipHash);

    AssertTipMNSet(dmnHashes);
}

BOOST_FIXTURE_TEST_CASE(dip3_invalidate_restores_multiple_collateral_spends_immediately, TestChainDIP3Setup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 11000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 5, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    uint256 firstRemovalBlockHash;
    std::vector<uint256> expectedAfterSpends = dmnHashes;
    for (size_t i = 0; i < 3; ++i) {
        auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[i], 0), payoutScript, coinbaseKey);
        ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);
        if (i == 0) {
            firstRemovalBlockHash = chainActive.Tip()->GetBlockHash();
        }
        expectedAfterSpends.erase(expectedAfterSpends.begin());
        AssertTipMNSet(expectedAfterSpends);
    }

    InvalidateBlockAndUpdateMNManager(firstRemovalBlockHash);

    AssertTipMNSet(dmnHashes);
}

BOOST_FIXTURE_TEST_CASE(dip3_invalidate_does_not_reuse_cached_descendant_mn_list, TestChainDIP3Setup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 12000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 4, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    auto preRemovalTip = chainActive.Tip();
    auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[0], 0), payoutScript, coinbaseKey);
    ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);
    auto descendantTip = chainActive.Tip();

    std::vector<uint256> afterSpend{dmnHashes.begin() + 1, dmnHashes.end()};
    AssertTipMNSet(afterSpend);

    // Populate manager caches for both sides of the rollback boundary before
    // invalidating, then assert the active tip list cannot be served from the
    // stale descendant entry after disconnect.
    BOOST_CHECK_EQUAL(deterministicMNManager->GetListForBlock(preRemovalTip).GetAllMNsCount(), dmnHashes.size());
    BOOST_CHECK_EQUAL(deterministicMNManager->GetListForBlock(descendantTip).GetAllMNsCount(), afterSpend.size());

    InvalidateBlockAndUpdateMNManager(descendantTip->GetBlockHash());

    BOOST_CHECK_EQUAL(chainActive.Tip()->GetBlockHash().ToString(), preRemovalTip->GetBlockHash().ToString());
    AssertTipMNSet(dmnHashes);
    BOOST_CHECK_EQUAL(deterministicMNManager->GetListForBlock(chainActive.Tip()).GetAllMNsCount(), dmnHashes.size());
}

BOOST_FIXTURE_TEST_CASE(dip3_invalidate_pure_disconnect_notification_updates_tip_list, TestChainDIP3Setup)
{
    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 13000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 3, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    auto preRemovalTip = chainActive.Tip();
    auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[0], 0), payoutScript, coinbaseKey);
    ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);

    std::vector<uint256> afterSpend{dmnHashes.begin() + 1, dmnHashes.end()};
    AssertTipMNSet(afterSpend);

    ExposedDSNotificationInterface notificationInterface(*connman);
    notificationInterface.UpdatedBlockTipForTest(preRemovalTip, preRemovalTip, false);
    AssertTipMNSet(dmnHashes);
}

BOOST_FIXTURE_TEST_CASE(dip3_repeated_invalidate_signal_restores_each_intermediate_tip, TestChainDIP3Setup)
{
    DeterministicMNManagerTipSignalBridge tipSignalBridge;
    ScopedValidationInterfaceRegistration bridgeRegistration(tipSignalBridge);

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 14000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 5, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    std::vector<std::vector<uint256>> expectedAfterDisconnect;
    std::vector<uint256> expectedAfterSpends = dmnHashes;

    for (size_t i = 0; i < 3; ++i) {
        auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[i], 0), payoutScript, coinbaseKey);
        ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);
        expectedAfterSpends.erase(expectedAfterSpends.begin());
        AssertTipMNSet(expectedAfterSpends);

        std::vector<uint256> restored{dmnHashes.begin() + i, dmnHashes.end()};
        expectedAfterDisconnect.emplace(expectedAfterDisconnect.begin(), std::move(restored));
    }

    for (size_t i = 0; i < expectedAfterDisconnect.size(); ++i) {
        InvalidateBlockUsingValidationSignals(chainActive.Tip()->GetBlockHash());
        AssertTipMNSet(expectedAfterDisconnect[i]);
    }
}

BOOST_FIXTURE_TEST_CASE(dip3_invalidate_tip_list_remains_consistent_for_parallel_readers, TestChainDIP3Setup)
{
    DeterministicMNManagerTipSignalBridge tipSignalBridge;
    ScopedValidationInterfaceRegistration bridgeRegistration(tipSignalBridge);

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    auto payoutScript = GetCoinbaseKeyScript(coinbaseKey);
    int port = 15000;

    auto dmnHashes = RegisterDeterministicMNs(*this, utxos, 6, port, payoutScript);
    AssertTipMNSet(dmnHashes);

    for (size_t i = 0; i < 3; ++i) {
        auto spendTx = CreateCollateralSpendTx(COutPoint(dmnHashes[i], 0), payoutScript, coinbaseKey);
        ProcessBlockAndUpdateMNManager(*this, {spendTx}, coinbaseKey);
    }

    InvalidateBlockUsingValidationSignals(chainActive.Tip()->GetBlockHash());
    std::vector<uint256> expectedAfterOneDisconnect{dmnHashes.begin() + 2, dmnHashes.end()};
    AssertTipMNSet(expectedAfterOneDisconnect);

    std::atomic<bool> failed{false};
    boost::thread_group readers;
    for (size_t i = 0; i < 8; ++i) {
        readers.create_thread([&]() {
            for (size_t j = 0; j < 100; ++j) {
                auto mnList = deterministicMNManager->GetListAtChainTip();
                if (mnList.GetAllMNsCount() != expectedAfterOneDisconnect.size()) {
                    failed = true;
                    return;
                }
                for (const auto& proTxHash : expectedAfterOneDisconnect) {
                    if (!mnList.HasMN(proTxHash)) {
                        failed = true;
                        return;
                    }
                }
            }
        });
    }
    readers.join_all();

    BOOST_CHECK(!failed);
}
BOOST_AUTO_TEST_SUITE_END()
