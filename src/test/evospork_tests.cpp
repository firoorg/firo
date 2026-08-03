#include "test/test_bitcoin.h"
#include "test/fixtures.h"

#include "chainparams.h"
#include "script/interpreter.h"
#include "script/standard.h"
#include "script/sign.h"
#include "utilmoneystr.h"
#include "base58.h"
#include "netbase.h"
#include "net.h"
#include "validation.h"
#include "txmempool.h"
#include "messagesigner.h"
#include "keystore.h"

#include "evo/specialtx.h"
#include "evo/spork.h"

#include "wallet/wallet.h"

#include <boost/test/unit_test.hpp>

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
    CAmount change;
    auto inputs = SelectUTXOs(utoxs, amount, change);
    for (size_t i = 0; i < inputs.size(); i++) {
        tx.vin.emplace_back(CTxIn(inputs[i]));
    }
    tx.vout.emplace_back(CTxOut(amount, scriptPayout));
    if (change > COIN/10) {
        tx.vout.emplace_back(CTxOut(change-COIN/10, scriptPayout));
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

static CMutableTransaction CreateSporkTx(SimpleUTXOMap &utxos, const CKey &coinbaseKey, const std::vector<CSporkAction> &actions)
{
    CBitcoinSecret secretKey;
    secretKey.SetString("cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ");

    CSporkTx sporkTxPayload;
    sporkTxPayload.actions = actions;

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_SPORK;

    CTxDestination txDest = coinbaseKey.GetPubKey().GetID();
    CScript scriptPayout = GetScriptForDestination(txDest);

    FundTransaction(tx, utxos, scriptPayout, COIN/10, coinbaseKey);
    sporkTxPayload.inputsHash = CalcTxInputsHash(tx);
    CHashSigner::SignHash(::SerializeHash(sporkTxPayload), secretKey.GetKey(), sporkTxPayload.vchSig);
    SetTxPayload(tx, sporkTxPayload);
    SignTransaction(tx, coinbaseKey);

    return tx;
}

static bool CommitToMempool(const CTransaction &tx)
{
    CWallet *wallet = pwalletMain;
    CWalletTx walletTx(wallet, MakeTransactionRef(tx));
    CReserveKey reserveKey(wallet);
    CValidationState state;
    wallet->CommitTransaction(walletTx, reserveKey, g_connman.get(), state);
    return mempool.exists(tx.GetHash());
}

// Extend spork stop block to 2000
struct SparkSporkTestingSetup : public SparkTestingSetup
{
    Consensus::Params &mutableParams;
    Consensus::Params originalParams;

    SparkSporkTestingSetup() : SparkTestingSetup(), mutableParams(const_cast<Consensus::Params&>(Params().GetConsensus()))
    {
        spark::CSparkState::GetState()->Reset();
        mempool.clear();
        originalParams = mutableParams;
        mutableParams.nEvoSporkStopBlock = 2000;
    }

    ~SparkSporkTestingSetup() {
        mutableParams = originalParams;
        spark::CSparkState::GetState()->Reset();
        mempool.clear();
    }

};

BOOST_FIXTURE_TEST_SUITE(evospork_spark_tests, SparkSporkTestingSetup)

BOOST_AUTO_TEST_CASE(general)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<1000; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureSpark, 0, 1075}
    });
    CMutableTransaction sporkTx2 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureSpark, 0, 1085}
    });
    CMutableTransaction sporkTx3 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkEnable, CSporkAction::featureSpark, 0, 0}
    });

    prevHeight = chainActive.Height();
    GenerateBlock({sporkTx1});
    // spork should be accepted
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    std::vector<CMutableTransaction> sparkMints;
    GenerateMints({1*COIN, 2*COIN}, sparkMints);

    prevHeight = chainActive.Height();
    GenerateBlock(sparkMints);
    // can't accept spark tx after spark
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // wait until the spork expires
    for (int n=chainActive.Height(); n<1075; n++)
        GenerateBlock({});
    prevHeight = chainActive.Height();
    GenerateBlock({sparkMints[0]});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // another disabling spork
    GenerateBlock({sporkTx2});
    // ensure lelantus is disabled
    prevHeight = chainActive.Height();
    GenerateBlock({sparkMints[1]});
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // block with enabling spork
    GenerateBlock({sporkTx3});
    // ensure lelantus is enabled now
    prevHeight = chainActive.Height();
    GenerateBlock({sparkMints[1]});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
}

BOOST_AUTO_TEST_CASE(mempool)
{
    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<1000; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureSpark, 0, 1075}
    });
    CMutableTransaction sporkTx2 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkDisable, CSporkAction::featureSpark, 0, 1085}
    });

    std::vector<CMutableTransaction> sparkMints;
    GenerateMints({1*COIN, 2*COIN}, sparkMints);
    ::mempool.removeRecursive(sparkMints[0]);
    ::mempool.removeRecursive(sparkMints[1]);

    CBlock blockWithSparkMint = CreateBlock({sparkMints[0]}, coinbaseKey);

    // put one mint into the mempool
    CommitToMempool(sparkMints[0]);
    BOOST_ASSERT(::mempool.size() == 1);

    // push spork to mempool
    CommitToMempool(sporkTx1);
    // spork should be in the mempool, spark mint should be pushed out of it
    BOOST_ASSERT(::mempool.size() == 1);
    BOOST_ASSERT(::mempool.exists(sporkTx1.GetHash()) && !::mempool.exists(sparkMints[0].GetHash()));

    // another spark tx shouldn't get to the mempool
    CommitToMempool(sparkMints[1]);
    BOOST_ASSERT(::mempool.size() == 1);

    // but should be accepted in block
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(blockWithSparkMint), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);

    // mine spork into the block
    CreateAndProcessBlock({sporkTx1}, coinbaseKey);
    // mempool should clear
    BOOST_ASSERT(::mempool.size() == 0);

    // because there is active spork at the tip spark mint shouldn't get into the mempool
    BOOST_ASSERT(!CommitToMempool(sparkMints[1]));

    for (int n=chainActive.Height(); n<1075; n++)
        CreateAndProcessBlock({}, coinbaseKey);

    // spork expired, should accept now
    BOOST_ASSERT(CommitToMempool(sparkMints[1]));
    // try and generate a block with second spork without it ever entering the mempool
    CreateAndProcessBlock({sporkTx2}, coinbaseKey);
    // now we have a mint in the mempool and active spork. Verify that miner correctly blocks the mint
    // from being mined
    fAllowMempoolTxsInCreateBlock = true;
    CBlock block = CreateBlock({}, coinbaseKey);
    for (CTransactionRef tx: block.vtx) {
        BOOST_ASSERT(!tx->IsSparkTransaction());
    }
    BOOST_ASSERT(::mempool.exists(sparkMints[1].GetHash()));
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(block), true, nullptr);
    BOOST_CHECK_EQUAL(chainActive.Height(), prevHeight+1);
}

BOOST_AUTO_TEST_CASE(malformed_spork_payload_is_consensus_invalid)
{
    for (int n = chainActive.Height(); n < 1000; ++n) {
        GenerateBlock({});
    }

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    const CMutableTransaction validSpork = CreateSporkTx(
        utxos,
        coinbaseKey,
        {{CSporkAction::sporkDisable,
          CSporkAction::featureSpark,
          0,
          1075}});

    const auto checkMalformedVersion = [&](
            int32_t version, const std::string& rejectReason) {
        CMutableTransaction malformedSpork(validSpork);
        malformedSpork.nVersion = version;
        malformedSpork.vExtraPayload.clear();
        for (CTxIn& input : malformedSpork.vin) {
            input.scriptSig.clear();
        }
        SignTransaction(malformedSpork, coinbaseKey);

        CBlock candidate = CreateBlock({malformedSpork}, coinbaseKey);
        uint256 candidateHash = candidate.GetHash();
        CBlockIndex candidateIndex(candidate);
        candidateIndex.phashBlock = &candidateHash;
        candidateIndex.pprev = chainActive.Tip();
        candidateIndex.nHeight = chainActive.Height() + 1;

        CValidationState state;
        CCoinsViewCache view(pcoinsTip);
        {
            LOCK(cs_main);
            BOOST_CHECK(!ConnectBlock(
                candidate,
                state,
                &candidateIndex,
                view,
                Params(),
                true));
        }

        int dosScore = 0;
        BOOST_REQUIRE(state.IsInvalid(dosScore));
        BOOST_CHECK_EQUAL(dosScore, 100);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), rejectReason);
        BOOST_CHECK(candidateIndex.activeDisablingSporks.empty());
    };

    // Version 3 is the deployed special-transaction format. A later version
    // with the same type tag must be rejected before any state update.
    checkMalformedVersion(3, "bad-protx-payload");
    checkMalformedVersion(4, "bad-protx-version");

    CMutableTransaction versionFourSpork(validSpork);
    versionFourSpork.nVersion = 4;
    CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
    encoded << versionFourSpork;
    CMutableTransaction decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded.vExtraPayload.empty());

    CValidationState contextualState;
    BOOST_CHECK(!ContextualCheckTransaction(
        decoded,
        contextualState,
        Params().GetConsensus(),
        chainActive.Tip()));
    BOOST_CHECK_EQUAL(contextualState.GetRejectReason(), "bad-txns-type");
}

BOOST_AUTO_TEST_CASE(limit)
{
    struct ResetSparkV2Height {
        ~ResetSparkV2Height()
        {
            UpdateRegtestSparkChaumV2Height(INT_MAX);
            UpdateRegtestSparkSingleInputHeight(INT_MAX);
        }
    } resetSparkV2Height;

    int prevHeight;
    pwalletMain->SetBroadcastTransactions(true);

    for (int n=chainActive.Height(); n<1000; n++)
        GenerateBlock({});

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);
    CMutableTransaction sporkTx1 = CreateSporkTx(utxos, coinbaseKey, {
        {CSporkAction::sporkLimit, CSporkAction::featureSparkTransparentLimit, 100*COIN, 1050}
    });

    FIRO_UNUSED auto params = spark::Params::get_default();

    BOOST_ASSERT(pwalletMain->sparkWallet);
    spark::Address address = pwalletMain->sparkWallet->generateNewAddress();

    // Upgraded wallets spend exactly one Spark coin per transaction. Mint
    // coins that individually fund each spend below: one 120-FIRO transparent
    // output (over the 100-FIRO spork limit) and two 70-FIRO outputs (each
    // under the limit, but 140 > 100 so only one fits per block).
    // Use fSplit=false so each requested amount becomes a single coin rather
    // than being fragmented across UTXO address groups.
    std::vector<CMutableTransaction> sparkMints;
    {
        std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
        std::vector<spark::MintedCoinData> mints{
            {address, static_cast<uint64_t>(150 * COIN), ""},
            {address, static_cast<uint64_t>(80 * COIN), ""},
            {address, static_cast<uint64_t>(80 * COIN), ""},
        };
        std::string error = pwalletMain->MintAndStoreSpark(mints, wtxAndFee, false, false);
        BOOST_ASSERT(error.empty());
        BOOST_ASSERT(!wtxAndFee.empty());
        for (auto& w : wtxAndFee)
            sparkMints.emplace_back(*w.first.tx);
    }

    BOOST_ASSERT(GenerateBlock(sparkMints));

    for (int i = 0; i < 10; i++)
        GenerateBlock({});

    // This test exercises the legacy Evo-spork amount limit, which requires
    // spends larger than any one minted coin. Enable versioned construction
    // locally so the test continues to exercise that amount boundary.
    UpdateRegtestSparkSingleInputHeight(chainActive.Height() + 1);
    UpdateRegtestSparkChaumV2Height(chainActive.Height() + 1);

    CAmount fee = 0;
    CWalletTx spendWalletTx = pwalletMain->SpendAndStoreSpark({{script, 120*COIN, false, ""}}, {}, fee);

    CMutableTransaction spendTx = *spendWalletTx.tx;

    ::mempool.removeRecursive(spendWalletTx);

    auto sparkSpend = spark::ParseSparkSpend(spendTx);
    std::vector<GroupElement> lTags = sparkSpend.getUsedLTags();
    BOOST_ASSERT(lTags.size() == 1);

    // generate two smaller spark spend txs
    CWalletTx smallSparkWalletTxs[2] = {
        pwalletMain->SpendAndStoreSpark({{script, 70*COIN, false, ""}}, {}, fee),
        pwalletMain->SpendAndStoreSpark({{script, 70*COIN, false, ""}}, {}, fee),
    };

    CMutableTransaction smallSparkTxs[2] = {*smallSparkWalletTxs[0].tx, *smallSparkWalletTxs[1].tx};

    // Each spend is within the active per-transaction limit, but the block is
    // over the aggregate limit introduced by its own spork. Rejection must
    // happen before either linking tag reaches process-global Spark state.
    const std::vector<GroupElement> firstSmallTags =
        spark::ParseSparkSpend(smallSparkTxs[0]).getUsedLTags();
    const std::vector<GroupElement> secondSmallTags =
        spark::ParseSparkSpend(smallSparkTxs[1]).getUsedLTags();
    CBlock aggregateLimitBlock =
        CreateBlock({sporkTx1, smallSparkTxs[0], smallSparkTxs[1]}, script);
    prevHeight = chainActive.Height();
    ProcessNewBlock(
        Params(),
        std::make_shared<const CBlock>(aggregateLimitBlock),
        true,
        nullptr);
    BOOST_CHECK_EQUAL(chainActive.Height(), prevHeight);
    {
        LOCK(cs_main);
        const auto candidate = mapBlockIndex.find(aggregateLimitBlock.GetHash());
        BOOST_REQUIRE(candidate != mapBlockIndex.end());
        BOOST_CHECK(candidate->second->activeDisablingSporks.empty());
    }
    for (const GroupElement& tag : firstSmallTags) {
        BOOST_CHECK(!spark::CSparkState::GetState()->IsUsedLTag(tag));
    }
    for (const GroupElement& tag : secondSmallTags) {
        BOOST_CHECK(!spark::CSparkState::GetState()->IsUsedLTag(tag));
    }

    CommitToMempool(sporkTx1);
    BOOST_ASSERT(::mempool.size() == 3);    // two small spark spends and spork

    fAllowMempoolTxsInCreateBlock = true;
    CBlock block = CreateBlock({}, script);
    // should only have one spark spend transaction in the block
    int nSparkSpends = 0;
    for (CTransactionRef ptx: block.vtx) {
        if (ptx->IsSparkSpend())
            nSparkSpends++;
    }
    BOOST_ASSERT(nSparkSpends == 1);
    prevHeight = chainActive.Height();
    ProcessNewBlock(Params(), std::make_shared<CBlock>(block), true, nullptr);
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    {
        CBlockIndex* tip = chainActive.Tip();
        struct RestoreSporkMap {
            CBlockIndex* index;
            ActiveSporkMap original;
            ~RestoreSporkMap()
            {
                LOCK(cs_main);
                index->activeDisablingSporks.swap(original);
            }
        } restoreSporkMap{tip, tip->activeDisablingSporks};

        BOOST_REQUIRE(tip->activeDisablingSporks.count(
            CSporkAction::featureSparkTransparentLimit));
        ++tip->activeDisablingSporks
              .at(CSporkAction::featureSparkTransparentLimit)
              .second;
        const ActiveSporkMap expectedSporks =
            tip->activeDisablingSporks;

        CVerifyDB verifier;
        BOOST_REQUIRE(verifier.VerifyDB(Params(), pcoinsTip, 4, 1));
        BOOST_CHECK(tip->activeDisablingSporks == expectedSporks);
    }
    // one spark spend should be left at the mempool
    BOOST_ASSERT(::mempool.size() == 1);

    // mine remaining spark spend into the block
    prevHeight = chainActive.Height();
    GenerateBlock({});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    BOOST_ASSERT(::mempool.size() == 0);
    fAllowMempoolTxsInCreateBlock = false;

    // large spark spend tx is out of range, should fail now
    BOOST_ASSERT(!CommitToMempool(spendTx));
    // should fail in block as well
    prevHeight = chainActive.Height();
    GenerateBlock({spendTx});
    BOOST_ASSERT(chainActive.Height() == prevHeight);

    // skip to 1050 (spork expiration block)
    for (int n=chainActive.Height(); n<1050; n++)
        GenerateBlock({});

    // should be accepted into the mempool
    BOOST_ASSERT(CommitToMempool(spendTx));
    // and be mined into the block
    prevHeight = chainActive.Height();
    GenerateBlock({spendTx});
    BOOST_ASSERT(chainActive.Height() == prevHeight+1);
    // mempool should be clear
    BOOST_ASSERT(::mempool.size() == 0);
    // lTags should go into the state
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    for (const GroupElement &lTag : lTags)
        BOOST_ASSERT(sparkState->IsUsedLTag(lTag));
}

BOOST_AUTO_TEST_SUITE_END()
