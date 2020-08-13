#include "test/test_bitcoin.h"

#include "script/interpreter.h"
#include "script/standard.h"
#include "script/sign.h"
#include "validation.h"
#include "zerocoin.h"
#include "netbase.h"
#include "keystore.h"
#include "base58.h"
#include "evo/specialtx.h"

#include <boost/test/unit_test.hpp>

typedef std::map<COutPoint, std::pair<int, CAmount>> SimpleUTXOMap;

static SimpleUTXOMap BuildSimpleUtxoMap(const std::vector<CTransaction>& txs)
{
    SimpleUTXOMap utxos;
    CAmount balance = 0;
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

static CScript GenerateRandomAddress()
{
    CKey key;
    key.MakeNewKey(false);
    return GetScriptForDestination(key.GetPubKey().GetID());
}

static CDeterministicMNCPtr FindPayoutDmn(const CBlock& block, CAmount &nValue)
{
    auto dmnList = deterministicMNManager->GetListAtChainTip();

    for (const auto& txout : block.vtx[0]->vout) {
        CDeterministicMNCPtr found;
        dmnList.ForEachMN(true, [&](const CDeterministicMNCPtr& dmn) {
            if (found == nullptr && txout.scriptPubKey == dmn->pdmnState->scriptPayout) {
                found = dmn;
                nValue = txout.nValue;
            }
        });
        if (found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

BOOST_AUTO_TEST_SUITE(firsthalving)

BOOST_FIXTURE_TEST_CASE(devpayout, TestChainDIP3BeforeActivationSetup)
{
    Consensus::Params   &consensusParams = const_cast<Consensus::Params &>(Params().GetConsensus());
    Consensus::Params   consensusParamsBackup = consensusParams;

    // Simulate testnet (and its founders' reward)
    consensusParams.chainType = Consensus::chainTestnet;

    consensusParams.nSubsidyHalvingFirst = 600;
    consensusParams.nSubsidyHalvingInterval = 10;
    consensusParams.nSubsidyHalvingStopBlock = 1000;

    CScript devPayoutScript = GenerateRandomAddress();
    CTxDestination devPayoutDest{CScriptID(devPayoutScript)};
    consensusParams.stage2DevelopmentFundAddress = CBitcoinAddress(devPayoutDest).ToString();

    auto utxos = BuildSimpleUtxoMap(coinbaseTxns);

    // we're at block 498, skip to block 499
    for (int i=498; i<499; i++)
        CreateAndProcessBlock({}, coinbaseKey);

    CKey ownerKey;
    CBLSSecretKey operatorSecretKey;
    CScript znodePayoutScript = GenerateRandomAddress();

    auto tx = CreateProRegTx(utxos, 4444, znodePayoutScript, coinbaseKey, ownerKey, operatorSecretKey);
    CreateAndProcessBlock({tx}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

    // we're at block 500, skip to 549
    for (int i=500; i<549; i++) {
        CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());
    }

    // blocks 550 through 599
    for (int i=550; i<600; i++) {
        CBlock block = CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());    

        CAmount nValue;
        auto dmnPayout = FindPayoutDmn(block, nValue);
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();

        BOOST_ASSERT(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        CValidationState state;
        BOOST_ASSERT(CheckZerocoinFoundersInputs(*block.vtx[0], state, consensusParams, chainActive.Height(), false));

        BOOST_ASSERT(nValue == 15*COIN);    // znode reward before the first halving
    }

    // halving occurs at block 600
    // devs fund is valid until second block halving at block 610
    for (int i=600; i<610; i++) {
        CBlock block = CreateAndProcessBlock({}, coinbaseKey);
        deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

        CAmount nValue;
        auto dmnPayout = FindPayoutDmn(block, nValue);

        BOOST_ASSERT(dmnPayout != nullptr && nValue == 875*COIN/100);   // 8.75 after halving (25*0.35)

        bool paymentToDevFound = false;
        for (const CTxOut &txout: block.vtx[0]->vout) {
            if (txout.scriptPubKey == GetScriptForDestination(CBitcoinAddress(consensusParams.stage2DevelopmentFundAddress).Get())) {
                BOOST_ASSERT(txout.nValue == 375*COIN/100); // 25*0.15
                paymentToDevFound = true;
            }
        }
        BOOST_ASSERT(paymentToDevFound);
    }

    CBlock block = CreateAndProcessBlock({}, coinbaseKey);
    deterministicMNManager->UpdatedBlockTip(chainActive.Tip());

    CAmount nValue;
    auto dmnPayout = FindPayoutDmn(block, nValue);

    BOOST_ASSERT(dmnPayout != nullptr && nValue == 4375*COIN/1000);   // 4.375 (12.5*0.35)

    // there should be no more payment to devs fund
    for (const CTxOut &txout: block.vtx[0]->vout) {
        BOOST_ASSERT(txout.scriptPubKey != GetScriptForDestination(CBitcoinAddress(consensusParams.stage2DevelopmentFundAddress).Get()));
    }

    // miner's reward should be 12.5-4.375 = 8.125
    BOOST_ASSERT(block.vtx[0]->vout[0].nValue == 8125*COIN/1000);
    // should be only 2 vouts in coinbase
    BOOST_ASSERT(block.vtx[0]->vout.size() == 2);

    consensusParams = consensusParamsBackup;
}

BOOST_FIXTURE_TEST_CASE(devpayoutverification, TestChainDIP3BeforeActivationSetup)
{
    Consensus::Params   &consensusParams = const_cast<Consensus::Params &>(Params().GetConsensus());
    Consensus::Params   consensusParamsBackup = consensusParams;

    consensusParams.nSubsidyHalvingFirst = 600;
    consensusParams.nSubsidyHalvingInterval = 10;
    consensusParams.nSubsidyHalvingStopBlock = 1000;

    // skip to block 600
    for (int i=498; i<600; i++)
        CreateAndProcessBlock({}, coinbaseKey);

    // try to send dev payout to different destination
    CKey key;
    key.MakeNewKey(false);
    consensusParams.stage2DevelopmentFundAddress = CBitcoinAddress(CTxDestination(key.GetPubKey().GetID())).ToString();

    {
        CBlock block = CreateBlock({}, coinbaseKey);
        consensusParams.stage2DevelopmentFundAddress = consensusParamsBackup.stage2DevelopmentFundAddress;

        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        BOOST_ASSERT(!ProcessNewBlock(Params(), shared_pblock, true, nullptr));
    }

    // now try to alter payment value
    {
        consensusParams.stage2DevelopmentFundShare /= 2;
        CBlock block = CreateBlock({}, coinbaseKey);
        consensusParams.stage2DevelopmentFundShare = consensusParamsBackup.stage2DevelopmentFundShare;
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        BOOST_ASSERT(!ProcessNewBlock(Params(), shared_pblock, true, nullptr));
    }

    // now try to alter payment value
    {
        consensusParams.stage2DevelopmentFundShare *= 2;
        CBlock block = CreateBlock({}, coinbaseKey);
        consensusParams.stage2DevelopmentFundShare = consensusParamsBackup.stage2DevelopmentFundShare;
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        BOOST_ASSERT(!ProcessNewBlock(Params(), shared_pblock, true, nullptr));
    }

    consensusParams = consensusParamsBackup;
}


BOOST_AUTO_TEST_SUITE_END()