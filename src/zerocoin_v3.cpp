#include "main.h"
#include "zerocoin_v3.h"
#include "zerocoin.h" // Mostly for reusing class libzerocoin::SpendMetaData
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "txmempool.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "crypto/sha256.h"
#include "sigma/coinspend.h"
#include "sigma/coin.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "primitives/zerocoin.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>

#include <ios>

namespace sigma {

// Set up the Sigma Params object
sigma::Params* SigmaParams = sigma::Params::get_default();

static CSigmaState sigmaState;

static bool CheckSigmaSpendSerial(
        CValidationState &state,
        CSigmaTxInfo *sigmaTxInfo,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip) {
    // check for zerocoin transaction in this block as well
    if (sigmaTxInfo &&
            !sigmaTxInfo->fInfoIsComplete &&
            sigmaTxInfo->spentSerials.find(serial) != sigmaTxInfo->spentSerials.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same serial in the same block"));

    // check for used serials in sigmaState
    if (sigmaState.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The sigma CoinSpend serial has been used"));
        }
    }
    return true;
}

bool IsSigmaAllowed()
{
    LOCK(cs_main);
    return IsSigmaAllowed(chainActive.Height());
}

bool IsSigmaAllowed(int height)
{
	return height >= ::Params().GetConsensus().nSigmaStartBlock;
}

secp_primitives::GroupElement ParseSigmaMintScript(const CScript& script)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Sigma mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());

    secp_primitives::GroupElement pub;
    pub.deserialize(serialized.data());

    return pub;
}

std::pair<std::unique_ptr<sigma::CoinSpend>, uint32_t> ParseSigmaSpend(const CTxIn& in)
{
    uint32_t groupId = in.prevout.n;

    if (groupId < 1 || groupId >= INT_MAX || in.scriptSig.size() < 1) {
        throw CBadTxIn();
    }

    CDataStream serialized(
        std::vector<unsigned char>(in.scriptSig.begin() + 1, in.scriptSig.end()),
        SER_NETWORK,
        PROTOCOL_VERSION
    );

	std::unique_ptr<sigma::CoinSpend> spend(new sigma::CoinSpend(SigmaParams, serialized));

    return std::make_pair(std::move(spend), groupId);
}

// This function will not report an error only if the transaction is sigma spend.
CAmount GetSpendAmount(const CTxIn& in) {
    if (in.IsSigmaSpend()) {
        std::unique_ptr<sigma::CoinSpend> spend;

        try {
            std::tie(spend, std::ignore) = ParseSigmaSpend(in);
        } catch (const std::ios_base::failure& e) {
            LogPrintf("GetSpendAmount: io error %s\n", e.what());
            return 0;
        } catch (const CBadTxIn& e) {
            LogPrintf("GetSpendAmount: %s\n", e.what());
            return 0;
        }

        return spend->getIntDenomination();
    }
    return 0;
}

CAmount GetSpendAmount(const CTransaction& tx) {
    CAmount sum(0);
    for (const auto& vin : tx.vin) {
        sum += GetSpendAmount(vin);
    }
    return sum;
}

bool CheckSigmaBlock(CValidationState &state, const CBlock& block) {
    auto& consensus = ::Params().GetConsensus();

    size_t blockSpendsAmount = 0;
    CAmount blockSpendsValue(0);

    for (const auto& tx : block.vtx) {
        auto txSpendsValue = GetSpendAmount(tx);
        size_t txSpendsAmount = 0;

        for (const auto& in : tx.vin) {
            if (in.IsSigmaSpend()) {
                txSpendsAmount++;
            }
        }

        if (txSpendsAmount > consensus.nMaxSigmaInputPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        if (txSpendsValue > consensus.nMaxValueSigmaSpendPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        blockSpendsAmount += txSpendsAmount;
        blockSpendsValue += txSpendsValue;
    }

    if (blockSpendsAmount > consensus.nMaxSigmaInputPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
            "bad-txns-spend-invalid");
    }

    if (blockSpendsValue > consensus.nMaxValueSigmaSpendPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
            "bad-txns-spend-invalid");
    }
    return true;
}

// Will return false for V1, V1.5 and V2 spends.
// Mixing V2 and sigma spends into the same transaction will fail.
bool CheckSigmaSpendTransaction(
        const CTransaction &tx,
        const vector<sigma::CoinDenomination>& targetDenominations,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSigmaTxInfo *sigmaTxInfo) {
    bool hasSigmaSpendInputs = false, hasNonSigmaInputs = false;
    int vinIndex = -1;
    std::unordered_set<Scalar, sigma::CScalarHash> txSerials;

    for (const CTxIn &txin : tx.vin)
    {
        std::unique_ptr<sigma::CoinSpend> spend;
        uint32_t pubcoinId;

        vinIndex++;
        if (txin.scriptSig.IsSigmaSpend())
            hasSigmaSpendInputs = true;
        else
            hasNonSigmaInputs = true;

        try {
            std::tie(spend, pubcoinId) = ParseSigmaSpend(txin);
        } catch (CBadTxIn&) {
            return state.DoS(100,
                false,
                REJECT_MALFORMED,
                "CheckSigmaSpendTransaction: invalid spend transaction");
        }

        if (spend->getVersion() != ZEROCOIN_TX_VERSION_3) {
            return state.DoS(100,
                             false,
                             NSEQUENCE_INCORRECT,
                             "CTransaction::CheckTransaction() : Error: incorrect spend transaction verion");
        }

        uint256 txHashForMetadata;

        // Obtain the hash of the transaction sans the zerocoin part
        CMutableTransaction txTemp = tx;
        BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
            if (txTempIn.scriptSig.IsSigmaSpend()) {
                txTempIn.scriptSig.clear();
            }
        }
        txHashForMetadata = txTemp.GetHash();

        LogPrintf("CheckSigmaSpendTransaction: tx version=%d, tx metadata hash=%s, serial=%s\n",
                spend->getVersion(), txHashForMetadata.ToString(),
                spend->getCoinSerialNumber().tostring());

        if (!fStatefulSigmaCheck) {
            continue;
        }

        CSigmaState::SigmaCoinGroupInfo coinGroup;
        if (!sigmaState.GetCoinGroupInfo(targetDenominations[vinIndex], pubcoinId, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN,
                    "CheckSigmaSpendTransaction: Error: no coins were minted with such parameters");

        bool passVerify = false;
        CBlockIndex *index = coinGroup.lastBlock;
        pair<sigma::CoinDenomination, int> denominationAndId = std::make_pair(
            targetDenominations[vinIndex], pubcoinId);

        uint256 accumulatorBlockHash = spend->getAccumulatorBlockHash();

        // We use incomplete transaction hash as metadata.
        sigma::SpendMetaData newMetaData(
            pubcoinId,
            accumulatorBlockHash,
            txHashForMetadata);

        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
            index = index->pprev;

        // Build a vector with all the public coins with given denomination and accumulator id before
        // the block on which the spend occured.
        // This list of public coins is required by function "Verify" of CoinSpend.
        std::vector<sigma::PublicCoin> anonymity_set;
        while(true) {
            BOOST_FOREACH(const sigma::PublicCoin& pubCoinValue,
                    index->sigmaMintedPubCoins[denominationAndId]) {
                anonymity_set.push_back(pubCoinValue);
            }
            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }

        passVerify = spend->Verify(anonymity_set, newMetaData);
        if (passVerify) {
            Scalar serial = spend->getCoinSerialNumber();
            // do not check for duplicates in case we've seen exact copy of this tx in this block before
            if (!(sigmaTxInfo && sigmaTxInfo->zcTransactions.count(hashTx) > 0)) {
                if (!CheckSigmaSpendSerial(
                            state, sigmaTxInfo, serial, nHeight, false)) {
                    LogPrintf("CheckSigmaSpendTransaction: serial check failed, serial=%s\n", serial);
                    return false;
                }
            }

            // check duplicated serials in same transaction.
            if (!txSerials.insert(serial).second) {
                return state.DoS(100,
                    error("CheckSigmaSpendTransaction: two or more spends with same serial in the same transaction"));
            }

            if(!isVerifyDB && !isCheckWallet) {
                if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
                    // add spend information to the index
                    sigmaTxInfo->spentSerials.insert(std::make_pair(
                                serial, (int)spend->getDenomination()));
                }
            }
        }
        else {
            LogPrintf("CheckSigmaSpendTransaction: verification failed at block %d\n", nHeight);
            return false;
        }
    }

    if(!isVerifyDB && !isCheckWallet) {
        if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete && hasSigmaSpendInputs) {
            sigmaTxInfo->zcTransactions.insert(hashTx);
        }
    }

    if (hasSigmaSpendInputs) {
        if (hasNonSigmaInputs) {
            // mixing zerocoin spend input with non-zerocoin inputs is prohibited
            return state.DoS(100, false,
                             REJECT_MALFORMED,
                             "CheckSigmaSpendTransaction: can't mix zerocoin spend input with regular ones");
        }
    }

    return true;
}

bool CheckSigmaMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSigmaTxInfo *sigmaTxInfo) {
    secp_primitives::GroupElement pubCoinValue;

    LogPrintf("CheckSigmaMintTransaction txHash = %s\n", txout.GetHash().ToString());
    LogPrintf("nValue = %d\n", txout.nValue);

    try {
        pubCoinValue = ParseSigmaMintScript(txout.scriptPubKey);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : PubCoin validation failed");
    }

    sigma::CoinDenomination denomination;
    if (!IntegerToDenomination(txout.nValue, denomination, state)) {
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CTransaction::CheckSigmaTransaction() : "
                "PubCoin validation failed, unknown denomination");
    }
    sigma::PublicCoin pubCoin(pubCoinValue, denomination);
    bool hasCoin = sigmaState.HasCoin(pubCoin);

    if (!hasCoin && sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const sigma::PublicCoin& mint, sigmaTxInfo->mints) {
            if (mint == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin && fStatefulSigmaCheck) {
       LogPrintf("CheckSigmaMintTransaction: double mint, tx=%s\n",
                txout.GetHash().ToString());
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckSigmaTransaction: double mint");
    }

    if (!pubCoin.validate())
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckSigmaTransaction : PubCoin validation failed");

    if (sigmaTxInfo != NULL && !sigmaTxInfo->fInfoIsComplete) {
        // Update public coin list in the info
        sigmaTxInfo->mints.push_back(pubCoin);
        sigmaTxInfo->zcTransactions.insert(hashTx);
    }

    return true;
}

bool CheckSigmaTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSigmaTxInfo *sigmaTxInfo)
{
    auto& consensus = ::Params().GetConsensus();

    // nHeight have special mode which value is INT_MAX so we need this.
    int realHeight;

    {
        LOCK(cs_main);
        realHeight = chainActive.Height();
    }

    bool allowSigma = (realHeight >= consensus.nSigmaStartBlock);

    // Check Mint Sigma Transaction
    if (allowSigma) {
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSigmaMint()) {
                if (!CheckSigmaMintTransaction(txout, state, hashTx, fStatefulSigmaCheck, sigmaTxInfo))
                    return false;
            }
        }
    }

    // Check Sigma Spend Transaction
    if(tx.IsSigmaSpend()) {
        // First check number of inputs does not exceed transaction limit
        if (tx.vin.size() > consensus.nMaxSigmaInputPerTransaction) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        if (GetSpendAmount(tx) > consensus.nMaxValueSigmaSpendPerTransaction) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        vector<sigma::CoinDenomination> denominations;
        uint64_t totalValue = 0;
        BOOST_FOREACH(const CTxIn &txin, tx.vin){
            if(!txin.scriptSig.IsSigmaSpend()) {
                return state.DoS(100, false,
                                 REJECT_MALFORMED,
                                 "CheckSigmaSpendTransaction: can't mix zerocoin spend input with regular ones");
            }
            // Get the CoinDenomination value of each vin for the CheckSigmaSpendTransaction function
            uint32_t pubcoinId = txin.prevout.n;
            if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
                // coin id should be positive integer
                return false;
            }

            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend newSpend(SigmaParams, serializedCoinSpend);
            uint64_t denom = newSpend.getIntDenomination();
            totalValue += denom;
            sigma::CoinDenomination denomination;
            if (!IntegerToDenomination(denom, denomination, state))
                return false;
            denominations.push_back(denomination);
        }

        // Check vOut
        // Only one loop, we checked on the format before entering this case
        if (!isVerifyDB) {
            if (!CheckSigmaSpendTransaction(
                tx, denominations, state, hashTx, isVerifyDB, nHeight,
                isCheckWallet, fStatefulSigmaCheck, sigmaTxInfo)) {
                    return false;
            }
        }
    }

    return true;
}

void RemoveSigmaSpendsReferencingBlock(CTxMemPool& pool, CBlockIndex* blockIndex) {
    LOCK2(cs_main, pool.cs);
    std:vector<CTransaction> txn_to_remove;
    for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); ++mi) {
        const CTransaction& tx = mi->GetTx();
        if (tx.IsSigmaSpend()) {
            // Run over all the inputs, check if their Accumulator block hash is equal to 
            // block removed. If any one is equal, remove txn from mempool. 
            for (const CTxIn& txin : tx.vin) {
                if (txin.IsSigmaSpend()) {
                    std::unique_ptr<sigma::CoinSpend> spend;
                    uint32_t pubcoinId;
                    std::tie(spend, pubcoinId) = ParseSigmaSpend(txin);
                    uint256 accumulatorBlockHash = spend->getAccumulatorBlockHash();
                    if (accumulatorBlockHash == blockIndex->GetBlockHash()) {
                        // Do not remove transaction immediately, that will invalidate iterator mi.
                        txn_to_remove.push_back(tx);
                        break;
                    }
                }
            }
        }
    }
    for (const CTransaction& tx: txn_to_remove) {
        std::list<CTransaction> removed;
        // Remove txn from mempool.
        pool.removeRecursive(tx, removed);
        LogPrintf("DisconnectTipSigma: removed sigma spend which referenced a removed blockchain tip.");
    }
}

void DisconnectTipSigma(CBlock& block, CBlockIndex *pindexDelete) {
    sigmaState.RemoveBlock(pindexDelete);

    // Also remove from mempool sigma spends that reference given block hash.
    RemoveSigmaSpendsReferencingBlock(mempool, pindexDelete);
    RemoveSigmaSpendsReferencingBlock(stempool, pindexDelete);
}

Scalar GetSigmaSpendSerialNumber(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsSigmaSpend())
        return Scalar(uint64_t(0));

    try {
        // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
        // OP_SIGMASPEND is written. In zerocoin you will see +4 instead,
        // because the size of serialized spend is also written, probably in 3 bytes.
        CDataStream serializedCoinSpend(
                (const char *)&*(txin.scriptSig.begin() + 1),
                (const char *)&*txin.scriptSig.end(),
                SER_NETWORK, PROTOCOL_VERSION);
        sigma::CoinSpend spend(SigmaParams, serializedCoinSpend);
        return spend.getCoinSerialNumber();
    }
    catch (const std::ios_base::failure &) {
        return Scalar(uint64_t(0));
    }
}

CAmount GetSigmaSpendInput(const CTransaction &tx) {
    if (!tx.IsSigmaSpend())
        return CAmount(0);

    try {
        CAmount sum(0);
        BOOST_FOREACH(const CTxIn& txin, tx.vin){
            // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
            // OP_ZEROCOINSPENDV3 is written. In zerocoin you will see +4 instead,
            // because the size of serialized spend is also written, probably in 3 bytes.
            CDataStream serializedCoinSpend(
                    (const char *)&*(txin.scriptSig.begin() + 1),
                    (const char *)&*txin.scriptSig.end(),
                    SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend spend(SigmaParams, serializedCoinSpend);
            sum += spend.getIntDenomination();
        }
        return sum;
    }
    catch (const std::runtime_error &) {
        return CAmount(0);
    }
}


/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockSigma(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {
    // Add zerocoin transaction information to index
    if (pblock && pblock->sigmaTxInfo) {
        if (!fJustCheck) {
            pindexNew->sigmaMintedPubCoins.clear();
            pindexNew->sigmaSpentSerials.clear();
        }

        if (!CheckSigmaBlock(state, *pblock)) {
            return false;
        }

        BOOST_FOREACH(auto& serial, pblock->sigmaTxInfo->spentSerials) {
            if (!CheckSigmaSpendSerial(
                    state,
                    pblock->sigmaTxInfo.get(),
                    serial.first,
                    pindexNew->nHeight,
                    true /* fConnectTip */
                    )) {
                return false;
            }

            if (!fJustCheck) {
                pindexNew->sigmaSpentSerials.insert(serial.first);
                sigmaState.AddSpend(serial.first);
            }
        }

        if (fJustCheck)
            return true;

        sigmaState.AddMintsToStateAndBlockIndex(pindexNew, pblock);
    }
    else if (!fJustCheck) { // TODO(martun): not sure if this else is necessary here. Check again later.
        sigmaState.AddBlock(pindexNew);
    }
    return true;
}

bool GetOutPointFromBlock(COutPoint& outPoint, const GroupElement &pubCoinValue, const CBlock &block){
    secp_primitives::GroupElement txPubCoinValue;
    // cycle transaction hashes, looking for this pubcoin.
    BOOST_FOREACH(CTransaction tx, block.vtx){
        if(tx.IsSigmaMint()){
            uint32_t nIndex = 0;
            for (const CTxOut &txout: tx.vout) {
                if (txout.scriptPubKey.IsSigmaMint()){

                    // If you wonder why +1, go to file wallet.cpp and read the comments in function
                    // CWallet::CreateZerocoinMintModelV3 around "scriptSerializedCoin << OP_ZEROCOINMINTV3";
                    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                                          txout.scriptPubKey.end());
                    txPubCoinValue.deserialize(&coin_serialised[0]);
                    if(pubCoinValue==txPubCoinValue){
                        outPoint = COutPoint(tx.GetHash(), nIndex);
                        return true;
                    }
                }
                nIndex++;
            }
        }
    }

    return false;
}

bool GetOutPoint(COutPoint& outPoint, const sigma::PublicCoin &pubCoin) {

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    auto mintedCoinHeightAndId = sigmaState->GetMintedCoinHeightAndId(pubCoin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    return GetOutPointFromBlock(outPoint, pubCoin.value, block);
}

bool GetOutPoint(COutPoint& outPoint, const GroupElement &pubCoinValue) {
    int mintHeight = 0;
    int coinId = 0;

    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    std::vector<sigma::CoinDenomination> denominations;
    GetAllDenoms(denominations);
    BOOST_FOREACH(sigma::CoinDenomination denomination, denominations){
        sigma::PublicCoin pubCoin(pubCoinValue, denomination);
        auto mintedCoinHeightAndId = sigmaState->GetMintedCoinHeightAndId(pubCoin);
        mintHeight = mintedCoinHeightAndId.first;
        coinId = mintedCoinHeightAndId.second;
        if(mintHeight!=-1 && coinId!=-1)
            break;
    }

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    return GetOutPointFromBlock(outPoint, pubCoinValue, block);
}

bool GetOutPoint(COutPoint& outPoint, const uint256 &pubCoinValueHash) {
    GroupElement pubCoinValue;
    sigma::CSigmaState *sigmaState = sigma::CSigmaState::GetState();
    if(!sigmaState->HasCoinHash(pubCoinValue, pubCoinValueHash)){
        return false;
    }

    return GetOutPoint(outPoint, pubCoinValue);
}

bool BuildSigmaStateFromIndex(CChain *chain) {
    sigmaState.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        sigmaState.AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
        "Latest IDs for sigma coin groups are %d, %d, %d, %d, %d\n",
        sigmaState.GetLatestCoinID(CoinDenomination::SIGMA_DENOM_0_1),
        sigmaState.GetLatestCoinID(CoinDenomination::SIGMA_DENOM_0_5),
        sigmaState.GetLatestCoinID(CoinDenomination::SIGMA_DENOM_1),
        sigmaState.GetLatestCoinID(CoinDenomination::SIGMA_DENOM_10),
        sigmaState.GetLatestCoinID(CoinDenomination::SIGMA_DENOM_100));
    return true;
}

uint256 GetSerialHash(const secp_primitives::Scalar& bnSerial)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    return Hash(ss.begin(), ss.end());
}

uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnValue;
    return Hash(ss.begin(), ss.end());
}

// CZerocoinTxInfoV3

void CSigmaTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it. Denomination doesn't matter but we will sort by it as well
    sort(mints.begin(), mints.end(),
            [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
            CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
            ds1 << m1;
            ds2 << m2;
            return ds1.str() < ds2.str();
            });

    // Mark this info as complete
    fInfoIsComplete = true;
}

// CSigmaState

CSigmaState::CSigmaState() {
}

void CSigmaState::AddMintsToStateAndBlockIndex(
        CBlockIndex *index,
        const CBlock* pblock) {

    std::unordered_map<sigma::CoinDenomination, std::vector<sigma::PublicCoin>> blockDenomMints;
    for (const auto& mint : pblock->sigmaTxInfo->mints) {
        blockDenomMints[mint.getDenomination()].push_back(mint);
    }

    for (const auto& it : blockDenomMints) {
        const sigma::CoinDenomination denomination = it.first;
        const std::vector<sigma::PublicCoin>& mintsWithThisDenom = it.second;

        if (latestCoinIds[denomination] < 1)
            latestCoinIds[denomination] = 1;
        auto mintCoinGroupId = latestCoinIds[denomination];


        SigmaCoinGroupInfo &coinGroup = coinGroups[make_pair(denomination, mintCoinGroupId)];

        if (coinGroup.nCoins + mintsWithThisDenom.size() <= ZC_SPEND_V3_COINSPERID_LIMIT) {
            if (coinGroup.nCoins == 0) {
                // first group of coins for given denomination
                assert(coinGroup.firstBlock == nullptr);
                assert(coinGroup.lastBlock == nullptr);

                coinGroup.firstBlock = coinGroup.lastBlock = index;
            } else {
                assert(coinGroup.firstBlock != nullptr);
                assert(coinGroup.lastBlock != nullptr);
                assert(coinGroup.lastBlock->nHeight <= index->nHeight);

                coinGroup.lastBlock = index;
            }
            coinGroup.nCoins += mintsWithThisDenom.size();
        }
        else {
            latestCoinIds[denomination] = ++mintCoinGroupId;
            SigmaCoinGroupInfo& newCoinGroup = coinGroups[std::make_pair(denomination, mintCoinGroupId)];
            newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
            newCoinGroup.nCoins = mintsWithThisDenom.size();
        }

        for (const auto& mint : mintsWithThisDenom) {
            CMintedCoinInfo coinInfo;
            coinInfo.denomination = denomination;
            coinInfo.id = mintCoinGroupId;
            coinInfo.nHeight = index->nHeight;
            mintedPubCoins.insert(std::make_pair(mint, coinInfo));

            LogPrintf("AddMintsToStateAndBlockIndex: mint added denomination=%d, id=%d\n", denomination, mintCoinGroupId);
            index->sigmaMintedPubCoins[{denomination, mintCoinGroupId}].push_back(mint);
        }
    }
}

void CSigmaState::AddSpend(const Scalar &serial) {
    usedCoinSerials.insert(serial);
}

void CSigmaState::AddBlock(CBlockIndex *index) {
    BOOST_FOREACH(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int), vector<sigma::PublicCoin>) &pubCoins,
            index->sigmaMintedPubCoins) {
        if (!pubCoins.second.empty()) {
            SigmaCoinGroupInfo& coinGroup = coinGroups[pubCoins.first];

            if (coinGroup.firstBlock == NULL)
                coinGroup.firstBlock = index;
            coinGroup.lastBlock = index;
            coinGroup.nCoins += pubCoins.second.size();
        }

        latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
        BOOST_FOREACH(const sigma::PublicCoin &coin, pubCoins.second) {
            CMintedCoinInfo coinInfo;
            coinInfo.denomination = pubCoins.first.first;
            coinInfo.id = pubCoins.first.second;
            coinInfo.nHeight = index->nHeight;
            mintedPubCoins.insert(pair<sigma::PublicCoin, CMintedCoinInfo>(coin, coinInfo));
        }
    }

    BOOST_FOREACH(const Scalar &serial, index->sigmaSpentSerials) {
        usedCoinSerials.insert(serial);
    }
}

void CSigmaState::RemoveBlock(CBlockIndex *index) {
    // roll back accumulator updates
    BOOST_FOREACH(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int),vector<sigma::PublicCoin>) &coin,
        index->sigmaMintedPubCoins)
    {
        SigmaCoinGroupInfo   &coinGroup = coinGroups[coin.first];
        int  nMintsToForget = coin.second.size();

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coin.first);
            // decrease pubcoin id for this denomination
            latestCoinIds[coin.first.first]--;
            if (0 == latestCoinIds[coin.first.first]) {
                latestCoinIds.erase(coin.first.first);
            }
        }
        else {
            // roll back lastBlock to previous position
            assert(coinGroup.lastBlock == index);

            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->sigmaMintedPubCoins.count(coin.first) == 0);
        }
    }

    // roll back mints
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int),vector<sigma::PublicCoin>) &pubCoins,
                  index->sigmaMintedPubCoins) {
        BOOST_FOREACH(const sigma::PublicCoin &coin, pubCoins.second) {
            auto coins = mintedPubCoins.equal_range(coin);
            auto coinIt = find_if(
                coins.first, coins.second,
                [=](const decltype(mintedPubCoins)::value_type &v) {
                    return v.second.denomination == pubCoins.first.first &&
                        v.second.id == pubCoins.first.second;
                });
            assert(coinIt != coins.second);
            mintedPubCoins.erase(coinIt);
        }
    }

    index->sigmaMintedPubCoins.clear();

    // roll back spends
    BOOST_FOREACH(const Scalar &serial, index->sigmaSpentSerials) {
        usedCoinSerials.erase(serial);
    }

    index->sigmaSpentSerials.clear();
}

bool CSigmaState::GetCoinGroupInfo(
        sigma::CoinDenomination denomination,
        int group_id,
        SigmaCoinGroupInfo& result) {
    std::pair<sigma::CoinDenomination, int> key =
        std::make_pair(denomination, group_id);
    if (coinGroups.count(key) == 0)
        return false;

    result = coinGroups[key];
    return true;
}

bool CSigmaState::IsUsedCoinSerial(const Scalar &coinSerial) {
    return usedCoinSerials.count(coinSerial) != 0;
}

bool CSigmaState::IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash) {
    for ( auto it = usedCoinSerials.begin(); it != usedCoinSerials.end(); ++it ){
        if(GetSerialHash(*it)==coinSerialHash){
            coinSerial = *it;
            return true;
        }
    }
    return false;
}

bool CSigmaState::HasCoin(const sigma::PublicCoin& pubCoin) {
    return mintedPubCoins.find(pubCoin) != mintedPubCoins.end();
}

bool CSigmaState::HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash) {
    for ( auto it = mintedPubCoins.begin(); it != mintedPubCoins.end(); ++it ){
    	const sigma::PublicCoin pubCoin = (*it).first;
        if(GetPubCoinValueHash(pubCoin.value)==pubCoinValueHash){
            pubCoinValue = pubCoin.value;
            return true;
        }
    }
    return false;
}

int CSigmaState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        sigma::CoinDenomination denomination,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<sigma::PublicCoin>& coins_out) {

    pair<sigma::CoinDenomination, int> denomAndId = std::make_pair(denomination, coinGroupID);

    if (coinGroups.count(denomAndId) == 0)
        return 0;

    SigmaCoinGroupInfo coinGroup = coinGroups[denomAndId];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;
            ;
            block = block->pprev) {
        if (block->sigmaMintedPubCoins[denomAndId].size() > 0) {
            if (block->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember block hash
                    blockHash_out = block->GetBlockHash();
                }
                numberOfCoins += block->sigmaMintedPubCoins[denomAndId].size();
                coins_out.insert(coins_out.end(),
                        block->sigmaMintedPubCoins[denomAndId].begin(),
                        block->sigmaMintedPubCoins[denomAndId].end());
            }
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
    return numberOfCoins;
}

std::pair<int, int> CSigmaState::GetMintedCoinHeightAndId(
        const sigma::PublicCoin& pubCoin) {
    auto coinIt = mintedPubCoins.find(pubCoin);

    if (coinIt != mintedPubCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.id);
    }
    return std::make_pair(-1, -1);
}

bool CSigmaState::AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash) {
    BOOST_FOREACH(Scalar coinSerial, coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
            return false;

        mempoolCoinSerials[coinSerial] = txHash;
    }

    return true;
}

bool CSigmaState::AddSpendToMempool(const Scalar &coinSerial, uint256 txHash) {
    if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
        return false;

    mempoolCoinSerials[coinSerial] = txHash;
    return true;
}

void CSigmaState::RemoveSpendFromMempool(const Scalar& coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

uint256 CSigmaState::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CSigmaState::CanAddSpendToMempool(const Scalar& coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

void CSigmaState::Reset() {
    coinGroups.clear();
    usedCoinSerials.clear();
    latestCoinIds.clear();
    mintedPubCoins.clear();
    mempoolCoinSerials.clear();
}

CSigmaState* CSigmaState::GetState() {
    return &sigmaState;
}

int CSigmaState::GetLatestCoinID(sigma::CoinDenomination denomination) const {
    auto iter = latestCoinIds.find(denomination);
    if (iter == latestCoinIds.end()) {
        // Do not throw here, if there was no sigma mint, that's fine.
        return 0;
    }
    return iter->second;
}

} // end of namespace sigma.
