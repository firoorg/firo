#include "state.h"
#include "../validation.h"
#include "../batchproof_container.h"

namespace spark {

static CSparkState sparkState;

static bool CheckLTag(
        CValidationState &state,
        CSparkTxInfo *sparkTxInfo,
        const GroupElement& lTag,
        int nHeight,
        bool fConnectTip) {
    // check for Spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
            sparkTxInfo->spentLTags.find(lTag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spands with same linking tag in the same block"));

    // check for used linking tags in state
    if (sparkState.IsUsedLTag(lTag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark coin has been used"));
        }
    }
    return true;
}

// CSparkTxInfo
void CSparkTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it.
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

bool IsSparkAllowed()
{
    LOCK(cs_main);
    return IsSparkAllowed(chainActive.Height());
}

bool IsSparkAllowed(int height)
{
    return height >= ::Params().GetConsensus().nSparkStartBlock;
}


/*
 * Util funtions
 */
size_t CountCoinInBlock(CBlockIndex *index, int id) {
    return index->sparkMintedCoins.count(id) > 0
           ? index->sparkMintedCoins[id].size() : 0;
}

std::vector<unsigned char> GetAnonymitySetHash(CBlockIndex *index, int group_id, bool generation = false) {
    std::vector<unsigned char> out_hash;

    CSparkState::SparkCoinGroupInfo coinGroup;
    if (!sparkState.GetCoinGroupInfo(group_id, coinGroup))
        return out_hash;

    if ((coinGroup.firstBlock == coinGroup.lastBlock && generation) || (coinGroup.nCoins == 0))
        return out_hash;

    while (index != coinGroup.firstBlock) {
        if (index->sparkSetHash.count(group_id) > 0) {
            out_hash = index->sparkSetHash[group_id];
            break;
        }
        index = index->pprev;
    }
    return out_hash;
}

void ParseSparkMintTransaction(const std::vector<CScript>& scripts, MintTransaction& mintTransaction)
{
    std::vector<CDataStream> serializedCoins;
    for (const auto& script : scripts) {
        if (!script.IsSparkMint())
            throw std::invalid_argument("Script is not a Spark mint");

        std::vector<unsigned char> serialized(script.begin() + 1, script.end());
        size_t size = spark::Coin::memoryRequired() + 8; // 8 is the size of uint64_t
        if (serialized.size() < size) {
            throw std::invalid_argument("Script is not a valid Spark mint");
        }

        CDataStream stream(
                std::vector<unsigned char>(serialized.begin(), serialized.end()),
                SER_NETWORK,
                PROTOCOL_VERSION
        );

        serializedCoins.push_back(stream);
    }

    mintTransaction.setMintTransaction(serializedCoins);
}

void ParseSparkMintCoin(const CScript& script, spark::Coin& txCoin)
{
    if (!script.IsSparkMint() && !script.IsSparkSMint())
        throw std::invalid_argument("Script is not a Spark mint");

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    CDataStream stream(
            std::vector<unsigned char>(serialized.begin(), serialized.end()),
            SER_NETWORK,
            PROTOCOL_VERSION
    );

    stream >> txCoin;
}

spark::SpendTransaction ParseSparkSpend(const CTransaction &tx)
{
    if (tx.vin.size() != 1 || tx.vin[0].scriptSig.size() < 1) {
        throw CBadTxIn();
    }
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);

    if (tx.vin[0].scriptSig[0] == OP_SPARKSPEND && tx.nVersion >= 3 && tx.nType == TRANSACTION_SPARK) {
        serialized.write((const char *)tx.vExtraPayload.data(), tx.vExtraPayload.size());
    }
    else
        throw CBadTxIn();
    const spark::Params* params = spark::Params::get_default();
    spark::SpendTransaction spendTransaction(params);
    serialized >> spendTransaction;
    return std::move(spendTransaction);
}


std::vector<GroupElement> GetSparkUsedTags(const CTransaction &tx)
{
    const spark::Params* params = spark::Params::get_default();

    spark::SpendTransaction spendTransaction(params);
    try {
        spendTransaction = ParseSparkSpend(tx);
    } catch (...) {
        return std::vector<GroupElement>();
    }

    return  spendTransaction.getUsedLTags();
}

std::vector<std::pair<spark::Coin, std::vector<unsigned char>>> GetSparkMintCoins(const CTransaction &tx)
{
    std::vector<std::pair<spark::Coin, std::vector<unsigned char>>> result;

    if (tx.IsSparkTransaction()) {
        CDataStream serialContextStream(SER_NETWORK, PROTOCOL_VERSION);
        if (tx.IsSparkSpend()) {
            try {
                spark::SpendTransaction spend = ParseSparkSpend(tx);
                serialContextStream << spend.getUsedLTags();
            } catch (...) {
                return result;
            }
        } else {
            for (auto &input: tx.vin) {
                serialContextStream << input;
            }
        }
        std::vector<unsigned char> serial_context(serialContextStream.begin(), serialContextStream.end());
        for (const auto& vout : tx.vout) {
            const auto& script = vout.scriptPubKey;
            if (script.IsSparkMint() || script.IsSparkSMint()) {
                try {
                    spark::Coin coin;
                    ParseSparkMintCoin(script, coin);
                    result.push_back({coin, serial_context});
                } catch (...) {
                    //Continue
                }
            }
        }
    }

    return result;
}

size_t GetSpendInputs(const CTransaction &tx) {
    return tx.IsSparkSpend() ?
           GetSparkUsedTags(tx).size() : 0;
}

CAmount GetSpendTransparentAmount(const CTransaction& tx) {
    CAmount result = 0;
    if(!tx.IsSparkSpend())
        return 0;

    for (const CTxOut &txout : tx.vout)
        result += txout.nValue;
    return result;
}

bool CheckSparkBlock(CValidationState &state, const CBlock& block) {
    auto& consensus = ::Params().GetConsensus();

    size_t blockSpendsAmount = 0;
    CAmount blockSpendsValue(0);

    for (const auto& tx : block.vtx) {
        auto txSpendsValue =  GetSpendTransparentAmount(*tx);
        size_t txSpendNumber = GetSpendInputs(*tx);

        if (txSpendNumber > consensus.nMaxLelantusInputPerTransaction) { //TODO levon define spark limits and refactor here
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-spark-spend-invalid");
        }

        if (txSpendsValue > consensus.nMaxValueLelantusSpendPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-spark-spend-invalid");
        }

        blockSpendsAmount += txSpendNumber;
        blockSpendsValue += txSpendsValue;
    }

    if (blockSpendsAmount > consensus.nMaxLelantusInputPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-spark-spend-invalid");
    }

    if (blockSpendsValue > consensus.nMaxValueLelantusSpendPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-spark-spend-invalid");
    }

    return true;
}


bool CheckSparkMintTransaction(
        const std::vector<CScript>& scripts,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkMintTransaction txHash = %s\n", hashTx.GetHex());
    const spark::Params* params = spark::Params::get_default();

    MintTransaction mintTransaction(params);
    try {
        ParseSparkMintTransaction(scripts, mintTransaction);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CTransaction::CheckTransaction() : SparkMint parsing failure.");
    }

    //checking whether MintTransaction is valid
    if(!mintTransaction.verify())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction : mintTransaction verification failed");

    std::vector<Coin> coins;
    mintTransaction.getCoins(coins);
    bool hasCoin = false;
    for (auto& coin : coins) {
        if (coin.v > ::Params().GetConsensus().nMaxValueLelantusMint)
            return state.DoS(100,
                             false,
                             REJECT_INVALID,
                             "CTransaction::CheckTransaction() : Spark Mint is out of limit.");

        hasCoin = sparkState.HasCoin(coin);

        if (!hasCoin && sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
            for (const auto& mint : sparkTxInfo->mints) {
                if (mint == coin) {
                    hasCoin = true;
                    break;
                }
            }

            // Update coin list in the info
            sparkTxInfo->mints.push_back(coin);
            sparkTxInfo->spTransactions.insert(hashTx);
        }

        if (hasCoin && fStatefulSigmaCheck)
            break;
    }

    if (hasCoin && fStatefulSigmaCheck) {
        LogPrintf("CheckSparkMintTransaction: double mint, tx=%s\n", hashTx.GetHex());
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction: double mint");
    }

    return true;
}

bool CheckSparkSMintTransaction(
        const std::vector<CTxOut>& vout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        std::vector<Coin>& out_coins,
        CSparkTxInfo* sparkTxInfo) {

    LogPrintf("CheckSparkSMintTransaction txHash = %s\n", hashTx.ToString());
    out_coins.clear();
    for (const auto& out : vout) {
        const auto& script = out.scriptPubKey;
        if (script.IsSparkMint() || script.IsSparkSMint()) {
            try {
                spark::Coin coin;
                ParseSparkMintCoin(script, coin);
                out_coins.push_back(coin);
            } catch (...) {
                return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "CTransaction::CheckTransaction() : Spark Mint is invalid.");
            }
        }
    }

    bool hasCoin = false;
    for (auto& coin : out_coins) {

        hasCoin = sparkState.HasCoin(coin);

        if (!hasCoin && sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
            for (const auto& mint : sparkTxInfo->mints) {
                if (mint == coin) {
                    hasCoin = true;
                    break;
                }
            }

            // Update coin list in the info
            sparkTxInfo->mints.push_back(coin);
            sparkTxInfo->spTransactions.insert(hashTx);
        }

        if (hasCoin && fStatefulSigmaCheck)
            break;

    }

    if (hasCoin && fStatefulSigmaCheck) {
        LogPrintf("CheckSparkMintTransaction: double mint, tx=%s\n", hashTx.GetHex());
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckSparkMintTransaction: double mint");
    }

    return true;
}

bool CheckSparkSpendTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        int realHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo) {
    std::unordered_set<GroupElement, spark::CLTagHash> txLTags;

    if(tx.vin.size() != 1 || !tx.vin[0].scriptSig.IsSparkSpend()) {
        // mixing spark spend input with non-spark inputs is prohibited
        return state.DoS(100, false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: can't mix spark spend input with other tx types or have more than one spend");
    }

    Consensus::Params const & params = ::Params().GetConsensus();
    int height = nHeight == INT_MAX ? chainActive.Height()+1 : nHeight;
    if (!isVerifyDB) {
            if (height >= params.nSparkStartBlock) {
                // data should be moved to v3 payload
                if (tx.nVersion < 3 || tx.nType != TRANSACTION_LELANTUS)
                    return state.DoS(100, false, NSEQUENCE_INCORRECT,
                                     "CheckSparkSpendTransaction: spark data should reside in transaction payload");
            }
    }

    std::unique_ptr<spark::SpendTransaction> spend;

    try {
        spend = std::make_unique<spark::SpendTransaction>(ParseSparkSpend(tx));
    }
    catch (CBadTxIn&) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: invalid spend transaction");
    }
    catch (...) {
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSparkSpendTransaction: failed to deserialize spend");
    }

    uint256 txHashForMetadata;

    // Obtain the hash of the transaction sans the zerocoin part
    CMutableTransaction txTemp = tx;
    txTemp.vin[0].scriptSig.clear();
    txTemp.vExtraPayload.clear();

    txHashForMetadata = txTemp.GetHash();

    LogPrintf("CheckSparkSpendTransaction: tx metadata hash=%s\n", txHashForMetadata.ToString());

    if (!fStatefulSigmaCheck) {
        return true;
    }

    bool passVerify = false;

    uint64_t Vout = 0;
    std::vector<CTxOut> vout;
    for (const CTxOut &txout : tx.vout) {
        const auto& script = txout.scriptPubKey;
        if (!script.empty() && script.IsSparkSMint()) {
            vout.push_back(txout);
        } else if(script.IsSparkMint() ||
                script.IsLelantusMint() ||
                script.IsLelantusJMint() ||
                script.IsSigmaMint()) {
            return false;
        } else {
            Vout += txout.nValue;
        }

    }

    std::vector<Coin> out_coins;
    if (!CheckSparkSMintTransaction(vout, state, hashTx, fStatefulSigmaCheck, out_coins, sparkTxInfo))
        return false;
    spend->setOutCoins(out_coins);

    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    const auto idAndBlockHashes = spend->getBlockHashes();
    for (const auto& idAndHash : idAndBlockHashes) {
        CSparkState::SparkCoinGroupInfo coinGroup;
        if (!sparkState.GetCoinGroupInfo(idAndHash.first, coinGroup))
                return state.DoS(100, false, NO_MINT_ZEROCOIN,
                                 "CheckSparkSpendTransaction: Error: no coins were minted with such parameters");

        CBlockIndex *index = coinGroup.lastBlock;
        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
            index = index->pprev;

        std::vector<Coin> cover_set;
        // Build a vector with all the public coins with given id before
        // the block on which the spend occurred.
        // This list of public coins is required by function "Verify" of spend.
        while (true) {
            if(index->sparkMintedCoins.count(idAndHash.first) > 0) {
                BOOST_FOREACH(
                const auto& coin,
                index->sparkMintedCoins[idAndHash.first]) {
                    cover_set.push_back(coin);
                }
            }
            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }

        // take the hash from last block of anonymity set
        std::vector<unsigned char> set_hash = GetAnonymitySetHash(index, idAndHash.first);
        CoverSetData setData;
        setData.cover_set = cover_set;
        if (!set_hash.empty())
            setData.cover_set_representation = set_hash;
        setData.cover_set_representation.insert(setData.cover_set_representation.end(), txHashForMetadata.begin(), txHashForMetadata.end());

        cover_sets[idAndHash.first] = cover_set;
        cover_set_data [idAndHash.first] = setData;
    }
    spend->setCoverSets(cover_set_data);

    BatchProofContainer* batchProofContainer = BatchProofContainer::get_instance();
    bool useBatching = batchProofContainer->fCollectProofs && !isVerifyDB && !isCheckWallet && sparkTxInfo && !sparkTxInfo->fInfoIsComplete;

    // if we are collecting proofs, skip verification and collect proofs
    // add proofs into container
    if(useBatching) {
        passVerify = true;
        batchProofContainer->add(*spend);
    } else {
        passVerify = spark::SpendTransaction::verify(*spend, cover_sets);
    }

    if (passVerify) {
        const std::vector<GroupElement>& lTags = spend->getUsedLTags();
        const std::vector<uint64_t>& ids = spend->getCoinGroupIds();

        if (lTags.size() != ids.size()) {
            return state.DoS(100,
                             error("CheckSparkSpendTransaction: size of lTags and group ids don't match."));
        }

        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(sparkTxInfo && sparkTxInfo->spTransactions.count(hashTx) > 0)) {
            for (size_t i = 0; i < lTags.size(); ++i) {
                    if (!CheckLTag(state, sparkTxInfo, lTags[i], nHeight, false)) {
                        LogPrintf("CheckSparkSpendTransaction: lTAg check failed, ltag=%s\n", lTags[i]);
                        return false;
                    }
            }
        }

        // check duplicated linking tags in same transaction.
        for (const auto &lTag : lTags) {
            if (!txLTags.insert(lTag).second) {
                return state.DoS(100,
                                 error("CheckSparkSpendTransaction: two or more spends with same linking tag in the same transaction"));
            }
        }

        if (!isVerifyDB && !isCheckWallet) {
            // add spend information to the index
            if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
                for (size_t i = 0; i < lTags.size(); i++) {
                    sparkTxInfo->spentLTags.insert(std::make_pair(lTags[i], ids[i]));
                }
            }
        }
    }
    else {
        LogPrintf("CheckSparkSpendTransaction: verification failed at block %d\n", nHeight);
        return false;
    }

    if(!isVerifyDB && !isCheckWallet) {
        if (sparkTxInfo && !sparkTxInfo->fInfoIsComplete) {
            sparkTxInfo->spTransactions.insert(hashTx);
        }
    }

    return true;
}

bool CheckSparkTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CSparkTxInfo* sparkTxInfo)
{
    Consensus::Params const & consensus = ::Params().GetConsensus();

    bool const allowSpark = IsSparkAllowed();

    // Check Spark Mint Transaction
    if (allowSpark && !isVerifyDB) {
        for (const CTxOut &txout : tx.vout) {
            std::vector<CScript> scripts;
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSparkMint()) {
                scripts.push_back(txout.scriptPubKey);
            }
            if (!scripts.empty()) {
                if (!CheckSparkMintTransaction(scripts, state, hashTx, fStatefulSigmaCheck, sparkTxInfo))
                    return false;
            }
        }
    }

    return true;
}

bool GetOutPoint(COutPoint& outPoint, const spark::Coin& coin)
{
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    auto mintedCoinHeightAndId = sparkState->GetMintedCoinHeightAndId(coin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    return GetOutPointFromBlock(outPoint, coin, block);
}

bool GetOutPoint(COutPoint& outPoint, const uint256& coinHash)
{
    spark::Coin coin;
    spark::CSparkState *sparkState = spark::CSparkState::GetState();
    if(!sparkState->HasCoinHash(coin, coinHash)) {
        return false;
    }

    return GetOutPoint(outPoint, coin);
}

bool GetOutPointFromBlock(COutPoint& outPoint, const spark::Coin& coin, const CBlock &block) {
    spark::Coin txCoin;
    // cycle transaction hashes, looking for this coin
    for (CTransactionRef tx : block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout : tx->vout) {
            if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSparkSMint()) {
                try {
                    ParseSparkMintCoin(txout.scriptPubKey, txCoin);
                }
                catch (...) {
                    continue;
                }
                if(coin == txCoin){
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    return true;
                }
            }
            nIndex++;
        }
    }
    return false;
}

static bool CheckSparkSpendTAg(
        CValidationState& state,
        CSparkTxInfo* sparkTxInfo,
        const GroupElement& tag,
        int nHeight,
        bool fConnectTip) {
    // check for spark transaction in this block as well
    if (sparkTxInfo &&
        !sparkTxInfo->fInfoIsComplete &&
        sparkTxInfo->spentLTags.find(tag) != sparkTxInfo->spentLTags.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spark spends with same tag in the same block"));

    // check for used tags in sparkState
    if (sparkState.IsUsedLTag(tag)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The Spark spend tag has been used"));
        }
    }
    return true;
}

/******************************************************************************/
// CLelantusState
/******************************************************************************/

CSparkState::CSparkState(
        size_t maxCoinInGroup,
        size_t startGroupSize)
        :
        maxCoinInGroup(maxCoinInGroup),
        startGroupSize(startGroupSize)
{
    Reset();
}

void CSparkState::Reset() {
    coinGroups.clear();
    latestCoinId = 0;
    mintedCoins.clear();
    usedLTags.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
}

std::pair<int, int> CSparkState::GetMintedCoinHeightAndId(const spark::Coin& coin) {
    auto coinIt = mintedCoins.find(coin);

    if (coinIt != mintedCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.coinGroupId);
    }
    return std::make_pair(-1, -1);
}

bool CSparkState::HasCoin(const spark::Coin& coin) {
    return mintedCoins.find(coin) != mintedCoins.end();

}

bool CSparkState::HasCoinHash(spark::Coin& coin, const uint256& coinHash) {
    for (auto it = mintedCoins.begin(); it != mintedCoins.end(); ++it ){
        const spark::Coin& coin_ = (*it).first;
        if(primitives::GetSparkCoinHash(coin_) == coinHash){
            coin = coin_;
            return true;
        }
    }
    return false;
}

bool CSparkState::GetCoinGroupInfo(
        int group_id,
        SparkCoinGroupInfo& result) {
    if (coinGroups.count(group_id) == 0)
        return false;

    result = coinGroups[group_id];
    return true;
}

int CSparkState::GetLatestCoinID() const {
    return latestCoinId;
}

bool CSparkState::IsUsedLTag(const GroupElement& lTag) {
    return usedLTags.count(lTag) != 0;
}

bool CSparkState::IsUsedLTagHash(GroupElement& lTag, const uint256 &coinLTaglHash) {
    for ( auto it = GetSpends().begin(); it != GetSpends().end(); ++it ) {
        if (primitives::GetLTagHash(it->first) == coinLTaglHash) {
            lTag = it->first;
            return true;
        }
    }
    return false;
}


bool CSparkState::CanAddSpendToMempool(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return !IsUsedLTag(lTag) && !mempool.sparkState.HasLTag(lTag);
}

bool CSparkState::CanAddMintToMempool(const spark::Coin& coin){
    LOCK(mempool.cs);
    return !HasCoin(coin) && !mempool.sparkState.HasMint(coin);
}

void CSparkState::AddMint(const spark::Coin& coin, const CMintedCoinInfo& coinInfo) {
    mintedCoins.insert(std::make_pair(coin, coinInfo));
    mintMetaInfo[coinInfo.coinGroupId] += 1;
}

void CSparkState::RemoveMint(const spark::Coin& coin) {
    auto iter = mintedCoins.find(coin);
    if (iter != mintedCoins.end()) {
        mintMetaInfo[iter->second.coinGroupId] -= 1;
        mintedCoins.erase(iter);
    }
}

void CSparkState::AddSpend(const GroupElement& lTag, int coinGroupId) {
    if (!mintMetaInfo.count(coinGroupId)) {
        throw std::invalid_argument("group id doesn't exist");
    }

    usedLTags[lTag] = coinGroupId;
    spendMetaInfo[coinGroupId] += 1;
}

void CSparkState::RemoveSpend(const GroupElement& lTag) {
    auto iter = usedLTags.find(lTag);
    if (iter != usedLTags.end()) {
        spendMetaInfo[iter->second] -= 1;
        usedLTags.erase(iter);
    }
}

bool CSparkState::AddSpendToMempool(const std::vector<GroupElement>& lTags, uint256 txHash) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags){
        if (IsUsedLTag(lTag) || mempool.sparkState.HasLTag(lTag))
            return false;

        mempool.sparkState.AddSpendToMempool(lTag, txHash);
    }

    return true;
}

void CSparkState::RemoveSpendFromMempool(const std::vector<GroupElement>& lTags) {
    LOCK(mempool.cs);
    for (const auto& lTag : lTags) {
        mempool.sparkState.RemoveSpendFromMempool(lTag);
    }
}

void CSparkState::AddMintsToMempool(const std::vector<std::pair<spark::Coin, std::vector<unsigned char>>>& coins) {
    LOCK(mempool.cs);
    for (const auto& coin : coins) {
        mempool.sparkState.AddMintToMempool(coin.first);
    }
}

void CSparkState::RemoveMintFromMempool(const spark::Coin& coin) {
    LOCK(mempool.cs);
    mempool.sparkState.RemoveMintFromMempool(coin);
}

uint256 CSparkState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolConflictingTxHash(lTag);
}

CSparkState* CSparkState::GetState() {
    return &sparkState;
}

int CSparkState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<spark::Coin>& coins_out,
        std::vector<unsigned char>& setHash_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0) {
        return 0;
    }

    SparkCoinGroupInfo &coinGroup = coinGroups[coinGroupID];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;; block = block->pprev) {

        // ignore block heigher than max height
        if (block->nHeight > maxHeight) {
            continue;
        }

        // check coins in group coinGroupID - 1 in the case that using coins from prev group.
        int id = 0;
        if (CountCoinInBlock(block, coinGroupID)) {
            id = coinGroupID;
        } else if (CountCoinInBlock(block, coinGroupID - 1)) {
            id = coinGroupID - 1;
        }

        if (id) {
            if (numberOfCoins == 0) {
                // latest block satisfying given conditions
                // remember block hash and set hash
                blockHash_out = block->GetBlockHash();
                setHash_out =  GetAnonymitySetHash(block, id);
            }
            numberOfCoins += block->sparkMintedCoins[id].size();
            if (block->sparkMintedCoins.count(id) > 0) {
                for (const auto &coin : block->sparkMintedCoins[id]) {
                    coins_out.push_back(coin);
                }
            }
        }

        if (block == coinGroup.firstBlock) {
            break ;
        }
    }

    return numberOfCoins;
}

std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> const & CSparkState::GetMints() const {
    return mintedCoins;
}
std::unordered_map<GroupElement, int, spark::CLTagHash> const & CSparkState::GetSpends() const {
    return usedLTags;
}

std::unordered_map<int, CSparkState::SparkCoinGroupInfo> const& CSparkState::GetCoinGroups() const {
    return coinGroups;
}

std::unordered_map<GroupElement, uint256, spark::CLTagHash> const& CSparkState::GetMempoolLTags() const {
    LOCK(mempool.cs);
    return mempool.sparkState.GetMempoolLTags();
}

// CSparkMempoolState
bool CSparkMempoolState::HasMint(const spark::Coin& coin) {
    return mempoolMints.count(coin) > 0;
}

void CSparkMempoolState::AddMintToMempool(const spark::Coin& coin) {
    mempoolMints.insert(coin);
}

void CSparkMempoolState::RemoveMintFromMempool(const spark::Coin& coin) {
    mempoolMints.erase(coin);
}

bool CSparkMempoolState::HasLTag(const GroupElement& lTag) {
    return mempoolLTags.count(lTag) > 0;
}

bool CSparkMempoolState::AddSpendToMempool(const GroupElement& lTag, uint256 txHash) {
    return mempoolLTags.insert({lTag, txHash}).second;
}

void CSparkMempoolState::RemoveSpendFromMempool(const GroupElement& lTag) {
    mempoolLTags.erase(lTag);
}

uint256 CSparkMempoolState::GetMempoolConflictingTxHash(const GroupElement& lTag) {
    if (mempoolLTags.count(lTag) == 0)
        return uint256();

    return mempoolLTags[lTag];
}

void CSparkMempoolState::Reset() {
    mempoolLTags.clear();
    mempoolMints.clear();
}

} // namespace spark