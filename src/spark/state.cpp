#include "state.h"
#include "../validation.h"

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


std::vector<GroupElement>  GetSparkUsedTags(const CTransaction &tx)
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
    //TODO levon implement this after spark spend implementation
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

    for (auto& coin : coins) {
        if (coin.v > ::Params().GetConsensus().nMaxValueLelantusMint)
            return state.DoS(100,
                             false,
                             REJECT_INVALID,
                             "CTransaction::CheckTransaction() : Spark Mint is out of limit.");

        bool hasCoin = sparkState.HasCoin(coin);
        if (hasCoin)
            break;

        if (sparkTxInfo != NULL && !sparkTxInfo->fInfoIsComplete) {
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

        if (hasCoin && fStatefulSigmaCheck) {
            LogPrintf("CheckSparkMintTransaction: double mint, tx=%s\n", hashTx.GetHex());
            return state.DoS(100,
                             false,
                             PUBCOIN_NOT_VALIDATE,
                             "CheckSparkMintTransaction: double mint");
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