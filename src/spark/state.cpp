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
    bool first = true;
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
            BOOST_FOREACH(const auto& mint, sparkTxInfo->mints) {
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

    if (!isVerifyDB && !isCheckWallet) {
        if (allowSpark && sparkState.IsSurgeConditionDetected()) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "Spark surge protection is ON.");
        }
    }

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

bool GetOutPoint(COutPoint& outPoint, const spark::Coin coin)
{
    // TODO levon, implement this function after state implementation
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
    surgeCondition = false;
}

bool CSparkState::IsSurgeConditionDetected() const {
    return surgeCondition;
}

bool CSparkState::HasCoin(const spark::Coin& coin) {
    return mintedCoins.find(coin) != mintedCoins.end();

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

std::unordered_map<spark::Coin, CMintedCoinInfo, spark::CoinHash> const & CSparkState::GetMints() const {
    return mintedCoins;
}
std::unordered_map<GroupElement, int, spark::CLTagHash> const & CSparkState::GetSpends() const {
    return usedLTags;
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