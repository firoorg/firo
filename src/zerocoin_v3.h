#ifndef _MAIN_ZEROCOIN_V3_H__
#define _MAIN_ZEROCOIN_V3_H__

#include "amount.h"
#include "chain.h"
#include "sigma/coin.h"
#include "sigma/coinspend.h"
#include "consensus/validation.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "sigma/params.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include "hash_functions.h"

using namespace sigma;

// zerocoin parameters
extern sigma::ParamsV3 *ZCParamsV3;

// Zerocoin transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into
// index
class CZerocoinTxInfoV3 {
public:
    // all the zerocoin transactions encountered so far
    std::set<uint256> zcTransactions;

    // Vector of <pubCoin> for all the mints.
    std::vector<PublicCoinV3> mints;

    // serial for every spend (map from serial to denomination)
    std::unordered_map<Scalar, int, sigma::CScalarHash> spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CZerocoinTxInfoV3(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

bool IsSigmaAllowed();
bool IsSigmaAllowed(int height);

secp_primitives::GroupElement ParseSigmaMintScript(const CScript& script);
std::pair<std::unique_ptr<sigma::CoinSpendV3>, uint32_t> ParseSigmaSpend(const CTxIn& in);

bool CheckZerocoinTransactionV3(
  const CTransaction &tx,
	CValidationState &state,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
  bool isCheckWallet,
  CZerocoinTxInfoV3 *zerocoinTxInfo);

void DisconnectTipZCV3(CBlock &block, CBlockIndex *pindexDelete);

bool ConnectBlockZCV3(
  CValidationState& state,
  const CChainParams& chainparams,
  CBlockIndex* pindexNew,
  const CBlock *pblock,
  bool fJustCheck=false);

bool ZerocoinBuildStateFromIndexV3(CChain *chain);

Scalar ZerocoinGetSpendSerialNumberV3(const CTransaction &tx, const CTxIn &txin);
CAmount GetSpendTransactionInputV3(const CTransaction &tx);

/*
 * State of minted/spent coins as extracted from the index
 */
class CZerocoinStateV3 {
friend bool ZerocoinBuildStateFromIndexV3(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint with given denomination and id was seen
    struct CoinGroupInfoV3 {
        CoinGroupInfoV3() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given denomination and id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

    struct CMintedCoinInfo {
        sigma::CoinDenominationV3 denomination;

        // ID of coin group.
        int id;
        int nHeight;
    };

    struct pairhash {
      public:
        template <typename T, typename U>
          std::size_t operator()(const std::pair<T, U> &x) const
          {
            return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
          }
    };
public:
    CZerocoinStateV3();

    // Add mint, automatically assigning id to it. Returns id and previous accumulator value (if any)
    int AddMint(
        CBlockIndex *index,
        const PublicCoinV3& pubCoin);

    // Add serial to the list of used ones
    void AddSpend(const Scalar& serial);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index);

    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given denomination and id
    bool GetCoinGroupInfo(sigma::CoinDenominationV3 denomination,
        int group_id, CoinGroupInfoV3 &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const Scalar& coinSerial);

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const PublicCoinV3& pubCoin);

    // Given denomination and id returns latest accumulator value and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        sigma::CoinDenominationV3 denomination,
        int id,
        uint256& blockHash_out,
        std::vector<PublicCoinV3>& coins_out);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const PublicCoinV3& pubCoin);

    // Reset to initial values
    void Reset();

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const Scalar& coinSerial);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const Scalar &coinSerial, uint256 txHash);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const Scalar& coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const Scalar& coinSerial);

    static CZerocoinStateV3* GetZerocoinState();

    int GetLatestCoinID(sigma::CoinDenominationV3 denomination) const;

// private: // martun: Changed to public just for unit tests.
    // Collection of coin groups. Map from <denomination,id> to CoinGroupInfoV3 structure
    std::unordered_map<pair<sigma::CoinDenominationV3, int>, CoinGroupInfoV3, pairhash> coinGroups;

    // Set of all minted pubCoin values, keyed by the public coin.
    // Used for checking if the given coin already exists.
    unordered_map<PublicCoinV3, CMintedCoinInfo, sigma::CPublicCoinHash> mintedPubCoins;

    // Latest IDs of coins by denomination
    std::unordered_map<sigma::CoinDenominationV3, int> latestCoinIds;

    // Set of all used coin serials.
    std::unordered_set<Scalar, sigma::CScalarHash> usedCoinSerials;

    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> mempoolCoinSerials;

};

#endif // _MAIN_ZEROCOIN_V3_H__
