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

namespace sigma {

// zerocoin parameters
extern Params *SigmaParams;

// Zerocoin transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into
// index
class CSigmaTxInfo {
public:
    // all the zerocoin transactions encountered so far
    std::set<uint256> zcTransactions;

    // Vector of <pubCoin> for all the mints.
    std::vector<sigma::PublicCoin> mints;

    // serial for every spend (map from serial to denomination)
    std::unordered_map<Scalar, int, sigma::CScalarHash> spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CSigmaTxInfo(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

bool IsSigmaAllowed();
bool IsSigmaAllowed(int height);

secp_primitives::GroupElement ParseSigmaMintScript(const CScript& script);
std::pair<std::unique_ptr<sigma::CoinSpend>, uint32_t> ParseSigmaSpend(const CTxIn& in);
CAmount GetSpendAmount(const CTxIn& in);
CAmount GetSpendAmount(const CTransaction& tx);
bool CheckSigmaBlock(CValidationState &state, const CBlock& block);

bool CheckSigmaTransaction(
  const CTransaction &tx,
	CValidationState &state,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
  bool isCheckWallet,
  bool fStatefulSigmaCheck,
  CSigmaTxInfo *zerocoinTxInfo);

void DisconnectTipSigma(CBlock &block, CBlockIndex *pindexDelete);

bool ConnectBlockSigma(
  CValidationState& state,
  const CChainParams& chainparams,
  CBlockIndex* pindexNew,
  const CBlock *pblock,
  bool fJustCheck=false);

/*
 * Get COutPoint(txHash, index) from the chain using pubcoin value alone.
 */
bool GetOutPointFromBlock(COutPoint& outPoint, const GroupElement &pubCoinValue, const CBlock &block);
bool GetOutPoint(COutPoint& outPoint, const sigma::PublicCoin &pubCoin);
bool GetOutPoint(COutPoint& outPoint, const GroupElement &pubCoinValue);
bool GetOutPoint(COutPoint& outPoint, const uint256 &pubCoinValueHash);

uint256 GetSerialHash(const secp_primitives::Scalar& bnSerial);
uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue);

bool BuildSigmaStateFromIndex(CChain *chain);

Scalar GetSigmaSpendSerialNumber(const CTransaction &tx, const CTxIn &txin);
CAmount GetSigmaSpendInput(const CTransaction &tx);

/*
 * State of minted/spent coins as extracted from the index
 */
class CSigmaState {
friend bool BuildSigmaStateFromIndex(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint with given denomination and id was seen
    struct SigmaCoinGroupInfo {
        SigmaCoinGroupInfo() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given denomination and id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

    struct CMintedCoinInfo {
        sigma::CoinDenomination denomination;

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
    CSigmaState();

    // Add mins in block, automatically assigning id to it
    void AddMintsToStateAndBlockIndex(CBlockIndex *index, const CBlock* pblock);

    // Add serial to the list of used ones
    void AddSpend(const Scalar& serial);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index);

    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given denomination and id
    bool GetCoinGroupInfo(sigma::CoinDenomination denomination,
        int group_id, SigmaCoinGroupInfo &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const Scalar& coinSerial);
        // Query if the hash of a coin serial was previously used. If so, store preimage in coinSerial param
    bool IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash);

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const sigma::PublicCoin& pubCoin);
    // Query if there is a coin with given hash of a pubCoin value. If so, store preimage in pubCoin param
    bool HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash);

    // Given denomination and id returns latest accumulator value and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        sigma::CoinDenomination denomination,
        int id,
        uint256& blockHash_out,
        std::vector<sigma::PublicCoin>& coins_out);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const sigma::PublicCoin& pubCoin);

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

    static CSigmaState* GetState();

    int GetLatestCoinID(sigma::CoinDenomination denomination) const;

// private: // martun: Changed to public just for unit tests.
    // Collection of coin groups. Map from <denomination,id> to SigmaCoinGroupInfo structure
    std::unordered_map<pair<sigma::CoinDenomination, int>, SigmaCoinGroupInfo, pairhash> coinGroups;

    // Set of all minted pubCoin values, keyed by the public coin.
    // Used for checking if the given coin already exists.
    unordered_map<sigma::PublicCoin, CMintedCoinInfo, sigma::CPublicCoinHash> mintedPubCoins;

    // Latest IDs of coins by denomination
    std::unordered_map<sigma::CoinDenomination, int> latestCoinIds;

    // Set of all used coin serials.
    std::unordered_set<Scalar, sigma::CScalarHash> usedCoinSerials;

    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> mempoolCoinSerials;

};

} // end of namespace sigma.

#endif // _MAIN_ZEROCOIN_V3_H__
