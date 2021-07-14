#ifndef _MAIN_SIGMA_H__
#define _MAIN_SIGMA_H__

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
#include "coin_containers.h"

//tests
namespace sigma_mintspend_many { class sigma_mintspend_many; }
namespace sigma_mintspend { class sigma_mintspend_test; }
namespace sigma_partialspend_mempool_tests { class partialspend; }
namespace zerocoin_tests3_v3 { class zerocoin_mintspend_v3; }

namespace sigma {

// Sigma transaction info, added to the CBlock to ensure sigma mint/spend transactions got their info stored into
// index
class CSigmaTxInfo {
public:
    // all the sigma transactions encountered so far
    std::set<uint256> zcTransactions;

    // Vector of <pubCoin> for all the mints.
    std::vector<sigma::PublicCoin> mints;

    // serial for every spend (map from serial to denomination)
    spend_info_container spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CSigmaTxInfo(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

bool IsSigmaAllowed();
bool IsSigmaAllowed(int height);

bool IsRemintWindow(int height);

bool CheckSigmaSpendSerial(
        CValidationState &state,
        CSigmaTxInfo *sigmaTxInfo,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip);

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
  CSigmaTxInfo *sigmaTxInfo);

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

bool BuildSigmaStateFromIndex(CChain *chain);

Scalar GetSigmaSpendSerialNumber(const CTransaction &tx, const CTxIn &txin);
CAmount GetSigmaSpendInput(const CTransaction &tx);

/*
 * State of minted/spent coins as extracted from the index
 */
class CSigmaState {
friend bool BuildSigmaStateFromIndex(CChain *, std::set<CBlockIndex *> &);
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
    void AddSpend(const Scalar &serial, CoinDenomination denom, int coinGroupId);

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

    void GetAnonymitySet(
            sigma::CoinDenomination denomination,
            int coinGroupID,
            bool fStartSigmaBlacklist,
            std::vector<GroupElement>& coins_out);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const sigma::PublicCoin& pubCoin);

    // Reset to initial values
    void Reset();

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const Scalar& coinSerial);

    bool CanAddMintToMempool(const GroupElement& pubCoin);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const Scalar &coinSerial, uint256 txHash);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const std::vector<Scalar> &coinSerials, uint256 txHash);

    void AddMintsToMempool(const std::vector<GroupElement>& pubCoins);

    void RemoveMintFromMempool(const GroupElement& pubCoin);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const Scalar& coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const Scalar& coinSerial);



    static CSigmaState* GetState();

    int GetLatestCoinID(sigma::CoinDenomination denomination) const;

    mint_info_container const & GetMints() const;
    spend_info_container const & GetSpends() const;
    std::unordered_map<std::pair<CoinDenomination, int>, SigmaCoinGroupInfo, pairhash> const & GetCoinGroups() const ;
    std::unordered_map<CoinDenomination, int> const & GetLatestCoinIds() const;
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> const & GetMempoolCoinSerials() const;

    std::size_t GetTotalCoins() const { return GetMints().size(); }

    bool IsSurgeConditionDetected() const;

private:
    // Collection of coin groups. Map from <denomination,id> to SigmaCoinGroupInfo structure
    std::unordered_map<std::pair<CoinDenomination, int>, SigmaCoinGroupInfo, pairhash> coinGroups;

    // Latest IDs of coins by denomination
    std::unordered_map<CoinDenomination, int> latestCoinIds;

    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256, CScalarHash> mempoolCoinSerials;

    std::unordered_set<GroupElement> mempoolMints;

    std::atomic<bool> surgeCondition;

    struct Containers {
        Containers(std::atomic<bool> & surgeCondition);

        void AddMint(sigma::PublicCoin const & pubCoin, CMintedCoinInfo const & coinInfo);
        void RemoveMint(sigma::PublicCoin const & pubCoin);

        void AddSpend(Scalar const & serial, CSpendCoinInfo const & coinInfo);
        void RemoveSpend(Scalar const & serial);

        void Reset();

        mint_info_container const & GetMints() const;
        spend_info_container const & GetSpends() const;
        bool IsSurgeCondition() const;
    private:
        // Set of all minted pubCoin values, keyed by the public coin.
        // Used for checking if the given coin already exists.
        mint_info_container mintedPubCoins;
        // Set of all used coin serials.
        spend_info_container usedCoinSerials;

        std::atomic<bool> & surgeCondition;

        typedef std::map<int, std::map<CoinDenomination, size_t>> metainfo_container_t;
        metainfo_container_t mintMetaInfo, spendMetaInfo;

        void CheckSurgeCondition(int groupId, CoinDenomination denom);

        friend class sigma_mintspend_many::sigma_mintspend_many;
        friend class zerocoin_tests3_v3::zerocoin_mintspend_v3;
        friend class sigma_mintspend::sigma_mintspend_test;
        friend class sigma_partialspend_mempool_tests::partialspend;
    };

    Containers containers;

    friend class sigma_mintspend_many::sigma_mintspend_many;
    friend class zerocoin_tests3_v3::zerocoin_mintspend_v3;
    friend class sigma_mintspend::sigma_mintspend_test;
    friend class sigma_partialspend_mempool_tests::partialspend;
};

} // end of namespace sigma.

#endif // _MAIN_SIGMA_H__
