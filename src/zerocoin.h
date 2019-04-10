#ifndef MAIN_ZEROCOIN_H
#define MAIN_ZEROCOIN_H

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "libzerocoin/Zerocoin.h"
#include "zerocoin_params.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>

// zerocoin parameters
extern libzerocoin::Params *ZCParams, *ZCParamsV2;

// Test for zerocoin transaction version 2
inline bool IsZerocoinTxV2(libzerocoin::CoinDenomination denomination, const Consensus::Params &params, int coinId) {
	return ((denomination == libzerocoin::ZQ_LOVELACE) && (coinId >= params.nSpendV2ID_1))
	    || ((denomination == libzerocoin::ZQ_GOLDWASSER) && (coinId >= params.nSpendV2ID_10))
	    || ((denomination == libzerocoin::ZQ_RACKOFF) && (coinId >= params.nSpendV2ID_25))
	    || ((denomination == libzerocoin::ZQ_PEDERSEN) && (coinId >= params.nSpendV2ID_50))
	    || ((denomination == libzerocoin::ZQ_WILLIAMSON) && (coinId >= params.nSpendV2ID_100));
}

// Zerocoin transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into
// index
class CZerocoinTxInfo {
public:
    // all the zerocoin transactions encountered so far
    set<uint256> zcTransactions;
    // <denomination, pubCoin> for all the mints
    vector<pair<int,CBigNum> > mints;
    // serial for every spend (map from serial to denomination)
    map<CBigNum,int> spentSerials;

    // are there v1 spends in the block?
    bool fHasSpendV1;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CZerocoinTxInfo(): fHasSpendV1(false), fInfoIsComplete(false) {}
    // finalize everything
    void Complete();
};

CBigNum ParseZerocoinMintScript(const CScript& script);
std::pair<std::unique_ptr<libzerocoin::CoinSpend>, uint32_t> ParseZerocoinSpend(const CTxIn& in);

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, const Consensus::Params &params, int nHeight, bool fMTP);
bool CheckZerocoinTransaction(const CTransaction &tx,
	CValidationState &state,
    const Consensus::Params &params,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
    bool isCheckWallet,
    bool fZerocoinStateCheck,
    CZerocoinTxInfo *zerocoinTxInfo);

void DisconnectTipZC(CBlock &block, CBlockIndex *pindexDelete);
bool ConnectBlockZC(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock, bool fJustCheck=false);

int ZerocoinGetNHeight(const CBlockHeader &block);

bool ZerocoinBuildStateFromIndex(CChain *chain, set<CBlockIndex *> &changes);

CBigNum ZerocoinGetSpendSerialNumber(const CTransaction &tx, const CTxIn &txin);

/*
 * State of minted/spent coins as extracted from the index
 */
class CZerocoinState {
friend bool ZerocoinBuildStateFromIndex(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint (and hence accumulator update) with given denomination and id was seen
    struct CoinGroupInfo {
        CoinGroupInfo() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given denomination and id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

private:
    // Custom hash for big numbers
    struct CBigNumHash {
        std::size_t operator()(const CBigNum &bn) const noexcept;
    };

    struct CMintedCoinInfo {
        int         denomination;
        int         id;
        int         nHeight;
    };

    // Collection of coin groups. Map from <denomination,id> to CoinGroupInfo structure
    map<pair<int, int>, CoinGroupInfo> coinGroups;
    // Set of all minted pubCoin values
    unordered_multimap<CBigNum,CMintedCoinInfo,CBigNumHash> mintedPubCoins;
    // Latest IDs of coins by denomination
    map<int, int> latestCoinIds;


public:
    CZerocoinState();

    // Set of all used coin serials. Allows multiple entries for the same coin serial for historical reasons
    unordered_multiset<CBigNum,CBigNumHash> usedCoinSerials;

    // serials of spends currently in the mempool mapped to tx hashes
    unordered_map<CBigNum,uint256,CBigNumHash> mempoolCoinSerials;

    // Add mint, automatically assigning id to it. Returns id and previous accumulator value (if any)
    int AddMint(CBlockIndex *index, int denomination, const CBigNum &pubCoin, CBigNum &previousAccValue);
    // Add serial to the list of used ones
    void AddSpend(const CBigNum &serial);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index, const Consensus::Params &params);
    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given denomination and id
    bool GetCoinGroupInfo(int denomination, int id, CoinGroupInfo &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const CBigNum &coinSerial);
    // Query if there is a coin with given pubCoin value
    bool HasCoin(const CBigNum &pubCoin);

    // Given denomination and id returns latest accumulator value and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetAccumulatorValueForSpend(CChain *chain, int maxHeight, int denomination, int id, CBigNum &accumulator, uint256 &blockHash, bool useModulusV2);

    // Get witness
    libzerocoin::AccumulatorWitness GetWitnessForSpend(CChain *chain, int maxHeight, int denomination, int id, const CBigNum &pubCoin, bool useModulusV2);

    // Return height of mint transaction and id of minted coin
    int GetMintedCoinHeightAndId(const CBigNum &pubCoin, int denomination, int &id);

    // If needed calculate accumulators for alternative accumulator modulus
    void CalculateAlternativeModulusAccumulatorValues(CChain *chain, int denomination, int id);

    // Reset to initial values
    void Reset();

    // Test function
    bool TestValidity(CChain *chain);

    // Recalculate accumulators. Needed if upgrade from pre-modulusv2 version is detected
    // Returns set of indices that changed
    set<CBlockIndex *> RecalculateAccumulators(CChain *chain);

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const CBigNum &coinSerial);

    // Add spend into the mempool. Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const CBigNum &coinSerial, uint256 txHash);

    // Add spend(s) into the mempool. Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const vector<CBigNum> &coinSerials, uint256 txHash);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const CBigNum &coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const CBigNum &coinSerial);

    static CZerocoinState *GetZerocoinState();
};

#endif
