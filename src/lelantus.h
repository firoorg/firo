#ifndef _MAIN_LELANTUS_H__
#define _MAIN_LELANTUS_H__

#include "amount.h"
#include "chain.h"
#include "liblelantus/coin.h"
#include "consensus/validation.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "liblelantus/params.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include "coin_containers.h"


namespace lelantus {

// Lelantus transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into index
class CLelantusTxInfo {
public:
    // all the zerocoin transactions encountered so far
    std::set<uint256> zcTransactions;

    // Vector of <pubCoin> for all the mints.
    std::vector<lelantus::PublicCoin> mints;

    // serial for every spend (map from serial to coin group id)
    std::unordered_map<Scalar, int> spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CLelantusTxInfo(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

bool IsLelantusAllowed();
bool IsLelantusAllowed(int height);

bool IsAvailableToMint(const CAmount& amount);

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, std::vector<unsigned char>&  serializedSchnorrProof);
bool VerifyMintSchnorrProof(const uint64_t& v, const secp_primitives::GroupElement& commit, const SchnorrProof<Scalar, GroupElement>& schnorrProof);
void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin,  SchnorrProof<Scalar, GroupElement>& schnorrProof);
void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin);

bool CheckLelantusTransaction(
    const CTransaction &tx,
	CValidationState &state,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
	bool isCheckWallet,
	bool fStatefulSigmaCheck,
	CLelantusTxInfo* lelantusTxInfo);

/*
 * State of minted/spent coins as extracted from the index
 */
class CLelantusState {
//friend bool BuildSigmaStateFromIndex(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint with given id was seen
    struct LelantusCoinGroupInfo {
        LelantusCoinGroupInfo() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given id minted
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
    CLelantusState();

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const lelantus::PublicCoin& pubCoin);

    bool CanAddMintToMempool(const GroupElement& pubCoin);


    void AddMintsToMempool(const vector<GroupElement>& pubCoins);
    void RemoveMintFromMempool(const GroupElement& pubCoin);

    static CLelantusState* GetState();

    int GetLatestCoinID() const;

    mint_info_container const & GetMints() const;
    std::unordered_map<Scalar, int> const & GetSpends() const;

    std::size_t GetTotalCoins() const { return GetMints().size(); }

    bool IsSurgeConditionDetected() const;

private:

    // Latest anonymity set id;
    int latestCoinId;

    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256> mempoolCoinSerials;

    std::unordered_set<GroupElement> mempoolMints;

    std::atomic<bool> surgeCondition;

    struct Containers {
        Containers(std::atomic<bool> & surgeCondition);

        mint_info_container const & GetMints() const;
        std::unordered_map<Scalar, int> const & GetSpends() const;
        bool IsSurgeCondition() const;
    private:
        // Set of all minted pubCoin values, keyed by the public coin.
        // Used for checking if the given coin already exists.
        std::unordered_map<lelantus::PublicCoin, CMintedCoinInfo, lelantus::CPublicCoinHash> mintedPubCoins;
        // Set of all used coin serials.
        std::unordered_map<Scalar, int> usedCoinSerials;

        std::atomic<bool> & surgeCondition;
        
    };

    Containers containers;
};

} // end of namespace lelantus

#endif // _MAIN_LELANTUS_H__
