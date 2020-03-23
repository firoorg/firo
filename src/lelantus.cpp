#include "validation.h"
#include "lelantus.h"
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
#include "liblelantus/coin.h"
#include "liblelantus/schnorr_prover.h"
#include "liblelantus/schnorr_verifier.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "primitives/zerocoin.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>
#include <boost/scope_exit.hpp>

#include <ios>

namespace lelantus {

static CLelantusState lelantusState;

bool IsLelantusAllowed()
{
    LOCK(cs_main);
    return IsLelantusAllowed(chainActive.Height());
}

bool IsLelantusAllowed(int height)
{
	return height >= ::Params().GetConsensus().nLelantusStartBlock;
}

bool IsAvailableToMint(const CAmount& amount)
{
    return amount >= 5 * CENT;
}

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, std::vector<unsigned char>&  serializedSchnorrProof)
{
    auto params = lelantus::Params::get_default();

    SchnorrProof<Scalar, GroupElement> schnorrProof;
    SchnorrProver<Scalar, GroupElement> schnorrProver(params->get_g(), params->get_h0());
    schnorrProver.proof(coin.getSerialNumber(), coin.getRandomness(), schnorrProof);

    serializedSchnorrProof.resize(schnorrProof.memoryRequired());
    schnorrProof.serialize(serializedSchnorrProof.data());
}

bool VerifyMintSchnorrProof(const uint64_t& v, const secp_primitives::GroupElement& commit, const SchnorrProof<Scalar, GroupElement>& schnorrProof)
{
    auto params = lelantus::Params::get_default();

    secp_primitives::GroupElement comm = commit + params->get_h1() * v;
    SchnorrVerifier<Scalar, GroupElement> verifier(params->get_g(), params->get_h0());
    return verifier.verify(commit, schnorrProof);
}

void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin,  SchnorrProof<Scalar, GroupElement>& schnorrProof)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Lelantus mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    if (serialized.size() < (pubcoin.memoryRequired() + schnorrProof.memoryRequired())) {
        throw std::invalid_argument("Script is not a valid Lelantus mint");
    }

    pubcoin.deserialize(serialized.data());
    schnorrProof.deserialize(serialized.data() + pubcoin.memoryRequired());
}

void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin)
{
    SchnorrProof<Scalar, GroupElement> schnorrProof;
    ParseLelantusMintScript(script, pubcoin, schnorrProof);
}

bool CheckLelantusMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        CLelantusTxInfo* lelantusTxInfo) {
    secp_primitives::GroupElement pubCoinValue;
    SchnorrProof<Scalar, GroupElement> schnorrProof;

    LogPrintf("CheckLelantusMintTransaction txHash = %s\n", txout.GetHash().ToString());
    LogPrintf("nValue = %d\n", txout.nValue);

    try {
        ParseLelantusMintScript(txout.scriptPubKey, pubCoinValue, schnorrProof);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : Mint parsing failure.");
    }

    lelantus::PublicCoin pubCoin(pubCoinValue);

    //checking whether commitment is valid
    if(!VerifyMintSchnorrProof(txout.nValue, pubCoinValue, schnorrProof) || !pubCoin.validate())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckLelantusMintTransaction : PubCoin validation failed");


    bool hasCoin = lelantusState.HasCoin(pubCoin);

    if (!hasCoin && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const lelantus::PublicCoin& mint, lelantusTxInfo->mints) {
            if (mint == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin && fStatefulSigmaCheck) {
       LogPrintf("CheckLelantusMintTransaction: double mint, tx=%s\n",
                txout.GetHash().ToString());
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckLelantusMintTransaction: double mint");
    }

    if (lelantusTxInfo != NULL && !lelantusTxInfo->fInfoIsComplete) {
        // Update public coin list in the info
        lelantusTxInfo->mints.push_back(pubCoin);
        lelantusTxInfo->zcTransactions.insert(hashTx);
    }

    return true;
}

bool CheckLelantusTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CLelantusTxInfo* lelantusTxInfo)
{
    Consensus::Params const & consensus = ::Params().GetConsensus();

    // nHeight have special mode which value is INT_MAX so we need this.
    int realHeight = nHeight;

    if (realHeight == INT_MAX) {
        LOCK(cs_main);
        realHeight = chainActive.Height();
    }

    bool const allowLelantus = (realHeight >= consensus.nLelantusStartBlock);

    if (!isVerifyDB && !isCheckWallet) {
        if (allowLelantus && lelantusState.IsSurgeConditionDetected()) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "Lelantus surge protection is ON.");
        }
    }

    // Check Mint Lelantus Transaction
    if (allowLelantus) {
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsLelantusMint()) {
                if (!CheckLelantusMintTransaction(txout, state, hashTx, fStatefulSigmaCheck, lelantusTxInfo))
                    return false;
            }
        }
    }

    return true;
}

// CLelantusTxInfo
void CLelantusTxInfo::Complete() {
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

/******************************************************************************/
// CLelantusState::Containers
/******************************************************************************/

CLelantusState::Containers::Containers(std::atomic<bool> & surgeCondition)
: surgeCondition(surgeCondition)
{}



std::unordered_map<Scalar, int> const & CLelantusState::Containers::GetSpends() const {
    return usedCoinSerials;
}

bool CLelantusState::Containers::IsSurgeCondition() const {
    return surgeCondition;
}


/******************************************************************************/
// CLelantusState
/******************************************************************************/

CLelantusState::CLelantusState()
:containers(surgeCondition)
{}

bool CLelantusState::HasCoin(const lelantus::PublicCoin& pubCoin) {
    return containers.GetMints().find(pubCoin) != containers.GetMints().end();
}

void CLelantusState::AddMintsToMempool(const vector<GroupElement>& pubCoins){
    BOOST_FOREACH(const GroupElement& pubCoin, pubCoins){
        mempoolMints.insert(pubCoin);
    }
}

void CLelantusState::RemoveMintFromMempool(const GroupElement& pubCoin){
    mempoolMints.erase(pubCoin);
}

bool CLelantusState::CanAddMintToMempool(const GroupElement& pubCoin){
    return mempoolMints.count(pubCoin) == 0;
}

CLelantusState* CLelantusState::GetState() {
    return &lelantusState;
}

int CLelantusState::GetLatestCoinID() const {
    return latestCoinId;
}

bool CLelantusState::IsSurgeConditionDetected() const {
    return surgeCondition;
}

mint_info_container const & CLelantusState::GetMints() const {
    return containers.GetMints();
}

std::unordered_map<Scalar, int> const & CLelantusState::GetSpends() const {
    return containers.GetSpends();
}

} // end of namespace lelantus.
