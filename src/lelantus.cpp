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
#include "policy/policy.h"
#include "coins.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>
#include <boost/scope_exit.hpp>

#include <ios>

namespace lelantus {

static CLelantusState lelantusState;

static bool CheckLelantusSpendSerial(
        CValidationState &state,
        CLelantusTxInfo *lelantusTxInfo,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip) {
    // check for Lelantus transaction in this block as well
    if (lelantusTxInfo &&
            !lelantusTxInfo->fInfoIsComplete &&
            lelantusTxInfo->spentSerials.find(serial) != lelantusTxInfo->spentSerials.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more joinsplits with same serial in the same block"));

    // check for used serials in sigmaState
    if (lelantusState.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The lelantus JoinSplit serial has been used"));
        }
    }
    return true;
}

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
    return amount <= ::Params().GetConsensus().nMaxValueLelantusMint;
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

    secp_primitives::GroupElement comm = commit + (params->get_h1() * Scalar(v).negate());
    SchnorrVerifier<Scalar, GroupElement> verifier(params->get_g(), params->get_h0());
    return verifier.verify(comm, schnorrProof);
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

void ParseLelantusJMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin, std::vector<unsigned char>& encryptedValue)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Lelantus jMint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());
    // 16 is the size of encrypted mint value
    if (serialized.size() < (pubcoin.memoryRequired() + 16)) {
        throw std::invalid_argument("Script is not a valid Lelantus jMint");
    }

    pubcoin.deserialize(serialized.data());
    encryptedValue.insert(encryptedValue.begin(), serialized.begin() + pubcoin.memoryRequired() + 1, serialized.end());
}


void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin)
{
    if(script.IsLelantusMint()) {
        SchnorrProof<Scalar, GroupElement> schnorrProof;
        ParseLelantusMintScript(script, pubcoin, schnorrProof);
    } else if (script.IsLelantusJMint()) {
        std::vector<unsigned char> encryptedValue;
        ParseLelantusJMintScript(script, pubcoin, encryptedValue);
    }
}

std::unique_ptr<JoinSplit> ParseLelantusJoinSplit(const CTxIn& in)
{
    if (in.scriptSig.size() < 1) {
        throw CBadTxIn();
    }

    CDataStream serialized(
        std::vector<unsigned char>(in.scriptSig.begin() + 1, in.scriptSig.end()),
        SER_NETWORK,
        PROTOCOL_VERSION
    );

    std::unique_ptr<lelantus::JoinSplit> joinsplit(new lelantus::JoinSplit(lelantus::Params::get_default(), serialized));

    return joinsplit;
}

bool CheckLelantusBlock(CValidationState &state, const CBlock& block) {
    auto& consensus = ::Params().GetConsensus();

    size_t blockSpendsAmount = 0;
    CAmount blockSpendsValue(0);

    for (const auto& tx : block.vtx) {
        auto txSpendsValue =  GetSpendTransparentAmount(*tx);
        size_t txSpendNumber = GetSpendInputs(*tx);

        if (txSpendNumber > consensus.nMaxLelantusInputPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                "bad-txns-lelantus-spend-invalid");
        }

        if (txSpendsValue > consensus.nMaxValueLelantusSpendPerTransaction) {
            return state.DoS(100, false, REJECT_INVALID,
                             "bad-txns-lelantus-spend-invalid");
        }

        blockSpendsAmount += txSpendNumber;
        blockSpendsValue += txSpendsValue;
    }

    if (blockSpendsAmount > consensus.nMaxLelantusInputPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
            "bad-txns-lelantus-spend-invalid");
    }

    if (blockSpendsValue > consensus.nMaxValueLelantusSpendPerBlock) {
        return state.DoS(100, false, REJECT_INVALID,
                         "bad-txns-lelantus-spend-invalid");
    }

    return true;
}

bool CheckLelantusJMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        bool fStatefulSigmaCheck,
        std::vector<PublicCoin>& Cout,
        CLelantusTxInfo* lelantusTxInfo) {

    LogPrintf("CheckLelantusJMintTransaction txHash = %s\n", txout.GetHash().ToString());

    secp_primitives::GroupElement pubCoinValue;
    std::vector<unsigned char> encryptedValue;
    try {
        ParseLelantusJMintScript(txout.scriptPubKey, pubCoinValue, encryptedValue);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : Mint parsing failure.");
    }

    lelantus::PublicCoin pubCoin(pubCoinValue);

    //checking whether commitment is valid
    if(!pubCoin.validate())
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckLelantusMintTransaction : PubCoin validation failed");

    bool hasCoin = lelantusState.HasCoin(pubCoin);

    if (!hasCoin && lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const auto& mint, lelantusTxInfo->mints) {
            if (mint.first == pubCoin) {
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
        uint64_t amount;
        if(!pwalletMain->DecryptMintAmount(encryptedValue, pubCoinValue, amount))
            amount = 0;
        lelantusTxInfo->mints.push_back(std::make_pair(pubCoin, amount));
        lelantusTxInfo->zcTransactions.insert(hashTx);
    }

    Cout.push_back(pubCoin);

    return true;
}

bool CheckLelantusJoinSplitTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        int nRealHeight,
        bool isCheckWallet,
        bool fStatefulSigmaCheck,
        CLelantusTxInfo* lelantusTxInfo) {
    std::unordered_set<Scalar, sigma::CScalarHash> txSerials;

    Consensus::Params const & params = ::Params().GetConsensus();

    if(tx.vin.size() != 1 || !tx.vin[0].scriptSig.IsLelantusJoinSplit()) {
        // mixing lelantus spend input with non-lelantus inputs is prohibited
        return state.DoS(100, false,
                         REJECT_MALFORMED,
                         "CheckLelantusJoinSplitTransaction: can't mix lelantus spend input with other tx types or have more than one spend");
    }

    const CTxIn &txin = tx.vin[0];
    std::unique_ptr<lelantus::JoinSplit> joinsplit;

    try {
        joinsplit = ParseLelantusJoinSplit(txin);
    }
    catch (CBadTxIn&) {
        return state.DoS(100,
            false,
            REJECT_MALFORMED,
            "CheckLelantusJoinSplitTransaction: invalid joinsplit transaction");
    }

    if (joinsplit->getVersion() != LELANTUS_TX_VERSION_4) {
        return state.DoS(100,
                         false,
                         NSEQUENCE_INCORRECT,
                         "CTransaction::CheckLelantusJoinSplitTransaction() : Error: incorrect joinsplit transaction verion");
    }

    uint256 txHashForMetadata;

    // Obtain the hash of the transaction sans the zerocoin part
    CMutableTransaction txTemp = tx;
    txTemp.vin[0].scriptSig.clear();

    txHashForMetadata = txTemp.GetHash();

    LogPrintf("CheckLelantusJoinSplitTransaction: tx version=%d, tx metadata hash=%s\n",
             joinsplit->getVersion(), txHashForMetadata.ToString());

    if (!fStatefulSigmaCheck) {
        return true;
    }

    bool passVerify = false;
    std::map<uint32_t, std::vector<PublicCoin>> anonymity_sets;
    std::vector<PublicCoin> Cout;
    uint64_t Vout = 0;

    for (const CTxOut &txout : tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsLelantusJMint()) {
            if (!CheckLelantusJMintTransaction(txout, state, hashTx, fStatefulSigmaCheck, Cout, lelantusTxInfo))
                return false;
        } else if(txout.scriptPubKey.IsLelantusMint()) {
            return false; //putting regular mints at JoinSplit transactions is not allowed
        } else {
            Vout += txout.nValue;
        }
    }

    for(auto& idAndHash : joinsplit->getIdAndBlockHashes()) {
        CLelantusState::LelantusCoinGroupInfo coinGroup;
        if(!lelantusState.GetCoinGroupInfo(idAndHash.first, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN,
                             "CheckLelantusJoinSplitTransaction: Error: no coins were minted with such parameters");

        CBlockIndex *index = coinGroup.lastBlock;

        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != idAndHash.second)
            index = index->pprev;

        // Build a vector with all the public coins with given id before
        // the block on which the spend occured.
        // This list of public coins is required by function "Verify" of JoinSplit.
        std::vector<lelantus::PublicCoin> anonymity_set;
        while(true) {
            BOOST_FOREACH(const lelantus::PublicCoin& pubCoinValue,
                    index->lelantusMintedPubCoins[idAndHash.first]) {
                anonymity_set.push_back(pubCoinValue);
            }
            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }
    }

    passVerify = joinsplit->Verify(anonymity_sets, Cout, Vout, txHashForMetadata);

    if (passVerify) {
        const std::vector<Scalar>& serials = joinsplit->getCoinSerialNumbers();
        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(lelantusTxInfo && lelantusTxInfo->zcTransactions.count(hashTx) > 0)) {
            for(const auto& serial : serials) {
                if (!CheckLelantusSpendSerial(
                        state, lelantusTxInfo, serial, nHeight, false)) {
                    LogPrintf("CheckLelantusJoinSplitTransaction: serial check failed, serial=%s\n", serial);
                    return false;

                }
            }
        }

        // check duplicated serials in same transaction.
        for(const auto& serial : serials) {
            if (!txSerials.insert(serial).second) {
                return state.DoS(100,
                                 error("CheckLelantusJoinSplitTransaction: two or more spends with same serial in the same transaction"));
            }
        }

            if(!isVerifyDB && !isCheckWallet) {
                if (lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
                    // add spend information to the index
                    const std::vector<uint32_t>& ids = joinsplit->getCoinGroupIds();
                    if(serials.size() != ids.size()) {
                        return state.DoS(100,
                                         error("CheckLelantusJoinSplitTransaction: sized of serials and group ids don't match."));
                    }

                    for(size_t i = 0; i < serials.size(); i++) {
                        lelantusTxInfo->spentSerials.insert(std::make_pair(serials[i], ids[i]));
                    }
                }
            }
    }
    else {
        LogPrintf("CheckLelantusJoinSplitTransaction: verification failed at block %d\n", nHeight);
        return false;
    }

    if(!isVerifyDB && !isCheckWallet) {
        if (lelantusTxInfo && !lelantusTxInfo->fInfoIsComplete) {
            lelantusTxInfo->zcTransactions.insert(hashTx);
        }
    }

    return true;
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
    if(txout.nValue > ::Params().GetConsensus().nMaxValueLelantusMint)
        return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "CTransaction::CheckTransaction() : Mint is out of limit.");

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
        BOOST_FOREACH(const auto& mint, lelantusTxInfo->mints) {
            if (mint.first == pubCoin) {
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
        lelantusTxInfo->mints.push_back(std::make_pair(pubCoin, txout.nValue));
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


    if(tx.IsLelantusJoinSplit()) {
        CAmount nFees;
        try {
            nFees = lelantus::ParseLelantusJoinSplit(tx.vin[0])->getFee();
        }
        catch (CBadTxIn&) {
            return state.DoS(0, false, REJECT_INVALID, "unable to parse joinsplit");
        }

        unsigned size = GetVirtualTransactionSize(tx);
        if(nFees < CWallet::GetMinimumFee(size, nTxConfirmTarget, mempool))
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "Lelantus invalid fee.");
    }


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

    // Check Lelantus JoinSplit Transaction
    if(tx.IsLelantusJoinSplit()) {
        // First check number of inputs does not exceed transaction limit
        if (GetSpendInputs(tx) > consensus.nMaxLelantusInputPerTransaction) {
            return state.DoS(100, false,
                REJECT_INVALID,
                "bad-txns-spend-invalid");
        }

        if (GetSpendTransparentAmount(tx) > consensus.nMaxValueLelantusSpendPerTransaction) {
            return state.DoS(100, false,
                             REJECT_INVALID,
                             "bad-txns-spend-invalid");
        }

        if (!isVerifyDB) {
            if (!CheckLelantusJoinSplitTransaction(
                tx, state, hashTx, isVerifyDB, nHeight, realHeight,
                isCheckWallet, fStatefulSigmaCheck, lelantusTxInfo)) {
                    return false;
            }
        }
    }

    return true;
}

void RemoveLelantusJoinSplitReferencingBlock(CTxMemPool& pool, CBlockIndex* blockIndex) {
    LOCK2(cs_main, pool.cs);
    std::vector<CTransaction> txn_to_remove;
    for (CTxMemPool::txiter mi = pool.mapTx.begin(); mi != pool.mapTx.end(); ++mi) {
        const CTransaction& tx = mi->GetTx();
        if (tx.IsLelantusJoinSplit()) {
            // Run over all the inputs, check if their CoinGroup block hash is equal to
            // block removed. If any one is equal, remove txn from mempool.
            for (const CTxIn& txin : tx.vin) {
                if (txin.IsLelantusJoinSplit()) {
                    std::unique_ptr<lelantus::JoinSplit> joinsplit;

                    try {
                        joinsplit = ParseLelantusJoinSplit(txin);
                    }
                    catch (const std::ios_base::failure &) {
                        txn_to_remove.push_back(tx);
                        break;
                    }

                    const std::vector<std::pair<uint32_t, uint256>>& coinGroupIdAndBlockHash = joinsplit->getIdAndBlockHashes();
                    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
                        if (idAndHash.second == blockIndex->GetBlockHash()) {
                        // Do not remove transaction immediately, that will invalidate iterator mi.
                        txn_to_remove.push_back(tx);
                        break;
                        }
                    }
                }
            }
        }
    }
    for (const CTransaction& tx: txn_to_remove) {
        // Remove txn from mempool.
        pool.removeRecursive(tx);
        LogPrintf("DisconnectTipLelantus: removed lelantus joinsplit which referenced a removed blockchain tip.");
    }
}

void DisconnectTipLelantus(CBlock& block, CBlockIndex *pindexDelete) {
    lelantusState.RemoveBlock(pindexDelete);

    // Also remove from mempool lelantus joinsplits that reference given block hash.
    RemoveLelantusJoinSplitReferencingBlock(mempool, pindexDelete);
    RemoveLelantusJoinSplitReferencingBlock(txpools.getStemTxPool(), pindexDelete);
}

std::vector<Scalar> GetLelantusJoinSplitSerialNumbers(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsLelantusJoinSplit())
        return std::vector<Scalar>();

    try {
        return ParseLelantusJoinSplit(txin)->getCoinSerialNumbers();
    }
    catch (const std::ios_base::failure &) {
        return std::vector<Scalar>();
    }
}

size_t GetSpendInputs(const CTransaction &tx, const CTxIn& in) {
    if (in.IsLelantusJoinSplit()) {
        GetLelantusJoinSplitSerialNumbers(tx, in).size();
    }
    return 0;
}

size_t GetSpendInputs(const CTransaction &tx) {
    size_t sum = 0;
    for (const auto& vin : tx.vin) {
        sum += GetSpendInputs(tx, vin);
    }
    return sum;
}

CAmount GetSpendTransparentAmount(const CTransaction& tx) {
    CAmount result = 0;
    if(!tx.IsLelantusJoinSplit())
        return 0;

    for (const CTxOut &txout : tx.vout)
        result += txout.nValue;
    return result;
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockLelantus(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {
    // Add lelantus transaction information to index
    if (pblock && pblock->lelantusTxInfo) {
        if (!fJustCheck) {
            pindexNew->lelantusMintedPubCoins.clear();
            pindexNew->lelantusSpentSerials.clear();
        }

        if (!CheckLelantusBlock(state, *pblock)) {
            return false;
        }

        BOOST_FOREACH(auto& serial, pblock->lelantusTxInfo->spentSerials) {
            if (!CheckLelantusSpendSerial(
                    state,
                    pblock->lelantusTxInfo.get(),
                    serial.first,
                    pindexNew->nHeight,
                    true /* fConnectTip */
                    )) {
                return false;
            }

            if (!fJustCheck) {
                pindexNew->lelantusSpentSerials.insert(serial);
                lelantusState.AddSpend(serial.first, serial.second);
            }
        }

        if (fJustCheck)
            return true;

        if (!pblock->lelantusTxInfo->mints.empty()) {
            lelantusState.AddMintsToStateAndBlockIndex(pindexNew, pblock);
        }
    }
    else if (!fJustCheck) {
        lelantusState.AddBlock(pindexNew);
    }
    return true;
}

bool GetOutPointFromBlock(COutPoint& outPoint, const GroupElement &pubCoinValue, const CBlock &block) {
    secp_primitives::GroupElement txPubCoinValue;
    // cycle transaction hashes, looking for this pubcoin.
    BOOST_FOREACH(CTransactionRef tx, block.vtx){
        uint32_t nIndex = 0;
        for (const CTxOut &txout: tx->vout) {
            if (txout.scriptPubKey.IsLelantusMint() || txout.scriptPubKey.IsLelantusJMint()) {
                ParseLelantusMintScript(txout.scriptPubKey, txPubCoinValue);
                if(pubCoinValue==txPubCoinValue){
                    outPoint = COutPoint(tx->GetHash(), nIndex);
                    return true;
                }
            }
            nIndex++;
        }
    }

    return false;
}

bool GetOutPoint(COutPoint& outPoint, const lelantus::PublicCoin &pubCoin) {

    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    auto mintedCoinHeightAndId = lelantusState->GetMintedCoinHeightAndId(pubCoin);
    int mintHeight = mintedCoinHeightAndId.first;
    int coinId = mintedCoinHeightAndId.second;

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock = chainActive[mintHeight];
    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, ::Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    return GetOutPointFromBlock(outPoint, pubCoin.getValue(), block);
}

bool GetOutPoint(COutPoint& outPoint, const GroupElement &pubCoinValue) {
    lelantus::PublicCoin pubCoin(pubCoinValue);

    return GetOutPoint(outPoint, pubCoin);
}

bool GetOutPoint(COutPoint& outPoint, const uint256 &pubCoinValueHash) {
    GroupElement pubCoinValue;
    lelantus::CLelantusState *lelantusState = lelantus::CLelantusState::GetState();
    if(!lelantusState->HasCoinHash(pubCoinValue, pubCoinValueHash)){
        return false;
    }

    return GetOutPoint(outPoint, pubCoinValue);
}

bool BuildLelantusStateFromIndex(CChain *chain) {
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        lelantusState.AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
        "Latest ID for Lelantus coin group  %d\n",
        lelantusState.GetLatestCoinID());
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

void CLelantusState::Containers::AddMint(lelantus::PublicCoin const & pubCoin, CMintedCoinInfo const & coinInfo) {
    mintedPubCoins.insert(std::make_pair(pubCoin, coinInfo));
    mintMetaInfo[coinInfo.coinGroupId] += 1;
    CheckSurgeCondition(coinInfo.coinGroupId);
}

void CLelantusState::Containers::RemoveMint(lelantus::PublicCoin const & pubCoin) {
    mint_info_container::const_iterator iter = mintedPubCoins.find(pubCoin);
    if (iter != mintedPubCoins.end()) {
        mintMetaInfo[iter->second.coinGroupId] -= 1;
        CMintedCoinInfo tmpMintInfo(iter->second);
        mintedPubCoins.erase(iter);
        CheckSurgeCondition(tmpMintInfo.coinGroupId);
    }
}

void CLelantusState::Containers::AddSpend(Scalar const & serial, int coinGroupId) {
    usedCoinSerials[serial] = coinGroupId;
    spendMetaInfo[coinGroupId] += 1;
    CheckSurgeCondition(coinGroupId);
}

void CLelantusState::Containers::RemoveSpend(Scalar const & serial) {
    auto iter = usedCoinSerials.find(serial);
    if (iter != usedCoinSerials.end()) {
        spendMetaInfo[iter->second] -= 1;
        int id = iter->second;
        usedCoinSerials.erase(iter);
        CheckSurgeCondition(id);
    }
}

mint_info_container const & CLelantusState::Containers::GetMints() const {
    return mintedPubCoins;
}

std::unordered_map<Scalar, int> const & CLelantusState::Containers::GetSpends() const {
    return usedCoinSerials;
}

bool CLelantusState::Containers::IsSurgeCondition() const {
    return surgeCondition;
}

void CLelantusState::Containers::Reset() {
    mintedPubCoins.clear();
    usedCoinSerials.clear();
    mintMetaInfo.clear();
    spendMetaInfo.clear();
    surgeCondition = false;
}

void CLelantusState::Containers::CheckSurgeCondition(int groupId) {
    bool result = spendMetaInfo[groupId] > mintMetaInfo[groupId];
    if( result ) {
        std::ostringstream ostr;
        ostr << "Turning sigma surge protection ON: groupId: " << groupId << '\n';
        error(ostr.str().c_str());
    }

    for(metainfo_container_t::const_iterator smi = spendMetaInfo.begin(); smi != spendMetaInfo.end() && !result; ++smi) {
        if(smi->second > mintMetaInfo[smi->first]) {
            result = true;
        }
    }
    surgeCondition = result;
}

/******************************************************************************/
// CLelantusState
/******************************************************************************/

CLelantusState::CLelantusState()
:containers(surgeCondition)
{}

void CLelantusState::AddMintsToStateAndBlockIndex(
        CBlockIndex *index,
        const CBlock* pblock) {

    std::vector<lelantus::PublicCoin> blockMints;
    for (const auto& mint : pblock->lelantusTxInfo->mints) {
        blockMints.push_back(mint.first);
    }

    latestCoinId = std::max(1, latestCoinId);

    auto &coinGroup = coinGroups[latestCoinId];

    if (coinGroup.nCoins + blockMints.size() <= ZC_LELANTUS_MAX_MINT_NUM) {
        if (coinGroup.nCoins == 0) {
            // first group of coins
            assert(coinGroup.firstBlock == nullptr);
            assert(coinGroup.lastBlock == nullptr);

            coinGroup.firstBlock = coinGroup.lastBlock = index;
        } else {
            assert(coinGroup.firstBlock != nullptr);
            assert(coinGroup.lastBlock != nullptr);
            assert(coinGroup.lastBlock->nHeight <= index->nHeight);

            coinGroup.lastBlock = index;
        }
        coinGroup.nCoins += blockMints.size();
    }
    else {
        LelantusCoinGroupInfo& oldCoinGroup = coinGroups[latestCoinId];
        latestCoinId += 1;
        LelantusCoinGroupInfo& newCoinGroup = coinGroups[latestCoinId];

        for (CBlockIndex *block = oldCoinGroup.lastBlock;
                ;
                block = block->pprev) {
            if (block->lelantusMintedPubCoins[latestCoinId - 1].size() > 0) {
                newCoinGroup.nCoins += block->lelantusMintedPubCoins[latestCoinId - 1].size();  // always start with non empty set

                if (newCoinGroup.nCoins >= ZC_LELANTUS_SET_START_SIZE) {
                    newCoinGroup.firstBlock = block;
                    break;
                }
            }
        }

        newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins += blockMints.size();
    }

    for (const auto& mint : blockMints) {
        containers.AddMint(mint, CMintedCoinInfo::make(latestCoinId, index->nHeight));

        LogPrintf("AddMintsToStateAndBlockIndex: Lelantus mint added id=%d\n", latestCoinId);
        index->lelantusMintedPubCoins[latestCoinId].push_back(mint);
    }
}

void CLelantusState::AddSpend(const Scalar &serial, int coinGroupId) {
    containers.AddSpend(serial, coinGroupId);
}

void CLelantusState::AddBlock(CBlockIndex *index) {
    BOOST_FOREACH(
        const PAIRTYPE(int, vector<lelantus::PublicCoin>) &pubCoins,
            index->lelantusMintedPubCoins) {
        if (!pubCoins.second.empty()) {
            LelantusCoinGroupInfo& coinGroup = coinGroups[pubCoins.first];

            if (coinGroup.firstBlock == NULL)
                coinGroup.firstBlock = index;
            coinGroup.lastBlock = index;
            coinGroup.nCoins += pubCoins.second.size();
        }

        latestCoinId = pubCoins.first;
        BOOST_FOREACH(const lelantus::PublicCoin &coin, pubCoins.second) {
            containers.AddMint(coin, CMintedCoinInfo::make(pubCoins.first, index->nHeight));
        }
    }

    BOOST_FOREACH(const auto& serial, index->lelantusSpentSerials) {
        AddSpend(serial.first, serial.second);
    }
}

void CLelantusState::RemoveBlock(CBlockIndex *index) {
    // roll back coin group updates
    BOOST_FOREACH(
        const PAIRTYPE(int,vector<lelantus::PublicCoin>)& coins,
        index->lelantusMintedPubCoins)
    {
        LelantusCoinGroupInfo& coinGroup = coinGroups[coins.first];
        int  nMintsToForget = coins.second.size();

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coins.first);
            // decrease pubcoin id
            latestCoinId--;
        }
        else {
            // roll back lastBlock to previous position
            assert(coinGroup.lastBlock == index);

            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->lelantusMintedPubCoins.count(coins.first) == 0);
        }
    }

    // roll back mints
    BOOST_FOREACH(const PAIRTYPE(int, vector<lelantus::PublicCoin>) &pubCoins,
                  index->lelantusMintedPubCoins) {
        BOOST_FOREACH(const lelantus::PublicCoin& coin, pubCoins.second) {
            auto coins = containers.GetMints().equal_range(coin);
            auto coinIt = find_if(
                coins.first, coins.second,
                [&pubCoins](const mint_info_container::value_type &v) {
                    return v.second.coinGroupId == pubCoins.first;
                });
            assert(coinIt != coins.second);
            containers.RemoveMint(coinIt->first);
        }
    }

    // roll back spends
    BOOST_FOREACH(const auto& serial, index->lelantusSpentSerials) {
        containers.RemoveSpend(serial.first);
    }
}

bool CLelantusState::GetCoinGroupInfo(
        int group_id,
        LelantusCoinGroupInfo& result) {
    if (coinGroups.count(group_id) == 0)
        return false;

    result = coinGroups[group_id];
    return true;
}

bool CLelantusState::IsUsedCoinSerial(const Scalar &coinSerial) {
    return containers.GetSpends().count(coinSerial) != 0;
}

bool CLelantusState::IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash) {
    for ( auto it = GetSpends().begin(); it != GetSpends().end(); ++it ){
        if(primitives::GetSerialHash(it->first)==coinSerialHash){
            coinSerial = it->first;
            return true;
        }
    }
    return false;
}

bool CLelantusState::HasCoin(const lelantus::PublicCoin& pubCoin) {
    return containers.GetMints().find(pubCoin) != containers.GetMints().end();
}

bool CLelantusState::HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash) {
    for ( auto it = GetMints().begin(); it != GetMints().end(); ++it ){
        const lelantus::PublicCoin & pubCoin = (*it).first;
        if(pubCoin.getValueHash()==pubCoinValueHash){
            pubCoinValue = pubCoin.getValue();
            return true;
        }
    }
    return false;
}

int CLelantusState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<lelantus::PublicCoin>& coins_out) {

    coins_out.clear();

    if (coinGroups.count(coinGroupID) == 0)
        return 0;

    LelantusCoinGroupInfo coinGroup = coinGroups[coinGroupID];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;
            ;
            block = block->pprev) {
        if (block->lelantusMintedPubCoins[coinGroupID].size() > 0) {
            if (block->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember block hash
                    blockHash_out = block->GetBlockHash();
                }
                numberOfCoins += block->lelantusMintedPubCoins[coinGroupID].size();
                coins_out.insert(coins_out.end(),
                        block->lelantusMintedPubCoins[coinGroupID].begin(),
                        block->lelantusMintedPubCoins[coinGroupID].end());
            }
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
    return numberOfCoins;
}

std::pair<int, int> CLelantusState::GetMintedCoinHeightAndId(
        const lelantus::PublicCoin& pubCoin) {
    auto coinIt = containers.GetMints().find(pubCoin);

    if (coinIt != containers.GetMints().end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.coinGroupId);
    }
    return std::make_pair(-1, -1);
}

bool CLelantusState::AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash) {
    BOOST_FOREACH(const Scalar& coinSerial, coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
            return false;

        mempoolCoinSerials[coinSerial] = txHash;
    }

    return true;
}

void CLelantusState::RemoveSpendFromMempool(const vector<Scalar> &coinSerials) {
    BOOST_FOREACH(const Scalar& coinSerial, coinSerials){
        mempoolCoinSerials.erase(coinSerial);
    }
}

void CLelantusState::AddMintsToMempool(const vector<GroupElement>& pubCoins){
    BOOST_FOREACH(const GroupElement& pubCoin, pubCoins){
        mempoolMints.insert(pubCoin);
    }
}

void CLelantusState::RemoveMintFromMempool(const GroupElement& pubCoin){
    mempoolMints.erase(pubCoin);
}

uint256 CLelantusState::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CLelantusState::CanAddSpendToMempool(const Scalar& coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

bool CLelantusState::CanAddMintToMempool(const GroupElement& pubCoin){
    return mempoolMints.count(pubCoin) == 0;
}

void CLelantusState::Reset() {
    coinGroups.clear();
    latestCoinId = 0;
    mempoolCoinSerials.clear();
    mempoolMints.clear();
    containers.Reset();
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

std::unordered_map<int, CLelantusState::LelantusCoinGroupInfo> const & CLelantusState::GetCoinGroups() const {
    return coinGroups;
}

std::unordered_map<Scalar, uint256, sigma::CScalarHash> const & CLelantusState::GetMempoolCoinSerials() const {
    return mempoolCoinSerials;
}

} // end of namespace lelantus.
