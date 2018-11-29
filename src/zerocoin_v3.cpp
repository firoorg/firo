#include "main.h"
#include "zerocoin_v3.h"
#include "zerocoin.h" // Mostly for reusing class libzerocoin::SpendMetaData
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "crypto/sha256.h"
#include "libzerocoin/sigma/CoinSpend.h"
#include "libzerocoin/sigma/Coin.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>

using namespace std;

// Settings
int64_t nTransactionFee = 0;
int64_t nMinimumInputValue = DUST_HARD_LIMIT;

// Set up the Zerocoin Params object
sigma::ParamsV3* ZCParamsV3 = sigma::ParamsV3::get_default();

static CZerocoinStateV3 zerocoinStateV3;

static bool CheckZerocoinSpendSerialV3(
        CValidationState &state, 
        CZerocoinTxInfoV3 *zerocoinTxInfoV3,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip) {
    // check for zerocoin transaction in this block as well
    if (zerocoinTxInfoV3 && 
        !zerocoinTxInfoV3->fInfoIsComplete && 
        zerocoinTxInfoV3->spentSerials.find(serial) != zerocoinTxInfoV3->spentSerials.end())
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same serial in the same block"));

    // check for used serials in zerocoinStateV3
    if (zerocoinStateV3.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The V3 CoinSpend serial has been used"));
        }
    }
    return true;
}

// This function will not report an error only if the transaction is zerocoin spend V3. 
// Will return false for V1, V1.5 and V2 spends.
// Mixing V2 and V3 spends into the same transaction will fail.
bool CheckSpendZcoinTransactionV3(
        const CTransaction &tx,
        sigma::CoinDenominationV3 targetDenomination,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        CZerocoinTxInfoV3 *zerocoinTxInfoV3) {

    // TODO(martun): add support of fHasSpendV1 and fHasSpendV2,
    // I'm thinking of making these checks somewhere else, for example adding a switch
    // based on spend txn version in ConnectBlockZCV3.

    // Check for inputs only, everything else was checked before
    LogPrintf("CheckSpendZcoinTransactionV3 denomination=%d nHeight=%d\n", 
            targetDenomination, nHeight);

    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        if (!txin.scriptSig.IsZerocoinSpend())
            continue;

        if (tx.vin.size() > 1)
            return state.DoS(100, false,
                    REJECT_MALFORMED,
                    "CheckSpendZcoinTransactionV3: can't have more than one input");

        uint32_t pubcoinId = txin.nSequence;
        if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
            // coin id should be positive integer
            return state.DoS(100,
                    false,
                    NSEQUENCE_INCORRECT,
                    "CTransaction::CheckTransaction() : Error: zerocoin spend nSequence is incorrect");
        }

        // pubcoinId -= ZC_MODULUS_V3_BASE_ID; TODO(martun): check if we need to fix the base id for V3 transactions and deduce that number here.

        if (txin.scriptSig.size() < 4)
            return state.DoS(100,
                    false,
                    REJECT_MALFORMED,
                    "CheckSpendZcoinTransactionV3: invalid spend transaction");

        // Deserialize the CoinSpend into a fresh object
        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                (const char *)&*txin.scriptSig.end(),
                SER_NETWORK, PROTOCOL_VERSION);
        sigma::CoinSpendV3 newSpend(ZCParamsV3, serializedCoinSpend);

        uint256 txHashForMetadata;

        // Obtain the hash of the transaction sans the zerocoin part
        CMutableTransaction txTemp = tx;
        BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
            if (txTempIn.scriptSig.IsZerocoinSpend()) {
                txTempIn.scriptSig.clear();
                txTempIn.prevout.SetNull();
            }
        }
        txHashForMetadata = txTemp.GetHash();

        LogPrintf("CheckSpendZcoinTransactionV3: tx version=%d, tx metadata hash=%s, serial=%s\n", 
                newSpend.getVersion(), txHashForMetadata.ToString(),
                newSpend.getCoinSerialNumber().tostring());

        const CChainParams& chainParams = Params();
        int txHeight = chainActive.Height();

        libzerocoin::SpendMetaData newMetadata(txin.nSequence, txHashForMetadata);

        CZerocoinStateV3::CoinGroupInfoV3 coinGroup;
        if (!zerocoinStateV3.GetCoinGroupInfo(targetDenomination, pubcoinId, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN, 
                    "CheckSpendZcoinTransactionV3: Error: no coins were minted with such parameters");

        bool passVerify = false;
        CBlockIndex *index = coinGroup.lastBlock;
        pair<int,int> denominationAndId = std::make_pair(targetDenomination, pubcoinId);

        uint256 accumulatorBlockHash = newSpend.getAccumulatorBlockHash();

        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
            index = index->pprev;

        // Build a vector with all the public coins with given denomination and accumulator id before
        // the block on which the spend occured.
        // This list of public coins is required by function "Verify" of CoinSpendV3.
        std::vector<PublicCoinV3> anonymity_set;
        while (index != coinGroup.firstBlock) {
            BOOST_FOREACH(const sigma::PublicCoinV3& pubCoinValue, 
                          index->mintedPubCoinsV3[std::make_pair(targetDenomination, pubcoinId)]) {
                anonymity_set.push_back(pubCoinValue);
            }
        }

        passVerify = newSpend.Verify(anonymity_set);
        if (passVerify) {
            Scalar serial = newSpend.getCoinSerialNumber();
            // do not check for duplicates in case we've seen exact copy of this tx in this block before
            if (!(zerocoinTxInfoV3 && zerocoinTxInfoV3->zcTransactions.count(hashTx) > 0)) {
                if (!CheckZerocoinSpendSerialV3(
                        state, zerocoinTxInfoV3, serial, nHeight, false))
                    return false;
            }

            if(!isVerifyDB && !isCheckWallet) {
                if (zerocoinTxInfoV3 && !zerocoinTxInfoV3->fInfoIsComplete) {
                    // add spend information to the index
                    zerocoinTxInfoV3->spentSerials.insert(std::make_pair(
                        serial, (int)newSpend.getDenomination()));
                    zerocoinTxInfoV3->zcTransactions.insert(hashTx);
                }
            }
        }
        else {
            LogPrintf("CheckSpendZCoinTransactionV3: verification failed at block %d\n", nHeight);
            return false;
        }
    }
    return true;
}

bool CheckMintZcoinTransactionV3(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        CZerocoinTxInfoV3 *zerocoinTxInfoV3) {
    LogPrintf("CheckMintZcoinTransactionV3 txHash = %s\n", txout.GetHash().ToString());
    LogPrintf("nValue = %d\n", txout.nValue);

    if (txout.scriptPubKey.size() < 6)
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CTransaction::CheckTransaction() : PubCoin validation failed");

    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 6, txout.scriptPubKey.end());
    secp_primitives::GroupElement pubCoinValue;
    pubCoinValue.deserialize(&coin_serialised[0]);

    sigma::CoinDenominationV3 denomination = (sigma::CoinDenominationV3)(txout.nValue / COIN);
    PublicCoinV3 pubCoin(pubCoinValue, denomination);
    bool hasCoin = zerocoinStateV3.HasCoin(pubCoin);

    if (!hasCoin && zerocoinTxInfoV3 && !zerocoinTxInfoV3->fInfoIsComplete) {
        BOOST_FOREACH(const PAIRTYPE(int, PublicCoinV3)& mint, zerocoinTxInfoV3->mints) {
            if (mint.second == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin) {
        // return state.DoS(100,
        //                 false,
        //                 PUBCOIN_NOT_VALIDATE,
        //                 "CheckZerocoinTransaction: duplicate mint");
        LogPrintf("CheckMintZerocoinTransactionV3: double mint, tx=%s\n", 
                txout.GetHash().ToString());
    }

    switch (txout.nValue) {
        default:
            return state.DoS(100,
                    false,
                    PUBCOIN_NOT_VALIDATE,
                    "CheckZerocoinTransactionV3 : PubCoin denomination is invalid");

        case CoinDenominationV3::ZQ_LOVELACE*COIN:
        case CoinDenominationV3::ZQ_GOLDWASSER*COIN:
        case CoinDenominationV3::ZQ_RACKOFF*COIN:
        case CoinDenominationV3::ZQ_PEDERSEN*COIN:
        case CoinDenominationV3::ZQ_WILLIAMSON*COIN:
            if (!pubCoin.validate())
                return state.DoS(100,
                        false,
                        PUBCOIN_NOT_VALIDATE,
                        "CheckZerocoinTransaction : PubCoin validation failed");

            if (zerocoinTxInfoV3 != NULL && !zerocoinTxInfoV3->fInfoIsComplete) {
                // Update public coin list in the info
                zerocoinTxInfoV3->mints.push_back(make_pair(denomination, pubCoin));
                zerocoinTxInfoV3->zcTransactions.insert(hashTx);
            }
            break;
    }

    return true;
}

bool CheckZerocoinTransactionV3(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        CZerocoinTxInfoV3 *zerocoinTxInfoV3)
{
    // Check Mint Zerocoin Transaction
    BOOST_FOREACH(const CTxOut &txout, tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
            if (!CheckMintZcoinTransactionV3(txout, state, hashTx, zerocoinTxInfoV3))
                return false;
        }
    }

    // Check Spend Zerocoin Transaction
    if(tx.IsZerocoinSpend()) {
        // Check vOut
        // Only one loop, we checked on the format before entering this case
        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (!isVerifyDB) {
                switch (txout.nValue) {
                    default:
                        return state.DoS(100, error("CheckZerocoinTransaction : invalid spending txout value"));
                    case CoinDenominationV3::ZQ_LOVELACE*COIN:
                    case CoinDenominationV3::ZQ_GOLDWASSER*COIN:
                    case CoinDenominationV3::ZQ_RACKOFF*COIN:
                    case CoinDenominationV3::ZQ_PEDERSEN*COIN:
                    case CoinDenominationV3::ZQ_WILLIAMSON*COIN:
                        sigma::CoinDenominationV3 denomination = (sigma::CoinDenominationV3)(txout.nValue / COIN);
                        if(!CheckSpendZcoinTransactionV3(
                                tx, denomination, state, hashTx, isVerifyDB, nHeight, 
                                isCheckWallet, zerocoinTxInfoV3))
                            return false;
                }
            }
        }
    }
    return true;
}

void DisconnectTipZCV3(CBlock & /*block*/, CBlockIndex *pindexDelete) {
    zerocoinStateV3.RemoveBlock(pindexDelete);
}

Scalar ZerocoinGetSpendSerialNumberV3(const CTransaction &tx) {
    if (!tx.IsZerocoinSpend() || tx.vin.size() != 1)
        return Scalar(uint64_t(0));

    const CTxIn &txin = tx.vin[0];

    try {
        CDataStream serializedCoinSpend(
                (const char *)&*(txin.scriptSig.begin() + 4),
                (const char *)&*txin.scriptSig.end(),
                SER_NETWORK, PROTOCOL_VERSION);
        sigma::CoinSpendV3 spend(ZCParamsV3, serializedCoinSpend);
        return spend.getCoinSerialNumber();
    }
    catch (const std::runtime_error &) {
        return Scalar(uint64_t(0));
    }
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockZCV3(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {
    // Add zerocoin transaction information to index
    if (pblock && pblock->zerocoinTxInfoV3) {
        // Don't allow spend v1s after some point of time
        if (pblock->zerocoinTxInfoV3->fHasSpendV1) {
            int allowV1Height = Params().nSpendV15StartBlock;
            if (pindexNew->nHeight >= allowV1Height + ZC_V1_5_GRACEFUL_PERIOD) {
                LogPrintf("ConnectTipZC: spend v1 is not allowed after block %d\n", allowV1Height);
                return false;
            }
        }

        // Also don't allow spend v2s after some other point in time.
        if (pblock->zerocoinTxInfoV3->fHasSpendV2) {
            int allowV2Height = Params().nSpendV2StartBlock;
            if (pindexNew->nHeight >= allowV2Height + ZC_V2_GRACEFUL_PERIOD) {
                LogPrintf("ConnectTipZC: spend v2 is not allowed after block %d\n", allowV2Height);
                return false;
            }
        }

        if (!fJustCheck)
            pindexNew->spentSerialsV3.clear();

        BOOST_FOREACH(auto& serial, pblock->zerocoinTxInfoV3->spentSerials) {
            if (!CheckZerocoinSpendSerialV3(
                    state, 
                    pblock->zerocoinTxInfoV3.get(), 
                    serial.first, 
                    pindexNew->nHeight, 
                    true /* fConnectTip */
                ))
                return false;

            if (!fJustCheck) {
                pindexNew->spentSerialsV3.insert(serial.first);
                zerocoinStateV3.AddSpend(serial.first);
            }
        }

        if (fJustCheck)
            return true;

        // Update pindexNew.mintedPubCoinsV3
        BOOST_FOREACH(const PAIRTYPE(int,PublicCoinV3) &mint, pblock->zerocoinTxInfoV3->mints) {
            int denomination = mint.first;            
            int mintId = zerocoinStateV3.AddMint(
                pindexNew,
                mint.second);

            LogPrintf("ConnectTipZC: mint added denomination=%d, id=%d\n", denomination, mintId);
            pair<int,int> denomAndId = make_pair(denomination, mintId);
            pindexNew->mintedPubCoinsV3[denomAndId].push_back(mint.second);
        }               
    }
    else if (!fJustCheck) {
        zerocoinStateV3.AddBlock(pindexNew);
    }
    return true;
}

bool ZerocoinBuildStateFromIndexV3(CChain *chain) {
    zerocoinStateV3.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
        zerocoinStateV3.AddBlock(blockIndex);

    // DEBUG
    LogPrintf("Latest IDs are %d, %d, %d, %d, %d\n",
            zerocoinStateV3.latestCoinIds[1],
            zerocoinStateV3.latestCoinIds[10],
            zerocoinStateV3.latestCoinIds[25],
            zerocoinStateV3.latestCoinIds[50],
            zerocoinStateV3.latestCoinIds[100]);
    return true;
}

// CZerocoinTxInfoV3

void CZerocoinTxInfoV3::Complete() {

    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it. Denomination doesn't matter but we will sort by it as well
    sort(mints.begin(), mints.end(),
        [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
            CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
            ds1 << m1.second;
            ds2 << m2.second;
        return (m1.first < m2.first) || ((m1.first == m2.first) && (ds1.str() < ds2.str()));
    });

    // Mark this info as complete
    fInfoIsComplete = true;
}

// CZerocoinStateV3

CZerocoinStateV3::CZerocoinStateV3() {
}

int CZerocoinStateV3::AddMint(
        CBlockIndex *index, 
        const PublicCoinV3 &pubCoin) {
    int     mintId = 1;

    int denomination =  pubCoin.getDenomination();

   if (latestCoinIds[denomination] < 1)
       latestCoinIds[denomination] = mintId;
   else
       mintId = latestCoinIds[denomination];

    // There is a limit of 15000 coins per group but mints belonging to the same block must have the same id thus going
    // beyond 15000
    CoinGroupInfoV3 &coinGroup = coinGroups[make_pair(denomination, mintId)];
    int coinsPerId =  ZC_SPEND_V3_COINSPERID;
    if (coinGroup.nCoins < coinsPerId || coinGroup.lastBlock == index) {
        if (coinGroup.nCoins++ == 0) {
            // first groups of coins for given denomination
            coinGroup.firstBlock = coinGroup.lastBlock = index;
        }
        else {
            coinGroup.lastBlock = index;
        }
    }
    else {
        latestCoinIds[denomination] = ++mintId;
        CoinGroupInfoV3 &newCoinGroup = coinGroups[make_pair(denomination, mintId)];
        newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = 1;
    }

    CMintedCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.id = mintId;
    coinInfo.nHeight = index->nHeight;
    mintedPubCoins.insert(pair<PublicCoinV3,CMintedCoinInfo>(pubCoin, coinInfo));

    return mintId;
}

void CZerocoinStateV3::AddSpend(const Scalar &serial) {
    usedCoinSerials.insert(serial);
}

void CZerocoinStateV3::AddBlock(CBlockIndex *index) {
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), vector<sigma::PublicCoinV3>)& coin, index->mintedPubCoinsV3)
    {
        if (!coin.second.empty()) {
            CoinGroupInfoV3& coinGroup = coinGroups[coin.first];

            if (coinGroup.firstBlock == NULL)
                coinGroup.firstBlock = index;
            coinGroup.lastBlock = index;
            coinGroup.nCoins += coin.second.size();
        }
    }
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int),vector<PublicCoinV3>) &pubCoins, index->mintedPubCoinsV3) {
       latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
       BOOST_FOREACH(const PublicCoinV3 &coin, pubCoins.second) {
           CMintedCoinInfo coinInfo;
           coinInfo.denomination = pubCoins.first.first;
           coinInfo.id = pubCoins.first.second;
           coinInfo.nHeight = index->nHeight;
           mintedPubCoins.insert(pair<PublicCoinV3,CMintedCoinInfo>(coin, coinInfo));
       }
    }

    BOOST_FOREACH(const Scalar &serial, index->spentSerialsV3) {
        usedCoinSerials.insert(serial);
    }
}

void CZerocoinStateV3::RemoveBlock(CBlockIndex *index) {
    // roll back accumulator updates
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int),vector<PublicCoinV3>) &coin, index->mintedPubCoinsV3)
    {
        CoinGroupInfoV3   &coinGroup = coinGroups[coin.first];
        int  nMintsToForget = coin.second.size();

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coin.first);
            // decrease pubcoin id for this denomination
            latestCoinIds[coin.first.first]--;
        }
        else {
            // roll back lastBlock to previous position
            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->mintedPubCoinsV3.count(coin.first) == 0);
        }
    }
//
    // roll back mints
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int),vector<PublicCoinV3>) &pubCoins, index->mintedPubCoinsV3) {
        BOOST_FOREACH(const PublicCoinV3 &coin, pubCoins.second) {
            auto coins = mintedPubCoins.equal_range(coin);
            auto coinIt = find_if(coins.first, coins.second, [=](const decltype(mintedPubCoins)::value_type &v) {
            return v.second.denomination == pubCoins.first.first &&
                    v.second.id == pubCoins.first.second;
            });
            assert(coinIt != coins.second);
            mintedPubCoins.erase(coinIt);
        }
    }

    // roll back spends
    BOOST_FOREACH(const Scalar &serial, index->spentSerialsV3) {
        usedCoinSerials.erase(serial);
    }
}

bool CZerocoinStateV3::GetCoinGroupInfo(int denomination, int id, CoinGroupInfoV3 &result) {
    pair<int,int> key = make_pair(denomination, id);
    if (coinGroups.count(key) == 0)
        return false;

    result = coinGroups[key];
    return true;
}

bool CZerocoinStateV3::IsUsedCoinSerial(const Scalar &coinSerial) {
    return usedCoinSerials.count(coinSerial) != 0;
}

bool CZerocoinStateV3::HasCoin(const PublicCoinV3& pubCoin) {
    return mintedPubCoins.find(pubCoin) != mintedPubCoins.end();
}

int CZerocoinStateV3::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int denomination,
        int id,
        uint256& blockHash_out,
        std::vector<PublicCoinV3>& coins_out) {

    pair<int, int> denomAndId = pair<int, int>(denomination, id);

    if (coinGroups.count(denomAndId) == 0)
        return 0;

    CoinGroupInfoV3 coinGroup = coinGroups[denomAndId];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;
         block != coinGroup.firstBlock;
         block = block->pprev) {
        if (block->mintedPubCoinsV3[denomAndId].size() > 0) {
            if (block->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember block hash
                    blockHash_out = block->GetBlockHash();
                }
                numberOfCoins += block->mintedPubCoinsV3[denomAndId].size();
                coins_out.insert(coins_out.end(), 
                                 block->mintedPubCoinsV3[denomAndId].begin(),
                                 block->mintedPubCoinsV3[denomAndId].end());
            }
        }
    }
    return numberOfCoins;
}

std::pair<int, int> CZerocoinStateV3::GetMintedCoinHeightAndId(
        const PublicCoinV3& pubCoin, 
        int denomination) {
    auto coinIt = mintedPubCoins.find(pubCoin);

    if (coinIt != mintedPubCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.id);
    }
    else
        return std::make_pair(-1, -1);
}

bool CZerocoinStateV3::TestValidity(CChain *chain) {
    /*
       BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), CoinGroupInfoV3) &coinGroup, coinGroups) {
       fprintf(stderr, "TestValidity[denomination=%d, id=%d]\n", coinGroup.first.first, coinGroup.first.second);

       bool fModulusV2 = IsZerocoinTxV2((sigma::CoinDenominationV3)coinGroup.first.first, coinGroup.first.second);
       sigma::ParamsV3 *zcParams = fModulusV2 ? ZCParamsV3V2 : ZCParamsV3;

       libzerocoin::Accumulator acc(&zcParams->accumulatorParams, (sigma::CoinDenominationV3)coinGroup.first.first);

       CBlockIndex *block = coinGroup.second.firstBlock;
       for (;;) {
       if (block->accumulatorChanges.count(coinGroup.first) > 0) {
       if (block->mintedPubCoinsV3.count(coinGroup.first) == 0) {
       fprintf(stderr, "  no minted coins\n");
       return false;
       }

       BOOST_FOREACH(const Scalar &pubCoin, block->mintedPubCoinsV3[coinGroup.first]) {
       acc += sigma::PublicCoinV3(zcParams, pubCoin, (sigma::CoinDenominationV3)coinGroup.first.first);
       }

       if (block->accumulatorChanges[coinGroup.first].second != (int)block->mintedPubCoinsV3[coinGroup.first].size()) {
       fprintf(stderr, "  number of minted coins mismatch at height %d\n", block->nHeight);
       return false;
       }
       }

       if (block != coinGroup.second.lastBlock)
       block = (*chain)[block->nHeight+1];
       else
       break;
       }

       fprintf(stderr, "  verified ok\n");
       }
     */
    return true;
}

bool CZerocoinStateV3::AddSpendToMempool(const Scalar &coinSerial, uint256 txHash) {
    if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
        return false;

    mempoolCoinSerials[coinSerial] = txHash;
    return true;
}

void CZerocoinStateV3::RemoveSpendFromMempool(const Scalar& coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

uint256 CZerocoinStateV3::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CZerocoinStateV3::CanAddSpendToMempool(const Scalar& coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

void CZerocoinStateV3::Reset() {
    coinGroups.clear();
//    all_minted_coins.clear();
    usedCoinSerials.clear();
    latestCoinIds.clear();
    mempoolCoinSerials.clear();
}

CZerocoinStateV3 *CZerocoinStateV3::GetZerocoinState() {
    return &zerocoinStateV3;
}

