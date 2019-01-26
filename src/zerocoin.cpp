#include "main.h"
#include "zerocoin.h"
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "znode-payments.h"
#include "znode-sync.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>

using namespace std;

// Settings
int64_t nTransactionFee = 0;
int64_t nMinimumInputValue = DUST_HARD_LIMIT;

// btzc: add zerocoin init
// zerocoin init
static CBigNum bnTrustedModulus(ZEROCOIN_MODULUS), bnTrustedModulusV2(ZEROCOIN_MODULUS_V2);

// Set up the Zerocoin Params object
uint32_t securityLevel = 80;
libzerocoin::Params *ZCParams = new libzerocoin::Params(bnTrustedModulus, bnTrustedModulus);
libzerocoin::Params *ZCParamsV2 = new libzerocoin::Params(bnTrustedModulusV2, bnTrustedModulus);

static CZerocoinState zerocoinState;

static bool CheckZerocoinSpendSerial(CValidationState &state, const Consensus::Params &params, CZerocoinTxInfo *zerocoinTxInfo, libzerocoin::CoinDenomination denomination, const CBigNum &serial, int nHeight, bool fConnectTip) {
    if (nHeight > params.nCheckBugFixedAtBlock) {
        // check for zerocoin transaction in this block as well
        if (zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete && zerocoinTxInfo->spentSerials.count(serial) > 0)
            return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same serial in the same block"));

        // check for used serials in zerocoinState
        if (zerocoinState.IsUsedCoinSerial(serial)) {
            // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
            if (nHeight == INT_MAX || fConnectTip) {
                if (nHeight < params.nSpendV15StartBlock)
                    LogPrintf("ZCSpend: height=%d, denomination=%d, serial=%s\n", nHeight, (int)denomination, serial.ToString());
                else
                    return state.DoS(0, error("CTransaction::CheckTransaction() : The CoinSpend serial has been used"));
            }
        }
    }

    return true;
}

bool CheckSpendZcoinTransaction(const CTransaction &tx,
                                const Consensus::Params &params,
                                const vector<libzerocoin::CoinDenomination>& targetDenominations,
                                CValidationState &state,
                                uint256 hashTx,
                                bool isVerifyDB,
                                int nHeight,
                                bool isCheckWallet,
                                bool fStatefulZerocoinCheck,
                                CZerocoinTxInfo *zerocoinTxInfo) {

    int txHeight = chainActive.Height();
    bool hasZerocoinSpendInputs = false, hasNonZerocoinInputs = false;
    int vinIndex = -1;

    set<CBigNum> serialsUsedInThisTx;

    BOOST_FOREACH(const CTxIn &txin, tx.vin){
        vinIndex++;
        if (txin.scriptSig.IsZerocoinSpend()) {
            hasZerocoinSpendInputs = true;
        }
        else {
            hasNonZerocoinInputs = true;
        }

        uint32_t pubcoinId = txin.nSequence;
        if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
             // coin id should be positive integer
            return state.DoS(100,
                false,
                NSEQUENCE_INCORRECT,
                "CTransaction::CheckTransaction() : Error: zerocoin spend nSequence is incorrect");
        }

        bool fModulusV2 = pubcoinId >= ZC_MODULUS_V2_BASE_ID, fModulusV2InIndex = false;
        if (fModulusV2)
            pubcoinId -= ZC_MODULUS_V2_BASE_ID;
        libzerocoin::Params *zcParams = fModulusV2 ? ZCParamsV2 : ZCParams;

        if (txin.scriptSig.size() < 4)
            return state.DoS(100,
                             false,
                             REJECT_MALFORMED,
                             "CheckSpendZcoinTransaction: invalid spend transaction");

        // Deserialize the CoinSpend intro a fresh object
        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                        (const char *)&*txin.scriptSig.end(),
                                        SER_NETWORK, PROTOCOL_VERSION);
        libzerocoin::CoinSpend newSpend(zcParams, serializedCoinSpend);

        int spendVersion = newSpend.getVersion();
        if (spendVersion != ZEROCOIN_TX_VERSION_1 &&
                spendVersion != ZEROCOIN_TX_VERSION_1_5 &&
                spendVersion != ZEROCOIN_TX_VERSION_2) {
            return state.DoS(100,
                false,
                NSEQUENCE_INCORRECT,
                "CTransaction::CheckTransaction() : Error: incorrect spend transaction verion");
        }

        if (IsZerocoinTxV2(targetDenominations[vinIndex], params, pubcoinId)) {
            // After threshold id all spends should be strictly 2.0
            if (spendVersion != ZEROCOIN_TX_VERSION_2)
                return state.DoS(100,
                    false,
                    NSEQUENCE_INCORRECT,
                    "CTransaction::CheckTransaction() : Error: zerocoin spend should be version 2.0");
            fModulusV2InIndex = true;
        }
        else {
            // old spends v2.0s are probably incorrect, force spend to version 1
            if (spendVersion == ZEROCOIN_TX_VERSION_2) {
                spendVersion = ZEROCOIN_TX_VERSION_1;
                newSpend.setVersion(ZEROCOIN_TX_VERSION_1);
            }
        }

        if (fModulusV2InIndex != fModulusV2 && fStatefulZerocoinCheck)
            zerocoinState.CalculateAlternativeModulusAccumulatorValues(&chainActive, (int)targetDenominations[vinIndex], pubcoinId);

        uint256 txHashForMetadata;

        if (spendVersion > ZEROCOIN_TX_VERSION_1) {
            // Obtain the hash of the transaction sans the zerocoin part
            CMutableTransaction txTemp = tx;
            BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
                if (txTempIn.scriptSig.IsZerocoinSpend()) {
                    txTempIn.scriptSig.clear();
                    txTempIn.prevout.SetNull();
                }
            }
            txHashForMetadata = txTemp.GetHash();
        }

        LogPrintf("CheckSpendZcoinTransaction: tx version=%d, tx metadata hash=%s, serial=%s\n", newSpend.getVersion(), txHashForMetadata.ToString(), newSpend.getCoinSerialNumber().ToString());

        int txHeight = chainActive.Height();

        if (spendVersion == ZEROCOIN_TX_VERSION_1 && nHeight == INT_MAX) {
            int allowedV1Height = params.nSpendV15StartBlock;
            if (txHeight >= allowedV1Height + ZC_V1_5_GRACEFUL_MEMPOOL_PERIOD) {
                LogPrintf("CheckSpendZcoinTransaction: cannot allow spend v1 into mempool after block %d\n",
                          allowedV1Height + ZC_V1_5_GRACEFUL_MEMPOOL_PERIOD);
                return false;
            }
        }

        // test if given modulus version is allowed at this point
        if (fModulusV2) {
            if ((nHeight == INT_MAX && txHeight < params.nModulusV2StartBlock) || nHeight < params.nModulusV2StartBlock)
                return state.DoS(100, false,
                                 NSEQUENCE_INCORRECT,
                                 "CheckSpendZcoinTransaction: cannon use modulus v2 at this point");
        }
        else {
            if ((nHeight == INT_MAX && txHeight >= params.nModulusV1MempoolStopBlock) ||
                    (nHeight != INT_MAX && nHeight >= params.nModulusV1StopBlock))
                return state.DoS(100, false,
                                 NSEQUENCE_INCORRECT,
                                 "CheckSpendZcoinTransaction: cannon use modulus v1 at this point");
        }

        if (!fStatefulZerocoinCheck)
            continue;

        CBigNum serial = newSpend.getCoinSerialNumber();
        // check if there are spends with the same serial within one block
        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (nHeight >= params.nDontAllowDupTxsStartBlock || !(zerocoinTxInfo && zerocoinTxInfo->zcTransactions.count(hashTx) > 0)) {
            if (serialsUsedInThisTx.count(serial) > 0)
                return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same serial in the same block"));
            serialsUsedInThisTx.insert(serial);

            if (!CheckZerocoinSpendSerial(state, params, zerocoinTxInfo, newSpend.getDenomination(), serial, nHeight, false))
                return false;
        }

        if(!isVerifyDB && !isCheckWallet) {
            if (zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete) {
                // add spend information to the index
                zerocoinTxInfo->spentSerials[serial] = (int)newSpend.getDenomination();
                zerocoinTxInfo->zcTransactions.insert(hashTx);

                if (newSpend.getVersion() == ZEROCOIN_TX_VERSION_1)
                    zerocoinTxInfo->fHasSpendV1 = true;
            }
        }

        libzerocoin::SpendMetaData newMetadata(txin.nSequence, txHashForMetadata);

        CZerocoinState::CoinGroupInfo coinGroup;
        if (!zerocoinState.GetCoinGroupInfo(targetDenominations[vinIndex], pubcoinId, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN, "CheckSpendZcoinTransaction: Error: no coins were minted with such parameters");

        bool passVerify = false;
        CBlockIndex *index = coinGroup.lastBlock;
        pair<int,int> denominationAndId = make_pair(targetDenominations[vinIndex], pubcoinId);
        
        bool spendHasBlockHash = false;
        
        // Zerocoin v1.5/v2 transaction can cointain block hash of the last mint tx seen at the moment of spend. It speeds
        // up verification
        if (spendVersion > ZEROCOIN_TX_VERSION_1 && !newSpend.getAccumulatorBlockHash().IsNull()) {
			spendHasBlockHash = true;
			uint256 accumulatorBlockHash = newSpend.getAccumulatorBlockHash();

			// find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
			while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
				index = index->pprev;
		}

        decltype(&CBlockIndex::accumulatorChanges) accChanges = fModulusV2 == fModulusV2InIndex ?
                    &CBlockIndex::accumulatorChanges : &CBlockIndex::alternativeAccumulatorChanges;

        // Enumerate all the accumulator changes seen in the blockchain starting with the latest block
        // In most cases the latest accumulator value will be used for verification
        do {
            if ((index->*accChanges).count(denominationAndId) > 0) {
                libzerocoin::Accumulator accumulator(zcParams,
                                                     (index->*accChanges)[denominationAndId].first,
                                                     targetDenominations[vinIndex]);
                LogPrintf("CheckSpendZcoinTransaction: accumulator=%s\n", accumulator.getValue().ToString().substr(0,15));
                passVerify = newSpend.Verify(accumulator, newMetadata);
            }

            // if spend has block hash we don't need to look further
            if (index == coinGroup.firstBlock || spendHasBlockHash)
                break;
            else
                index = index->pprev;
        } while (!passVerify);

        // Rare case: accumulator value contains some but NOT ALL coins from one block. In this case we will
        // have to enumerate over coins manually. No optimization is really needed here because it's a rarity
        // This can't happen if spend is of version 1.5 or 2.0
        if (!passVerify && spendVersion == ZEROCOIN_TX_VERSION_1) {
            // Build vector of coins sorted by the time of mint
            index = coinGroup.lastBlock;
            vector<CBigNum> pubCoins = index->mintedPubCoins[denominationAndId];
            if (index != coinGroup.firstBlock) {
                do {
                    index = index->pprev;
                    if (index->mintedPubCoins.count(denominationAndId) > 0)
                        pubCoins.insert(pubCoins.begin(),
                                        index->mintedPubCoins[denominationAndId].cbegin(),
                                        index->mintedPubCoins[denominationAndId].cend());
                } while (index != coinGroup.firstBlock);
            }

            libzerocoin::Accumulator accumulator(zcParams, targetDenominations[vinIndex]);
            BOOST_FOREACH(const CBigNum &pubCoin, pubCoins) {
                accumulator += libzerocoin::PublicCoin(zcParams, pubCoin, (libzerocoin::CoinDenomination)targetDenominations[vinIndex]);
                LogPrintf("CheckSpendZcoinTransaction: accumulator=%s\n", accumulator.getValue().ToString().substr(0,15));
                if ((passVerify = newSpend.Verify(accumulator, newMetadata)) == true)
                    break;
            }

            if (!passVerify) {
                // One more time now in reverse direction. The only reason why it's required is compatibility with
                // previous client versions
                libzerocoin::Accumulator accumulator(zcParams, targetDenominations[vinIndex]);
                BOOST_REVERSE_FOREACH(const CBigNum &pubCoin, pubCoins) {
                    accumulator += libzerocoin::PublicCoin(zcParams, pubCoin, (libzerocoin::CoinDenomination)targetDenominations[vinIndex]);
                    LogPrintf("CheckSpendZcoinTransaction: accumulatorRev=%s\n", accumulator.getValue().ToString().substr(0,15));
                    if ((passVerify = newSpend.Verify(accumulator, newMetadata)) == true)
                        break;
                }
            }
        }

        if (!passVerify) {
            LogPrintf("CheckSpendZCoinTransaction: verification failed at block %d\n", nHeight);
            return false;
        }
    }

    if (hasZerocoinSpendInputs) {
        if (hasNonZerocoinInputs) {
            // mixing zerocoin spend input with non-zerocoin inputs is prohibited
            return state.DoS(100, false,
                            REJECT_MALFORMED,
                            "CheckSpendZcoinTransaction: can't mix zerocoin spend input with regular ones");
        }
        else if (tx.vin.size() > 1) {
            // having tx with several zerocoin spend inputs is possible since nMultipleSpendInputsInOneTxStartBlock
            if ((nHeight == INT_MAX && txHeight < params.nMultipleSpendInputsInOneTxStartBlock) ||
                    (nHeight < params.nMultipleSpendInputsInOneTxStartBlock)) {
                return state.DoS(100, false,
                             REJECT_MALFORMED,
                             "CheckSpendZcoinTransaction: can't have more than one input");
            }
        }
    }

    return true;
}

bool CheckMintZcoinTransaction(const CTxOut &txout,
                               CValidationState &state,
                               uint256 hashTx,
                               CZerocoinTxInfo *zerocoinTxInfo) {

    LogPrintf("CheckMintZcoinTransaction txHash = %s\n", txout.GetHash().ToString());
    LogPrintf("nValue = %d\n", txout.nValue);

    if (txout.scriptPubKey.size() < 6)
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : PubCoin validation failed");

    CBigNum pubCoin(vector<unsigned char>(txout.scriptPubKey.begin()+6, txout.scriptPubKey.end()));

    bool hasCoin = zerocoinState.HasCoin(pubCoin);

    if (!hasCoin && zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const PAIRTYPE(int,CBigNum) &mint, zerocoinTxInfo->mints) {
            if (mint.second == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin) {
        /*return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckZerocoinTransaction: duplicate mint");*/
        LogPrintf("CheckMintZerocoinTransaction: double mint, tx=%s\n", txout.GetHash().ToString());
    }

    switch (txout.nValue) {
    default:
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CheckZerocoinTransaction : PubCoin denomination is invalid");

    case libzerocoin::ZQ_LOVELACE*COIN:
    case libzerocoin::ZQ_GOLDWASSER*COIN:
    case libzerocoin::ZQ_RACKOFF*COIN:
    case libzerocoin::ZQ_PEDERSEN*COIN:
    case libzerocoin::ZQ_WILLIAMSON*COIN:
        libzerocoin::CoinDenomination denomination = (libzerocoin::CoinDenomination)(txout.nValue / COIN);
        libzerocoin::PublicCoin checkPubCoin(ZCParamsV2, pubCoin, denomination);
        if (!checkPubCoin.validate())
            return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckZerocoinTransaction : PubCoin validation failed");

        if (zerocoinTxInfo != NULL && !zerocoinTxInfo->fInfoIsComplete) {
            // Update public coin list in the info
            zerocoinTxInfo->mints.push_back(make_pair(denomination, pubCoin));
            zerocoinTxInfo->zcTransactions.insert(hashTx);
        }

        break;
    }

    return true;
}

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, const Consensus::Params &params, int nHeight, bool fMTP) {
    // Check for founders inputs
    if ((nHeight > params.nCheckBugFixedAtBlock) && (nHeight < 305000)) {
        // Reduce everything by a factor of two when MTP is in place
        int reductionFactor = fMTP ? params.nMTPRewardReduction : 1;

        bool found_1 = false;
        bool found_2 = false;
        bool found_3 = false;
        bool found_4 = false;
        bool found_5 = false;
        int total_payment_tx = 0; // no more than 1 output for payment
        CScript FOUNDER_1_SCRIPT;
        CScript FOUNDER_2_SCRIPT;
        CScript FOUNDER_3_SCRIPT;
        CScript FOUNDER_4_SCRIPT;
        CScript FOUNDER_5_SCRIPT;
        if (nHeight < params.nZnodePaymentsStartBlock) {
            if (params.IsMain() && GetAdjustedTime() > nStartRewardTime) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && GetAdjustedTime() <= nStartRewardTime) {
                return state.DoS(100, false, REJECT_TRANSACTION_TOO_EARLY,
                                 "CTransaction::CheckTransaction() : transaction is too early");
            } else {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (output.scriptPubKey == FOUNDER_1_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_1 = true;
                }
                if (output.scriptPubKey == FOUNDER_2_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_2 = true;
                }
                if (output.scriptPubKey == FOUNDER_3_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_3 = true;
                }
                if (output.scriptPubKey == FOUNDER_4_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_4 = true;
                }
                if (output.scriptPubKey == FOUNDER_5_SCRIPT && output.nValue == (int64_t)(2 * COIN)/reductionFactor) {
                    found_5 = true;
                }
            }
        } else {

            if (params.IsMain() && GetAdjustedTime() > nStartRewardTime) {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
                if (nHeight < 14000) {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
                } else {
                    FOUNDER_2_SCRIPT = GetScriptForDestination(
                            CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
                }
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
            } else if (params.IsMain() && GetAdjustedTime() <= nStartRewardTime) {
                return state.DoS(100, false, REJECT_TRANSACTION_TOO_EARLY,
                                 "CTransaction::CheckTransaction() : transaction is too early");
            } else {
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS").Get());
            }

            CAmount znodePayment = GetZnodePayment(params, fMTP);
            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (output.scriptPubKey == FOUNDER_1_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_1 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_2_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_2 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_3_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_3 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_4_SCRIPT && output.nValue == (int64_t)(3 * COIN)/reductionFactor) {
                    found_4 = true;
                    continue;
                }
                if (output.scriptPubKey == FOUNDER_5_SCRIPT && output.nValue == (int64_t)(1 * COIN)/reductionFactor) {
                    found_5 = true;
                    continue;
                }
                if (znodePayment == output.nValue) {
                    total_payment_tx = total_payment_tx + 1;
                }
            }

            bool validZnodePayment;

            if (nHeight > params.nZnodePaymentsBugFixedAtBlock) {
                if (!znodeSync.IsSynced()) {
                    validZnodePayment = true;
                } else {
                    validZnodePayment = mnpayments.IsTransactionValid(tx, nHeight, fMTP);
                }
            } else {
                validZnodePayment = total_payment_tx <= 1;
            }

            if (!validZnodePayment) {
                return state.DoS(100, false, REJECT_INVALID_ZNODE_PAYMENT,
                                 "CTransaction::CheckTransaction() : invalid znode payment");
            }
        }

        if (!(found_1 && found_2 && found_3 && found_4 && found_5)) {
            return state.DoS(100, false, REJECT_FOUNDER_REWARD_MISSING,
                             "CTransaction::CheckTransaction() : founders reward missing");
        }
    }

    return true;
}

bool CheckZerocoinTransaction(const CTransaction &tx,
                              CValidationState &state,
                              const Consensus::Params &params,
                              uint256 hashTx,
                              bool isVerifyDB,
                              int nHeight,
                              bool isCheckWallet,
                              bool fStatefulZerocoinCheck,
                              CZerocoinTxInfo *zerocoinTxInfo)
{
    // Check Mint Zerocoin Transaction
    BOOST_FOREACH(const CTxOut &txout, tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
            if (!CheckMintZcoinTransaction(txout, state, hashTx, zerocoinTxInfo))
                return false;
        }
    }

    // Check Spend Zerocoin Transaction
    vector<libzerocoin::CoinDenomination> denominations;
    if(tx.IsZerocoinSpend()) {
        if (tx.vout.size() > 1) {
            // TODO: enable such spends after some block number
            return state.DoS(100, error("Zerocoin spend with more than 1 output"));
        }

        // First check number of inputs does not exceed transaction limit
        if(tx.vin.size() > ZC_SPEND_LIMIT){
            return false;
        }

        // Check for any non spend inputs and fail if so
        int64_t totalValue = 0;
        BOOST_FOREACH(const CTxIn &txin, tx.vin){
            if(!txin.scriptSig.IsZerocoinSpend()) {
                return state.DoS(100, false,
                                REJECT_MALFORMED,
                                "CheckSpendZcoinTransaction: can't mix zerocoin spend input with regular ones");
            }
            // Get the CoinDenomination value of each vin for the CheckSpendZcoinTransaction function
            uint32_t pubcoinId = txin.nSequence;
            if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
                 // coin id should be positive integer
                return false;
            }
            libzerocoin::Params *zcParams = (pubcoinId >= ZC_MODULUS_V2_BASE_ID) ? ZCParamsV2 : ZCParams;

            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                    (const char *)&*txin.scriptSig.end(),
                                    SER_NETWORK, PROTOCOL_VERSION);
            libzerocoin::CoinSpend newSpend(zcParams, serializedCoinSpend);
            denominations.push_back(newSpend.getDenomination());
            totalValue += newSpend.getDenomination();
        }

        // Check vOut
        // Only one loop, we checked on the format before enter this case
        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if(!isVerifyDB) {
                if (txout.nValue == totalValue * COIN) {
                    if(!CheckSpendZcoinTransaction(tx, params, denominations, state, hashTx, isVerifyDB, nHeight, isCheckWallet, fStatefulZerocoinCheck, zerocoinTxInfo)){
                        return false;
                    }
                }
                else {
                    return state.DoS(100, error("CheckZerocoinTransaction : invalid spending txout value"));
                }
            }
        }
    }

    return true;
}

void DisconnectTipZC(CBlock & /*block*/, CBlockIndex *pindexDelete) {
    zerocoinState.RemoveBlock(pindexDelete);
}

CBigNum ZerocoinGetSpendSerialNumber(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsZerocoinSpend())
        return CBigNum(0);

    try {
        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                    (const char *)&*txin.scriptSig.end(),
                                    SER_NETWORK, PROTOCOL_VERSION);
        libzerocoin::CoinSpend spend(txin.nSequence >= ZC_MODULUS_V2_BASE_ID ? ZCParamsV2 : ZCParams, serializedCoinSpend);
        return spend.getCoinSerialNumber();
    }
    catch (const std::runtime_error &) {
        return CBigNum(0);
    }
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockZC(CValidationState &state, const CChainParams &chainParams, CBlockIndex *pindexNew, const CBlock *pblock, bool fJustCheck) {

    // Add zerocoin transaction information to index
    if (pblock && pblock->zerocoinTxInfo) {
        if (pblock->zerocoinTxInfo->fHasSpendV1) {
            // Don't allow spend v1s after some point of time
            int allowV1Height = chainParams.GetConsensus().nSpendV15StartBlock;
            if (pindexNew->nHeight >= allowV1Height + ZC_V1_5_GRACEFUL_PERIOD) {
                LogPrintf("ConnectTipZC: spend v1 is not allowed after block %d\n", allowV1Height);
                return false;
            }
        }

	    if (!fJustCheck) {
            // clear the state
			pindexNew->spentSerials.clear();
            pindexNew->mintedPubCoins.clear();
            pindexNew->accumulatorChanges.clear();
            pindexNew->alternativeAccumulatorChanges.clear();
        }
	    
        if (pindexNew->nHeight > chainParams.GetConsensus().nCheckBugFixedAtBlock) {
            BOOST_FOREACH(const PAIRTYPE(CBigNum,int) &serial, pblock->zerocoinTxInfo->spentSerials) {
                if (!CheckZerocoinSpendSerial(state, chainParams.GetConsensus(), pblock->zerocoinTxInfo.get(), (libzerocoin::CoinDenomination)serial.second, serial.first, pindexNew->nHeight, true))
                    return false;
                
                if (!fJustCheck) {
                    pindexNew->spentSerials.insert(serial.first);
                    zerocoinState.AddSpend(serial.first);
                }
            }
        }

        if (fJustCheck)
            return true;

        // Update minted values and accumulators
        BOOST_FOREACH(const PAIRTYPE(int,CBigNum) &mint, pblock->zerocoinTxInfo->mints) {
            CBigNum oldAccValue(0);
            int denomination = mint.first;
            int mintId = zerocoinState.AddMint(pindexNew, denomination, mint.second, oldAccValue);

            libzerocoin::Params *zcParams = IsZerocoinTxV2((libzerocoin::CoinDenomination)denomination, 
                                                chainParams.GetConsensus(), mintId) ? ZCParamsV2 : ZCParams;

            if (!oldAccValue)
                oldAccValue = zcParams->accumulatorParams.accumulatorBase;

            LogPrintf("ConnectTipZC: mint added denomination=%d, id=%d\n", denomination, mintId);
            pair<int,int> denomAndId = make_pair(denomination, mintId);

            pindexNew->mintedPubCoins[denomAndId].push_back(mint.second);

            CZerocoinState::CoinGroupInfo coinGroupInfo;
            zerocoinState.GetCoinGroupInfo(denomination, mintId, coinGroupInfo);

            libzerocoin::PublicCoin pubCoin(zcParams, mint.second, (libzerocoin::CoinDenomination)denomination);
            libzerocoin::Accumulator accumulator(zcParams,
                                                 oldAccValue,
                                                 (libzerocoin::CoinDenomination)denomination);
            accumulator += pubCoin;

            if (pindexNew->accumulatorChanges.count(denomAndId) > 0) {
                pair<CBigNum,int> &accChange = pindexNew->accumulatorChanges[denomAndId];
                accChange.first = accumulator.getValue();
                accChange.second++;
            }
            else {
                pindexNew->accumulatorChanges[denomAndId] = make_pair(accumulator.getValue(), 1);
            }
            // invalidate alternative accumulator value for this denomination and id
            pindexNew->alternativeAccumulatorChanges.erase(denomAndId);
        }
    }
    else if (!fJustCheck) {
        zerocoinState.AddBlock(pindexNew, chainParams.GetConsensus());
    }

    return true;
}

int ZerocoinGetNHeight(const CBlockHeader &block) {
    CBlockIndex *pindexPrev = NULL;
    int nHeight = 0;
    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi != mapBlockIndex.end()) {
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight + 1;
    }
    return nHeight;
}


bool ZerocoinBuildStateFromIndex(CChain *chain, set<CBlockIndex *> &changes) {
    auto params = Params().GetConsensus();

    zerocoinState.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
        zerocoinState.AddBlock(blockIndex, params);

    changes = zerocoinState.RecalculateAccumulators(chain);

    // DEBUG
    LogPrintf("Latest IDs are %d, %d, %d, %d, %d\n",
              zerocoinState.latestCoinIds[1],
               zerocoinState.latestCoinIds[10],
            zerocoinState.latestCoinIds[25],
            zerocoinState.latestCoinIds[50],
            zerocoinState.latestCoinIds[100]);
    return true;
}

// CZerocoinTxInfo

void CZerocoinTxInfo::Complete() {
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

// CZerocoinState::CBigNumHash

std::size_t CZerocoinState::CBigNumHash::operator ()(const CBigNum &bn) const noexcept {
    // we are operating on almost random big numbers and least significant bytes (save for few last bytes) give us a good hash
    vector<unsigned char> bnData = bn.ToBytes();
    if (bnData.size() < sizeof(size_t)*3)
        // rare case, put ones like that into one hash bin
        return 0;
    else
        return ((size_t*)bnData.data())[1];
}

// CZerocoinState

CZerocoinState::CZerocoinState() {
}

int CZerocoinState::AddMint(CBlockIndex *index, int denomination, const CBigNum &pubCoin, CBigNum &previousAccValue) {

    int mintId = 1;

    if (latestCoinIds[denomination] < 1)
        latestCoinIds[denomination] = mintId;
    else
        mintId = latestCoinIds[denomination];

    // There is a limit of 10 coins per group but mints belonging to the same block must have the same id thus going
    // beyond 10
    CoinGroupInfo &coinGroup = coinGroups[make_pair(denomination, mintId)];
    int coinsPerId = IsZerocoinTxV2((libzerocoin::CoinDenomination)denomination,
                        Params().GetConsensus(), mintId) ? ZC_SPEND_V2_COINSPERID : ZC_SPEND_V1_COINSPERID;
    if (coinGroup.nCoins < coinsPerId || coinGroup.lastBlock == index) {
        if (coinGroup.nCoins++ == 0) {
            // first groups of coins for given denomination
            coinGroup.firstBlock = coinGroup.lastBlock = index;
        }
        else {
            previousAccValue = coinGroup.lastBlock->accumulatorChanges[make_pair(denomination,mintId)].first;
            coinGroup.lastBlock = index;
        }
    }
    else {
        latestCoinIds[denomination] = ++mintId;
        CoinGroupInfo &newCoinGroup = coinGroups[make_pair(denomination, mintId)];
        newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = 1;
    }

    CMintedCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.id = mintId;
    coinInfo.nHeight = index->nHeight;
    mintedPubCoins.insert(pair<CBigNum,CMintedCoinInfo>(pubCoin, coinInfo));

    return mintId;
}

void CZerocoinState::AddSpend(const CBigNum &serial) {
    usedCoinSerials.insert(serial);
}

void CZerocoinState::AddBlock(CBlockIndex *index, const Consensus::Params &params) {
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), PAIRTYPE(CBigNum,int)) &accUpdate, index->accumulatorChanges)
    {
        CoinGroupInfo   &coinGroup = coinGroups[accUpdate.first];

        if (coinGroup.firstBlock == NULL)
            coinGroup.firstBlock = index;
        coinGroup.lastBlock = index;
        coinGroup.nCoins += accUpdate.second.second;
    }

    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int),vector<CBigNum>) &pubCoins, index->mintedPubCoins) {
        latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second) {
            CMintedCoinInfo coinInfo;
            coinInfo.denomination = pubCoins.first.first;
            coinInfo.id = pubCoins.first.second;
            coinInfo.nHeight = index->nHeight;
            mintedPubCoins.insert(pair<CBigNum,CMintedCoinInfo>(coin, coinInfo));
        }
    }

    if (index->nHeight > params.nCheckBugFixedAtBlock) {
        BOOST_FOREACH(const CBigNum &serial, index->spentSerials) {
            usedCoinSerials.insert(serial);
        }
    }
}

void CZerocoinState::RemoveBlock(CBlockIndex *index) {
    // roll back accumulator updates
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), PAIRTYPE(CBigNum,int)) &accUpdate, index->accumulatorChanges)
    {
        CoinGroupInfo   &coinGroup = coinGroups[accUpdate.first];
        int  nMintsToForget = accUpdate.second.second;

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(accUpdate.first);
            // decrease pubcoin id for this denomination
            latestCoinIds[accUpdate.first.first]--;
        }
        else {
            // roll back lastBlock to previous position
            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->accumulatorChanges.count(accUpdate.first) == 0);
        }
    }

    // roll back mints
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int),vector<CBigNum>) &pubCoins, index->mintedPubCoins) {
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second) {
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
    BOOST_FOREACH(const CBigNum &serial, index->spentSerials) {
        usedCoinSerials.erase(serial);
    }
}

bool CZerocoinState::GetCoinGroupInfo(int denomination, int id, CoinGroupInfo &result) {
    pair<int,int>   key = make_pair(denomination, id);
    if (coinGroups.count(key) == 0)
        return false;

    result = coinGroups[key];
    return true;
}

bool CZerocoinState::IsUsedCoinSerial(const CBigNum &coinSerial) {
    return usedCoinSerials.count(coinSerial) != 0;
}

bool CZerocoinState::HasCoin(const CBigNum &pubCoin) {
    return mintedPubCoins.count(pubCoin) != 0;
}

int CZerocoinState::GetAccumulatorValueForSpend(CChain *chain, int maxHeight, int denomination, int id,
                                                CBigNum &accumulator, uint256 &blockHash, bool useModulusV2) {

    pair<int, int> denomAndId = pair<int, int>(denomination, id);

    if (coinGroups.count(denomAndId) == 0)
        return 0;

    CoinGroupInfo coinGroup = coinGroups[denomAndId];
    CBlockIndex *lastBlock = coinGroup.lastBlock;

    assert(lastBlock->accumulatorChanges.count(denomAndId) > 0);
    assert(coinGroup.firstBlock->accumulatorChanges.count(denomAndId) > 0);

    // is native modulus for denomination and id v2?
    bool nativeModulusIsV2 = IsZerocoinTxV2((libzerocoin::CoinDenomination)denomination, Params().GetConsensus(), id);
    // field in the block index structure for accesing accumulator changes
    decltype(&CBlockIndex::accumulatorChanges) accChangeField;
    if (nativeModulusIsV2 != useModulusV2) {
        CalculateAlternativeModulusAccumulatorValues(chain, denomination, id);
        accChangeField = &CBlockIndex::alternativeAccumulatorChanges;
    }
    else {
        accChangeField = &CBlockIndex::accumulatorChanges;
    }

    int numberOfCoins = 0;
    for (;;) {
        map<pair<int,int>, pair<CBigNum,int>> &accumulatorChanges = lastBlock->*accChangeField;
        if (accumulatorChanges.count(denomAndId) > 0) {
            if (lastBlock->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember accumulator value and block hash
                    accumulator = accumulatorChanges[denomAndId].first;
                    blockHash = lastBlock->GetBlockHash();
                }
                numberOfCoins += accumulatorChanges[denomAndId].second;
            }
        }

        if (lastBlock == coinGroup.firstBlock)
            break;
        else
            lastBlock = lastBlock->pprev;
    }

    return numberOfCoins;
}

libzerocoin::AccumulatorWitness CZerocoinState::GetWitnessForSpend(CChain *chain, int maxHeight, int denomination,
                                                                   int id, const CBigNum &pubCoin, bool useModulusV2) {

    libzerocoin::CoinDenomination d = (libzerocoin::CoinDenomination)denomination;
    pair<int, int> denomAndId = pair<int, int>(denomination, id);

    assert(coinGroups.count(denomAndId) > 0);

    CoinGroupInfo coinGroup = coinGroups[denomAndId];

    int coinId;
    int mintHeight = GetMintedCoinHeightAndId(pubCoin, denomination, coinId);

    assert(coinId == id);

    libzerocoin::Params *zcParams = useModulusV2 ? ZCParamsV2 : ZCParams;
    bool nativeModulusIsV2 = IsZerocoinTxV2((libzerocoin::CoinDenomination)denomination, Params().GetConsensus(), id);
    decltype(&CBlockIndex::accumulatorChanges) accChangeField;
    if (nativeModulusIsV2 != useModulusV2) {
        CalculateAlternativeModulusAccumulatorValues(chain, denomination, id);
        accChangeField = &CBlockIndex::alternativeAccumulatorChanges;
    }
    else {
        accChangeField = &CBlockIndex::accumulatorChanges;
    }

    // Find accumulator value preceding mint operation
    CBlockIndex *mintBlock = (*chain)[mintHeight];
    CBlockIndex *block = mintBlock;
    libzerocoin::Accumulator accumulator(zcParams, d);
    if (block != coinGroup.firstBlock) {
        do {
            block = block->pprev;
        } while ((block->*accChangeField).count(denomAndId) == 0);
        accumulator = libzerocoin::Accumulator(zcParams, (block->*accChangeField)[denomAndId].first, d);
    }

    // Now add to the accumulator every coin minted since that moment except pubCoin
    block = coinGroup.lastBlock;
    for (;;) {
        if (block->nHeight <= maxHeight && block->mintedPubCoins.count(denomAndId) > 0) {
            vector<CBigNum> &pubCoins = block->mintedPubCoins[denomAndId];
            for (const CBigNum &coin: pubCoins) {
                if (block != mintBlock || coin != pubCoin)
                    accumulator += libzerocoin::PublicCoin(zcParams, coin, d);
            }
        }
        if (block != mintBlock)
            block = block->pprev;
        else
            break;
    }

    return libzerocoin::AccumulatorWitness(zcParams, accumulator, libzerocoin::PublicCoin(zcParams, pubCoin, d));
}

int CZerocoinState::GetMintedCoinHeightAndId(const CBigNum &pubCoin, int denomination, int &id) {
    auto coins = mintedPubCoins.equal_range(pubCoin);
    auto coinIt = find_if(coins.first, coins.second,
                          [=](const decltype(mintedPubCoins)::value_type &v) { return v.second.denomination == denomination; });

    if (coinIt != coins.second) {
        id = coinIt->second.id;
        return coinIt->second.nHeight;
    }
    else
        return -1;
}

void CZerocoinState::CalculateAlternativeModulusAccumulatorValues(CChain *chain, int denomination, int id) {
    libzerocoin::CoinDenomination d = (libzerocoin::CoinDenomination)denomination;
    pair<int, int> denomAndId = pair<int, int>(denomination, id);
    libzerocoin::Params *altParams = IsZerocoinTxV2(d, Params().GetConsensus(), id) ? ZCParams : ZCParamsV2;
    libzerocoin::Accumulator accumulator(altParams, d);

    if (coinGroups.count(denomAndId) == 0) {
        // Can happen when verification is done prior to syncing with network
        return;
    }

    CoinGroupInfo coinGroup = coinGroups[denomAndId];

    CBlockIndex *block = coinGroup.firstBlock;
    for (;;) {
        if (block->accumulatorChanges.count(denomAndId) > 0) {
            if (block->alternativeAccumulatorChanges.count(denomAndId) > 0)
                // already calculated, update accumulator with cached value
                accumulator = libzerocoin::Accumulator(altParams, block->alternativeAccumulatorChanges[denomAndId].first, d);
            else {
                // re-create accumulator changes with alternative params
                assert(block->mintedPubCoins.count(denomAndId) > 0);
                const vector<CBigNum> &mintedCoins = block->mintedPubCoins[denomAndId];
                BOOST_FOREACH(const CBigNum &c, mintedCoins) {
                    accumulator += libzerocoin::PublicCoin(altParams, c, d);
                }
                block->alternativeAccumulatorChanges[denomAndId] = make_pair(accumulator.getValue(), (int)mintedCoins.size());
            }
        }

        if (block != coinGroup.lastBlock)
            block = (*chain)[block->nHeight+1];
        else
            break;
    }
}

bool CZerocoinState::TestValidity(CChain *chain) {
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), CoinGroupInfo) &coinGroup, coinGroups) {
        fprintf(stderr, "TestValidity[denomination=%d, id=%d]\n", coinGroup.first.first, coinGroup.first.second);

        bool fModulusV2 = IsZerocoinTxV2((libzerocoin::CoinDenomination)coinGroup.first.first, Params().GetConsensus(), coinGroup.first.second);
        libzerocoin::Params *zcParams = fModulusV2 ? ZCParamsV2 : ZCParams;

        libzerocoin::Accumulator acc(&zcParams->accumulatorParams, (libzerocoin::CoinDenomination)coinGroup.first.first);

        CBlockIndex *block = coinGroup.second.firstBlock;
        for (;;) {
            if (block->accumulatorChanges.count(coinGroup.first) > 0) {
                if (block->mintedPubCoins.count(coinGroup.first) == 0) {
                    fprintf(stderr, "  no minted coins\n");
                    return false;
                }

                BOOST_FOREACH(const CBigNum &pubCoin, block->mintedPubCoins[coinGroup.first]) {
                    acc += libzerocoin::PublicCoin(zcParams, pubCoin, (libzerocoin::CoinDenomination)coinGroup.first.first);
                }

                if (acc.getValue() != block->accumulatorChanges[coinGroup.first].first) {
                    fprintf (stderr, "  accumulator value mismatch at height %d\n", block->nHeight);
                    return false;
                }

                if (block->accumulatorChanges[coinGroup.first].second != (int)block->mintedPubCoins[coinGroup.first].size()) {
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

    return true;
}

set<CBlockIndex *> CZerocoinState::RecalculateAccumulators(CChain *chain) {
    set<CBlockIndex *> changes;

    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), CoinGroupInfo) &coinGroup, coinGroups) {
        // Skip non-modulusv2 groups
        if (!IsZerocoinTxV2((libzerocoin::CoinDenomination)coinGroup.first.first, Params().GetConsensus(), coinGroup.first.second))
            continue;

        libzerocoin::Accumulator acc(&ZCParamsV2->accumulatorParams, (libzerocoin::CoinDenomination)coinGroup.first.first);

        // Try to calculate accumulator for the first batch of mints. If it doesn't match we need to recalculate the rest of it
        CBlockIndex *block = coinGroup.second.firstBlock;
        for (;;) {
            if (block->accumulatorChanges.count(coinGroup.first) > 0) {
                BOOST_FOREACH(const CBigNum &pubCoin, block->mintedPubCoins[coinGroup.first]) {
                    acc += libzerocoin::PublicCoin(ZCParamsV2, pubCoin, (libzerocoin::CoinDenomination)coinGroup.first.first);
                }

                // First block case is special: do the check
                if (block == coinGroup.second.firstBlock) {
                    if (acc.getValue() != block->accumulatorChanges[coinGroup.first].first)
                        // recalculation is needed
                        LogPrintf("ZerocoinState: accumulator recalculation for denomination=%d, id=%d\n", coinGroup.first.first, coinGroup.first.second);
                    else
                        // everything's ok
                        break;
                }

                block->accumulatorChanges[coinGroup.first] = make_pair(acc.getValue(), (int)block->mintedPubCoins[coinGroup.first].size());
                changes.insert(block);
            }

            if (block != coinGroup.second.lastBlock)
                block = (*chain)[block->nHeight+1];
            else
                break;
        }
    }

    return changes;
}

bool CZerocoinState::AddSpendToMempool(const vector<CBigNum> &coinSerials, uint256 txHash) {
    BOOST_FOREACH(CBigNum coinSerial, coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
            return false;

        mempoolCoinSerials[coinSerial] = txHash;        
    }

    return true;
}

bool CZerocoinState::AddSpendToMempool(const CBigNum &coinSerial, uint256 txHash) {
    if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
        return false;

    mempoolCoinSerials[coinSerial] = txHash;
    return true;
}

void CZerocoinState::RemoveSpendFromMempool(const CBigNum &coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

uint256 CZerocoinState::GetMempoolConflictingTxHash(const CBigNum &coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CZerocoinState::CanAddSpendToMempool(const CBigNum &coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

void CZerocoinState::Reset() {
    coinGroups.clear();
    usedCoinSerials.clear();
    mintedPubCoins.clear();
    latestCoinIds.clear();
    mempoolCoinSerials.clear();
}

CZerocoinState *CZerocoinState::GetZerocoinState() {
    return &zerocoinState;
}

