#include "main.h"
#include "zerocoin.h"
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>

using namespace std;

#define ZEROCOIN_MODULUS   "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"

// Settings
int64_t nTransactionFee = 0;
int64_t nMinimumInputValue = DUST_HARD_LIMIT;

// btzc: add zerocoin init
// zerocoin init
static CBigNum bnTrustedModulus;
bool setParams = bnTrustedModulus.SetHexBool(ZEROCOIN_MODULUS);

// Set up the Zerocoin Params object
uint32_t securityLevel = 80;
static libzerocoin::Params *ZCParams = new libzerocoin::Params(bnTrustedModulus);

static CZerocoinState zerocoinState;

bool CheckSpendZcoinTransaction(const CTransaction &tx,
                                libzerocoin::CoinDenomination targetDenomination,
                                CValidationState &state,
                                uint256 hashTx,
                                bool isVerifyDB,
                                int nHeight,
                                bool isCheckWallet,
                                CZerocoinTxInfo *zerocoinTxInfo) {

    // Check for inputs only, everything else was checked before
	LogPrintf("CheckSpendZcoinTransaction denomination=%d nHeight=%d\n", targetDenomination, nHeight);

	BOOST_FOREACH(const CTxIn &txin, tx.vin)
	{
        if (!txin.scriptSig.IsZerocoinSpend())
            continue;

        uint32_t pubcoinId = txin.nSequence;
        if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
             // coin id should be positive integer
            return state.DoS(100,
                false,
                NSEQUENCE_INCORRECT,
                "CTransaction::CheckTransaction() : Error: zerocoin spend nSequence is incorrect");
        }

        if (txin.scriptSig.size() < 4)
            return state.DoS(100,
                             false,
                             REJECT_MALFORMED,
                             "CheckSpendZcoinTransaction: invalid spend transaction");

        // Deserialize the CoinSpend intro a fresh object
        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                        (const char *)&*txin.scriptSig.end(),
                                        SER_NETWORK, PROTOCOL_VERSION);
        libzerocoin::CoinSpend newSpend(ZCParams, serializedCoinSpend);

        if (((targetDenomination == libzerocoin::ZQ_LOVELACE) && (pubcoinId >= ZC_V2_SWITCH_ID_1))
                || ((targetDenomination == libzerocoin::ZQ_GOLDWASSER) && (pubcoinId >= ZC_V2_SWITCH_ID_10))
                || ((targetDenomination == libzerocoin::ZQ_RACKOFF) && (pubcoinId >= ZC_V2_SWITCH_ID_25))
                || ((targetDenomination == libzerocoin::ZQ_PEDERSEN) && (pubcoinId >= ZC_V2_SWITCH_ID_50))
                || ((targetDenomination == libzerocoin::ZQ_WILLIAMSON) && (pubcoinId >= ZC_V2_SWITCH_ID_100))) {
            newSpend.setVersion(2);
        }

        // Create a new metadata object to contain the hash of the received
        // ZEROCOIN_SPEND transaction. If we were a real client we'd actually
        // compute the hash of the received transaction here.
        libzerocoin::SpendMetaData newMetadata(0, uint256());
        if ((pubcoinId > 0) && (((targetDenomination == libzerocoin::ZQ_LOVELACE) && (pubcoinId >= ZC_V2_SWITCH_ID_1))
                || ((targetDenomination == libzerocoin::ZQ_GOLDWASSER) && (pubcoinId >= ZC_V2_SWITCH_ID_10))
                || ((targetDenomination == libzerocoin::ZQ_RACKOFF) && (pubcoinId >= ZC_V2_SWITCH_ID_25))
                || ((targetDenomination == libzerocoin::ZQ_PEDERSEN) && (pubcoinId >= ZC_V2_SWITCH_ID_50))
                || ((targetDenomination == libzerocoin::ZQ_WILLIAMSON) && (pubcoinId >= ZC_V2_SWITCH_ID_100)))) {
            newMetadata.accumulatorId = txin.nSequence;
            newMetadata.txHash = tx.GetNormalizedHash();
        }

        CZerocoinState::CoinGroupInfo coinGroup;
        if (!zerocoinState.GetCoinGroupInfo(targetDenomination, pubcoinId, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN, "CheckSpendZcoinTransaction: Error: no coins were minted with such parameters");

        bool passVerify = false;
        CBlockIndex *index = coinGroup.lastBlock;
        pair<int,int> denominationAndId = make_pair(targetDenomination, pubcoinId);

        // Enumerate all the accumulator changes seen in the blockchain starting with the latest block
        // In most cases the latest accumulator value will be used for verification
        do {
            if (index->accumulatorChanges.count(denominationAndId) > 0) {
                libzerocoin::Accumulator accumulator(ZCParams,
                                                     index->accumulatorChanges[denominationAndId].first,
                                                     targetDenomination);
                LogPrintf("CheckSpendZcoinTransaction: accumulator=%s\n", accumulator.getValue().ToString().substr(0,15));
                passVerify = newSpend.Verify(accumulator, newMetadata);
            }

            if (index == coinGroup.firstBlock)
                break;
            else
                index = index->pprev;
        } while (!passVerify);

        // Rare case: accumulator value contains some but NOT ALL coins from one block. In this case we will
        // have to enumerate over coins manually. No optimization is really needed here because it's a rarity
        if (!passVerify) {
            // Build vector of coins sorted by the time of mint
            index = coinGroup.lastBlock;
            vector<CBigNum> pubCoins = index->mintedPubCoins[denominationAndId];
            do {
                index = index->pprev;
                if (index->mintedPubCoins.count(denominationAndId) > 0)
                    pubCoins.insert(pubCoins.begin(),
                                    index->mintedPubCoins[denominationAndId].cbegin(),
                                    index->mintedPubCoins[denominationAndId].cend());
            } while (index != coinGroup.firstBlock);

            libzerocoin::Accumulator accumulator(ZCParams, targetDenomination);
            BOOST_FOREACH(const CBigNum &pubCoin, pubCoins) {
                accumulator += libzerocoin::PublicCoin(ZCParams, pubCoin, (libzerocoin::CoinDenomination)targetDenomination);
                LogPrintf("CheckSpendZcoinTransaction: accumulator=%s\n", accumulator.getValue().ToString().substr(0,15));
                if ((passVerify = newSpend.Verify(accumulator, newMetadata)) == true)
                    break;
            }

            if (!passVerify) {
                // One more time now in reverse direction. The only reason why it's required is compatibility with
                // previous client versions
                libzerocoin::Accumulator accumulator(ZCParams, targetDenomination);
                BOOST_REVERSE_FOREACH(const CBigNum &pubCoin, pubCoins) {
                    accumulator += libzerocoin::PublicCoin(ZCParams, pubCoin, (libzerocoin::CoinDenomination)targetDenomination);
                    LogPrintf("CheckSpendZcoinTransaction: accumulatorRev=%s\n", accumulator.getValue().ToString().substr(0,15));
                    if ((passVerify = newSpend.Verify(accumulator, newMetadata)) == true)
                        break;
                }
            }
        }


        if (passVerify) {
            // Pull the serial number out of the CoinSpend object. If we
            // were a real Zerocoin client we would now check that the serial number
            // has not been spent before (in another ZEROCOIN_SPEND) transaction.
            // The serial number is stored as a Bignum.
            if(!isVerifyDB && !isCheckWallet) {
                CBigNum serial = newSpend.getCoinSerialNumber();
                if (nHeight > ZC_CHECK_BUG_FIXED_AT_BLOCK &&
                        // do not check for duplicates in case we've seen exact copy of this tx in this block before
                        !(zerocoinTxInfo &&
                            zerocoinTxInfo->zcTransactions.count(hashTx) > 0) &&
                        // check for used serials both in zerocoinState and in other transactions of this block
                        (zerocoinState.IsUsedCoinSerial(serial) ||
                            // check for zerocoin transaction in the same block as well
                            (zerocoinTxInfo &&
                                !zerocoinTxInfo->fInfoIsComplete &&
                                zerocoinTxInfo->spentSerials.count(serial) > 0)))
                    return state.DoS(0, error("CTransaction::CheckTransaction() : The CoinSpend serial has been used"));

                if (zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete) {
                    // add spend information to the index
                    zerocoinTxInfo->spentSerials.insert(serial);
                    zerocoinTxInfo->zcTransactions.insert(hashTx);
                }
            }
        }
        else {
            LogPrintf("CheckSpendZCoinTransaction: verification failed at block %d\n", nHeight);
            return false;
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
        libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, denomination);
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

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet) {
	//BTZC: add ZCOIN code
	// Check for founders inputs
	if((nHeight > ZC_CHECK_BUG_FIXED_AT_BLOCK) && (nHeight < 210000)) {
		bool found_1 = false;
		bool found_2 = false;
		bool found_3 = false;
		bool found_4 = false;
		bool found_5 = false;

		CScript FOUNDER_1_SCRIPT;
		CScript FOUNDER_2_SCRIPT;
		CScript FOUNDER_3_SCRIPT;
		CScript FOUNDER_4_SCRIPT;
		CScript FOUNDER_5_SCRIPT;

		if (!fTestNet && GetAdjustedTime() > nStartRewardTime) {
			FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("aCAgTPgtYcA4EysU4UKC86EQd5cTtHtCcr").Get());
			if (nHeight < 14000) {
				FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aLrg41sXbXZc5MyEj7dts8upZKSAtJmRDR").Get());
			}
			else {
				FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("aHu897ivzmeFuLNB6956X6gyGeVNHUBRgD").Get());
			}
			FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN").Get());
			FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1HwTdCmQV3NspP2QqCGpehoFpi8NY4Zg3").Get());
			FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U").Get());
		}
		else if (!fTestNet && GetAdjustedTime() <= nStartRewardTime) {
			return state.DoS(100,
				false,
				REJECT_TRANSACTION_TOO_EARLY,
				"CTransaction::CheckTransaction() : transaction is too early");
		}
		else {
			FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TCE4hvs2UTDjYriey7R9qBkbvUAYxWmZni").Get());
			FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("TPyA7d3fribqxXm9uJU61S76Lzuj7F8jLz").Get());
			FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TXatvpS15EvejVuJVC2rgD73rSaQz8JiX6").Get());
			FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TJMpFjtDi8s5AM3GyW41QshH2NNmKgrGNq").Get());
			FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TTtLk1iapn8QebamQcb8GEh1MNq8agYcVk").Get());
		}

		BOOST_FOREACH(const CTxOut &output, tx.vout) {
			if (output.scriptPubKey == FOUNDER_1_SCRIPT && output.nValue == (int64_t)(2 * COIN)) {
				found_1 = true;
			}
			if (output.scriptPubKey == FOUNDER_2_SCRIPT && output.nValue == (int64_t)(2 * COIN)) {
				found_2 = true;
			}
			if (output.scriptPubKey == FOUNDER_3_SCRIPT && output.nValue == (int64_t)(2 * COIN)) {
				found_3 = true;
			}
			if (output.scriptPubKey == FOUNDER_4_SCRIPT && output.nValue == (int64_t)(2 * COIN)) {
				found_4 = true;
			}
			if (output.scriptPubKey == FOUNDER_5_SCRIPT && output.nValue == (int64_t)(2 * COIN)) {
				found_5 = true;
			}
		}

		if (!(found_1 && found_2 && found_3 && found_4 && found_5)) {
			return state.DoS(100,
				false,
				REJECT_FOUNDER_REWARD_MISSING,
				"CTransaction::CheckTransaction() : founders reward missing");
		}
	}
	return true;
}

bool CheckZerocoinTransaction(const CTransaction &tx,
                              CValidationState &state,
                              uint256 hashTx,
                              bool isVerifyDB,
                              int nHeight,
                              bool isCheckWallet,
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
	if(tx.IsZerocoinSpend()) {
		// Check vOut
		// Only one loop, we checked on the format before enter this case
		BOOST_FOREACH(const CTxOut &txout, tx.vout)
		{
			if (!isVerifyDB) {
                switch (txout.nValue) {
                case libzerocoin::ZQ_LOVELACE*COIN:
                case libzerocoin::ZQ_GOLDWASSER*COIN:
                case libzerocoin::ZQ_RACKOFF*COIN:
                case libzerocoin::ZQ_PEDERSEN*COIN:
                case libzerocoin::ZQ_WILLIAMSON*COIN:
                    if(!CheckSpendZcoinTransaction(tx, (libzerocoin::CoinDenomination)(txout.nValue / COIN), state, hashTx, isVerifyDB, nHeight, isCheckWallet, zerocoinTxInfo))
                        return false;
                    break;

                default:
                    return state.DoS(100, error("CheckZerocoinTransaction : invalid spending txout value"));
                }
			}
		}
	}
	
	return true;
}

void DisconnectTipZC(CBlock & /*block*/, CBlockIndex *pindexDelete) {
    zerocoinState.RemoveBlock(pindexDelete);

    // TODO: notify the wallet
}


/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectTipZC(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock) {

    // Add zerocoin transaction information to index
    if (pblock && pblock->zerocoinTxInfo) {
        pindexNew->spentSerials = pblock->zerocoinTxInfo->spentSerials;

        // Update minted values and accumulators
        BOOST_FOREACH(const PAIRTYPE(int,CBigNum) &mint, pblock->zerocoinTxInfo->mints) {
            int denomination = mint.first;
            CBigNum oldAccValue = ZCParams->accumulatorParams.accumulatorBase;
            int mintId = zerocoinState.AddMint(pindexNew, denomination, mint.second, oldAccValue);
            pair<int,int> denomAndId = make_pair(denomination, mintId);

            pindexNew->mintedPubCoins[denomAndId].push_back(mint.second);

            CZerocoinState::CoinGroupInfo coinGroupInfo;
            zerocoinState.GetCoinGroupInfo(denomination, mintId, coinGroupInfo);

            libzerocoin::PublicCoin pubCoin(ZCParams, mint.second, (libzerocoin::CoinDenomination)denomination);
            libzerocoin::Accumulator accumulator(ZCParams,
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
        }
    }
    else {
        zerocoinState.AddBlock(pindexNew);
    }

    // TODO: notify the wallet
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


bool ZerocoinBuildStateFromIndex(CChain *chain) {
    zerocoinState.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
        zerocoinState.AddBlock(blockIndex);
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

    int     mintId = 1;

    if (latestCoinIds[denomination] < 1)
        latestCoinIds[denomination] = mintId;
    else
        mintId = latestCoinIds[denomination];

    // There is a limit of 10 coins per group but mints belonging to the same block must have the same id thus going
    // beyond 10
    CoinGroupInfo &coinGroup = coinGroups[make_pair(denomination, mintId)];
    if (coinGroup.nCoins < 10 || coinGroup.lastBlock == index) {
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

    mintedPubCoins.insert(pubCoin);

    return mintId;
}

void CZerocoinState::AddSpend(const CBigNum &serial) {
    usedCoinSerials.insert(serial);
}

void CZerocoinState::AddBlock(CBlockIndex *index) {
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
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second)
            mintedPubCoins.insert(coin);
    }

    BOOST_FOREACH(const CBigNum &serial, index->spentSerials) {
        usedCoinSerials.insert(serial);
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
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second)
            mintedPubCoins.erase(coin);
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

void CZerocoinState::Reset() {
    coinGroups.clear();
    usedCoinSerials.clear();
    mintedPubCoins.clear();
    latestCoinIds.clear();
}
