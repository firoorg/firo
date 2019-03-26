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
#include "sigma/coinspend.h"
#include "sigma/coin.h"
#include "znode-payments.h"
#include "znode-sync.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>

#include <ios>

using namespace std;

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
		const vector<sigma::CoinDenominationV3>& targetDenominations,
		CValidationState &state,
		uint256 hashTx,
		bool isVerifyDB,
		int nHeight,
		bool isCheckWallet,
		CZerocoinTxInfoV3 *zerocoinTxInfoV3) {
	int txHeight = chainActive.Height();
	bool hasZerocoinSpendInputs = false, hasNonZerocoinInputs = false;
	int vinIndex = -1;

	BOOST_FOREACH(const CTxIn &txin, tx.vin)
	{
		vinIndex++;
		if (txin.scriptSig.IsZerocoinSpendV3())
			hasZerocoinSpendInputs = true;
		else
			hasNonZerocoinInputs = true;

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
					"CheckSpendZcoinTransactionV3: invalid spend transaction");

		// Deserialize the CoinSpend into a fresh object
        // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
        // OP_ZEROCOINSPENDV3 is written. In zerocoin you will see +4 instead,
        // because the size of serialized spend is also written, probably in 3 bytes.
		CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
				(const char *)&*txin.scriptSig.end(),
				SER_NETWORK, PROTOCOL_VERSION);
		sigma::CoinSpendV3 newSpend(ZCParamsV3, serializedCoinSpend);

		if (newSpend.getVersion() != ZEROCOIN_TX_VERSION_3) {
			return state.DoS(100,
							 false,
							 NSEQUENCE_INCORRECT,
							 "CTransaction::CheckTransaction() : Error: incorrect spend transaction verion");
		}

		uint256 txHashForMetadata;

		// Obtain the hash of the transaction sans the zerocoin part
		CMutableTransaction txTemp = tx;
		BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
			if (txTempIn.scriptSig.IsZerocoinSpendV3()) {
				txTempIn.scriptSig.clear();
				txTempIn.prevout.SetNull();
			}
		}
		txHashForMetadata = txTemp.GetHash();

		LogPrintf("CheckSpendZcoinTransactionV3: tx version=%d, tx metadata hash=%s, serial=%s\n",
				newSpend.getVersion(), txHashForMetadata.ToString(),
				newSpend.getCoinSerialNumber().tostring());

		CZerocoinStateV3::CoinGroupInfoV3 coinGroup;
		if (!zerocoinStateV3.GetCoinGroupInfo(targetDenominations[vinIndex], pubcoinId, coinGroup))
			return state.DoS(100, false, NO_MINT_ZEROCOIN,
					"CheckSpendZcoinTransactionV3: Error: no coins were minted with such parameters");

		bool passVerify = false;
		CBlockIndex *index = coinGroup.lastBlock;
		pair<sigma::CoinDenominationV3, int> denominationAndId = std::make_pair(
            targetDenominations[vinIndex], pubcoinId);

		uint256 accumulatorBlockHash = newSpend.getAccumulatorBlockHash();

        // We use incomplete transaction hash as metadata.
        sigma::SpendMetaDataV3 newMetaData(
            txin.nSequence,
            accumulatorBlockHash,
            txHashForMetadata);

		// find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
		while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
			index = index->pprev;

		// Build a vector with all the public coins with given denomination and accumulator id before
		// the block on which the spend occured.
		// This list of public coins is required by function "Verify" of CoinSpendV3.
		std::vector<PublicCoinV3> anonymity_set;
        while(true) {
			BOOST_FOREACH(const sigma::PublicCoinV3& pubCoinValue,
					index->mintedPubCoinsV3[denominationAndId]) {
				anonymity_set.push_back(pubCoinValue);
			}
            if (index == coinGroup.firstBlock)
                break;
			index = index->pprev;
        }

		passVerify = newSpend.Verify(anonymity_set, newMetaData);
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

	if (hasZerocoinSpendInputs) {
		if (hasNonZerocoinInputs) {
			// mixing zerocoin spend input with non-zerocoin inputs is prohibited
			return state.DoS(100, false,
							 REJECT_MALFORMED,
							 "CheckSpendZcoinTransaction: can't mix zerocoin spend input with regular ones");
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

	if (txout.scriptPubKey.size() < 4)
		return state.DoS(100,
				false,
				PUBCOIN_NOT_VALIDATE,
				"CTransaction::CheckTransactionV3() : PubCoin validation failed");

    // If you wonder why +1, go to file wallet.cpp and read the comments in function
    // CWallet::CreateZerocoinMintModelV3 around "scriptSerializedCoin << OP_ZEROCOINMINTV3";
	vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
	secp_primitives::GroupElement pubCoinValue;
	pubCoinValue.deserialize(&coin_serialised[0]);

	sigma::CoinDenominationV3 denomination;
    if (!IntegerToDenomination(txout.nValue, denomination, state)) {
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CTransaction::CheckTransactionV3() : "
                "PubCoin validation failed, unknown denomination");
    }
	PublicCoinV3 pubCoin(pubCoinValue, denomination);
	bool hasCoin = zerocoinStateV3.HasCoin(pubCoin);

	if (!hasCoin && zerocoinTxInfoV3 && !zerocoinTxInfoV3->fInfoIsComplete) {
		BOOST_FOREACH(const PublicCoinV3& mint, zerocoinTxInfoV3->mints) {
			if (mint == pubCoin) {
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

    if (!pubCoin.validate())
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckZerocoinTransaction : PubCoin validation failed");

    if (zerocoinTxInfoV3 != NULL && !zerocoinTxInfoV3->fInfoIsComplete) {
        // Update public coin list in the info
        zerocoinTxInfoV3->mints.push_back(pubCoin);
        zerocoinTxInfoV3->zcTransactions.insert(hashTx);
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
		if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMintV3()) {
			if (!CheckMintZcoinTransactionV3(txout, state, hashTx, zerocoinTxInfoV3))
				return false;
		}
	}

	// Check Spend Zerocoin Transaction
	if(tx.IsZerocoinSpendV3()) {
		// First check number of inputs does not exceed transaction limit
		if(tx.vin.size() > ZC_SPEND_LIMIT){
			return false;
		}
		vector<sigma::CoinDenominationV3> denominations;
		uint64_t totalValue = 0;
		BOOST_FOREACH(const CTxIn &txin, tx.vin){
			if(!txin.scriptSig.IsZerocoinSpendV3()) {
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

			CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
											(const char *)&*txin.scriptSig.end(),
											SER_NETWORK, PROTOCOL_VERSION);
			sigma::CoinSpendV3 newSpend(ZCParamsV3, serializedCoinSpend);
			uint64_t denom = newSpend.getIntDenomination();
			totalValue += denom;
			sigma::CoinDenominationV3 denomination;
			if (!IntegerToDenomination(denom, denomination, state))
				return false;
			denominations.push_back(denomination);
		}

		// Check vOut
		// Only one loop, we checked on the format before entering this case
		if (!isVerifyDB) {
			BOOST_FOREACH(const CTxOut &txout, tx.vout)
			{
				if (!CheckSpendZcoinTransactionV3(
					tx, denominations, state, hashTx, isVerifyDB, nHeight,
					isCheckWallet, zerocoinTxInfoV3)) {
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

Scalar ZerocoinGetSpendSerialNumberV3(const CTransaction &tx, const CTxIn &txin) {
	if (!tx.IsZerocoinSpendV3())
		return Scalar(uint64_t(0));

	try {
        // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
        // OP_ZEROCOINSPENDV3 is written. In zerocoin you will see +4 instead,
        // because the size of serialized spend is also written, probably in 3 bytes.
		CDataStream serializedCoinSpend(
				(const char *)&*(txin.scriptSig.begin() + 1),
				(const char *)&*txin.scriptSig.end(),
				SER_NETWORK, PROTOCOL_VERSION);
		sigma::CoinSpendV3 spend(ZCParamsV3, serializedCoinSpend);
		return spend.getCoinSerialNumber();
	}
	catch (const std::ios_base::failure &) {
		return Scalar(uint64_t(0));
	}
}

CAmount GetSpendTransactionInputV3(const CTransaction &tx) {
	if (!tx.IsZerocoinSpendV3())
		return CAmount(0);

	try {
		CAmount sum(0);
		BOOST_FOREACH(const CTxIn& txin, tx.vin){
			// NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
			// OP_ZEROCOINSPENDV3 is written. In zerocoin you will see +4 instead,
			// because the size of serialized spend is also written, probably in 3 bytes.
			CDataStream serializedCoinSpend(
					(const char *)&*(txin.scriptSig.begin() + 1),
					(const char *)&*txin.scriptSig.end(),
					SER_NETWORK, PROTOCOL_VERSION);
			sigma::CoinSpendV3 spend(ZCParamsV3, serializedCoinSpend);
			sum += spend.getIntDenomination();
		}
		return sum;
	}
	catch (const std::runtime_error &) {
		return CAmount(0);
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
        // Martun: Commented out the next code, uncomment if we decide to stop zerocoin V2 spends
        // after some point in time. The current decision is to allow them forever.
		// Also don't allow spend v2s after some other point in time.
		//if (pblock->zerocoinTxInfoV3->fHasSpendV2) {
		//	int allowV2Height = Params().nSpendV2StartBlock;
		//	if (pindexNew->nHeight >= allowV2Height + ZC_V2_GRACEFUL_PERIOD) {
		//		LogPrintf("ConnectTipZC: spend v2 is not allowed after block %d\n", allowV2Height);
		//		return false;
		//	}
		//}

		if (!fJustCheck)
			pindexNew->spentSerialsV3.clear();

		BOOST_FOREACH(auto& serial, pblock->zerocoinTxInfoV3->spentSerials) {
			if (!CheckZerocoinSpendSerialV3(
					state,
					pblock->zerocoinTxInfoV3.get(),
					serial.first,
					pindexNew->nHeight,
					true /* fConnectTip */
					)) {
				return false;
            }

			if (!fJustCheck) {
				pindexNew->spentSerialsV3.insert(serial.first);
				zerocoinStateV3.AddSpend(serial.first);
			}
		}
        // Shows if V3 sigma mints are now allowed.
        bool V3MintsAllowed = (pindexNew->nHeight >= Params().nMintV3SigmaStartBlock);

        // If V3 mints are not allowed in this block, but some client tries to mint.
        if (!V3MintsAllowed && !pblock->zerocoinTxInfoV3->mints.empty())
		    return state.DoS(0, error("ConnectBlockZCV3 : V3 sigma mints not allowed until a given block"));
		if (fJustCheck)
			return true;

		// Update pindexNew.mintedPubCoinsV3
		BOOST_FOREACH(const PublicCoinV3& mint, pblock->zerocoinTxInfoV3->mints) {
			CoinDenominationV3 denomination = mint.getDenomination();
			int mintId = zerocoinStateV3.AddMint(pindexNew,	mint);

			LogPrintf("ConnectTipZC: mint added denomination=%d, id=%d\n", denomination, mintId);
			pair<CoinDenominationV3, int> denomAndId = make_pair(denomination, mintId);
			pindexNew->mintedPubCoinsV3[denomAndId].push_back(mint);
		}
	}
	else if (!fJustCheck) { // TODO(martun): not sure if this else is necessary here. Check again later.
		zerocoinStateV3.AddBlock(pindexNew);
	}
	return true;
}


bool ZerocoinBuildStateFromIndexV3(CChain *chain) {
	zerocoinStateV3.Reset();
	for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
		zerocoinStateV3.AddBlock(blockIndex);
    }
	// DEBUG
	LogPrintf(
        "Latest IDs for sigma coin groups are %d, %d, %d, %d, %d\n",
		zerocoinStateV3.GetLatestCoinID(CoinDenominationV3::SIGMA_DENOM_0_1),
		zerocoinStateV3.GetLatestCoinID(CoinDenominationV3::SIGMA_DENOM_0_5),
		zerocoinStateV3.GetLatestCoinID(CoinDenominationV3::SIGMA_DENOM_1),
		zerocoinStateV3.GetLatestCoinID(CoinDenominationV3::SIGMA_DENOM_10),
		zerocoinStateV3.GetLatestCoinID(CoinDenominationV3::SIGMA_DENOM_100));
	return true;
}

// CZerocoinTxInfoV3

void CZerocoinTxInfoV3::Complete() {
	// We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
	// works, we need to stick to it. Denomination doesn't matter but we will sort by it as well
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

// CZerocoinStateV3

CZerocoinStateV3::CZerocoinStateV3() {
}

int CZerocoinStateV3::AddMint(
		CBlockIndex *index,
		const PublicCoinV3 &pubCoin) {
	sigma::CoinDenominationV3 denomination = pubCoin.getDenomination();

	if (latestCoinIds[denomination] < 1)
		latestCoinIds[denomination] = 1;
    int	mintCoinGroupId = latestCoinIds[denomination];

    // ZC_SPEND_V3_COINSPERID = 15.000, yet the actual limit of coins per accumlator is 16.000.
    // We need to cut at 15.000, such that we always have enough space for new mints. Mints for
    // each block will end up in the same accumulator.
	CoinGroupInfoV3 &coinGroup = coinGroups[make_pair(denomination, mintCoinGroupId)];
	int coinsPerId = ZC_SPEND_V3_COINSPERID;
	if (coinGroup.nCoins < coinsPerId // there's still space in the accumulator
        || coinGroup.lastBlock == index // or we have already placed some coins from current block.
        ) {
		if (coinGroup.nCoins++ == 0) {
			// first group of coins for given denomination
			coinGroup.firstBlock = coinGroup.lastBlock = index;
		}
		else {
			coinGroup.lastBlock = index;
		}
	}
	else {
		latestCoinIds[denomination] = ++mintCoinGroupId;
		CoinGroupInfoV3& newCoinGroup = coinGroups[std::make_pair(denomination, mintCoinGroupId)];
		newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
		newCoinGroup.nCoins = 1;
	}
	CMintedCoinInfo coinInfo;
	coinInfo.denomination = denomination;
	coinInfo.id = mintCoinGroupId;
	coinInfo.nHeight = index->nHeight;
	mintedPubCoins.insert(std::make_pair(pubCoin, coinInfo));
	return mintCoinGroupId;
}

void CZerocoinStateV3::AddSpend(const Scalar &serial) {
	usedCoinSerials.insert(serial);
}

void CZerocoinStateV3::AddBlock(CBlockIndex *index) {
	BOOST_FOREACH(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenominationV3, int), vector<PublicCoinV3>) &pubCoins,
            index->mintedPubCoinsV3) {
        if (!pubCoins.second.empty()) {
			CoinGroupInfoV3& coinGroup = coinGroups[pubCoins.first];

			if (coinGroup.firstBlock == NULL)
				coinGroup.firstBlock = index;
			coinGroup.lastBlock = index;
			coinGroup.nCoins += pubCoins.second.size();
		}

		latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
		BOOST_FOREACH(const PublicCoinV3 &coin, pubCoins.second) {
			CMintedCoinInfo coinInfo;
			coinInfo.denomination = pubCoins.first.first;
			coinInfo.id = pubCoins.first.second;
			coinInfo.nHeight = index->nHeight;
			mintedPubCoins.insert(pair<PublicCoinV3, CMintedCoinInfo>(coin, coinInfo));
		}
	}

	BOOST_FOREACH(const Scalar &serial, index->spentSerialsV3) {
		usedCoinSerials.insert(serial);
	}
}

void CZerocoinStateV3::RemoveBlock(CBlockIndex *index) {
	// roll back accumulator updates
	BOOST_FOREACH(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenominationV3, int),vector<PublicCoinV3>) &coin,
        index->mintedPubCoinsV3)
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

	// roll back mints
	BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(CoinDenominationV3, int),vector<PublicCoinV3>) &pubCoins,
                  index->mintedPubCoinsV3) {
		BOOST_FOREACH(const PublicCoinV3 &coin, pubCoins.second) {
			auto coins = mintedPubCoins.equal_range(coin);
			auto coinIt = find_if(
                coins.first, coins.second,
                [=](const decltype(mintedPubCoins)::value_type &v) {
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

bool CZerocoinStateV3::GetCoinGroupInfo(
        sigma::CoinDenominationV3 denomination,
        int group_id,
        CoinGroupInfoV3& result) {
	std::pair<sigma::CoinDenominationV3, int> key =
        std::make_pair(denomination, group_id);
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
		sigma::CoinDenominationV3 denomination,
		int coinGroupID,
		uint256& blockHash_out,
		std::vector<PublicCoinV3>& coins_out) {

	pair<sigma::CoinDenominationV3, int> denomAndId = std::make_pair(denomination, coinGroupID);

	if (coinGroups.count(denomAndId) == 0)
		return 0;

	CoinGroupInfoV3 coinGroup = coinGroups[denomAndId];

	int numberOfCoins = 0;
	for (CBlockIndex *block = coinGroup.lastBlock;
			;
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
        if (block == coinGroup.firstBlock) {
            break ;
        }
	}
	return numberOfCoins;
}

std::pair<int, int> CZerocoinStateV3::GetMintedCoinHeightAndId(
		const PublicCoinV3& pubCoin) {
	auto coinIt = mintedPubCoins.find(pubCoin);

	if (coinIt != mintedPubCoins.end()) {
		return std::make_pair(coinIt->second.nHeight, coinIt->second.id);
	}
    return std::make_pair(-1, -1);
}

bool CZerocoinStateV3::AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash) {
    BOOST_FOREACH(Scalar coinSerial, coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
            return false;

        mempoolCoinSerials[coinSerial] = txHash;
    }

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
	usedCoinSerials.clear();
	latestCoinIds.clear();
	mintedPubCoins.clear();
	mempoolCoinSerials.clear();
}

CZerocoinStateV3* CZerocoinStateV3::GetZerocoinState() {
	return &zerocoinStateV3;
}

int CZerocoinStateV3::GetLatestCoinID(sigma::CoinDenominationV3 denomination) const {
    auto iter = latestCoinIds.find(denomination);
    if (iter == latestCoinIds.end()) {
        // Do not throw here, if there was no sigma mint, that's fine.
        return 0;
    }
    return iter->second;
}
