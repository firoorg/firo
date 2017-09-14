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

bool CheckSpendZcoinTransaction(const CTransaction &tx, CZerocoinEntry pubCoinTx, list <CZerocoinEntry> listPubCoin, libzerocoin::CoinDenomination targetDenomination, CValidationState &state, uint256 hashTx, bool isVerifyDB, int nHeight, bool isCheckWallet) {
    // Check vOut
    // Only one loop, we checked on the format before enter this case
    // Check vIn
	CWalletDB walletdb(pwalletMain->strWalletFile);
	LogPrintf("CheckSpendZcoinTransaction denomination=%d nHeight=%d\n", targetDenomination, nHeight);
	BOOST_FOREACH(const CTxIn &txin, tx.vin)
	{
		if (txin.scriptSig.IsZerocoinSpend()) {
		    // Deserialize the CoinSpend intro a fresh object
			std::vector<char, zero_after_free_allocator<char> > dataTxIn;
			dataTxIn.insert(dataTxIn.end(), txin.scriptSig.begin() + 4, txin.scriptSig.end());
			CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
			serializedCoinSpend.vch = dataTxIn;
			libzerocoin::CoinSpend newSpend(ZCParams, serializedCoinSpend);
			// Create a new metadata object to contain the hash of the received
			// ZEROCOIN_SPEND transaction. If we were a real client we'd actually
			// compute the hash of the received transaction here.
			libzerocoin::SpendMetaData newMetadata(0, 0);
			libzerocoin::Accumulator accumulator(ZCParams, targetDenomination);
			libzerocoin::Accumulator accumulatorRev(ZCParams, targetDenomination);
			libzerocoin::Accumulator accumulatorPrecomputed(ZCParams, targetDenomination);
			bool passVerify = false;
			uint32_t pubcoinId = txin.nSequence;
			if (pubcoinId < 1 || pubcoinId >= INT_MAX) { // IT BEGINS WITH 1
				return state.DoS(100,
					false,
					NSEQUENCE_INCORRECT,
					"CTransaction::CheckTransaction() : Error: nSequence is not correct format");
			}

			            // VERIFY COINSPEND TX
			            // used pre-computed accumulator
			walletdb.ReadZerocoinAccumulator(accumulatorPrecomputed, targetDenomination, pubcoinId);
			if (newSpend.Verify(accumulatorPrecomputed, newMetadata)) {
				passVerify = true;
			}
			int countPubcoin = 0;
			if (!passVerify) {
				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.denomination == targetDenomination &&
					    (pubCoinItem.id >= 0 && (uint32_t) pubCoinItem.id == pubcoinId) &&
					    pubCoinItem.nHeight != -1) {
						libzerocoin::PublicCoin pubCoinTemp(ZCParams, pubCoinItem.value, targetDenomination);
						if (!pubCoinTemp.validate()) {
							return state.DoS(100,
								false,
								PUBLIC_COIN_FOR_ACCUMULATOR_INVALID,
								"CTransaction::CheckTransaction() : Error: Public Coin for Accumulator is not valid !!!");
						}
						countPubcoin++;
						accumulator += pubCoinTemp;
						LogPrintf("countPubcoin=%s\n", countPubcoin);
						LogPrintf("accumulator=%s\n", accumulator.getValue().ToString());
						if (countPubcoin >= 2) { // MINIMUM REQUIREMENT IS 2 PUBCOINS
							if (newSpend.Verify(accumulator, newMetadata)) {
								LogPrintf("COIN SPEND TX DID VERIFY - accumulator!\n");
								// store this accumulator
								if (!isCheckWallet) {
									walletdb.WriteZerocoinAccumulator(accumulator, targetDenomination, pubcoinId);
								}
								passVerify = true;
								break;
							}
						}
					}
				}

				                // It does not have this mint coins id, still sync
				if (countPubcoin == 0) {
					return state.DoS(0, false, NO_MINT_ZEROCOIN, "CTransaction::CheckTransaction() : Error: Node does not have mint zerocoin to verify, please wait until ");
				}
			}

			if (!passVerify) {
				int countPubcoin = 0;
				//                LogPrint("CheckSpendZcoinTransaction", "Check reverse\n");
				BOOST_REVERSE_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
				//                    LogPrintf("--denomination = %d, id = %d, pubcoinId = %d height = %d\n",
				//                              pubCoinItem.denomination, pubCoinItem.id, pubcoinId, pubCoinItem.nHeight);
					if (pubCoinItem.denomination == targetDenomination &&
					    (pubCoinItem.id >= 0 && (uint32_t) pubCoinItem.id == pubcoinId) &&
					    pubCoinItem.nHeight != -1) {
						LogPrint("CheckSpendZcoinTransaction",
							"--## denomination = %d, id = %d, pubcoinId = %d height = %d\n",
							pubCoinItem.denomination,
							pubCoinItem.id,
							pubcoinId,
							pubCoinItem.nHeight);
						libzerocoin::PublicCoin pubCoinTemp(ZCParams, pubCoinItem.value, targetDenomination);
						if (!pubCoinTemp.validate()) {
							return state.DoS(100,
								error("CTransaction::CheckTransaction() : Error: Public Coin for Accumulator is not valid !!!"));
						}
						countPubcoin++;
						accumulatorRev += pubCoinTemp;
						LogPrintf("countPubcoin=%s\n", countPubcoin);
						LogPrintf("accumulatorRev=%s\n", accumulatorRev.getValue().ToString());
						if (countPubcoin >= 2) { // MINIMUM REQUIREMENT IS 2 PUBCOINS
							if (newSpend.Verify(accumulatorRev, newMetadata)) {
								LogPrintf("COIN SPEND TX DID VERIFY - accumulatorRev!\n");
								passVerify = true;
								break;
							}
						}
					}
				}

				                // It does not have this mint coins id, still sync
				if (countPubcoin == 0) {
					return state.DoS(0, false, NO_MINT_ZEROCOIN, "CTransaction::CheckTransaction() : Error: Node does not have mint zerocoin to verify, please wait until ");
				}
			}

			if (passVerify) {
			    // Pull the serial number out of the CoinSpend object. If we
			    // were a real Zerocoin client we would now check that the serial number
			    // has not been spent before (in another ZEROCOIN_SPEND) transaction.
			    // The serial number is stored as a Bignum.
				if (!isVerifyDB && !isCheckWallet) {
				    // chceck already store
					bool isAlreadyStored = false;

					CBigNum serialNumber = newSpend.getCoinSerialNumber();
					CWalletDB walletdb(pwalletMain->strWalletFile);

					std::list <CZerocoinSpendEntry> listCoinSpendSerial;
					walletdb.ListCoinSpendSerial(listCoinSpendSerial);
					BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial) {
						if (item.coinSerial == serialNumber
						    && item.denomination == targetDenomination
						    && (item.id >= 0 && (uint32_t) item.id == pubcoinId)
						    && item.hashTx != hashTx) {
							return state.DoS(100, error("CTransaction::CheckTransaction() : The CoinSpend serial has been used"));
						}
						else if (item.coinSerial == serialNumber
						           && item.hashTx == hashTx
						           && item.denomination == targetDenomination
						           && (item.id >= 0 && (uint32_t) item.id == pubcoinId)
						           && item.pubCoin != 0) {
							// UPDATING PROCESS
							BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
								if (pubCoinItem.value == item.pubCoin) {
									pubCoinTx.nHeight = pubCoinItem.nHeight;
									pubCoinTx.denomination = pubCoinItem.denomination;
									// UPDATE FOR INDICATE IT HAS BEEN USED
									pubCoinTx.IsUsed = true;
									// REMOVE RANDOMNESS FOR PREVENT FUTURE USE
									// pubCoinTx.randomness = 0;
									// pubCoinTx.serialNumber = 0;
									pubCoinTx.value = pubCoinItem.value;
									pubCoinTx.id = pubCoinItem.id;
									walletdb.WriteZerocoinEntry(pubCoinTx);
									// Update UI wallet
									// LogPrint("CheckSpendZcoinTransaction", "pubcoin=%s, isUsed=Used\n", pubCoinItem.value.GetHex());
									pwalletMain->NotifyZerocoinChanged(pwalletMain, pubCoinItem.value.GetHex(), "Used", CT_UPDATED);
									break;
								}
							}
							isAlreadyStored = true;
							break;
						}
						else if (item.coinSerial == serialNumber
						           && item.hashTx == hashTx
						           && item.denomination == targetDenomination
						           && (item.id >= 0 && (uint32_t) item.id == pubcoinId)
						           && item.pubCoin == 0) {
							isAlreadyStored = true;
							break;
						}
					}

					if (!isAlreadyStored) {
					    // INSERTING COINSPEND TO DB
						CZerocoinSpendEntry zccoinSpend;
						zccoinSpend.coinSerial = serialNumber;
						zccoinSpend.hashTx = hashTx;
						zccoinSpend.pubCoin = 0;
						zccoinSpend.id = pubcoinId;
						if (nHeight > 22000 && nHeight < INT_MAX) {
							zccoinSpend.denomination = targetDenomination;
						}
						//                        LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s", serialNumber.ToString());
						walletdb.WriteCoinSpendSerialEntry(zccoinSpend);
					}
				}
			}
			else {
				return false;
			}
		}
	}
	return true;
}

bool CheckZerocoinFoundersInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet) {
        //BTZC: add ZCOIN code
        // Check for founders inputs
	if ((nHeight > 0) && (nHeight < 210000)) {
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

bool CheckZerocoinTransaction(const CTransaction &tx, CValidationState &state, uint256 hashTx, bool isVerifyDB, int nHeight, bool isCheckWallet)
{
    // Check Mint Zerocoin Transaction
	BOOST_FOREACH(const CTxOut &txout, tx.vout) {
		if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
			LogPrintf("CheckMintZcoinTransaction txHash = %s, isVerifyDB = %d\n", txout.GetHash().ToString(), isVerifyDB);
			LogPrintf("nValue = %d\n", txout.nValue);
			vector<unsigned char> vchZeroMint;
			vchZeroMint.insert(vchZeroMint.end(),
				txout.scriptPubKey.begin() + 6,
				txout.scriptPubKey.begin() + txout.scriptPubKey.size());
			CBigNum pubCoin;
			pubCoin.setvch(vchZeroMint);
			libzerocoin::CoinDenomination denomination;
			if (txout.nValue == libzerocoin::ZQ_LOVELACE * COIN) {
				denomination = libzerocoin::ZQ_LOVELACE;
				libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, libzerocoin::ZQ_LOVELACE);
				if (!checkPubCoin.validate()) {
					return state.DoS(100,
						false,
						PUBCOIN_NOT_VALIDATE,
						"CTransaction::CheckTransaction() : PubCoin is not validate");
				}
			}
			else if (txout.nValue == libzerocoin::ZQ_GOLDWASSER * COIN) {
				denomination = libzerocoin::ZQ_GOLDWASSER;
				libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, libzerocoin::ZQ_GOLDWASSER);
				if (!checkPubCoin.validate()) {
					return state.DoS(100,
						false,
						PUBCOIN_NOT_VALIDATE,
						"CTransaction::CheckTransaction() : PubCoin is not validate");
				}
			}
			else if (txout.nValue == libzerocoin::ZQ_RACKOFF * COIN) {
				denomination = libzerocoin::ZQ_RACKOFF;
				libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, libzerocoin::ZQ_RACKOFF);
				if (!checkPubCoin.validate()) {
					return state.DoS(100,
						false,
						PUBCOIN_NOT_VALIDATE,
						"CTransaction::CheckTransaction() : PubCoin is not validate");
				}
			}
			else if (txout.nValue == libzerocoin::ZQ_PEDERSEN * COIN) {
				denomination = libzerocoin::ZQ_PEDERSEN;
				libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, libzerocoin::ZQ_PEDERSEN);
				if (!checkPubCoin.validate()) {
					return state.DoS(100,
						false,
						PUBCOIN_NOT_VALIDATE,
						"CTransaction::CheckTransaction() : PubCoin is not validate");
				}
			}
			else if (txout.nValue == libzerocoin::ZQ_WILLIAMSON * COIN) {
				denomination = libzerocoin::ZQ_WILLIAMSON;
				libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, libzerocoin::ZQ_WILLIAMSON);
				if (!checkPubCoin.validate()) {
					return state.DoS(100,
						false,
						PUBCOIN_NOT_VALIDATE,
						"CTransaction::CheckTransaction() : PubCoin is not validate");
				}
			}
			else {
				return state.DoS(100,
					false,
					PUBCOIN_NOT_VALIDATE,
					"CTransaction::CheckTransaction() : PubCoin is not validate");
			}
			if (!isVerifyDB && !isCheckWallet) {
			    // Check the pubCoinValue didn't alr`eady store in the wallet
				CZerocoinEntry pubCoinTx;
				list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
				CWalletDB walletdb(pwalletMain->strWalletFile);
				walletdb.ListPubCoin(listPubCoin);
				bool isAlreadyStored = false;

				                    // CHECKING PROCESS
				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.value == pubCoin && pubCoinItem.denomination == denomination) {
						isAlreadyStored = true;
						break;
					}
				}
				// INSERT PROCESS
				if (!isAlreadyStored) {
				    // TX DOES NOT INCLUDE IN DB
					LogPrintf("INSERTING\n");
					pubCoinTx.id = -1;
					pubCoinTx.denomination = denomination;
					pubCoinTx.value = pubCoin;
					pubCoinTx.randomness = 0;
					pubCoinTx.serialNumber = 0;
					pubCoinTx.nHeight = -1;
					LogPrintf("INSERT PUBCOIN ID: %d\n", pubCoinTx.id);
					walletdb.WriteZerocoinEntry(pubCoinTx);
				}
			}
		}
	}
	// Check Spend Zerocoin Transaction
	if (tx.IsZerocoinSpend()) {
	    // Check vOut
	    // Only one loop, we checked on the format before enter this case
		BOOST_FOREACH(const CTxOut &txout, tx.vout)
		{
			CZerocoinEntry pubCoinTx;
			list <CZerocoinEntry> listPubCoin;
			if (!isVerifyDB) {
				CWalletDB walletdb(pwalletMain->strWalletFile);
				listPubCoin.clear();
				walletdb.ListPubCoin(listPubCoin);
				listPubCoin.sort(CompHeight);
				if (txout.nValue == libzerocoin::ZQ_LOVELACE * COIN) {
				    // Check vIn
					if (!CheckSpendZcoinTransaction(tx, pubCoinTx, listPubCoin, libzerocoin::ZQ_LOVELACE, state, hashTx, isVerifyDB, nHeight, isCheckWallet)) {
						return state.DoS(100, error("CTransaction::CheckTransaction() : COIN SPEND TX IN ZQ_LOVELACE DID NOT VERIFY!"));
					}
					;
				}
				else if (txout.nValue == libzerocoin::ZQ_GOLDWASSER * COIN) {
					if (!CheckSpendZcoinTransaction(tx, pubCoinTx, listPubCoin, libzerocoin::ZQ_GOLDWASSER, state, hashTx, isVerifyDB, nHeight, isCheckWallet)) {
						return state.DoS(100, error("CTr[ansaction::CheckTransaction() : COIN SPEND TX IN ZQ_GOLDWASSER DID NOT VERIFY!"));
					}
					;
				}
				else if (txout.nValue == libzerocoin::ZQ_RACKOFF * COIN) {
					if (!CheckSpendZcoinTransaction(tx, pubCoinTx, listPubCoin, libzerocoin::ZQ_RACKOFF, state, hashTx, isVerifyDB, nHeight, isCheckWallet)) {
						return state.DoS(100, error("CTransaction::CheckTransaction() : COIN SPEND TX IN ZQ_RACKOFF DID NOT VERIFY!"));
					}
					;
				}
				else if (txout.nValue == libzerocoin::ZQ_PEDERSEN * COIN) {
					if (!CheckSpendZcoinTransaction(tx, pubCoinTx, listPubCoin, libzerocoin::ZQ_PEDERSEN, state, hashTx, isVerifyDB, nHeight, isCheckWallet)) {
						return state.DoS(100, error("CTransaction::CheckTransaction() : COIN SPEND TX IN ZQ_PEDERSEN DID NOT VERIFY!"));
					}
					;
				}
				else if (txout.nValue == libzerocoin::ZQ_WILLIAMSON * COIN) {
					if (!CheckSpendZcoinTransaction(tx, pubCoinTx, listPubCoin, libzerocoin::ZQ_WILLIAMSON, state, hashTx, isVerifyDB, nHeight, isCheckWallet)) {
						return state.DoS(100, error("CTransaction::CheckTransaction() : COIN SPEND TX IN ZQ_WILLIAMSON DID NOT VERIFY!"));
					}
					;
				}
				else {
					return state.DoS(100, error("CTransaction::CheckTransaction() : Your spending txout value does not match"));
				}
				walletdb.Flush();
				walletdb.Close();
			}
		}
	}
	return true;
}

void DisconnectTipZC(CBlock &block, CBlockIndex *pindexDelete) {
	
    // Zerocoin reorg, set mint to height -1, id -1
	list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
	CWalletDB walletdb(pwalletMain->strWalletFile);
	walletdb.ListPubCoin(listPubCoin);
	//    listPubCoin.sort(CompHeight);

	list <CZerocoinSpendEntry> listCoinSpendSerial;
	walletdb.ListCoinSpendSerial(listCoinSpendSerial);

	BOOST_FOREACH(const CTransaction &tx, block.vtx) {
	    // Check Spend Zerocoin Transaction
		if (tx.IsZerocoinSpend()) {
			BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial) {
				if (item.hashTx == tx.GetHash()) {
					BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
						if (pubCoinItem.value == item.pubCoin) {
							CZerocoinEntry pubCoinTx;
							pubCoinTx.nHeight = pubCoinItem.nHeight;
							pubCoinTx.denomination = pubCoinItem.denomination;
							// UPDATE FOR INDICATE IT HAS BEEN RESET
							pubCoinTx.IsUsed = false;
							pubCoinTx.randomness = pubCoinItem.randomness;
							pubCoinTx.serialNumber = pubCoinItem.serialNumber;
							pubCoinTx.value = pubCoinItem.value;
							pubCoinTx.id = pubCoinItem.id;
							walletdb.WriteZerocoinEntry(pubCoinTx);
							LogPrintf("DisconnectTip() -> NotifyZerocoinChanged\n");
							LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
							pwalletMain->NotifyZerocoinChanged(pwalletMain, pubCoinItem.value.GetHex(), "New", CT_UPDATED);
							walletdb.EraseCoinSpendSerialEntry(item);
							pwalletMain->EraseFromWallet(item.hashTx);
						}
					}
				}
			}
		}

		        // Check Mint Zerocoin Transaction
		BOOST_FOREACH(const CTxOut txout, tx.vout) {
			if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
				vector<unsigned char> vchZeroMint;
				vchZeroMint.insert(vchZeroMint.end(), txout.scriptPubKey.begin() + 6, txout.scriptPubKey.begin() + txout.scriptPubKey.size());
				CBigNum pubCoin;
				pubCoin.setvch(vchZeroMint);
				int zerocoinMintHeight = -1;
				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.value == pubCoin) {
						zerocoinMintHeight = pubCoinItem.nHeight;
						CZerocoinEntry pubCoinTx;
						pubCoinTx.id = -1;
						pubCoinTx.IsUsed = pubCoinItem.IsUsed;
						pubCoinTx.randomness = pubCoinItem.randomness;
						pubCoinTx.denomination = pubCoinItem.denomination;
						pubCoinTx.serialNumber = pubCoinItem.serialNumber;
						pubCoinTx.value = pubCoin;
						pubCoinTx.nHeight = -1;
						LogPrintf("- Pubcoin Disconnect Reset Pubcoin Id: %d Height: %d\n", pubCoinTx.id, pindexDelete->nHeight);
						walletdb.WriteZerocoinEntry(pubCoinTx);
					}

				}

				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.nHeight > zerocoinMintHeight) {
						CZerocoinEntry pubCoinTx;
						pubCoinTx.id = -1;
						pubCoinTx.IsUsed = pubCoinItem.IsUsed;
						pubCoinTx.randomness = pubCoinItem.randomness;
						pubCoinTx.denomination = pubCoinItem.denomination;
						pubCoinTx.serialNumber = pubCoinItem.serialNumber;
						pubCoinTx.value = pubCoin;
						pubCoinTx.nHeight = -1;
						LogPrintf("- Disconnect Reset Pubcoin Id: %d Height: %d\n", pubCoinTx.id, pindexDelete->nHeight);
						walletdb.WriteZerocoinEntry(pubCoinTx);
					}

				}
			}
		}
	}
	
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectTipZC(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock) {
	CBlock block;
	if (!pblock) {
		if (!ReadBlockFromDisk(block, pindexNew, chainparams.GetConsensus()))
			return false;
		pblock = &block;
	}
	// Zerocoin reorg, calculate new height and id
	list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
	CWalletDB walletdb(pwalletMain->strWalletFile);
	walletdb.ListPubCoin(listPubCoin);
	//    listPubCoin.sort(CompHeight);

	BOOST_FOREACH(const CTransaction &tx, pblock->vtx) {
	    // Check Mint Zerocoin Transaction
		BOOST_FOREACH(const CTxOut txout, tx.vout) {
			if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
				vector<unsigned char> vchZeroMint;
				vchZeroMint.insert(vchZeroMint.end(), txout.scriptPubKey.begin() + 6, txout.scriptPubKey.begin() + txout.scriptPubKey.size());

				CBigNum pubCoin;
				pubCoin.setvch(vchZeroMint);
				int zerocoinMintHeight = -1;
				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.value == pubCoin) {
					//                        zerocoinMintHeight = pubCoinItem.nHeight;
						CZerocoinEntry pubCoinTx;
						pubCoinTx.id = -1;
						pubCoinTx.IsUsed = pubCoinItem.IsUsed;
						pubCoinTx.randomness = pubCoinItem.randomness;
						pubCoinTx.denomination = pubCoinItem.denomination;
						pubCoinTx.serialNumber = pubCoinItem.serialNumber;
						pubCoinTx.value = pubCoinItem.value;
						pubCoinTx.nHeight = -1;
						walletdb.WriteZerocoinEntry(pubCoinTx);
						LogPrintf("- Pubcoin Connect Reset Pubcoin Denomination: %d Pubcoin Id: %d Height: %d\n", pubCoinTx.denomination, pubCoinTx.id, pubCoinItem.nHeight);
						zerocoinMintHeight = pindexNew->nHeight;
					}
				}
				BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
					if (pubCoinItem.nHeight > zerocoinMintHeight) {
						CZerocoinEntry pubCoinTx;
						pubCoinTx.id = -1;
						pubCoinTx.IsUsed = pubCoinItem.IsUsed;
						pubCoinTx.randomness = pubCoinItem.randomness;
						pubCoinTx.denomination = pubCoinItem.denomination;
						pubCoinTx.serialNumber = pubCoinItem.serialNumber;
						pubCoinTx.value = pubCoin;
						pubCoinTx.nHeight = -1;
						LogPrintf("- Connect Reset Pubcoin Denomination: %d Pubcoin Id: %d Height: %d\n", pubCoinTx.denomination, pubCoinTx.id, pubCoinItem.nHeight);
						walletdb.WriteZerocoinEntry(pubCoinTx);
					}
				}
			}
		}
	}
	return true;
}

/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ReArrangeZcoinMint(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock) {
//    LogPrintf("[ReArrangeZcoinMint]\n");
	CBlock block;
	if (!pblock) {
		if (!ReadBlockFromDisk(block, pindexNew, chainparams.GetConsensus()))
			return false;
		pblock = &block;
	}
	// Zerocoin reorg, calculate new height and id
	list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
	CWalletDB walletdb(pwalletMain->strWalletFile);
	walletdb.ListPubCoin(listPubCoin);

	BOOST_FOREACH(const CTransaction &tx, pblock->vtx) {
	    // Check Mint Zerocoin Transaction
		BOOST_FOREACH(const CTxOut txout, tx.vout) {
			if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
				vector<unsigned char> vchZeroMint;
				vchZeroMint.insert(vchZeroMint.end(),
					txout.scriptPubKey.begin() + 6,
					txout.scriptPubKey.begin() + txout.scriptPubKey.size());
				CBigNum pubCoin;
				pubCoin.setvch(vchZeroMint);

				BOOST_FOREACH(
				const CZerocoinEntry &pubCoinItem,
					listPubCoin) {
					if (pubCoinItem.value == pubCoin) {
						CZerocoinEntry pubCoinTx;
						// PUBCOIN IS IN DB, BUT NOT UPDATE ID
						int currentId = 1;
						unsigned int countExistingItems = 0;
						listPubCoin.sort(CompHeight);
						BOOST_FOREACH(const CZerocoinEntry &pubCoinIdItem, listPubCoin) {
						//                            LogPrintf("denomination = %d, id = %d, height = %d\n", pubCoinIdItem.denomination, pubCoinIdItem.id, pubCoinIdItem.nHeight);
							if (pubCoinIdItem.id > 0) {
								if (pubCoinIdItem.nHeight <= pindexNew->nHeight) {
									if (pubCoinIdItem.denomination == pubCoinItem.denomination) {
										countExistingItems++;
										if (pubCoinIdItem.id > currentId) {
											currentId = pubCoinIdItem.id;
											countExistingItems = 1;
										}
									}
								}
								else {
									break;
								}
							}
						}

						if (countExistingItems > 9) {
							currentId++;
						}
						pubCoinTx.id = currentId;

						pubCoinTx.IsUsed = pubCoinItem.IsUsed;
						pubCoinTx.randomness = pubCoinItem.randomness;
						pubCoinTx.denomination = pubCoinItem.denomination;
						pubCoinTx.serialNumber = pubCoinItem.serialNumber;
						pubCoinTx.value = pubCoinItem.value;
						pubCoinTx.nHeight = pindexNew->nHeight;
						LogPrintf("REORG PUBCOIN DENOMINATION: %d PUBCOIN ID: %d HEIGHT: %d\n",
							pubCoinTx.denomination,
							pubCoinTx.id,
							pubCoinTx.nHeight);
						walletdb.WriteZerocoinEntry(pubCoinTx);
					}
				}
			}
		}
	}
	walletdb.WriteCalculatedZCBlock(pindexNew->nHeight);
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
