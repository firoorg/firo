// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "rpc/server.h"
#include "util.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.h"
#include "lelantus.h"
#include "client-api/bigint.h"
#include "client-api/server.h"
#include "client-api/send.h"
#include "client-api/privatetransaction.h"
#include "client-api/protocol.h"
#include "client-api/wallet.h"
#include "wallet/coincontrol.h"
#include "univalue.h"
#include "./elysium.h"
#include "wallet/bip39.h"
#include "validation.h"
#include "consensus/consensus.h"
#include <boost/algorithm/string.hpp>
#include "../elysium/wallettxs.h"
#include "../elysium/tx.h"
#include "../elysium/lelantusdb.h"
#include "../elysium/lelantuswallet.h"
#include "../elysium/wallet.h"

namespace fs = boost::filesystem;
using namespace boost::chrono;
std::map<COutPoint, bool> pendingLockCoins;
const int WALLET_SEGMENT_SIZE = 100;
std::atomic<bool> fHasSentInitialStateWallet {false};

bool GetCoinControl(const UniValue& data, CCoinControl& cc) {
    if (find_value(data, "coinControl").isNull()) return false;
    UniValue uniValCC(UniValue::VOBJ);
    uniValCC = find_value(data, "coinControl");
    UniValue uniSelected(UniValue::VSTR);
    uniSelected = find_value(uniValCC, "selected");

    std::string selected = boost::algorithm::trim_copy(uniSelected.getValStr());
    if (selected.empty()) return false;

    std::vector<std::string> selectedKeys;
    boost::split(selectedKeys, selected, boost::is_any_of(":"));

    for(size_t i = 0; i < selectedKeys.size(); i++) {
        std::vector<std::string> splits;
        boost::split(splits, selectedKeys[i], boost::is_any_of("-"));
        if (splits.size() != 2) continue;

        uint256 hash;
        hash.SetHex(splits[0]);
        UniValue idx(UniValue::VNUM);
        idx.setNumStr(splits[1]);
        COutPoint op(hash, idx.get_int());
        cc.Select(op);
    }
    return true;
}

std::string ReadMnemonics() {
    // add the base58check encoded extended master if the wallet uses HD
    MnemonicContainer mContainer = pwalletMain->GetMnemonicContainer();
    const CHDChain& chain = pwalletMain->GetHDChain();
    if(!mContainer.IsNull() && chain.nVersion >= CHDChain::VERSION_WITH_BIP39)
    {
        if(mContainer.IsCrypted())
        {
            if(!pwalletMain->DecryptMnemonicContainer(mContainer))
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot decrypt hd chain");
        }

        SecureString mnemonic;
        //Don't dump mnemonic words in case user has set only hd seed during wallet creation
        if(mContainer.GetMnemonic(mnemonic))
            return std::string(mnemonic.begin(), mnemonic.end()).c_str();;
    }
    return "";
}

bool doesWalletHaveMnemonics() {
    MnemonicContainer mContainer = pwalletMain->GetMnemonicContainer();
    const CHDChain& chain = pwalletMain->GetHDChain();
    return (!mContainer.IsNull() && chain.nVersion >= CHDChain::VERSION_WITH_BIP39);
}

bool readShowMnemonicWarning() {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return false;
    CWalletDB db(pwalletMain->strWalletFile);
    return db.ReadShowMnemonicsWarning();
}

bool isMnemonicExist() {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return false;
    return doesWalletHaveMnemonics();
}

CAmount getLockUnspentAmount()
{
    CTransactionRef tx;
    uint256 hashBlock;
    uint256 hash;
    std::vector<COutPoint> vOutpts;
    CAmount total = 0;

    pwalletMain->ListLockedCoins(vOutpts);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        uint256 hash = outpt.hash;
        if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
            continue;
        total += tx->vout[outpt.n].nValue;
    }

    return total;
}

void IsTxOutSpendable(const CWalletTx& wtx, const COutPoint& outPoint, UniValue& entry) {
    // 0 indicates that the transaction may be spent immediately; -1 that it may not be spent at all; and any other
    // value that it may be spent at the given block height. The lock status of a transaction does not affect this
    // value.
    int nSpendableAt;

    int nBlockHeight;
    auto blockIndex = mapBlockIndex.find(wtx.hashBlock);
    if (blockIndex == mapBlockIndex.end()) {
        nBlockHeight = -1;
    } else {
        nBlockHeight = mapBlockIndex[wtx.hashBlock]->nHeight;
    }

    if (wtx.isAbandoned()) {
        nSpendableAt = -1;
    } else if (wtx.GetDepthInMainChain() < 0) {
        nSpendableAt = -1;
    } else if (pwalletMain->IsSpent(outPoint.hash, outPoint.n)) {
        nSpendableAt = -1;
    } else if (wtx.IsCoinBase() && nBlockHeight != 0) { // block 0 coinbase is unspendable
        nSpendableAt = nBlockHeight + COINBASE_MATURITY + 1;
    } else if (wtx.tx->vout[outPoint.n].scriptPubKey.IsLelantusJoinSplit() ||
        wtx.tx->vout[outPoint.n].scriptPubKey.IsLelantusJMint() ||
        wtx.tx->vout[outPoint.n].scriptPubKey.IsLelantusMint() ||
        wtx.tx->vout[outPoint.n].scriptPubKey.IsSigmaMint()
    ) {
        if (nBlockHeight != -1) {
            nSpendableAt = nBlockHeight + ZC_MINT_CONFIRMATIONS;
        } else {
            nSpendableAt = -1;
        }
    } else if (nBlockHeight != -1) {
        nSpendableAt = 0;
    } else if (wtx.IsTrusted()) {
        nSpendableAt = 0;
    } else {
        nSpendableAt = -1;
    }

    bool fLocked = pwalletMain->IsLockedCoin(outPoint.hash, outPoint.n);

    entry.push_back(Pair("locked", fLocked));
    entry.push_back(Pair("spendableAt", nSpendableAt));
}

UniValue getBlockHeight(const std::string strHash)
{
    LOCK(cs_main);

    uint256 hash(uint256S(strHash));

    if (mapBlockIndex.count(hash) == 0)
        return -1;

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    return pblockindex->nHeight;
}

void APIWalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    std::string hash = wtx.GetHash().GetHex();
    if (confirms > 0) {
        entry.push_back(Pair("blockHash", wtx.hashBlock.GetHex()));
        UniValue blocktime = mapBlockIndex[wtx.hashBlock]->GetBlockTime();
        entry.push_back(Pair("blockTime", blocktime));
        entry.push_back(Pair("blockHeight", getBlockHeight(wtx.hashBlock.GetHex())));
    }

    entry.push_back(Pair("firstSeenAt", wtx.GetTxTime()));
    entry.push_back(Pair("txid", hash));
}

std::string ScriptType(const CScript &script) {
    if (script.IsPayToPublicKey()) return "pay-to-public-key";
    else if (script.IsPayToPublicKeyHash()) return "pay-to-public-key-hash";
    else if (script.IsPayToScriptHash()) return "pay-to-script-hash";
    else if (script.IsPayToWitnessScriptHash()) return "pay-to-witness-script-hash";
    else if (script.IsZerocoinMint()) return "zerocoin-mint";
    else if (script.IsZerocoinRemint()) return "zerocoin-remint";
    else if (script.IsZerocoinSpend()) return "zerocoin-spend";
    else if (script.IsSigmaSpend()) return "sigma-spend";
    else if (script.IsSigmaMint()) return "sigma-mint";
    else if (script.IsLelantusMint()) return "lelantus-mint";
    else if (script.IsLelantusJMint()) return "lelantus-jmint";
    else if (script.IsLelantusJoinSplit()) return "lelantus-joinsplit";
    else if (script.IsElysium()) return "elysium";
    else if (script.IsSparkMint()) return "spark-mint";
    else if (script.IsSparkSMint()) return "spark-smint";
    else if (script.IsSparkSpend()) return "spark-spend";
    else return "unknown";
}

UniValue FormatWalletTxForClientAPI(CWalletDB &db, const CWalletTx &wtx)
{
    AssertLockHeld(cs_main);
    if (isElysiumEnabled()) {
        assert(elysium::wallet);
        assert(elysium::wallet->lelantusWallet.database);
    }

    UniValue txData = UniValue::VOBJ;

    bool fIsFromMe = false;
    bool fIsMining = false;

    UniValue publicInputs = UniValue::VARR;
    std::string inputType = "public";
    for (const CTxIn &txin: wtx.tx->vin) {
        UniValue pin = UniValue::VARR;
        pin.push_back(txin.prevout.hash.ToString());
        pin.push_back((uint64_t)txin.prevout.n);
        publicInputs.push_back(pin);

        if (txin.IsZerocoinSpend() || txin.IsZerocoinRemint()) inputType = "zerocoin";
        else if (txin.IsSigmaSpend()) inputType = "sigma";
        else if (txin.IsLelantusJoinSplit()) inputType = "lelantus";
    }
    if (wtx.tx->IsSparkSpend()) inputType = "sparkspend";
    if (wtx.tx->IsSparkMint()) inputType = "sparkmint";  
    if (inputType == "public" && wtx.tx->vin.size() == 1 && wtx.tx->vin[0].prevout.IsNull()) {
        inputType = "mined";
        fIsMining = true;
    }
    txData.pushKV("publicInputs", publicInputs);

    UniValue lelantusInputSerialHashes = UniValue::VARR;
    std::unique_ptr<lelantus::JoinSplit> joinSplit;
    if (wtx.tx->IsLelantusJoinSplit()) {
        joinSplit = lelantus::ParseLelantusJoinSplit(*wtx.tx);
        for (const Scalar& serial: joinSplit->getCoinSerialNumbers()) {
            lelantusInputSerialHashes.push_back(primitives::GetSerialHash(serial).GetHex());
        }
    }
    txData.pushKV("lelantusInputSerialHashes", lelantusInputSerialHashes);

    int64_t fee;
    int64_t amount = 0;
    UniValue sparkInputLTagHashes = UniValue::VARR;
    if (wtx.tx->IsSparkSpend()) {
        try {
            spark::SpendTransaction spend = spark::ParseSparkSpend(*wtx.tx);
            for (const auto& lTag : spend.getUsedLTags()) {
                sparkInputLTagHashes.push_back(primitives::GetLTagHash(lTag).GetHex());
            }
            CAmount nDebit = wtx.GetDebit(ISMINE_SPENDABLE);
            if (nDebit > 0) fIsFromMe = true;
            fee = spend.getFee();
            CAmount nCredit = wtx.GetCredit(ISMINE_SPENDABLE);
            if(nCredit > nDebit) {
                amount = nCredit - nDebit - fee;
            } else {
                amount = nDebit - nCredit - fee;
            }
        } catch (...) {
        }
    }
    txData.pushKV("sparkInputLTagHashes", sparkInputLTagHashes);

    if (fIsMining) { // mining transaction
        fee = 0;
    } else if (joinSplit) {
        fee = joinSplit->getFee();
    } else if (wtx.tx->IsSparkSpend()) {
        //already set
    } else {
        CAmount nDebit = wtx.GetDebit(ISMINE_SPENDABLE);
        CAmount nValueOut = wtx.tx->GetValueOut();

        if (nDebit > 0) fIsFromMe = true;
        fee = nDebit - nValueOut;
    }

    UniValue outputs = UniValue::VARR;
    int n = -1;
    for (const CTxOut &txout: wtx.tx->vout) {
        n += 1;

        // IsChange incorrectly reports mining outputs as change.
        bool fIsChange = !fIsMining && wtx.IsChange(n);
        bool fIsToMe = false;
        bool fIsSpent = true;

        uint256 lelantusSerialHash;
        if (txout.scriptPubKey.IsLelantusMint()) {
            secp_primitives::GroupElement pub;
            bool ok = true;
            try {
                lelantus::ParseLelantusMintScript(txout.scriptPubKey, pub);
            } catch (std::invalid_argument&) {
                ok = false;
            }

            if (ok) {
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pub);
                CHDMint dMint;
                if (db.ReadHDMint(hashPubcoin, true, dMint)) {
                    amount = dMint.GetAmount();
                    fIsSpent = dMint.IsUsed();
                    fIsFromMe = true; // If we can parse a Lelantus mint, the transaction is from us.
                    fIsToMe = true;
                    lelantusSerialHash = dMint.GetSerialHash();
                }
            }
        } else if (txout.scriptPubKey.IsLelantusJMint()) {
            secp_primitives::GroupElement pub;
            std::vector<unsigned char> encryptedValue;
            bool ok = true;
            try {
                lelantus::ParseLelantusJMintScript(txout.scriptPubKey, pub, encryptedValue);
            } catch (std::invalid_argument&) {
                ok = false;
            }

            if (ok) {
                uint256 hashPubcoin = primitives::GetPubCoinValueHash(pub);
                CHDMint dMint;
                if (db.ReadHDMint(hashPubcoin, true, dMint)) {
                    amount = dMint.GetAmount();
                    fIsSpent = dMint.IsUsed();
                    fIsFromMe = true; // If we can parse a Lelantus mint, the transaction is from us.
                    fIsToMe = true;
                    lelantusSerialHash = dMint.GetSerialHash();
                }
            }
        } else if (txout.scriptPubKey.IsSparkMint() || txout.scriptPubKey.IsSparkSMint()) {
            spark::Coin coin(spark::Params::get_default());
            bool ok = true;
            try {
                spark::ParseSparkMintCoin(txout.scriptPubKey, coin);
            } catch (std::invalid_argument&) {
                ok = false;
            }

            if (ok) {
                 CSparkMintMeta mintMeta;
                 coin.setSerialContext(spark::getSerialContext(* wtx.tx));
                if (pwalletMain->sparkWallet->getMintMeta(coin, mintMeta)) {
                    amount = mintMeta.v;
                    fIsSpent = mintMeta.isUsed;
                    fIsToMe = true;
                } else {
                    fIsToMe = false;
                    fIsSpent = pwalletMain->IsSpent(wtx.tx->GetHash(), n);
                    if(txout.scriptPubKey.IsSparkMint()) {
                        amount = txout.nValue;
                    }
                }
            }
        } else {
            fIsSpent = pwalletMain->IsSpent(wtx.tx->GetHash(), n);
            amount = txout.nValue;
        }

        bool hasDestination = false;
        CTxDestination destination;
        if (ExtractDestination(txout.scriptPubKey, destination)) {
            hasDestination = true;
            fIsToMe = pwalletMain->IsMine(txout);
        }

        UniValue output = UniValue::VOBJ;
        output.pushKV("scriptType", ScriptType(txout.scriptPubKey));
        output.pushKV("amount", BigInt(amount));
        output.pushKV("isChange", fIsChange);
        output.pushKV("isLocked", !!pwalletMain->setLockedCoins.count(COutPoint(wtx.tx->GetHash(), n)));
        output.pushKV("isSpent", fIsSpent);
        output.pushKV("isToMe", fIsToMe);
        output.pushKV("isElysiumReferenceOutput", wtx.tx->IsElysiumReferenceOutput(n));
        if (hasDestination) output.pushKV("destination", CBitcoinAddress(destination).ToString());
        if (!lelantusSerialHash.IsNull()) output.pushKV("lelantusSerialHash", lelantusSerialHash.GetHex());

        outputs.push_back(output);
    }

    CBlockIndex *block = nullptr;
    if (!wtx.hashBlock.IsNull()) {
        auto blockIt = mapBlockIndex.find(wtx.hashBlock);
        if (blockIt != mapBlockIndex.end()) {
            block = blockIt->second;
        }
    }

    int nHeight = block ? block->nHeight : 0;
    int nTime = block ? block->nTime : 0;
    CMPTransaction mp_obj;
    if (isElysiumEnabled() && ParseTransaction(*wtx.tx, nHeight, 0, mp_obj, nTime) >= 0 && mp_obj.interpret_Transaction()) {
        UniValue elysiumData = UniValue::VOBJ;

        elysiumData.pushKV("isToMe", (bool)IsMine(*pwalletMain, CBitcoinAddress(mp_obj.getReceiver()).Get()) || pwalletMain->IsSparkAddressMine(mp_obj.getReceiver()));
        elysiumData.pushKV("sender", mp_obj.getSender());
        elysiumData.pushKV("receiver", mp_obj.getReceiver());
        elysiumData.pushKV("type", mp_obj.getTypeString());
        elysiumData.pushKV("version", mp_obj.getVersion());

        if (nHeight > 0) {
            bool isValid = elysium::getValidMPTX(wtx.tx->GetHash());
            elysiumData.pushKV("valid", isValid);
            if (!isValid)
                elysiumData.pushKV("invalidReason", elysium::p_ElysiumTXDB->FetchInvalidReason(wtx.tx->GetHash()));
        } else {
            elysiumData.pushKV("valid", false);
        }

        int txType = mp_obj.getType();

        CMPSPInfo::Entry info;
        UniValue propertyData = UniValue::VNULL;
        switch (txType) {
            case ELYSIUM_TYPE_LELANTUS_JOINSPLIT: {
                boost::optional<elysium::JoinSplitMint> jsm = mp_obj.getLelantusJoinSplitMint();
                if (jsm) {
                    elysium::LelantusMint mint;
                    if (elysium::wallet->lelantusWallet.database->ReadMint(jsm->id, mint, &db)) {
                        elysiumData.pushKV("joinmintAmount", BigInt(mint.amount));
                    } else {
                        LogPrintf("Error retrieving joinmintAmount for Elysium tx %s\n", wtx.GetHash().GetHex());
                        elysiumData.pushKV("joinmintAmount", BigInt(-1));
                    }
                } else {
                    elysiumData.pushKV("joinmintAmount", BigInt(0));
                }
            }

            case ELYSIUM_TYPE_SIMPLE_SEND:
            case ELYSIUM_TYPE_LELANTUS_MINT:
            case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS:
            case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS:
                try {
                    propertyData = getPropertyData(mp_obj.getProperty());
                } catch(UniValue &e) {
                    PrintToLog("failed to get property data for transaction %s", wtx.tx->GetHash().GetHex());
                }

                break;

            case ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE:
            case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED:
            case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL: {
                try {
                    propertyData = getPropertyData(wtx.tx->GetHash());
                } catch(UniValue &e) {
                    PrintToLog("failed to get property data for transactions %s", wtx.tx->GetHash().GetHex());
                }

                break;
            }
        }
        elysiumData.pushKV("property", propertyData);

        switch (txType) {
            case ELYSIUM_TYPE_SIMPLE_SEND:
            case ELYSIUM_TYPE_LELANTUS_MINT:
            case ELYSIUM_TYPE_LELANTUS_JOINSPLIT:
            case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED:
            case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS:
            case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS:
                // If the property is divisible, the actual amount is 1/1e8 of the value here.
                uint64_t amount;
                if (txType == ELYSIUM_TYPE_LELANTUS_MINT) amount = mp_obj.getLelantusMintValue();
                else if (txType == ELYSIUM_TYPE_LELANTUS_JOINSPLIT) amount = mp_obj.getLelantusSpendAmount();
                else amount = mp_obj.getAmount();
                elysiumData.pushKV("amount", BigInt(amount));
                break;

            default:
                elysiumData.pushKV("amount", UniValue::VNULL);
        }

        txData.pushKV("elysium", elysiumData);
    } else {
        txData.pushKV("elysium", UniValue::VNULL);
    }

    txData.pushKV("isInstantSendLocked", wtx.IsLockedByLLMQInstantSend());
    txData.pushKV("txid", wtx.GetHash().ToString());
    txData.pushKV("inputType", inputType);
    txData.pushKV("isFromMe", fIsFromMe);
    txData.pushKV("firstSeenAt", wtx.GetTxTime());
    txData.pushKV("fee", BigInt(fee));
    txData.pushKV("outputs", outputs);

    if (block) {
        txData.pushKV("blockHash", wtx.hashBlock.ToString());
        txData.pushKV("blockTime", block->GetBlockTime());
        txData.pushKV("blockHeight", block->nHeight);
    }

    return txData;
}

UniValue statewallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CWalletDB db(pwalletMain->strWalletFile);
    UniValue transactions(UniValue::VARR);
    for (std::map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;
        transactions.push_back(FormatWalletTxForClientAPI(db, tx));
    }
    return transactions;
}

UniValue setpassphrase(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    // encrypt's the wallet should be the wallet be unencrypted.
    // if already encrypted, it checks for a `newpassphrase` field, and updates the passphrase accordingly.
    if (!EnsureWalletIsAvailable(pwalletMain, fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;

    switch(type){
        case Update: {
            if(pwalletMain && pwalletMain->IsCrypted()){
                SecureString strOldWalletPass;
                SecureString strNewWalletPass;
                strOldWalletPass.reserve(100);
                strNewWalletPass.reserve(100);
                try{
                    strOldWalletPass = find_value(auth, "passphrase").get_str().c_str();
                    strNewWalletPass = find_value(auth, "newPassphrase").get_str().c_str();

                }catch(const std::exception& e){
                    throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
                }

                if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
                    throw std::runtime_error("");

                if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
                    throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

                return true;
            }
            else {
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "Error: Update type called, but wallet is unencrypted.");
            }
            break;
        }
        case Create: {
            if (pwalletMain->IsCrypted())
                throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

            SecureString strWalletPass;
            strWalletPass.reserve(100);

            try{
                strWalletPass = find_value(auth, "passphrase").get_str().c_str();

            }catch(const std::exception& e){
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
            }

            if (strWalletPass.length() < 1)
                throw std::runtime_error(
                    "encryptwallet <passphrase>\n"
                    "Encrypts the wallet with <passphrase>.");

            if (!pwalletMain->EncryptWallet(strWalletPass))
                throw JSONAPIError(API_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

            // BDB seems to have a bad habit of writing old data into
            // slack space in .dat files; that is bad if the old data is
            // unencrypted private keys. So:
            StartShutdown();
            return "wallet encrypted; zcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";   
            break;
        }
        default: {
            throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
        }
    }
    return true;
}

UniValue lockwallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (data.size() != 0))
        throw std::runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletunlock again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
        );

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but lockwallet was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return true;
}

UniValue unlockwallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    LOCK(cs_main);

    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in data[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make data[0] mlock()'d to begin with.

    try{
        strWalletPass = find_value(auth, "passphrase").get_str().c_str();

    }catch(const std::exception& e){
        throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
    }

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    }
    else //TODO length error
        throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect");

    pwalletMain->TopUpKeyPool();
    return true;
}

void parseCoins(const std::string input, std::vector<COutPoint>& output) 
{
    std::vector<std::string> selectedKeys;
    boost::split(selectedKeys, input, boost::is_any_of(":"));

    for(size_t i = 0; i < selectedKeys.size(); i++) {
        std::vector<std::string> splits;
        boost::split(splits, selectedKeys[i], boost::is_any_of("-"));
        if (splits.size() != 2) continue;

        uint256 hash;
        hash.SetHex(splits[0]);
        UniValue idx(UniValue::VNUM);
        idx.setNumStr(splits[1]);
        COutPoint op(hash, idx.get_int());
        output.push_back(op);
    }
}

UniValue lockStatus(Type type, const UniValue &data, const UniValue &auth, bool fHelp) {
    return data;
}

UniValue lockcoins(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    //Reading locked list
    LOCK(pwalletMain->cs_wallet);
    std::vector<COutPoint> lockedList, unlockedList;
    UniValue uniLocked(UniValue::VSTR);
    UniValue uniUnLocked(UniValue::VSTR);
    if (!find_value(data, "lockedCoins").isNull()) {
        uniLocked = find_value(data, "lockedCoins");
    }
    if (!find_value(data, "unlockedCoins").isNull()) {
        uniUnLocked = find_value(data, "unlockedCoins");
    }
    std::string locked = boost::algorithm::trim_copy(uniLocked.getValStr());
    std::string unlocked = boost::algorithm::trim_copy(uniUnLocked.getValStr());

    parseCoins(locked, lockedList);
    parseCoins(unlocked, unlockedList);
    for(const COutPoint l: lockedList) {
        pwalletMain->LockCoin(l);
        pendingLockCoins[l] = true;
    }
    LogPrintf("locking coins\n");

    for(const COutPoint l: unlockedList) {
        pwalletMain->UnlockCoin(l);
        pendingLockCoins[l] = false;
    }
    return true;
}

UniValue showmnemonics(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    // add the base58check encoded extended master if the wallet uses HD
    std::string memonics = ReadMnemonics();
    return memonics;
}

UniValue writeshowmnemonicwarning(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;
    CWalletDB db(pwalletMain->strWalletFile);
    UniValue temp(UniValue::VBOOL, data.getValStr());
    bool shouldShow = temp.get_bool();
    db.WriteShowMnemonicsWarning(shouldShow);
    return true;
}

UniValue readwalletmnemonicwarningstate(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hasMnemonic", isMnemonicExist()));
    ret.push_back(Pair("shouldShowWarning", readShowMnemonicWarning()));
    LogPrintf("%s\n", __func__);
    return ret;
}

bool isMnemonicValid(std::string mnemonic, std::string& failReason) {
    const char* str = mnemonic.c_str();
    bool space = true;
    int n = 0;

    while (*str != '\0')
    {
        if (std::isspace(*str))
        {
            space = true;
        }
        else if (space)
        {
            n++;
            space = false;
        }
        ++str;
    }

    if(n != 24) {
        failReason = "Wrong number of words. Please try again.";
        return false;
    }

    if(mnemonic.empty()) {
        failReason = "Mnemonic can't be empty.";
        return false;
    }

    SecureString secmnemonic(mnemonic.begin(), mnemonic.end());
    return Mnemonic::mnemonic_check(secmnemonic);
}

UniValue verifymnemonicvalidity(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (find_value(data, "mnemonic").isNull()){
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    std::string mnemonic = find_value(data, "mnemonic").getValStr();
    boost::trim(mnemonic);
    std::string failReason = "Invalid mnemonic recovery phrase";
    bool result = isMnemonicValid(mnemonic, failReason);
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("valid", result));
    if(!result)
        ret.push_back(Pair("reason", failReason));
    return ret;
}

UniValue readaddressbook(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    LOCK(pwalletMain->cs_wallet);

    UniValue addressBook(UniValue::VARR);

    for (std::map<CTxDestination, CAddressBookData>::const_iterator it = pwalletMain->mapAddressBook.begin(); it != pwalletMain->mapAddressBook.end(); ++it) {
        CBitcoinAddress addr;
        if (addr.Set(it->first)) 
        {
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("addressType", "Transparent"));
            item.push_back(Pair("address", addr.ToString()));
            item.push_back(Pair("label", it->second.name));
            item.push_back(Pair("purpose", it->second.purpose.empty()? "unknown":it->second.purpose));
            item.push_back(Pair("createdAt", it->second.nCreatedAt));
            addressBook.push_back(item);
        }
    }

    for (std::map<std::string, CAddressBookData>::const_iterator it = pwalletMain->mapSparkAddressBook.begin(); it != pwalletMain->mapSparkAddressBook.end(); ++it) {
        std::string addr = it->first;
        if (isSparkAddress(addr)) 
        {
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("addressType", "Spark"));
            item.push_back(Pair("address", addr));
            item.push_back(Pair("label", it->second.name));
            item.push_back(Pair("purpose", it->second.purpose.empty()? "unknown":it->second.purpose));
            item.push_back(Pair("createdAt", it->second.nCreatedAt));
            addressBook.push_back(item);
        }
    }

    return addressBook;
}

UniValue editaddressbook(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;
    LOCK(pwalletMain->cs_wallet);
    if (find_value(data, "action").isNull()) 
    {
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    std::string action = find_value(data, "action").getValStr();
    if (action != "add" && action != "edit" && action != "delete") 
    {
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    if (find_value(data, "address").isNull()) 
    {
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    std::string address = find_value(data, "address").getValStr();

    CTxDestination inputAddress = CBitcoinAddress(address).Get();
    // Refuse to set invalid address, set error status and return false
    if(boost::get<CNoDestination>(&inputAddress) && !isSparkAddress(address))
    {
       throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    if (action != "delete") 
    {
        if (find_value(data, "label").isNull() || find_value(data, "purpose").isNull()) 
        {
            throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
        }
        if (action == "add") 
        {
            if(isSparkAddress(address)) {
                pwalletMain->SetSparkAddressBook(address, find_value(data, "label").getValStr(), find_value(data, "purpose").getValStr());
            } else {
                pwalletMain->SetAddressBook(inputAddress, find_value(data, "label").getValStr(), find_value(data, "purpose").getValStr());
            }
        }
        else {
            if (find_value(data, "updatedlabel").isNull() || find_value(data, "updatedaddress").isNull()) {
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
            }
            std::string updatedLabel = find_value(data, "updatedlabel").getValStr();
            std::string updatedStrAddress = find_value(data, "updatedaddress").getValStr();
            CTxDestination updatedAddress = CBitcoinAddress(updatedStrAddress).Get();
            if(boost::get<CNoDestination>(&updatedAddress) && !isSparkAddress(updatedStrAddress)) 
            {
                throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            if(isSparkAddress(updatedStrAddress)) {
                pwalletMain->SetSparkAddressBook(updatedStrAddress, updatedLabel, find_value(data, "purpose").getValStr());
            } else {
                pwalletMain->SetAddressBook(updatedAddress, updatedLabel, find_value(data, "purpose").getValStr());
            }
        }
    } else {
        pwalletMain->DelAddressBook(address);
    }

    // If we're manipulating the default payment request address, create a new one to take our place.
    CWalletDB walletdb(pwalletMain->strWalletFile);
    if(isSparkAddress(address)) {
        std::string defaultPaymentRequestAddress;
        walletdb.ReadPaymentRequestSparkAddress(defaultPaymentRequestAddress);
        if (defaultPaymentRequestAddress == address) {
            spark::Address newaddress = pwalletMain->sparkWallet->generateNewAddress();
            unsigned char network = spark::GetNetworkType();
            pwalletMain->SetSparkAddressBook(newaddress.encode(network), "", "receive");
            walletdb.WritePaymentRequestSparkAddress(newaddress.encode(network));
        }
    } else {
        std::string defaultPaymentRequestAddress;
        walletdb.ReadPaymentRequestAddress(defaultPaymentRequestAddress);
        if (defaultPaymentRequestAddress == address) {
            CPubKey newKey;
            if (!pwalletMain->GetKeyFromPool(newKey))
                throw JSONAPIError(API_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
            CKeyID keyID = newKey.GetID();
            pwalletMain->SetAddressBook(keyID, "", "receive");
            CBitcoinAddress newPaymentRequestAddress {keyID};
            walletdb.WritePaymentRequestAddress(newPaymentRequestAddress.ToString());
        }
    }

    return true;
}

UniValue validateSparkAddress(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    std::string address = find_value(data, "address").getValStr();
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    unsigned char coinNetwork;
    spark::Address addr(params);
    UniValue retval(UniValue::VOBJ);
    try {
        coinNetwork = addr.decode(address);
    } catch (...) {
        retval.push_back(Pair("valid", false));
        return retval;
    }
    retval.push_back(Pair("valid", network == coinNetwork));
    return retval;
}

UniValue getAvailableSparkBalance(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("amount", pwalletMain->GetAvailableSparkBalance()));
    return retval;
}

UniValue getUnconfirmedSparkBalance(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("amount", pwalletMain->GetUnconfirmedSparkBalance()));
    return retval;
}

bool isSparkAddress(const std::string& address)
{
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    unsigned char coinNetwork;
    spark::Address addr(params);
    try {
        coinNetwork = addr.decode(address);
    } catch (...) {
        return false;
    }
    return network == coinNetwork;
}

static const CAPICommand commands[] =
{ //  category              collection                        actor (function)                 authPort   authPassphrase   warmupOk
  //  --------------------- ------------                      ----------------                 --------   --------------   --------
    { "wallet",             "lockWallet",                     &lockwallet,                     true,      false,           false  },
    { "wallet",             "unlockWallet",                   &unlockwallet,                   true,      false,           false  },
    { "wallet",             "stateWallet",                    &statewallet,                    true,      false,           false  },
    { "wallet",             "setPassphrase",                  &setpassphrase,                  true,      false,           false  },
    { "wallet",             "lockCoins",                      &lockcoins,                      true,      false,           false  },
    { "wallet",             "writeShowMnemonicWarning",       &writeshowmnemonicwarning,       true,      false,           false  },
    { "wallet",             "readWalletMnemonicWarningState", &readwalletmnemonicwarningstate, true,      false,           false  },
    { "wallet",             "showMnemonics",                  &showmnemonics,                  true,      true,            false  },
    { "wallet",             "verifyMnemonicValidity",         &verifymnemonicvalidity,         true,      false,           false  },
    { "wallet",             "readAddressBook",                &readaddressbook,                true,      false,           false  },
    { "wallet",             "editAddressBook",                &editaddressbook,                true,      false,           false  },
    { "wallet",             "lockStatus",                     &lockStatus,                     true,      false,           false  },
    { "wallet",             "validateSparkAddress",           &validateSparkAddress,           true,      false,           false  },
    { "wallet",             "getAvailableSparkBalance",       &getAvailableSparkBalance,       true,      false,           false  },
    { "wallet",             "getUnconfirmedSparkBalance",     &getUnconfirmedSparkBalance,     true,      false,           false  },
};
void RegisterWalletAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
