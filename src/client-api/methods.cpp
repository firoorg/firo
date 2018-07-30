// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "client-api/server.h"
#include "streams.h"
#include "znode-sync.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.cpp"
#include <stdint.h>
#include <client-api/protocol.h>
#include <zmqserver.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

namespace fs = boost::filesystem;
using namespace std::chrono;
using namespace std;

bool setTxFee(const UniValue& feeperkb){
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CAmount nAmount = feeperkb.get_int64();

    payTxFee = CFeeRate(nAmount, 1000);

    return true;
}

UniValue getNewAddress()
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, "", "receive");

    return CBitcoinAddress(keyID).ToString();
}

UniValue getBlockHeight(const string strHash)
{
    LOCK(cs_main);

    uint256 hash(uint256S(strHash));

    if (mapBlockIndex.count(hash) == 0)
        return -1;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    return pblockindex->nHeight;
}

void APIWalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
        entry.push_back(Pair("blockheight", getBlockHeight(wtx.hashBlock.GetHex())));
    } 

    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void ListAPITransactions(const CWalletTx& wtx, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    CBitcoinAddress addr;
    string addrStr;
    CTxOut txout;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    // Sent
    if ((!listSent.empty() || nFee != 0))
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
        {   
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue categories(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            uint256 txid = wtx.GetHash();
            if (addr.Set(s.destination)){
                addrStr = addr.ToString();
            }

            string category;
            
            if(wtx.IsZerocoinMint(txout)){
                category = "mint";
                addrStr = "ZEROCOIN_MINT";
                if(pwalletMain){
                    entry.push_back(Pair("used", pwalletMain->IsMintFromTxOutUsed(txout)));
                }
            }
            else if(wtx.IsZerocoinSpend()){
                category = "spend";                
            }
            else {
                category = "send";
            }
            entry.push_back(Pair("category", category));
            entry.push_back(Pair("address", addrStr));

            CAmount amount = ValueFromAmount(s.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name));
            entry.push_back(Pair("fee", ValueFromAmount(nFee).get_real() * COIN));
            APIWalletTxToJSON(wtx, entry);


            if(!ret[addrStr].isNull()){
                address = ret[addrStr];
            }

            if(!address["total"].isNull()){
                total = address["total"];
            }

            if(!address["txids"].isNull()){
                txids = address["txids"];
            }

            if(!txids[category].isNull()){
                categories = txids[category];
            }

            if(!total["sent"].isNull()){
                UniValue totalSent = find_value(total, "sent");
                UniValue newTotal = totalSent.get_real() + amount;
                total.replace("sent", newTotal);
            }
            else{
                total.push_back(Pair("sent", amount));
            }
            categories.replace(txid.GetHex(), entry);
            txids.replace(category, categories);
            address.replace("total", total);
            address.replace("txids", txids);
            ret.replace(addrStr, address);
        }
    }

    //Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= 0)
    {
       // LogPrintf("api: in list received \n");
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue categories(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            string account;
            if (pwalletMain->mapAddressBook.count(r.destination)){
                account = pwalletMain->mapAddressBook[r.destination].name;
            }

            uint256 txid = wtx.GetHash();
            string category;
            if (addr.Set(r.destination)){
                addrStr = addr.ToString();
                entry.push_back(Pair("address", addr.ToString()));
            }
            if (wtx.IsCoinBase())
            {
                int txHeight = chainActive.Height() - wtx.GetDepthInMainChain();
                CScript payee;

                mnpayments.GetBlockPayee(txHeight, payee);
                //compare address of payee to addr. 
                CTxDestination payeeDest;
                ExtractDestination(payee, payeeDest);
                CBitcoinAddress payeeAddr(payeeDest);
                if(addr.ToString() == payeeAddr.ToString()){
                    category = "znode";
                }
                else if (wtx.GetDepthInMainChain() < 1)
                    category = "orphan";
                else
                    category = "mined";
            }
            else if(wtx.IsZerocoinSpend()){
                category = "spend";
            }
            else {
                category = "receive";
            }
            entry.push_back(Pair("category", category));

            CAmount amount = ValueFromAmount(r.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));
            if (pwalletMain->mapAddressBook.count(r.destination))
                entry.push_back(Pair("label", account));

            APIWalletTxToJSON(wtx, entry);

            if(!ret[addrStr].isNull()){
                address = ret[addrStr];
            }

            if(!address["total"].isNull()){
                total = address["total"];
            }

            if(!address["txids"].isNull()){
                txids = address["txids"];
            }

            if(!txids[category].isNull()){
                categories = txids[category];
            }

            if(!total["balance"].isNull()){
                UniValue totalBalance = find_value(total, "balance");
                UniValue newTotal = totalBalance.get_real() + amount;
                total.replace("balance", newTotal);
            }
            else{
                total.push_back(Pair("balance", amount));
            }
            
            categories.replace(txid.GetHex(), entry);
            txids.replace(category, categories);
            address.replace("total", total);
            address.replace("txids", txids);

            ret.replace(addrStr, address);
        }
    }
}

UniValue StateSinceBlock(UniValue& ret, std::string block){

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;

    blockId.SetHex(block); //set block hash
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end())
        pindex = it->second;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VOBJ);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListAPITransactions(tx, transactions, filter);
    }

    ret.push_back(Pair("addresses", transactions));

    return ret;
}


UniValue sendzcoin(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    LogPrintf("API: in sendzcoin\n");
    UniValue feeperkb = find_value(data,"feeperkb");
    setTxFee(feeperkb);

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue sendTo = find_value(data,"addresses").get_obj();
    int nMinDepth = 1;

    CWalletTx wtx;

    UniValue subtractFeeFromAmount(UniValue::VARR);

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = sendTo[name_].get_int64();
        LogPrintf("nAmount sendmanyfromany: %s\n", nAmount);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    // Try each of our accounts looking for one with enough balance
    vector<string> accounts = GetMyAccountNames();
    bool isValid = false;
    BOOST_FOREACH(string strAccount, accounts){      
        CAmount nBalance = pwalletMain->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
        LogPrintf("nBalance: %s\n", nBalance);
        LogPrintf("totalAmount: %s\n", totalAmount);
        if (totalAmount <= nBalance){
           LogPrintf("ZMQ: found valid address. address: %s\n", strAccount);
           wtx.strFromAccount = strAccount;
           isValid = true; 
           break;
        }
    }
    if(!isValid){
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No account has sufficient funds. Consider moving enough funds to a single account");
    }
    
    // Send
    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}



UniValue txfee(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    // first set the tx fee per kb, then return the total fee with addresses.   
    LogPrintf("API: in txfee\n");
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    UniValue feeperkb = find_value(data, "feeperkb");

    setTxFee(feeperkb);

    LOCK2(cs_main, pwalletMain->cs_wallet);
    
    UniValue sendTo = find_value(data, "addresses").get_obj();

    CWalletTx wtx;
    wtx.strFromAccount = "";

    UniValue subtractFeeFromAmount(UniValue::VARR);

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = sendTo[name_].get_int64();
        LogPrintf("nAmount gettransactionfee: %s\n", nAmount);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked();

    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    
    LogPrintf("API: returning from txfee\n");
    return nFeeRequired;
}


UniValue mint(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    //TODO verify enough balance available before starting to mint.
    UniValue txids(UniValue::VARR);

    int64_t denomination_int = 0;
    libzerocoin::CoinDenomination denomination;

    UniValue sendTo = data[0].get_obj();

    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& denomination_str, keys){

        denomination_int = stoi(denomination_str.c_str());

        switch(denomination_int){
            case 1:
                denomination = libzerocoin::ZQ_LOVELACE;
                break;
            case 10:
                denomination = libzerocoin::ZQ_GOLDWASSER;
                break;
            case 25:
                denomination = libzerocoin::ZQ_RACKOFF;
                break;
            case 50:
                denomination = libzerocoin::ZQ_PEDERSEN;
                break;
            case 100:
                denomination = libzerocoin::ZQ_WILLIAMSON;                                                
                break;
            default:
                throw runtime_error(
                    "mintzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
        }


        int64_t amount = sendTo[denomination_str].get_int();

        LogPrintf("rpcWallet.mintzerocoin() denomination = %s, nAmount = %s \n", denomination_str, amount);

        

        if(amount < 0){
                throw runtime_error(
                    "mintzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
        }

        for(int64_t i=0; i<amount; i++){
            bool valid_coin = false;
            // Always use modulus v2
            libzerocoin::Params *zcParams = ZCParamsV2;
            //do {
            // The following constructor does all the work of minting a brand
            // new zerocoin. It stores all the private values inside the
            // PrivateCoin object. This includes the coin secrets, which must be
            // stored in a secure location (wallet) at the client.
            libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
            // Get a copy of the 'public' portion of the coin. You should
            // embed this into a Zerocoin 'MINT' transaction along with a series
            // of currency inputs totaling the assigned value of one zerocoin.
            
            libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();
            
            //Validate
            valid_coin = pubCoin.validate();

            // loop until we find a valid coin
            while(!valid_coin){
                libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
                libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();
                valid_coin = pubCoin.validate();
            }

            // Validate
            CScript scriptSerializedCoin =
                    CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

            // Wallet comments
            CWalletTx wtx;

            string strError = pwalletMain->MintZerocoin(scriptSerializedCoin, (denomination_int * COIN), wtx);

            if (strError != "")
                throw JSONRPCError(RPC_WALLET_ERROR, strError);

            CWalletDB walletdb(pwalletMain->strWalletFile);
            CZerocoinEntry zerocoinTx;
            zerocoinTx.IsUsed = false;
            zerocoinTx.denomination = denomination;
            zerocoinTx.value = pubCoin.getValue();
            libzerocoin::PublicCoin checkPubCoin(zcParams, zerocoinTx.value, denomination);
            if (!checkPubCoin.validate()) {
                return false;
            }
            zerocoinTx.randomness = newCoin.getRandomness();
            zerocoinTx.serialNumber = newCoin.getSerialNumber();
            const unsigned char *ecdsaSecretKey = newCoin.getEcdsaSeckey();
            zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
            walletdb.WriteZerocoinEntry(zerocoinTx);

            txids.push_back(wtx.GetHash().GetHex());
        }
    }

    return txids;
}

UniValue sendprivate(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {

    switch(type){
        case Create: {
            UniValue txids(UniValue::VARR);

            LOCK2(cs_main, pwalletMain->cs_wallet);

            int64_t denomination_in = 0;
            libzerocoin::CoinDenomination denomination;

            UniValue inputs = find_value(data, "denominations");

            for(size_t i=0; i<inputs.size();i++) {

                const UniValue& input_obj = inputs[i].get_obj();

                int amount = find_value(input_obj, "amount").get_int();

                denomination_in = find_value(input_obj, "denomination").get_int();

                string address_str = find_value(input_obj, "address").get_str();

                switch(denomination_in){
                    case 1:
                        denomination = libzerocoin::ZQ_LOVELACE;
                        break;
                    case 10:
                        denomination = libzerocoin::ZQ_GOLDWASSER;
                        break;
                    case 25:
                        denomination = libzerocoin::ZQ_RACKOFF;
                        break;
                    case 50:
                        denomination = libzerocoin::ZQ_PEDERSEN;
                        break;
                    case 100:
                        denomination = libzerocoin::ZQ_WILLIAMSON;                                                
                        break;
                    default:
                        throw runtime_error(
                            "spendmanyzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
                }

                string thirdPartyaddress = "";
                if (!(address_str == "")){
                    CBitcoinAddress address(address_str);
                    if (!address.IsValid())
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address");
                    thirdPartyaddress = address_str;
                }

                EnsureWalletIsUnlocked();

                // Wallet comments
                CWalletTx wtx;
                CBigNum coinSerial;
                uint256 txHash;
                CBigNum zcSelectedValue;
                bool zcSelectedIsUsed;

                for(int j=0;j<amount;j++) {

                    string strError = pwalletMain->SpendZerocoin(thirdPartyaddress, 
                                                                (denomination_in * COIN), denomination, wtx, coinSerial, txHash, zcSelectedValue,
                                                                 zcSelectedIsUsed);

                    if (strError != "")
                        throw JSONRPCError(RPC_WALLET_ERROR, strError);

                    txids.push_back(wtx.GetHash().GetHex());
                }
            }

            return txids;
        }
        default: {
           throw JSONRPCError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it."); 
        }
    }
}


UniValue apistatus(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    UniValue obj(UniValue::VOBJ);
    UniValue modules(UniValue::VOBJ);

    modules.push_back(Pair("API", !APIIsInWarmup()));

    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    }
    if (pwalletMain && pwalletMain->IsCrypted()){
        obj.push_back(Pair("walletlock",    "true"));
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    }
    obj.push_back(Pair("datadir",       GetDataDir(true).string()));
    obj.push_back(Pair("network",       ChainNameFromCommandLine()));
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("devauth",       DEV_AUTH));
    obj.push_back(Pair("synced",       znodeSync.IsBlockchainSynced()));
    obj.push_back(Pair("modules",       modules));

    return obj;
}

UniValue setpassphrase(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    // encrypt's the wallet should be the wallet be unencrypted.
    // if already encrypted, it checks for a `newpassphrase` field, and updates the passphrase accordingly.
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;

    switch(type){
        case Update: {
            if(pwalletMain && pwalletMain->IsCrypted()){
                SecureString strOldWalletPass;
                strOldWalletPass.reserve(100);
                strOldWalletPass = find_value(auth, "passphrase").get_str().c_str();

                SecureString strNewWalletPass;
                strNewWalletPass.reserve(100);
                strNewWalletPass = find_value(auth, "newpassphrase").get_str().c_str();

                if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
                    throw runtime_error(
                        "walletpassphrase <oldpassphrase> <newpassphrase>\n"
                        "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

                if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
                    throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

                return true;
            }
            else {
                throw JSONRPCError(API_WRONG_TYPE_CALLED, "Error: MODIFY type called, but wallet is unencrypted.");
            }
            break;
        }
        case Create: {
            if (pwalletMain->IsCrypted())
                throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

            SecureString strWalletPass;
            strWalletPass.reserve(100);
            strWalletPass = find_value(auth, "passphrase").get_str().c_str();

            if (strWalletPass.length() < 1)
                throw runtime_error(
                    "encryptwallet <passphrase>\n"
                    "Encrypts the wallet with <passphrase>.");

            if (!pwalletMain->EncryptWallet(strWalletPass))
                throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

            // BDB seems to have a bad habit of writing old data into
            // slack space in .dat files; that is bad if the old data is
            // unencrypted private keys. So:
            StartShutdown();
            return "wallet encrypted; zcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";   
            break;
        }
        default: {
            throw JSONRPCError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
        }
    }
    return true;
}

UniValue lockwallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (data.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletunlock again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

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
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in data[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make data[0] mlock()'d to begin with.

    LogPrintf("getting values \n");
    vector<UniValue> values = data.getValues();
    LogPrintf("values size: %s\n", to_string(values.size()));
    

    UniValue passphrase = find_value(auth, "passphrase");

    strWalletPass = passphrase.get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else //TODO length error
        throw runtime_error(
            "walletunlock <passphrase>\n"
            "Stores the wallet decryption key in memory.");

    pwalletMain->TopUpKeyPool();

    return true;
}

UniValue statewallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    UniValue ret(UniValue::VOBJ);

    std::string genesisBlock = chainActive[0]->GetBlockHash().ToString();

    StateSinceBlock(ret, genesisBlock);

    return ret;
}

UniValue paymentrequest(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    fs::path const &path = CreatePaymentRequestFile();
    LogPrintf("paymentrequest path: %s\n", path.string());

    // get data as ifstream
    std::ifstream paymentRequestIn(path.string());

    // parse as std::string
    std::string paymentRequestStr((std::istreambuf_iterator<char>(paymentRequestIn)), std::istreambuf_iterator<char>());
    LogPrintf("paymentRequestStr: %s\n", paymentRequestStr);

    // finally as UniValue
    UniValue paymentRequestUni(UniValue::VOBJ);
    paymentRequestUni.read(paymentRequestStr);
    LogPrintf("paymentRequestUni write: %s\n", paymentRequestUni.write());

    UniValue paymentRequestData(UniValue::VOBJ);
    if(!paymentRequestUni["data"].isNull()){
        paymentRequestData = paymentRequestUni["data"];
    }

    switch(type){
        case Initial: {
            return paymentRequestUni;
            break; 
        }
        case Create: {
            UniValue entry(UniValue::VOBJ);

            UniValue newAddress = getNewAddress();
            milliseconds ms = duration_cast< milliseconds >(
                 system_clock::now().time_since_epoch()
            );
            UniValue createdAt = to_string(ms.count());

            LogPrintf("data write: %s\n", data.write());
            entry.push_back(Pair("address", newAddress.get_str()));
            entry.push_back(Pair("created_at", createdAt.get_str()));
            entry.push_back(Pair("amount", find_value(data, "amount").get_real()));
            entry.push_back(Pair("message", find_value(data, "message").get_str()));
            entry.push_back(Pair("label", find_value(data, "label").get_str()));
            

            paymentRequestData.push_back(Pair(newAddress.get_str(), entry));
            LogPrintf("paymentRequestData write: %s\n", paymentRequestData.write());

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            break;
        }
        case Delete: {
            const UniValue id = find_value(data, "id");
            if(id.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid parameter, expected id");
            }

            const UniValue addressObj = find_value(paymentRequestData, id.get_str());
            if(addressObj.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid data, id does not exist");
            }  

            const UniValue addressStr = find_value(addressObj, "address");

            paymentRequestData.erase(addressStr);

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            break;      
        }

        case Update: {
            string id = find_value(data, "id").get_str();
            UniValue paymentRequestId(UniValue::VOBJ);
            paymentRequestId = find_value(paymentRequestData, id);
            if(paymentRequestId.isNull()){
                throw runtime_error("Invalid param.");
            }

            std::vector<std::string> dataKeys = data.getKeys();

            for (std::vector<std::string>::iterator it = dataKeys.begin(); it != dataKeys.end(); it++){
                string key = (*it);
                LogPrintf("key: %s\n",  key);
                if(!(key=="id")){
                    paymentRequestId.replace(key, find_value(data, key)); //todo might have to specify type
                }
            }

            paymentRequestData.replace(id, paymentRequestId);


            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }

            break;
        }
        default: {

        }
    }

    //write back UniValue
    std::ofstream paymentRequestOut(path.string());

    paymentRequestOut << paymentRequestUni.write(4,0) << endl;

    return true;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "misc",               "apistatus",       &apistatus,               false,     false,           true   },
    { "wallet",             "lockwallet",      &lockwallet,              true,      false,           false  },
    { "wallet",             "unlockwallet",    &unlockwallet,            true,      false,           false  },
    { "wallet",             "statewallet",     &statewallet,             true,      false,           false  },
    { "zerocoin",           "mint",            &mint,                    true,      true,            false  },
    { "zerocoin",           "sendprivate",     &sendprivate,             true,      true,            false  },
    { "sending",            "txfee",           &txfee,                   true,      true,            false  },
    { "sending",            "sendzcoin",       &sendzcoin,               true,      true,            false  },
    { "wallet",             "setpassphrase",   &setpassphrase,           true,      true,            false  },
    { "sending",            "paymentrequest",  &paymentrequest,          true,      true,            false  }
};
void RegisterAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
