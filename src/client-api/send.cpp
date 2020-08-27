// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "validation.h"
#include "send.h"
#include "client-api/server.h"
#include "util.h"
#include "init.h"
#include "net.h"
#include "wallet/wallet.h"
#include <client-api/wallet.h>
#include "client-api/protocol.h"
#include "rpc/server.h"
#include "univalue.h"
#include "wallet/coincontrol.h"
#include <fstream>

namespace fs = boost::filesystem;
using namespace boost::chrono;
using namespace std;

std::map<std::string, int> nStates = {
        {"active",0},
        {"deleted",1},
        {"hidden",2},
        {"archived",3}
};

bool setPaymentRequest(UniValue paymentRequestUni){
    //write back UniValue
    fs::path const &path = CreatePaymentRequestFile();

    std::ofstream paymentRequestOut(path.string());

    paymentRequestOut << paymentRequestUni.write(4,0) << endl;

    return true;
}

bool getPaymentRequest(UniValue &paymentRequestUni, UniValue &paymentRequestData){
    fs::path const &path = CreatePaymentRequestFile();

    // get data as ifstream
    std::ifstream paymentRequestIn(path.string());

    // parse as std::string
    std::string paymentRequestStr((std::istreambuf_iterator<char>(paymentRequestIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    paymentRequestUni.read(paymentRequestStr);
    LogPrintf("paymentRequest: %s\n", paymentRequestUni.write());

    if(!paymentRequestUni["data"].isNull()){
        paymentRequestData = paymentRequestUni["data"];
    }
    
    return true;
}

bool setTxFee(const UniValue& feeperkb){
    CAmount nAmount = feeperkb.get_int64();

    payTxFee = CFeeRate(nAmount, 1000);

    return true;
}

UniValue getNewAddress()
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONAPIError(API_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, "", "receive");

    return CBitcoinAddress(keyID).ToString();
}


UniValue paymentrequestaddress(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    UniValue ret(UniValue::VOBJ);
    std::string address = "";
    CWalletDB walletdb(pwalletMain->strWalletFile);
    if(!walletdb.ReadPaymentRequestAddress(address)){
       address = getNewAddress().get_str();
       walletdb.WritePaymentRequestAddress(address);
    }
    ret.push_back(Pair("address", address));
    return ret;
}

UniValue sendzcoin(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{   
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CCoinControl cc;
    bool hasCoinControl = GetCoinControl(data, cc);

    switch(type){
        case Create: {
            UniValue feePerKb;
            UniValue sendTo(UniValue::VOBJ);
            bool fSubtractFeeFromAmount;
            try{
                feePerKb = find_value(data,"feePerKb");
                sendTo = find_value(data,"addresses").get_obj();
                fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();
            }catch (const std::exception& e){
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
            }

            UniValue txid(UniValue::VOBJ);
            setTxFee(feePerKb);

            int nMinDepth = 1;

            CWalletTx wtx;

            set<CBitcoinAddress> setAddress;
            vector<CRecipient> vecSend;

            CAmount totalAmount = 0;
            vector<string> keys = sendTo.getKeys();
            BOOST_FOREACH(const string& name_, keys)
            {
                
                UniValue entry(UniValue::VOBJ);
                try{
                    entry = find_value(sendTo, name_).get_obj();
                }catch (const std::exception& e){
                    throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
                }

                CBitcoinAddress address(name_);
                if (!address.IsValid())
                    throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

                if (setAddress.count(address))
                    throw JSONAPIError(API_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
                setAddress.insert(address);

                CScript scriptPubKey = GetScriptForDestination(address.Get());
                CAmount nAmount = find_value(entry, "amount").get_int64();
                string label = find_value(entry, "label").get_str();
                if (nAmount <= 0)
                    throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
                totalAmount += nAmount;

                wtx.mapValue["label"] = label;

                CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }

            // Try each of our accounts looking for one with enough balance
            vector<string> accounts = GetMyAccountNames();
            bool isValid = false;
            BOOST_FOREACH(string strAccount, accounts){      
                CAmount nBalance = pwalletMain->GetAccountBalance(strAccount, nMinDepth, ISMINE_ALL);
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
                throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, "No account has sufficient funds. Consider moving enough funds to a single account");
            }
            
            // Send
            CReserveKey keyChange(pwalletMain);
            CAmount nFeeRequired = 0;
            int nChangePosRet = -1;
            string strFailReason;
            bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, hasCoinControl? (&cc):NULL);
            if (!fCreated)
                throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);

            string txidStr = wtx.GetHash().GetHex();

            CValidationState state;
            if (!pwalletMain->CommitTransaction(wtx, keyChange, g_connman.get(), state))
                throw JSONAPIError(API_WALLET_ERROR, "Transaction commit failed");

            txid.push_back(Pair("txid", txidStr));
            return txid;
        }
        default: {

        }
    }

    return NullUniValue;
}

UniValue txfee(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    // first set the tx fee per kb, then return the total fee with addresses.   
    if (!EnsureWalletIsAvailable(pwalletMain, fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VOBJ);
    UniValue feePerKb;
    UniValue sendTo(UniValue::VOBJ);
    bool fSubtractFeeFromAmount;
    try{
        feePerKb = find_value(data, "feePerKb");
        sendTo = find_value(data, "addresses").get_obj();
        fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();
    }catch (const std::exception& e){
        throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
    }
    setTxFee(feePerKb);

    CWalletTx wtx;
    wtx.strFromAccount = "";

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONAPIError(API_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount;
        try{
            nAmount = sendTo[name_].get_int64();
        }catch (const std::exception& e){
            throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
        }

        LogPrintf("nAmount getTransactionFee: %s\n", nAmount);
        if (nAmount <= 0)
            throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, NULL, false);
    if (!fCreated)
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);  
    
    ret.push_back(Pair("fee", nFeeRequired));
    LogPrintf("Transaction fee:%d\n", nFeeRequired);
    return ret;
}

UniValue paymentrequest(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    UniValue paymentRequestUni(UniValue::VOBJ);
    UniValue paymentRequestData(UniValue::VOBJ);

    getPaymentRequest(paymentRequestUni, paymentRequestData);

    bool returnEntry = false;
    UniValue entry(UniValue::VOBJ);

    switch(type){
        case Initial: {
            return paymentRequestData;
            break;
        }
        case Create: {     

            milliseconds secs = duration_cast< milliseconds >(
                 system_clock::now().time_since_epoch()
            );
            UniValue createdAt = secs.count();

            std::string paymentRequestAddress;
            entry.push_back(Pair("createdAt", createdAt.get_int64()));
            entry.push_back(Pair("state", "active"));

            try{
                paymentRequestAddress = find_value(data, "address").get_str();
                entry.push_back(Pair("amount", find_value(data, "amount")));
                entry.push_back(Pair("address", paymentRequestAddress));
                entry.push_back(Pair("message", find_value(data, "message").get_str()));
                entry.push_back(Pair("label", find_value(data, "label").get_str()));
            }catch (const std::exception& e){
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
            }
            
            CWalletDB walletdb(pwalletMain->strWalletFile);
            std::string nextPaymentRequestAddress;
            if(!walletdb.ReadPaymentRequestAddress(nextPaymentRequestAddress))
                throw runtime_error("Could not retrieve wallet payment address.");

            if(nextPaymentRequestAddress != paymentRequestAddress)
                throw runtime_error("Payment request address passed does not match wallet.");

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            returnEntry = true;

            // remove payment request address
            if(!walletdb.ErasePaymentRequestAddress())
                throw runtime_error("Could not reset payment request address.");
                    
            break;
        }
        case Delete: {
            string id = find_value(data, "id").get_str();
            
            const UniValue addressObj = find_value(paymentRequestData, id);
            if(addressObj.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid data, id does not exist");
            }

            const UniValue addressStr = find_value(addressObj, "address");
            if(addressStr.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid data, address not found");
            }

            paymentRequestData.erase(addressStr);

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            return true;
            break;      
        }
        /*
          "Update" can be used to either:
            - Update an existing address and metadata associated with a payment request
            - Create a new entry for address and metadata that was NOT created through a payment request (eg. created with the Qt application).
        */
        case Update: {
            string id;
            std::vector<std::string> dataKeys;
            try{
                id = find_value(data, "id").get_str();
                dataKeys = data.getKeys();
            }catch (const std::exception& e){
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
            }

            entry = find_value(paymentRequestData, id);

            // If null, declare the object again.
             if(entry.isNull()){
                 entry.setObject();
                 entry.push_back(Pair("address", id));
             }

            for (std::vector<std::string>::iterator it = dataKeys.begin(); it != dataKeys.end(); it++){
                string key = (*it);
                UniValue value = find_value(data, key);
                if(!(key=="id")){
                    if(key=="state"){
                        // Only update state should it be a valid value
                        if(!(value.getType()==UniValue::VSTR) && !nStates.count(value.get_str()))
                          throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
                    }
                    entry.replace(key, value); //todo might have to specify type
                }
            }

            paymentRequestData.replace(id, entry);

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            returnEntry = true;
            break;
        }
        default: {

        }
    }

    setPaymentRequest(paymentRequestUni);

    if(returnEntry){
        return entry;
    }

    return true;
}

static void SendMoney(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    // Parse Zcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee");
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

UniValue sendtopaymentcode(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CCoinControl cc;
    bool hasCoinControl = GetCoinControl(data, cc);
    string pcodeString = find_value(data, "paymentCode").get_str();
    string myPCodeString = find_value(data, "myPaymentCode").get_str();
    int accIndex = pwalletMain->getBIP47AccountIndex(myPCodeString);

    CPaymentCode paymentCode(pcodeString);

    // Amount
    CAmount nAmount = find_value(data, "amount").get_int64();
    UniValue feePerKb;
    bool fSubtractFeeFromAmount;
    feePerKb = find_value(data,"feePerKb");
    fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();
    
    CBIP47PaymentChannel* channel = pwalletMain->getPaymentChannelFromPaymentCode(paymentCode.toString(), myPCodeString);
    
    if (channel->isNotificationTransactionSent()) 
    {
        std::string addressTo = pwalletMain->getCurrentOutgoingAddress(*channel);
        CBitcoinAddress pcAddress(addressTo);
        CWalletTx wtx;

        channel->addAddressToOutgoingAddresses(addressTo);
        channel->incrementOutgoingIndex();
        SendMoney(pwalletMain, pcAddress.Get(), nAmount, fSubtractFeeFromAmount, wtx);
        pwalletMain->savePaymentCode(pcodeString);
        pwalletMain->saveCBIP47PaymentChannelData(pcodeString);

        return wtx.GetHash().GetHex();
    }
    else
    {
        return pwalletMain->makeNotificationTransaction(paymentCode.toString(), accIndex);
    }   
}


static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "send",            "paymentRequest",         &paymentrequest,         true,      false,           false  },
    { "send",            "paymentRequestAddress",  &paymentrequestaddress,  true,      false,           false  },
    { "send",            "txFee",                  &txfee,                  true,      false,           false  },
    { "send",            "sendZcoin",              &sendzcoin,              true,      true,            false  },
    { "send",            "sendToPaymentCode",              &sendtopaymentcode,              true,      true,            false  }
};

void RegisterSendAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
