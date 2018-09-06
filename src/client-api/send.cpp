// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "main.h"
#include "client-api/server.h"
#include "util.h"
#include "wallet/wallet.h"
#include <client-api/wallet.h>
#include <client-api/protocol.h>
#include "rpc/server.h"
#include <univalue.h>

namespace fs = boost::filesystem;
using namespace std::chrono;
using namespace std;

UniValue getPaymentRequest(string address){
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

    UniValue entry(UniValue::VOBJ);

    entry = find_value(paymentRequestData, address);

    return entry;

}

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
        throw JSONAPIError(API_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, "", "receive");

    return CBitcoinAddress(keyID).ToString();
}

UniValue sendzcoin(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue feeperkb = find_value(data,"feePerKb");
    UniValue txid(UniValue::VOBJ);
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
        UniValue entry(UniValue::VOBJ);
        entry = find_value(sendTo, name_).get_obj();

        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONAPIError(API_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = find_value(entry, "amount").get_int64();
        LogPrintf("nAmount sendmanyfromany: %s\n", nAmount);
        if (nAmount <= 0)
            throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
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
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONAPIError(API_WALLET_ERROR, "Transaction commit failed");

    txid.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return txid;
}

UniValue txfee(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    // first set the tx fee per kb, then return the total fee with addresses.   
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    UniValue ret(UniValue::VOBJ);

    UniValue feeperkb = find_value(data, "feePerKb");

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
            throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONAPIError(API_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = sendTo[name_].get_int64();
        LogPrintf("nAmount gettransactionfee: %s\n", nAmount);
        if (nAmount <= 0)
            throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
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
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    
    LogPrintf("API: returning from txfee\n");
    ret.push_back(Pair("fee", nFeeRequired));
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

    LogPrintf("API: data in write: %s\n", data.write());

    bool returnEntry = false;
    UniValue entry(UniValue::VOBJ);

    switch(type){
        case Initial: {
            LogPrintf ("API: returning initial layout..\n");
            return paymentRequestData;
            break; 
        }
        case Create: {     
            UniValue newAddress = getNewAddress();
            milliseconds secs = duration_cast< milliseconds >(
                 system_clock::now().time_since_epoch()
            );
            UniValue createdAt = secs.count();

            LogPrintf("data write: %s\n", data.write());
            entry.push_back(Pair("address", newAddress.get_str()));
            entry.push_back(Pair("createdAt", createdAt.get_int64()));
            entry.push_back(Pair("amount", find_value(data, "amount")));
            entry.push_back(Pair("message", find_value(data, "message").get_str()));
            entry.push_back(Pair("label", find_value(data, "label").get_str()));
            

            paymentRequestData.push_back(Pair(newAddress.get_str(), entry));
            LogPrintf("paymentRequestData write: %s\n", paymentRequestData.write());

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            returnEntry = true;
            break;
        }
        case Delete: {
            string id = find_value(data, "id").get_str();
            
            const UniValue addressObj = find_value(paymentRequestData, id);
            if(addressObj.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid data, id does not exist");
            }  

            const UniValue addressStr = find_value(addressObj, "address");

            paymentRequestData.erase(addressStr);

            if(!paymentRequestUni.replace("data", paymentRequestData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            return true;
            break;      
        }

        case Update: {
            string id = find_value(data, "id").get_str();
            entry = find_value(paymentRequestData, id);
            if(entry.isNull()){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid data, id does not exist");
            }

            std::vector<std::string> dataKeys = data.getKeys();

            for (std::vector<std::string>::iterator it = dataKeys.begin(); it != dataKeys.end(); it++){
                string key = (*it);
                if(!(key=="id")){
                    entry.replace(key, find_value(data, key)); //todo might have to specify type
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

    //write back UniValue
    std::ofstream paymentRequestOut(path.string());

    paymentRequestOut << paymentRequestUni.write(4,0) << endl;

    if(returnEntry){
        return entry;
    }

    return true;
}


static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "send",            "paymentRequest",  &paymentrequest,          true,      false,           false  },
    { "send",            "txFee",           &txfee,                   true,      false,           false  },
    { "send",            "sendZcoin",       &sendzcoin,               true,      true,            false  }
};

void RegisterSendAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}