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
#include "client-api/bigint.h"
#include "rpc/server.h"
#include "univalue.h"
#include "wallet/coincontrol.h"
#include <fstream>

namespace fs = boost::filesystem;
using namespace boost::chrono;

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

    paymentRequestOut << paymentRequestUni.write(4,0) << std::endl;

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

UniValue getNewSparkAddress()
{
    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    spark::Address address = pwalletMain->sparkWallet->generateNewAddress();
    unsigned char network = spark::GetNetworkType();
    pwalletMain->SetSparkAddressBook(address.encode(network), "", "receive");

    return address.encode(network);
}

UniValue paymentrequestaddress(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    if (!EnsureWalletIsAvailable(pwalletMain, false))
        return NullUniValue;

    std::string addressType = find_value(data, "addressType").getValStr();
    UniValue ret(UniValue::VOBJ);
    std::string address = "";
    CWalletDB walletdb(pwalletMain->strWalletFile);

    if(addressType == "Spark") {
        address = getNewSparkAddress().get_str();
    } else if (addressType == "Transparent") {
        address = getNewAddress().get_str();
    } else {
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid addressType");
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
            UniValue sendTo(UniValue::VOBJ);
            bool fSubtractFeeFromAmount;
            payTxFee = CFeeRate(get_bigint(data["feePerKb"]));
            sendTo = find_value(data,"addresses").get_obj();
            fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();

            int nMinDepth = 1;

            CWalletTx wtx;

            std::set<CBitcoinAddress> setAddress;
            std::vector<CRecipient> vecSend;

            CAmount totalAmount = 0;
            std::vector<std::string> keys = sendTo.getKeys();
            BOOST_FOREACH(const std::string& name_, keys)
            {

                UniValue entry(UniValue::VOBJ);
                try{
                    entry = find_value(sendTo, name_).get_obj();
                }catch (const std::exception& e){
                    throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
                }

                CBitcoinAddress address(name_);
                if (!address.IsValid())
                    throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, std::string("Invalid zcoin address: ")+name_);

                if (setAddress.count(address))
                    throw JSONAPIError(API_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+name_);
                setAddress.insert(address);

                CScript scriptPubKey = GetScriptForDestination(address.Get());
                CAmount nAmount = get_bigint(entry["amount"]);
                std::string label = find_value(entry, "label").get_str();
                if (nAmount <= 0)
                    throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
                totalAmount += nAmount;

                wtx.mapValue["label"] = label;

                CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }

            // Send
            CReserveKey keyChange(pwalletMain);
            CAmount nFeeRequired = 0;
            int nChangePosRet = -1;
            std::string strFailReason;
            bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, hasCoinControl? (&cc):NULL);
            if (!fCreated)
                throw JSONAPIError(API_WALLET_ERROR, strFailReason);

            CValidationState state;
            if (!pwalletMain->CommitTransaction(wtx, keyChange, g_connman.get(), state))
                throw JSONAPIError(API_WALLET_ERROR, "Transaction commit failed");

            GetMainSignals().WalletTransaction(wtx);

            UniValue retval(UniValue::VOBJ);
            retval.push_back(Pair("txid",  wtx.GetHash().GetHex()));
            return retval;
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

    CCoinControl coinControl;
    bool hasCoinControl = GetCoinControl(data, coinControl);

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

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    BOOST_FOREACH(const std::string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, std::string("Invalid zcoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONAPIError(API_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+name_);
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
    std::string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, hasCoinControl ? &coinControl : NULL, false);
    if (!fCreated)
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, strFailReason);

    ret.push_back(Pair("fee", nFeeRequired));
    return ret;
}


static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "send",            "paymentRequestAddress",  &paymentrequestaddress,  true,      false,           false  },
    { "send",            "txFee",                  &txfee,                  true,      false,           false  },
    { "send",            "sendZcoin",              &sendzcoin,              true,      true,            false  }

};

void RegisterSendAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
