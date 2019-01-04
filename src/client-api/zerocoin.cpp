// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "client-api/server.h"
#include "rpc/server.h"
#include "util.h"
#include "client-api/wallet.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "client-api/send.h"
#include "client-api/protocol.h"
#include <zerocoin.h>

#include "univalue.h"

using namespace std;

UniValue mintstatus(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    return data;
}

UniValue mint(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue ret(UniValue::VOBJ);

    int64_t denominationInt = 0;
    libzerocoin::CoinDenomination denomination;
    // Always use modulus v2
    libzerocoin::Params *zcParams = ZCParamsV2;

    vector<CRecipient> vecSend;
    vector<libzerocoin::PrivateCoin> privCoins;
    CWalletTx wtx;
    UniValue sendTo(UniValue::VOBJ);
    try {
        sendTo = data[0].get_obj();
    }catch (const std::exception& e){
        throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
    }

    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& denominationStr, keys){

        try {
            denominationInt = stoi(denominationStr.c_str());
        }catch (const std::exception& e){
            throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
        }

        switch(denominationInt){
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


        int64_t amount = sendTo[denominationStr].get_int();

        LogPrintf("rpcWallet.mintzerocoin() denomination = %s, nAmount = %s \n", denominationStr, amount);

        
        if(amount < 0){
                throw runtime_error(
                    "Mint amount must be 1 of (1,10,25,50,100)\n");
        }

        for(int64_t i=0; i<amount; i++){
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
            bool validCoin = pubCoin.validate();

            // loop until we find a valid coin
            while(!validCoin){
                libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
                libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();
                validCoin = pubCoin.validate();
            }

            // Create script for coin
            CScript scriptSerializedCoin =
                    CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

            CRecipient recipient = {scriptSerializedCoin, (denominationInt * COIN), false};

            vecSend.push_back(recipient);
            privCoins.push_back(newCoin);
        }
    }

    string strError = pwalletMain->MintAndStoreZerocoin(vecSend, privCoins, wtx);

    if (strError != "")
        throw JSONAPIError(API_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

UniValue sendprivate(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {

    UniValue txMetadataUni(UniValue::VOBJ);
    UniValue txMetadataData(UniValue::VOBJ);
    UniValue txMetadataEntry(UniValue::VOBJ);

    getTxMetadata(txMetadataUni, txMetadataData);

    if(txMetadataUni.empty()){
        UniValue txMetadataUni(UniValue::VOBJ);
    }

    if(txMetadataData.empty()){
        UniValue txMetadataData(UniValue::VOBJ);
    }

    switch(type){
        case Create: {
            
            UniValue txMetadataSubEntry(UniValue::VOBJ);
            UniValue ret(UniValue::VOBJ);
            UniValue txids(UniValue::VARR);

            UniValue inputs(UniValue::VARR);;
            string addressStr;
            string label;

            LOCK2(cs_main, pwalletMain->cs_wallet);

            int64_t value = 0;
            int64_t amount = 0;
            libzerocoin::CoinDenomination denomination;
            std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>> denominations;

            try {
                inputs = find_value(data, "denomination");
                addressStr = find_value(data, "address").get_str();
                label = find_value(data, "label").get_str();
            }catch (const std::exception& e){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
            }

            int64_t totalAmount = 0;

            for(size_t i=0; i<inputs.size();i++) {

                const UniValue& inputObj = inputs[i].get_obj();

                amount = find_value(inputObj, "amount").get_int();

                value = find_value(inputObj, "value").get_int();

                switch(value){
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
                for(int64_t j=0; j<amount; j++){
                    denominations.push_back(std::make_pair(value * COIN, denomination));
                }

                // write label and amount to entry object
            }
            txMetadataSubEntry.push_back(Pair("amount", totalAmount));
            txMetadataSubEntry.push_back(Pair("label", label));
            txMetadataEntry.push_back(Pair(addressStr, txMetadataSubEntry));

            string thirdPartyaddress = "";
            if (!(addressStr == "")){
                CBitcoinAddress address(addressStr);
                if (!address.IsValid())
                    throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address");
                thirdPartyaddress = addressStr;
            }

            EnsureWalletIsUnlocked();

            // Wallet comments
            CWalletTx wtx;
            vector<CBigNum> coinSerials;
            uint256 txHash;
            vector<CBigNum> zcSelectedValues;
            UniValue mintUpdates;
            string strError = "";

            // begin spend process
            // TODO: update SpendMultipleZerocoin to include mintUpdate code
            CReserveKey reservekey(pwalletMain);

            if (pwalletMain->IsLocked()) {
                strError = _("Error: Wallet locked, unable to create transaction!");
                LogPrintf("SpendZerocoin() : %s", strError);
                throw JSONAPIError(API_WALLET_ERROR, strError);
            }

            if (!pwalletMain->CreateMultipleZerocoinSpendTransaction(thirdPartyaddress, denominations, wtx, reservekey, coinSerials, txHash,
                                                zcSelectedValues, strError, mintUpdates)) {
                LogPrintf("SpendZerocoin() : %s\n", strError);
                throw JSONAPIError(API_WALLET_ERROR, strError);
            }

            string txidStr = wtx.GetHash().GetHex();

            // write back tx metadata object
            txMetadataData.push_back(Pair(txidStr, txMetadataEntry));
            if(!txMetadataUni.replace("data", txMetadataData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            setTxMetadata(txMetadataUni);

            if (!pwalletMain->CommitZerocoinSpendTransaction(wtx, reservekey)) {
                LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
                CZerocoinEntry pubCoinTx;
                list <CZerocoinEntry> listPubCoin;
                listPubCoin.clear();
                CWalletDB walletdb(pwalletMain->strWalletFile);
                walletdb.ListPubCoin(listPubCoin);

                for (std::vector<CBigNum>::iterator it = coinSerials.begin(); it != coinSerials.end(); it++){
                    unsigned index = it - coinSerials.begin();
                    CBigNum zcSelectedValue = zcSelectedValues[index];
                    BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
                        if (zcSelectedValue == pubCoinItem.value) {
                            pubCoinTx.id = pubCoinItem.id;
                            pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                            pubCoinTx.value = pubCoinItem.value;
                            pubCoinTx.nHeight = pubCoinItem.nHeight;
                            pubCoinTx.randomness = pubCoinItem.randomness;
                            pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                            pubCoinTx.denomination = pubCoinItem.denomination;
                            pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                            CWalletDB(pwalletMain->strWalletFile).WriteZerocoinEntry(pubCoinTx);
                            LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                            LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                        }
                    }
                    CZerocoinSpendEntry entry;
                    entry.coinSerial = coinSerials[index];
                    entry.hashTx = txHash;
                    entry.pubCoin = zcSelectedValue;
                    if (!CWalletDB(pwalletMain->strWalletFile).EraseCoinSpendSerialEntry(entry)) {
                        strError.append("Error: It cannot delete coin serial number in wallet.\n");
                    }
                }
                strError.append("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
            }

            if (strError != "")
                throw JSONAPIError(API_WALLET_ERROR, strError);

            // publish mintUpdates
            GetMainSignals().UpdatedMintStatus(mintUpdates.write());

            txids.push_back(wtx.GetHash().GetHex());
            ret.push_back(Pair("txids", txids));
            return ret;
        }
     
        default: {
           throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it."); 
        }
    }
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "zerocoin",           "mint",            &mint,                    true,      true,            false  },
    { "zerocoin",           "mintStatus",      &mintstatus,              true,      true,            false  }, 
    { "zerocoin",           "sendPrivate",     &sendprivate,             true,      true,            false  },
};
void RegisterZerocoinAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
