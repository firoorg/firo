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
    sigma::ParamsV3* zcParams = sigma::ParamsV3::get_default();

    vector<CRecipient> vecSend;
    vector<sigma::PrivateCoinV3> privCoins;
    CWalletTx wtx;

    UniValue sendTo = data[0].get_obj();
    sigma::CoinDenominationV3 denomination;

    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& denominationStr, keys){
        if (!StringToDenomination(denominationStr, denomination)) {
            throw runtime_error(
                "mintzerocoin <amount>(0.1,0.5,1,10,100) (\"zcoinaddress\")\n");
        }
        int64_t coinValue;
        DenominationToInteger(denomination, coinValue);
        int64_t numberOfCoins = sendTo[denominationStr].get_int();

        LogPrintf("rpcWallet.mintmanyzerocoin() denomination = %s, nAmount = %s \n",
            denominationStr, numberOfCoins);

        if(numberOfCoins < 0) {
            throw runtime_error(
                    "mintmanyzerocoin {<denomination>(0.1,0.5,1,10,100):\"amount\"...}\n");
        }

        for(int64_t i = 0; i < numberOfCoins; ++i) {
            // The following constructor does all the work of minting a brand
            // new zerocoin. It stores all the private values inside the
            // PrivateCoin object. This includes the coin secrets, which must be
            // stored in a secure location (wallet) at the client.
            sigma::PrivateCoinV3 newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_3);
            // Get a copy of the 'public' portion of the coin. You should
            // embed this into a Zerocoin 'MINT' transaction along with a series
            // of currency inputs totaling the assigned value of one zerocoin.

            sigma::PublicCoinV3 pubCoin = newCoin.getPublicCoin();

            //Validate
            bool validCoin = pubCoin.validate();

            // no need to loop until we find a valid coin for sigma coins, they are always valid.
            //while(!validCoin){
            //    sigma::PrivateCoinV3 newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_3);
            //    sigma::PublicCoinV3 pubCoin = newCoin.getPublicCoin();
            //    validCoin = pubCoin.validate();
            //}

            // Create script for coin
            CScript scriptSerializedCoin;
            // opcode is inserted as 1 byte according to file script/script.h
            scriptSerializedCoin << OP_ZEROCOINMINTV3;

            // MARTUN: Commenting this for now.
            // this one will probably be written as int64_t, which means it will be written in as few bytes as necessary, and one more byte for sign. In our case our 34 will take 2 bytes, 1 for the number 34 and another one for the sign.
            // scriptSerializedCoin << pubCoin.getValue().memoryRequired();

            // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
            std::vector<unsigned char> vch = pubCoin.getValue().getvch();
            scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

            CRecipient recipient = {scriptSerializedCoin, coinValue, false};

            vecSend.push_back(recipient);
            privCoins.push_back(newCoin);
        }
    }

    string strError = pwalletMain->MintAndStoreZerocoinV3(vecSend, privCoins, wtx);

    if (strError != "")
        throw runtime_error(strError);

    return wtx.GetHash().GetHex();
}

UniValue sendprivate(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {

    // Initially grab the existing transaction metadata from the filesystem.
    UniValue txMetadataUni(UniValue::VOBJ);
    UniValue txMetadataData(UniValue::VOBJ);
    getTxMetadata(txMetadataUni, txMetadataData);

    if(txMetadataUni.empty()){
        UniValue txMetadataUni(UniValue::VOBJ);
    }

    if(txMetadataData.empty()){
        UniValue txMetadataData(UniValue::VOBJ);
    }

    switch(type){
        case Create: {
            // return object
            UniValue ret(UniValue::VOBJ);
            // data for return object
            UniValue txids(UniValue::VARR);
            // denominations
            UniValue inputs(UniValue::VARR);
            // Updates to mints are stored in here
            UniValue mintUpdates(UniValue::VOBJ);
            // receiving address
            string addressStr;
            // transaction label
            string label;
            // Storage of errors
            string strError = "";

            // To ensure atomic updates, spend creation/validation and broadcasting are separated.
            // As a result we need to temporarily store transaction related data, until the broadcasting stage.
            struct TempSpend {
                CWalletTx wtx;
                vector<CBigNum> coinSerials;
                uint256 txHash;
                vector<CBigNum> zcSelectedValues;
                CReserveKey reservekey;
            };
            vector<TempSpend> tempSpends;

            LOCK2(cs_main, pwalletMain->cs_wallet);

            libzerocoin::CoinDenomination denomination;

            try {
                inputs = find_value(data, "denomination");
                addressStr = find_value(data, "address").get_str();
                label = find_value(data, "label").get_str();
            }catch (const std::exception& e){
                throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
            }

            for(size_t i=0; i<inputs.size();i++) {

                const UniValue& inputObj = inputs[i].get_obj();

                int64_t amount = find_value(inputObj, "amount").get_int();

                int64_t value = find_value(inputObj, "value").get_int();

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
                    UniValue txMetadataEntry(UniValue::VOBJ);
                    UniValue txMetadataSubEntry(UniValue::VOBJ);
                    std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>> denominations;
                    denominations.push_back(std::make_pair(value * COIN, denomination));
                        
                    // write label and amount to entry object
                    txMetadataSubEntry.push_back(Pair("amount", value * COIN));
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
                    CReserveKey reservekey(pwalletMain);

                    if (pwalletMain->IsLocked()) {
                        strError = _("Error: Wallet locked, unable to create transaction!");
                        LogPrintf("SpendZerocoin() : %s", strError);
                        throw JSONAPIError(API_WALLET_ERROR, strError);
                    }

                    if (!pwalletMain->CreateMultipleZerocoinSpendTransactionV3(thirdPartyaddress, denominations, wtx, reservekey, coinSerials, txHash,
                                                        zcSelectedValues, strError, mintUpdates)) {
                        LogPrintf("SpendZerocoin() : %s\n", strError);
                        throw JSONAPIError(API_WALLET_ERROR, strError);
                    }

                    TempSpend tempSpend {
                        wtx,
                        coinSerials,
                        txHash,
                        zcSelectedValues,
                        reservekey,
                    };
                    tempSpends.push_back(tempSpend);

                    string txidStr = wtx.GetHash().GetHex();
                    // write tx metadata to data object
                    txMetadataData.push_back(Pair(txidStr, txMetadataEntry));
                    if(!txMetadataUni.replace("data", txMetadataData)){
                        throw runtime_error("Could not replace key/value pair.");
                    }
                }
            }

            // Start broadcasting logic.
            BOOST_FOREACH(TempSpend tempSpend, tempSpends){
                CWalletTx wtx = tempSpend.wtx;
                CReserveKey reservekey = tempSpend.reservekey;
                if (!pwalletMain->CommitZerocoinSpendTransaction(wtx, reservekey)) {
                    LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
                    vector<CBigNum> coinSerials = tempSpend.coinSerials;
                    uint256 txHash = tempSpend.txHash;
                    vector<CBigNum> zcSelectedValues = tempSpend.zcSelectedValues;

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
                txids.push_back(wtx.GetHash().GetHex());
            }

            if (strError != "")
                throw JSONAPIError(API_WALLET_ERROR, strError);

            //write back tx metadata to FS
            setTxMetadata(txMetadataUni);

            // publish mintUpdates
            GetMainSignals().UpdatedMintStatus(mintUpdates.write());

            // Populate return object
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
    { "zerocoin",           "sendPrivate",     &sendprivate,             true,      true,            false  },
    { "zerocoin",           "mintStatus",      &mintstatus,              true,      false,           false  }
};
void RegisterZerocoinAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
