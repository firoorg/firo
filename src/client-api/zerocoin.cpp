// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "client-api/server.h"
#include "rpc/server.h"
#include "util.h"
#include "client-api/wallet.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"
#include "base58.h"
#include "client-api/send.h"
#include "client-api/protocol.h"
#include <zerocoin.h>
#include <zerocoin_v3.h>
#include <vector>

#include "univalue.h"

using namespace std;

UniValue mintstatus(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    return data;
}

UniValue mint(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    // Ensure Sigma mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!IsSigmaAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not activated yet");
    }

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

    // Ensure Sigma mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!IsSigmaAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not activated yet");
    }

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
            LOCK2(cs_main, pwalletMain->cs_wallet);
            UniValue outputs(UniValue::VARR);
            outputs = find_value(data, "outputs").get_array();
            std::string label = find_value(data, "label").get_str();

            CWalletTx wtx; 

            std::set<CBitcoinAddress> setAddress;
            std::vector<CRecipient> vecSend;

            CAmount totalAmount = 0;
            if (outputs.size() <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Required at least an address to send");
            }

            UniValue txMetadataEntry(UniValue::VOBJ);
            UniValue output(UniValue::VOBJ);
            for(size_t index=0; index<outputs.size(); index++){
                output = outputs[index];
                std::string strAddr = find_value(output, "address").get_str();
                int64_t amount = find_value(output, "amount").get_int64();
                CBitcoinAddress address(strAddr);
                CAmount nAmount = AmountFromValue(amount);
                CScript scriptPubKey = GetScriptForDestination(address.Get());

                if (!address.IsValid())
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address: " + strAddr);

                if (!setAddress.insert(address).second)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicated address: " + strAddr);

                if (nAmount <= 0) {
                    throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
                }
                totalAmount += nAmount;

                bool fSubtractFeeFromAmount = false;
                vecSend.push_back({scriptPubKey, nAmount, fSubtractFeeFromAmount});

                UniValue txMetadataSubEntry(UniValue::VOBJ);

                // write label and amount to entry object
                txMetadataSubEntry.push_back(Pair("amount", amount * COIN));
                txMetadataSubEntry.push_back(Pair("label", label));
                txMetadataEntry.push_back(Pair(strAddr, txMetadataSubEntry));
            }

            EnsureWalletIsUnlocked();

            CAmount nFeeRequired = 0;
            std::vector<CZerocoinEntryV3> coins;

            try {
                coins = pwalletMain->SpendZerocoinV3(vecSend, wtx, nFeeRequired);
            }
            catch (const InsufficientFunds& e) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
            }
            catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR, e.what());
            }


            // publish spent mint data to API
            UniValue mintUpdates(UniValue::VOBJ);
            unsigned int index;
            string txid;

            BOOST_FOREACH(CZerocoinEntryV3 coin, coins){
                if(!pwalletMain->GetTxInfoForPubcoinV3(coin, txid, index)){
                    throw runtime_error("Mint tx not found!");
                }
                string key = txid + to_string(index);
                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("txid", txid));
                entry.push_back(Pair("index", to_string(index)));
                entry.push_back(Pair("available", false));
                mintUpdates.push_back(Pair(key, entry));
            }
            LogPrintf("mintUpdates: %s\n", mintUpdates.write());
            GetMainSignals().UpdatedMintStatus(mintUpdates.write());

            string txidStr = wtx.GetHash().GetHex();
            txMetadataData.push_back(Pair(txidStr, txMetadataEntry));
            if(!txMetadataUni.replace("data", txMetadataData)){
                throw runtime_error("Could not replace key/value pair.");
            }
            //write back tx metadata to FS
            setTxMetadata(txMetadataUni);

            return txidStr;
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
