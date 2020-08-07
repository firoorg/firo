// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"
#include "client-api/server.h"
#include "rpc/server.h"
#include "util.h"
#include "client-api/wallet.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"
#include "base58.h"
#include "client-api/send.h"
#include "client-api/protocol.h"
#include "wallet/coincontrol.h"
#include <zerocoin.h>
#include <sigma.h>
#include <vector>

#include "univalue.h"

using namespace std;

const struct {
    int CONFIRMED;
    int UNCONFIRMED;
    int size;
} MintStatus = {0, 1, 2};

bool createSigmaMintAPITransaction(const UniValue& data,
                                   vector<CRecipient>& vecSend,
                                   vector<sigma::PrivateCoin>& privCoins,
                                   vector<CHDMint>& vHdMints){
    // Ensure Sigma mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!sigma::IsSigmaAllowed()) {
        throw JSONAPIError(API_WALLET_ERROR, "Sigma is not activated yet");
    }
    sigma::Params* sigmaParams = sigma::Params::get_default();
    if (pwalletMain->zwallet) {
        pwalletMain->zwallet->ResetCount(walletdb); // Reset count to original
    }

    UniValue denominationsObj = find_value(data, "denominations");
    if(!denominationsObj.isNull()){
        UniValue denominations = denominationsObj.get_obj();
        sigma::CoinDenomination denomination;

        vector<string> keys = denominations.getKeys();
        BOOST_FOREACH(const string& denominationStr, keys){
            if (!StringToDenomination(denominationStr, denomination)) {
                throw runtime_error(
                    "mint <amount>(0.1, 0.5, 1, 10, 25, 100) (\"zcoinaddress\")\n");
            }
            int64_t coinValue;
            DenominationToInteger(denomination, coinValue);
            int64_t numberOfCoins = denominations[denominationStr].get_int();

            LogPrintf("mint: denomination = %s, nAmount = %s \n",
                denominationStr, numberOfCoins);

            if(numberOfCoins < 0) {
                throw runtime_error(
                        "mint {<denomination>(0.1, 0.5, 1, 10, 25, 100):\"amount\"...}\n");
            }

            for(int64_t i = 0; i < numberOfCoins; ++i) {
                // The following constructor does all the work of minting a brand
                // new sigma mint. It stores all the private values inside the
                // PrivateCoin object. This includes the coin secrets, which must be
                // stored in a secure location (wallet) at the client.
                sigma::PrivateCoin newCoin(sigmaParams, denomination, ZEROCOIN_TX_VERSION_3);
                // Get a copy of the 'public' portion of the coin. You should
                // embed this into a Sigma 'MINT' transaction along with a series
                // of currency inputs totaling the assigned value of one sigma mint.

                // Generate and store secrets deterministically in the following function.
                CHDMint fHdMint;
                pwalletMain->zwallet->GenerateMint(walletdb, newCoin.getPublicCoin().getDenomination(), newCoin, fHdMint);

                sigma::PublicCoin pubCoin = newCoin.getPublicCoin();

                // Create script for coin
                CScript scriptSerializedCoin;
                // opcode is inserted as 1 byte according to file script/script.h
                scriptSerializedCoin << OP_SIGMAMINT;

                // MARTUN: Commenting this for now.
                // this one will probably be written as int64_t, which means it will be written in as few bytes as necessary, and one more byte for sign. In our case our 34 will take 2 bytes, 1 for the number 34 and another one for the sign.
                // scriptSerializedCoin << pubCoin.getValue().memoryRequired();

                // and this one will write the size in different byte lengths depending on the length of vector. If vector size is <0.4c, which is 76, will write the size of vector in just 1 byte. In our case the size is always 34, so must write that 34 in 1 byte.
                std::vector<unsigned char> vch = pubCoin.getValue().getvch();
                scriptSerializedCoin.insert(scriptSerializedCoin.end(), vch.begin(), vch.end());

                CRecipient recipient = {scriptSerializedCoin, coinValue, false};

                vecSend.push_back(recipient);
                privCoins.push_back(newCoin);
                vHdMints.push_back(fHdMint);
            }
        }
    }else {
        CAmount nAmount = find_value(data, "value").get_int();

        std::vector<sigma::CoinDenomination> denominations;
        sigma::GetAllDenoms(denominations);

        CAmount smallestDenom;
        DenominationToInteger(denominations.back(), smallestDenom);

        if (nAmount % smallestDenom != 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount to mint is invalid.\n");
        }

        std::vector<sigma::CoinDenomination> mints;
        if (CWallet::SelectMintCoinsForAmount(nAmount, denominations, mints) != nAmount) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Problem with coin selection.\n");
        }

        std::transform(mints.begin(), mints.end(), std::back_inserter(privCoins),
            [sigmaParams](const sigma::CoinDenomination& denom) -> sigma::PrivateCoin {
                return sigma::PrivateCoin(sigmaParams, denom);
            });
        vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vHdMints);
    }

    return true;
}

bool createSigmaSpendAPITransaction(CWalletTx& wtx,
                                    const UniValue& data,
                                    CAmount& nFeeRequired,
                                    std::vector<CSigmaEntry>& coins,
                                    std::vector<CHDMint> changes,
                                    bool fDummy){
    // Ensure Sigma is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!sigma::IsSigmaAllowed()) {
        throw JSONAPIError(API_WALLET_ERROR, "Sigma is not activated yet");
    }
    UniValue outputs(UniValue::VARR);
    outputs = find_value(data, "outputs").get_array();
    std::string label = find_value(data, "label").get_str();
    bool fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();

    CCoinControl cc;
    bool hasCoinControl = GetCoinControl(data, cc);

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    if (outputs.size() <= 0) {
        throw JSONAPIError(API_INVALID_PARAMETER, "Required at least an address to send");
    }
    UniValue output(UniValue::VOBJ);
    for(size_t index=0; index<outputs.size(); index++){
        output = outputs[index];
        std::string strAddr = find_value(output, "address").get_str();
        // satoshi amount
        CAmount nAmount = find_value(output, "amount").get_int64();
        CBitcoinAddress address(strAddr);
        CScript scriptPubKey = GetScriptForDestination(address.Get());

        if (!address.IsValid())
            throw JSONAPIError(API_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address: " + strAddr);

        if (!setAddress.insert(address).second)
            throw JSONAPIError(API_INVALID_PARAMETER, "Invalid parameter, duplicated address: " + strAddr);

        if (nAmount <= 0) {
            throw JSONAPIError(API_TYPE_ERROR, "Invalid amount for send");
        }
        totalAmount += nAmount;

        vecSend.push_back({scriptPubKey, nAmount, fSubtractFeeFromAmount});
    }

    if(!fDummy)
        EnsureWalletIsUnlocked(pwalletMain);

    bool fChangeAddedToFee;

    try {
        // create transaction
        wtx = pwalletMain->CreateSigmaSpendTransaction(vecSend, nFeeRequired, coins, changes, fChangeAddedToFee, hasCoinControl? (&cc):NULL, fDummy);
    }catch (const InsufficientFunds& e) {
        throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, e.what());
    }
    catch (const std::exception& e) {
        throw JSONAPIError(API_WALLET_ERROR, e.what());
    }
    wtx.mapValue["label"] = label;
    return true;
}

UniValue GetDenominations(){
    std::vector<CMintMeta> listMints = pwalletMain->zwallet->GetTracker().ListMints(true, false, false);

    UniValue denominations(UniValue::VOBJ);
    map<string, vector<int>> denominationsMap;
    std::vector<sigma::CoinDenomination> denominationsVector;

    // Initialize map
    GetAllDenoms(denominationsVector);
    BOOST_FOREACH(sigma::CoinDenomination denomination, denominationsVector){
        for(unsigned long i=0; i<MintStatus.size; i++){
            denominationsMap[DenominationToString(denomination)].push_back(0);
        }
    }

    // Add denominations to map
    BOOST_FOREACH(CMintMeta &mintMeta, listMints) {
        std::string index = DenominationToString(mintMeta.denom);
        if (mintMeta.nHeight==-1 || chainActive.Height() < (mintMeta.nHeight + (ZC_MINT_CONFIRMATIONS-1)))
            denominationsMap[index][MintStatus.UNCONFIRMED]++;
        else
            denominationsMap[index][MintStatus.CONFIRMED]++;
    }

    // Add map to UniValue object
    map<string, vector<int>>::iterator it;
    for ( it = denominationsMap.begin(); it != denominationsMap.end(); it++ ){
        UniValue confirmations(UniValue::VOBJ);
        confirmations.push_back(Pair("confirmed", it->second[MintStatus.CONFIRMED]));
        confirmations.push_back(Pair("unconfirmed", it->second[MintStatus.UNCONFIRMED]));

        denominations.push_back(Pair(it->first, confirmations));

    }

    return denominations;
}

UniValue minttxfee(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    UniValue result(UniValue::VOBJ);
    vector<CRecipient> vecSend;
    vector<sigma::PrivateCoin> privCoins;
    vector<CHDMint> vHdMints;
    CWalletTx wtx;
    int64_t nFeeRequired = 0;

    createSigmaMintAPITransaction(data, vecSend, privCoins, vHdMints);

    string strError = pwalletMain->GetSigmaMintFee(vecSend, privCoins, vHdMints, wtx, nFeeRequired);

    if (strError != "")
        throw runtime_error(strError);

    result.push_back(Pair("fee", nFeeRequired));

    return result;
}

UniValue mint(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    vector<CRecipient> vecSend;
    vector<sigma::PrivateCoin> privCoins;
    vector<CHDMint> vHdMints;
    CWalletTx wtx;

    createSigmaMintAPITransaction(data, vecSend, privCoins, vHdMints);

    string strError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vHdMints, wtx);

    if (strError != "")
        throw runtime_error(strError);

    return wtx.GetHash().GetHex();
}

UniValue privatetxfee(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    UniValue result(UniValue::VOBJ);

    CWalletTx wtx;
    CAmount nFeeRequired;
    std::vector<CSigmaEntry> coins;
    std::vector<CHDMint> changes;

    createSigmaSpendAPITransaction(wtx, data, nFeeRequired, coins, changes, true);

    result.push_back(Pair("fee", nFeeRequired));
    result.push_back(Pair("inputs", int64_t(coins.size())));

    return result;
}

UniValue sendprivate(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {

    switch(type){
        case Create: {
            CWalletTx wtx;
            CAmount nFeeRequired;
            std::vector<CSigmaEntry> coins;
            std::vector<CHDMint> changes;
            std::string txidStr;
            try {
                createSigmaSpendAPITransaction(wtx, data, nFeeRequired, coins, changes, false);

                txidStr = wtx.GetHash().GetHex();

                // commit transaction
                pwalletMain->CommitSigmaTransaction(wtx, coins, changes);

            }
            catch (const InsufficientFunds& e) {
                throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, e.what());
            }
            catch (const std::exception& e) {
                throw JSONAPIError(API_WALLET_ERROR, e.what());
            }

            return txidStr;
        }

        default: {
           throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it."); 
        }
    }
}

UniValue listmints(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {

    EnsureWalletIsUnlocked(pwalletMain);

    list <CSigmaEntry> listPubcoin = pwalletMain->zwallet->GetTracker().MintsAsSigmaEntries(true, false);
    UniValue results(UniValue::VOBJ);

    BOOST_FOREACH(const CSigmaEntry &sigmaItem, listPubcoin) {
        uint256 serialNumberHash = primitives::GetSerialHash(sigmaItem.serialNumber);

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("id", sigmaItem.id));
        entry.push_back(Pair("IsUsed", sigmaItem.IsUsed));
        entry.push_back(Pair("denomination", sigmaItem.get_denomination_value()));
        entry.push_back(Pair("value", sigmaItem.value.GetHex()));
        entry.push_back(Pair("serialNumber", sigmaItem.serialNumber.GetHex()));
        entry.push_back(Pair("nHeight", sigmaItem.nHeight));
        entry.push_back(Pair("randomness", sigmaItem.randomness.GetHex()));
        results.push_back(Pair(serialNumberHash.ToString(), entry));
    }

    return results;
}

static const CAPICommand commands[] =
{ //  category              collection            actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------          ----------------          --------   --------------   --------
    { "sigma",              "mint",               &mint,                    true,      true,            false  },
    { "sigma",              "sendPrivate",        &sendprivate,             true,      true,            false  },
    { "sigma",              "listMints",          &listmints,               true,      true,            false  },
    { "sigma",              "mintTxFee",          &minttxfee,               true,      false,           false  },
    { "sigma",              "privateTxFee",       &privatetxfee,            true,      false,           false  }
};
void RegisterSigmaAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
