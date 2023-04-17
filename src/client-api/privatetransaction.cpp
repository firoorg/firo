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
#include "lelantus.h"
#include <sigma.h>
#include <vector>
#include "client-api/bigint.h"
#include "univalue.h"
#include "privatetransaction.h"
#include "net.h"

UniValue lelantusTxFee(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    CAmount nAmount = get_bigint(data["amount"]);
    bool fSubtractFeeFromAmount = data["subtractFeeFromAmount"].get_bool();

    CCoinControl coinControl;
    GetCoinControl(data, coinControl);

    CCoinControl *ccp = coinControl.HasSelected() ? &coinControl : NULL;

    // payTxFee is a global variable that will be used to estimate the fee.
    payTxFee = CFeeRate(get_bigint(data["feePerKb"]));

    std::list<CSigmaEntry> sigmaCoins = pwalletMain->GetAvailableCoins(ccp, false, true);
    std::list<CLelantusEntry> lelantusCoins = pwalletMain->GetAvailableLelantusCoins(ccp, false, true);
    std::pair<CAmount, unsigned int> txFeeAndSize = pwalletMain->EstimateJoinSplitFee(nAmount, fSubtractFeeFromAmount, sigmaCoins, lelantusCoins, ccp);
    return txFeeAndSize.first;
}

UniValue sendLelantus(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    CBitcoinAddress address = find_value(data, "recipient").get_str();
    CAmount amount = get_bigint(data["amount"]);

    if (!address.IsValid()) throw JSONAPIError(API_INVALID_REQUEST, "invalid address");
    if (!amount) throw JSONAPIError(API_INVALID_REQUEST, "amount must be greater than 0");

    CCoinControl coinControl;
    bool fHasCoinControl = GetCoinControl(data, coinControl);

    // payTxFee is a global variable that will be used in CreateLelantusJoinSplitTransaction.
    payTxFee = CFeeRate(get_bigint(data["feePerKb"]));

    bool fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    CRecipient recipient = {scriptPubKey, amount, fSubtractFeeFromAmount};
    std::vector<CRecipient> recipients = {recipient};

    std::vector<CAmount> amounts = {amount};

    try {
        CAmount fee = 0;
        std::vector<CAmount> newMints;
        std::vector<CLelantusEntry> spendCoins;
        std::vector<CSigmaEntry> sigmaSpendCoins;
        std::vector<CHDMint> mintCoins;

        UniValue retval = UniValue::VOBJ;

        CWalletTx transaction = pwalletMain->CreateLelantusJoinSplitTransaction(
            recipients,
            fee, // clobbered
            newMints, // clobbered
            spendCoins, // clobbered
            sigmaSpendCoins, // clobbered
            mintCoins, // clobbered
            fHasCoinControl ? &coinControl : nullptr
        );

        if (fee > 10000000) {
            throw JSONAPIError(API_INTERNAL_ERROR, "We have produced a transaction with a fee above 1 FIRO. This is almost certainly a bug.");
        }

        if (!pwalletMain->CommitLelantusTransaction(transaction, spendCoins, sigmaSpendCoins, mintCoins)) {
            throw JSONAPIError(API_INTERNAL_ERROR, "The produced transaction was invalid and was not accepted into the mempool.");
        }

        GetMainSignals().WalletTransaction(transaction);

        retval.pushKV("txid", transaction.GetHash().ToString());

        return retval;
    }
    catch (const InsufficientFunds& e) {
       throw JSONAPIError(API_WALLET_INSUFFICIENT_FUNDS, e.what());
    }
    catch (const std::exception& e) {
      throw JSONAPIError(API_WALLET_ERROR, e.what());
    }
}

UniValue autoMintLelantus(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    // Ensure Lelantus mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    EnsureWalletIsUnlocked(pwalletMain);
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFees;
    std::vector<CHDMint> mints;

    UniValue mintTxs = UniValue::VARR;

    std::string strError = pwalletMain->MintAndStoreLelantus(0, wtxAndFees, mints, true);

    if (strError != "" && strError != "Insufficient funds") {
        throw JSONAPIError(RPC_WALLET_ERROR, strError);
    }

    for (std::pair<CWalletTx, CAmount> wtxAndFee: wtxAndFees) {
        CWalletTx tx = wtxAndFee.first;
        GetMainSignals().WalletTransaction(tx);

        mintTxs.push_back(tx.GetHash().GetHex());
    }

    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("mints", mintTxs));
    return retval;
}

UniValue mintSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    EnsureWalletIsUnlocked(pwalletMain);
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }

    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);

    std::string strAddress = find_value(data, "recipient").get_str();
    if (!isSparkAddress(address, strAddress)) throw JSONAPIError(API_INVALID_REQUEST, "invalid address");
    CAmount amount = get_bigint(data["amount"]);
    if (!amount) throw JSONAPIError(API_INVALID_REQUEST, "amount must be greater than 0");
    std::string label = find_value(data, "label").get_str();
    CCoinControl coinControl;
    bool fHasCoinControl = GetCoinControl(data, coinControl);
    // payTxFee is a global variable that will be used in CreateLelantusJoinSplitTransaction.
    payTxFee = CFeeRate(get_bigint(data["feePerKb"]));
    bool fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();

    address.decode(strAddress);
    std::vector<spark::MintedCoinData> outputs;
    spark::MintedCoinData mdata;
    mdata.address = address;
    mdata.memo = "";
    mdata.v = amount;
    outputs.push_back(mdata);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    // wtxAndFee[0].first.mapValue["label"] = label;
    std::string strError = pwalletMain->MintAndStoreSpark(outputs, wtxAndFee, false, fSubtractFeeFromAmount, fHasCoinControl? (&coinControl):NULL);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("txid", wtxAndFee[0].first.GetHash().GetHex()));
    return retval;
}

UniValue spendSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    EnsureWalletIsUnlocked(pwalletMain);
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }

    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);

    std::string strAddress = find_value(data, "recipient").get_str();

    if (!isSparkAddress(address, strAddress) && !CBitcoinAddress(strAddress).IsValid()) throw JSONAPIError(API_INVALID_REQUEST, "invalid address");
    CAmount amount = get_bigint(data["amount"]);
    if (!amount) throw JSONAPIError(API_INVALID_REQUEST, "amount must be greater than 0");
    std::string label = find_value(data, "label").get_str();
    CCoinControl coinControl;
    bool fHasCoinControl = GetCoinControl(data, coinControl);
    // payTxFee is a global variable that will be used in CreateLelantusJoinSplitTransaction.
    payTxFee = CFeeRate(get_bigint(data["feePerKb"]));
    bool fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();

    std::vector<CRecipient> recipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients;

    if(CBitcoinAddress(strAddress).IsValid()) {
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(strAddress).Get());
        CRecipient recipient = {scriptPubKey, amount, fSubtractFeeFromAmount};
        recipients.push_back(recipient);
    } else {
        spark::OutputCoinData data;
        address.decode(strAddress);
        data.address = address;
        data.memo = "";
        data.v = amount;
        privateRecipients.push_back(std::make_pair(data, fSubtractFeeFromAmount));
    }

    CAmount fee;
    std::vector<CWalletTx> wtxs;
    // wtxs[0].mapValue["label"] = label;
    // try {
        // wtxs = pwalletMain->SpendAndStoreSpark(recipients, privateRecipients, fee, fHasCoinControl? (&coinControl):NULL);
    // } catch (...) {
    //     throw JSONRPCError(RPC_WALLET_ERROR, "Spark spend creation failed.");
    // }

    auto result = pwalletMain->CreateSparkSpendTransaction(recipients, privateRecipients, fee, fHasCoinControl? (&coinControl):NULL);
    if (true) {
        throw JSONAPIError(API_INTERNAL_ERROR, "aaaaa");
    }
    // commit
    for (auto& wtxNew : result) {
        try {
            CValidationState state;
            CReserveKey reserveKey(pwalletMain);
            pwalletMain->CommitTransaction(wtxNew, reserveKey, g_connman.get(), state);
        } catch (...) {
            auto error = _(
                    "Error: The transaction was rejected! This might happen if some of "
                    "the coins in your wallet were already spent, such as if you used "
                    "a copy of wallet.dat and coins were spent in the copy but not "
                    "marked as spent here."
            );

            std::throw_with_nested(std::runtime_error(error));
        }
    }

    if (fee > 10000000) {
        throw JSONAPIError(API_INTERNAL_ERROR, "We have produced a transaction with a fee above 1 FIRO. This is almost certainly a bug.");
    }

    // GetMainSignals().WalletTransaction(wtxs[0]);
    // UniValue retval(UniValue::VOBJ);
    // retval.push_back(Pair("spendSpark", wtxs[0].GetHash().GetHex()));
    // return retval;
    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("txid", wtxs[0].GetHash().GetHex()));
    return retval;
}

UniValue lelantusToSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    EnsureWalletIsUnlocked(pwalletMain);
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }

    std::string strFailReason = "";
    bool passed = false;
    try {
        passed = pwalletMain->LelantusToSpark(strFailReason);
    } catch (...) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed!");
    }
    if (!passed || strFailReason != "")
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed. " + strFailReason);

    return NullUniValue;
}

bool isSparkAddress(spark::Address addr, const std::string& address)
{
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    unsigned char coinNetwork;
    try {
        coinNetwork = addr.decode(address);
    } catch (...) {
        return false;
    }
    return network == coinNetwork;
}

static const CAPICommand commands[] =
{ //  category               collection            actor (function)          authPort   authPassphrase   warmupOk
  //  ---------------------  ------------          ----------------          --------   --------------   --------
    { "privatetransaction",  "lelantusTxFee",      &lelantusTxFee,           true,      false,           false  },
    { "privatetransaction",  "sendLelantus",       &sendLelantus,            true,      true,            false  },
    { "privatetransaction",  "autoMintLelantus",   &autoMintLelantus,        true,      true,            false  },
    { "privatetransaction",  "mintSpark",          &mintSpark,               true,      true,            false  },
    { "privatetransaction",  "spendSpark",         &spendSpark,              true,      true,            false  },
    { "privatetransaction",  "lelantusToSpark",    &lelantusToSpark,         true,      true,            false  }
};
void RegisterSigmaAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
