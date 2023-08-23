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
    // Ensure Lelantus mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    EnsureWalletIsUnlocked(pwalletMain);

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
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    EnsureWalletIsUnlocked(pwalletMain);

    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);

    std::string strAddress = find_value(data, "recipient").get_str();
    if (!isSparkAddress(address, strAddress)) throw JSONAPIError(API_INVALID_REQUEST, "invalid address");
    CAmount amount = get_bigint(data["amount"]);
    if (amount <= 0) throw JSONAPIError(API_INVALID_REQUEST, "amount must be greater than 0");
    std::string label = find_value(data, "label").get_str();
    CCoinControl coinControl;
    bool fHasCoinControl = GetCoinControl(data, coinControl);
    payTxFee = CFeeRate(get_bigint(data["feePerKb"]));
    bool fSubtractFeeFromAmount = find_value(data, "subtractFeeFromAmount").get_bool();

    address.decode(strAddress);
    std::vector<spark::MintedCoinData> outputs;
    spark::MintedCoinData mdata;
    mdata.address = address;
    mdata.memo = "";
    mdata.v = amount;
    outputs.push_back(mdata);

    std::vector<std::pair<CWalletTx, CAmount>> wtxsAndFees;

    uint64_t value = 0;
    for (auto& output : outputs)
        value += output.v;

    int64_t nFeeRequired = 0;
    int nChangePosRet = -1;
    std::list<CReserveKey> reservekeys;
    std::string strError;
    if (!pwalletMain->CreateSparkMintTransactions(outputs, wtxsAndFees, nFeeRequired, reservekeys, nChangePosRet, fSubtractFeeFromAmount, strError, fHasCoinControl? (&coinControl) : nullptr, false)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue txids(UniValue::VARR);
    CValidationState state;
    auto reservekey = reservekeys.begin();
    for(size_t i = 0; i < wtxsAndFees.size(); i++) {
        if (!pwalletMain->CommitTransaction(wtxsAndFees[i].first, *reservekey++, g_connman.get(), state)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        }

        txids.push_back(wtxsAndFees[i].first.GetHash().GetHex());
        GetMainSignals().WalletTransaction(wtxsAndFees[i].first);
    }

    UniValue retval(UniValue::VOBJ);
    retval.pushKV("txids", txids);
    return retval;
}

UniValue spendSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (type != Create) {
        throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
    }

    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    EnsureWalletIsUnlocked(pwalletMain);

    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);

    std::string strAddress = find_value(data, "recipient").get_str();

    if (!isSparkAddress(address, strAddress) && !CBitcoinAddress(strAddress).IsValid()) throw JSONAPIError(API_INVALID_REQUEST, "invalid address");
    CAmount amount = get_bigint(data["amount"]);
    if (!amount) throw JSONAPIError(API_INVALID_REQUEST, "amount must be greater than 0");
    std::string label = find_value(data, "label").get_str();
    CCoinControl coinControl;
    bool fHasCoinControl = GetCoinControl(data, coinControl);
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

    CAmount fee = 0;
    CWalletTx wtx;

    try {
        wtx = pwalletMain->SpendAndStoreSpark(recipients, privateRecipients, fee, fHasCoinControl? (&coinControl):NULL);
    } catch (...) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark spend creation failed.");
    }

    if (fee > 10000000) {
        throw JSONAPIError(API_INTERNAL_ERROR, "We have produced a transaction with a fee above 1 FIRO. This is almost certainly a bug.");
    }

    GetMainSignals().WalletTransaction(wtx);

    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return retval;
}

UniValue autoMintSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    EnsureWalletIsUnlocked(pwalletMain);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<spark::MintedCoinData> outputs;
    std::string strError = pwalletMain->MintAndStoreSpark(outputs, wtxAndFee, true, true);

    UniValue mintTxs = UniValue::VARR;

    if (strError != "" && strError != "Insufficient funds") {
        throw JSONAPIError(RPC_WALLET_ERROR, strError);
    }

    for (std::pair<CWalletTx, CAmount> wtx: wtxAndFee) {
        CWalletTx tx = wtx.first;
        GetMainSignals().WalletTransaction(tx);

        mintTxs.push_back(tx.GetHash().GetHex());
    }

    UniValue retval(UniValue::VOBJ);
    retval.push_back(Pair("mints", mintTxs));
    return retval;
}

UniValue lelantusToSpark(Type type, const UniValue& data, const UniValue& auth, bool fHelp) {
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
    EnsureWalletIsUnlocked(pwalletMain);

    std::string strFailReason = "";
    bool passed = false;
    try {
        passed = pwalletMain->LelantusToSpark(strFailReason);
    } catch (...) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed!");
    }
    if (!passed || strFailReason != "")
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed. " + strFailReason);

    // TODO: The client must call stateWallet after this method. We should send relevant transactions instead.

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
    { "privatetransaction",  "lelantusToSpark",    &lelantusToSpark,         true,      true,            false  },
    { "privatetransaction",  "autoMintSpark",      &autoMintSpark,           true,      true,            false  }
};
void RegisterSigmaAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
