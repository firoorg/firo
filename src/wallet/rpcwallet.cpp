// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2016-2019 The Firo Core developers
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "validation.h"
#include "zerocoin.h"
#include "sigma.h"
#include "lelantus.h"
#include "../sigma/coinspend.h"
#include "net.h"
#include "policy/policy.h"
#include "policy/rbf.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "hdmint/tracker.h"
#include "zerocoin.h"
#include "walletexcept.h"
#include "masternode-payments.h"
#include "lelantusjoinsplitbuilder.h"
#include "bip47/paymentchannel.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

using namespace std;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

static void EnsureZerocoinMintIsAllowed()
{
    // We want to make sure the new mint still accept by network when we broadcast.
    // So we will not allow users to use this RPC anymore 10 blocks before it completely
    // disabled at consensus level. We don't need this for spend because it does not make sense
    // since users still lost their mints when it completely disable.
    auto& consensus = Params().GetConsensus();
    constexpr int threshold = 10; // 10 blocks should be enough for mints to get mined.
    int disableHeight = consensus.nSigmaStartBlock + consensus.nZerocoinV2MintMempoolGracefulPeriod - threshold;

    LOCK(cs_main);

    if (chainActive.Height() > disableHeight) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Zerocoin mint is not allowed on network anymore");
    }
}

CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    return pwalletMain;
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (!pwallet) {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true;
}

void EnsureSigmaWalletIsAvailable()
{
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "sigma mint/spend is not allowed for legacy wallet");
    }
}

void EnsureLelantusWalletIsAvailable()
{
    if (!pwalletMain || !pwalletMain->zwallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "lelantus mint/joinsplit is not allowed for legacy wallet");
    }
}

void EnsureWalletIsUnlocked(CWallet * const pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

bool ValidMultiMint(CWallet * const pwallet, const UniValue& data){
    vector<string> keys = data.getKeys();
    CAmount totalValue = 0;
    int totalInputs = 0;
    int denomination;
    int64_t amount;
    BOOST_FOREACH(const string& denominationStr, keys){
        denomination = stoi(denominationStr.c_str());
        amount = data[denominationStr].get_int();
        totalInputs += amount;
        totalValue += denomination * amount * COIN;
    }

    return ((totalValue <= pwallet->GetBalance()) &&
            (totalInputs <= ZC_MINT_LIMIT));

}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true));
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
    } else {
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    UniValue conflicts(UniValue::VARR);
    BOOST_FOREACH(const uint256& conflict, wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        LOCK(mempool.cs);
        RBFTransactionState rbfState = IsRBFOptIn(wtx, mempool);
        if (rbfState == RBF_TRANSACTIONSTATE_UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.push_back(Pair("bip125-replaceable", rbfStatus));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const UniValue& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue getnewaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new Firo address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"firoaddress\"    (string) The new Firo address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (request.params.size() > 0)
        strAccount = AccountFromValue(request.params[0]);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    CKeyID keyID = newKey.GetID();

    pwallet->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(CWallet * const pwallet, string strAccount, bool bForceNew=false)
{
    CPubKey pubKey;
    if (!pwallet->GetAccountPubkey(pubKey, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return CBitcoinAddress(pubKey.GetID());
}

UniValue getaccountaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Firo address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"firoaddress\"   (string) The account Firo address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(request.params[0]);

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(pwallet, strAccount).ToString();
    return ret;
}


UniValue getrawchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new Firo address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}


UniValue setaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "setaccount \"firoaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");

    string strAccount;
    if (request.params.size() > 1)
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(address.Get())) {
            string strOldAccount = pwallet->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(pwallet, strOldAccount)) {
                GetAccountAddress(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(address.Get(), strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getaccount \"firoaddress\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
            + HelpExampleRpc("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");

    string strAccount;
    map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}

UniValue setmininput(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw runtime_error(
                "setmininput <amount>\n"
                        "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64_t nAmount = 0;
    if (request.params[0].get_real() != 0.0)
        nAmount = AmountFromValue(request.params[0]);        // rejects 0.0 amounts

    nMinimumInputValue = nAmount;
    return true;
}


UniValue getaddressesbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"firoaddress\"  (string) a Firo address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
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

    // Parse Firo address
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
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

UniValue sendtoaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw runtime_error(
            "sendtoaddress \"firoaddress\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 4)
        fSubtractFeeFromAmount = request.params[4].get_bool();

    EnsureWalletIsUnlocked(pwallet);

    SendMoney(pwallet, address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"firoaddress\",     (string) The Firo address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) DEPRECATED. The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (set<CTxDestination> grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwallet->mapAddressBook.end()) {
                    addressInfo.push_back(pwallet->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue listaddressbalances(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listaddressbalances ( minamount )\n"
            "\nLists addresses of this wallet and their balances\n"
            "\nArguments:\n"
            "1. minamount               (numeric, optional, default=0) Minimum balance in " + CURRENCY_UNIT + " an address should have to be shown in the list\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": amount,       (string) The dash address and the amount in " + CURRENCY_UNIT + "\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressbalances", "")
            + HelpExampleCli("listaddressbalances", "10")
            + HelpExampleRpc("listaddressbalances", "")
            + HelpExampleRpc("listaddressbalances", "10")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CAmount nMinAmount = 0;
    if (request.params.size() > 0)
        nMinAmount = AmountFromValue(request.params[0]);

    if (nMinAmount < 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");

    UniValue jsonBalances(UniValue::VOBJ);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (auto& balance : balances)
        if (balance.second >= nMinAmount)
            jsonBalances.push_back(Pair(CBitcoinAddress(balance.first).ToString(), ValueFromAmount(balance.second)));

    return jsonBalances;
}

UniValue signmessage(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "signmessage \"firoaddress\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    string strAddress = request.params[0].get_str();
    string strMessage = request.params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwallet->GetKey(keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress \"firoaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given firoaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", 6")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Firo address
    CBitcoinAddress address = CBitcoinAddress(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwallet, scriptPubKey)) {
        return ValueFromAmount(0);
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(request.params[0]);
    set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return ValueFromAmount(nAmount);
}


UniValue getbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw runtime_error(
            "getbalance ( \"account\" minconf include_watchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"         (string, optional) DEPRECATED. The account string may be given as a\n"
            "                     specific account name to find the balance associated with wallet keys in\n"
            "                     a named account, or as the empty string (\"\") to find the balance\n"
            "                     associated with wallet keys not in any named account, or as \"*\" to find\n"
            "                     the balance associated with all wallet keys regardless of account.\n"
            "                     When this option is specified, it calculates the balance in a different\n"
            "                     way than when it is not specified, and which can count spends twice when\n"
            "                     there are conflicting pending transactions (such as those created by\n"
            "                     the bumpfee command), temporarily resulting in low or even negative\n"
            "                     balances. In general, account balance calculation is not considered\n"
            "                     reliable and has resulted in confusing outcomes, so it is recommended to\n"
            "                     avoid passing this argument.\n"
            "2. minconf           (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. include_watchonly (bool, optional, default=false) Also include balance in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 5 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 0)
        return  ValueFromAmount(pwallet->GetBalance());

    const std::string* account = request.params[0].get_str() != "*" ? &request.params[0].get_str() : nullptr;

    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(request.params.size() > 2)
        if(request.params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account));
}

UniValue getunconfirmedbalance(const JSONRPCRequest &request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}


UniValue movecmd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
    	    return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. (dummy)           (numeric, optional) Ignored. Remains for backward compatibility.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strFrom = AccountFromValue(request.params[0]);
    string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (request.params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    string strComment;
    if (request.params.size() > 4)
        strComment = request.params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}


UniValue sendfrom(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 6)
        throw runtime_error(
            "sendfrom \"fromaccount\" \"toaddress\" amount ( minconf \"comment\" \"comment_to\" )\n"
            "\nDEPRECATED (use sendtoaddress). Sent an amount from an account to a bitcoin address."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "                       Specifying an account does not influence coin selection, but it does associate the newly created\n"
            "                       transaction with the account, so the account's balance computation and transaction history can reflect\n"
            "                       the spend.\n"
            "2. \"toaddress\"         (string, required) The Firo address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment_to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"txid\"                 (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("sendfrom", "\"\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strAccount = AccountFromValue(request.params[0]);
    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (request.params.size() > 3)
        nMinDepth = request.params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 4 && !request.params[4].isNull() && !request.params[4].get_str().empty())
        wtx.mapValue["comment"] = request.params[4].get_str();
    if (request.params.size() > 5 && !request.params[5].isNull() && !request.params[5].get_str().empty())
        wtx.mapValue["to"]      = request.params[5].get_str();

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(pwallet, address.Get(), nAmount, false, wtx);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The Firo address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefrom         (array, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.\n"
            "    [\n"
            "      \"address\"          (string) Subtract fee from this address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult:\n"
            "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 1 \"\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendmany", "\"\", \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\", 6, \"testing\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    string strAccount = AccountFromValue(request.params[0]);
    UniValue sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (request.params.size() > 2)
        nMinDepth = request.params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (request.params.size() > 4)
        subtractFeeFromAmount = request.params[4].get_array();

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Firo address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
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

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, strAccount.empty() ? nullptr : &strAccount);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return wtx.GetHash().GetHex();
}

// Defined in rpc/misc.cpp
extern CScript _createmultisig_redeemScript(CWallet * const pwallet, const UniValue& params);

UniValue addmultisigaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is a Firo address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"         (string, required) A json array of Firo addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) Firo address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"address\"         (string) A Firo address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    string strAccount;
    if (request.params.size() > 2)
        strAccount = AccountFromValue(request.params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(pwallet, request.params);
    CScriptID innerID(inner);
    pwallet->AddCScript(inner);

    pwallet->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}

class Witnessifier : public boost::static_visitor<bool>
{
public:
    CWallet * const pwallet;
    CScriptID result;

    Witnessifier(CWallet *_pwallet) : pwallet(_pwallet) {}

    bool operator()(const CNoDestination &dest) const { return false; }

    bool operator()(const CKeyID &keyID) {
        CPubKey pubkey;
        if (pwallet) {
            CScript basescript = GetScriptForDestination(keyID);
            isminetype typ;
            typ = IsMine(*pwallet, basescript, SIGVERSION_WITNESS_V0);
            if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
                return false;
            CScript witscript = GetScriptForWitness(basescript);
            pwallet->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }

    bool operator()(const CScriptID &scriptID) {
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            int witnessversion;
            std::vector<unsigned char> witprog;
            if (subscript.IsWitnessProgram(witnessversion, witprog)) {
                result = scriptID;
                return true;
            }
            isminetype typ;
            typ = IsMine(*pwallet, subscript, SIGVERSION_WITNESS_V0);
            if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
                return false;
            CScript witscript = GetScriptForWitness(subscript);
            pwallet->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }
};

UniValue addwitnessaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
    {
        string msg = "addwitnessaddress \"address\"\n"
            "\nAdd a witness address for a script (with pubkey or redeemscript known).\n"
            "It returns the witness script.\n"

            "\nArguments:\n"
            "1. \"address\"       (string, required) An address known to the wallet\n"

            "\nResult:\n"
            "\"witnessaddress\",  (string) The value of the new address (P2SH of witness script).\n"
            "}\n"
        ;
        throw runtime_error(msg);
    }

    {
        LOCK(cs_main);
        if (!IsWitnessEnabled(chainActive.Tip(), Params().GetConsensus()) && !GetBoolArg("-walletprematurewitness", false)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Segregated witness not enabled on network");
        }
    }

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");

    Witnessifier w(pwallet);
    CTxDestination dest = address.Get();
    bool ret = boost::apply_visitor(w, dest);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Public key or redeemscript not known to wallet, or the key is uncompressed");
    }

    pwallet->SetAddressBook(w.result, "", "receive");

    return CBitcoinAddress(w.result).ToString();
}

struct tallyitem
{
    CAmount nAmount;
    int nConf;
    vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    map<string, tallyitem> mapAccountTally;
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second.name;
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            if (!fByAccounts)
                obj.push_back(Pair("label", strAccount));
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                BOOST_FOREACH(const uint256& _item, (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            CAmount nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            UniValue obj(UniValue::VOBJ);
            if((*it).second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw runtime_error(
            "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\",               (string) A comment for the address/transaction, if any\n"
            "    \"txids\": [\n"
            "       n,                                (numeric) The ids of transactions received with the address \n"
            "       ...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw runtime_error(
            "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaccount", "")
            + HelpExampleCli("listreceivedbyaccount", "6 true")
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest, CBitcoinAddress &addr)
{
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(CWallet * const pwallet, const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    CBitcoinAddress addr;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY)) {
                entry.push_back(Pair("involvesWatchonly", true));
            }
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination, addr);
            if (wtx.tx->IsZerocoinSpend() || wtx.tx->IsSigmaSpend() || wtx.tx->IsZerocoinRemint() || wtx.tx->IsLelantusJoinSplit()) {
                entry.push_back(Pair("category", "spend"));
            }
            else if (wtx.tx->IsZerocoinMint() || wtx.tx->IsSigmaMint() || wtx.tx->IsLelantusMint()) {
                entry.push_back(Pair("category", "mint"));
            }
            else {
                entry.push_back(Pair("category", "send"));
            }
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.push_back(Pair("label", pwallet->mapAddressBook[s.destination].name));
            }
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.push_back(Pair("abandoned", wtx.isAbandoned()));
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            string account;
            if (pwallet->mapAddressBook.count(r.destination)) {
                account = pwallet->mapAddressBook[r.destination].name;
            }
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination, addr);
                if (wtx.IsCoinBase())
                {
                    int txHeight = chainActive.Height() - wtx.GetDepthInMainChain();

                    std::vector<CTxOut> voutMasternodePaymentsRet;
                    mnpayments.GetBlockTxOuts(txHeight, CAmount(), voutMasternodePaymentsRet);
                    //compare address of payee to addr.

                    bool its_znode_payment = false;
                    for(CTxOut const & out : voutMasternodePaymentsRet) {
                        CTxDestination payeeDest;
                        ExtractDestination(out.scriptPubKey, payeeDest);
                        CBitcoinAddress payeeAddr(payeeDest);

                        if(addr.ToString() == payeeAddr.ToString()) {
                            its_znode_payment = true;
                        }
                    }
                    if(its_znode_payment){
                        entry.push_back(Pair("category", "znode"));
                    }
                    else if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (pwallet->mapAddressBook.count(r.destination)) {
                    entry.push_back(Pair("label", account));
                }
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue listtransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw runtime_error(
            "listtransactions ( \"account\" count skip include_watchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. skip           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. include_watchonly (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"firoaddress\",    (string) The Firo address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"label\": \"label\",       (string) A comment for the address/transaction, if any\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx,           (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) DEPRECATED. For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    string strAccount = "*";
    if (request.params.size() > 0)
        strAccount = request.params[0].get_str();
    int nCount = 10;
    if (request.params.size() > 1)
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (request.params.size() > 2)
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(request.params.size() > 3)
        if(request.params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    vector<UniValue> arrTmp = ret.getValues();

    vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw runtime_error(
            "listaccounts ( minconf include_watchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. include_watchonly   (bool, optional, default=false) Include balances in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n"
            + HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n"
            + HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n"
            + HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("listaccounts", "6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(request.params.size() > 1)
        if(request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    map<string, CAmount> mapAccountBalances;
    for (const std::pair<CTxDestination, CAddressBookData>& entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
        }
    }

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        CAmount nFee;
        string strSentAccount;
        list<COutputEntry> listReceived;
        list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const COutputEntry& s, listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth)
        {
            BOOST_FOREACH(const COutputEntry& r, listReceived)
                if (pwallet->mapAddressBook.count(r.destination)) {
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                }
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const list<CAccountingEntry> & acentries = pwallet->laccentries;
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    BOOST_FOREACH(const PAIRTYPE(string, CAmount)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue listsinceblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp)
        throw runtime_error(
            "listsinceblock ( \"blockhash\" target_confirmations include_watchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
            "2. target_confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. include_watchonly:       (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"firoaddress\",    (string) The Firo address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "                                          When it's < 0, it means the transaction conflicted that many blocks ago.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
             "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the last block\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (request.params.size() > 0)
    {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
        {
            pindex = it->second;
            if (chainActive[pindex->nHeight] != pindex)
            {
                // the block being asked for is a part of a deactivated chain;
                // we don't want to depend on its perceived height in the block
                // chain, we want to instead use the last common ancestor
                pindex = chainActive.FindFork(pindex);
            }
        }
    }

    if (request.params.size() > 1)
    {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if (request.params.size() > 2 && request.params[2].get_bool())
    {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue gettransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "gettransaction \"txid\" ( include_watchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"                  (string, required) The transaction id\n"
            "2. \"include_watchonly\"     (bool, optional, default=false) Whether to include watch-only addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"fee\": x.xxx,            (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                              'send' category of transactions.\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"firoaddress\",   (string) The Firo address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "      \"fee\": x.xxx,                     (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                           'send' category of transactions.\n"
            "      \"abandoned\": xxx                  (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                           'send' category of transactions.\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(request.params.size() > 1)
        if(request.params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = pwallet->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.tx->GetValueOut() - nDebit : 0);
    if (wtx.tx->vin[0].IsLelantusJoinSplit())
        nFee = (0 - lelantus::ParseLelantusJoinSplit(wtx.tx->vin[0])->getFee());

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));

    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx), RPCSerializationFlags());
    entry.push_back(Pair("hex", strHex));

    return entry;
}

UniValue abandontransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already conflicted or abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return NullUniValue;
}


UniValue backupwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    // WARNING: don't lock any mutexes here before calling into pwallet->BackupWallet() due to it can cause dead
    // lock. Here is the example scenario that will cause dead lock if we lock cs_wallet before calling into
    // pwallet->BackupWallet():
    //
    // 1. Other threads construct CWalletDB without locking cs_wallet. This is safe because CWalletDB is a thread safe.
    // 2. This RPC get invoked. Then it lock cs_wallet before calling into pwallet->BackupWallet().
    // 3. pwallet->BackupWallet() will loop until the CWalletDB in the step 1 closed.
    // 4. Thread in step 1 try to lock cs_wallet while CWalletDB still open but it will wait forever due to it already
    //    locked by this RPC.
    //
    // We don't need to worry about pwallet->BackupWallet() due to it already thread safe.

    string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return NullUniValue;
}


UniValue keypoolrefill(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (request.params.size() > 0) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nRelockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 2)) {
        throw runtime_error(
            "walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending firos\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds.\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nunlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwallet->TopUpKeyPool();

    int64_t nSleepTime = request.params[1].get_int64();
    pwallet->nRelockTime = GetTime() + nSleepTime;
    RPCRunLater(strprintf("lockwallet(%s)", pwallet->strWalletFile), boost::bind(LockWallet, pwallet), nSleepTime);

    return NullUniValue;
}


UniValue walletpassphrasechange(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 2)) {
        throw runtime_error(
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return NullUniValue;
}


UniValue walletlock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (pwallet->IsCrypted() && (request.fHelp || request.params.size() != 0)) {
        throw runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletlock", "")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
}


UniValue encryptwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (!pwallet->IsCrypted() && (request.fHelp || request.params.size() != 1)) {
        throw runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt you wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending bitcoin\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can so something like sign\n"
            + HelpExampleCli("signmessage", "\"firoaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();

    return "wallet encrypted; Firo server stopping, restart to run with encrypted wallet.";
}

UniValue lockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "lockunspent unlock ([{\"txid\":\"txid\",\"vout\":n},...])\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, optional) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.params.size() == 1)
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VBOOL));
    else
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = request.params[0].get_bool();

    if (request.params.size() == 1) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    UniValue outputs = request.params[1].get_array();
    for (unsigned int idx = 0; idx < outputs.size(); idx++) {
        const UniValue& output = outputs[idx];
        if (!output.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected object");
        const UniValue& o = output.get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        string txid = find_value(o, "txid").get_str();
        if (!IsHex(txid))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");

        int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        COutPoint outpt(uint256S(txid), nOutput);

        if (fUnlock)
            pwallet->UnlockCoin(outpt);
        else
            pwallet->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listlockunspent", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
	return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or string, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("settxfee", "0.00000001 FIRO")
            + HelpExampleRpc("settxfee", "0.00000001 FIRO")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletversion\": xxxxx,       (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,           (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx,   (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx,   (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,           (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,      (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,          (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,        (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,           (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "  \"hdmasterkeyid\": \"<hash160>\" (string) the Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("walletversion", pwallet->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance())));
    obj.push_back(Pair("txcount",       (int)pwallet->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)pwallet->GetKeyPoolSize()));
    if (pwallet->IsCrypted()) {
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull())
         obj.push_back(Pair("hdmasterkeyid", masterKeyID.GetHex()));
    return obj;
}

UniValue resendwallettransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(GetTime(), g_connman.get());
    UniValue result(UniValue::VARR);
    BOOST_FOREACH(const uint256& txid, txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw runtime_error(
            "listunspent ( minconf maxconf  [\"addresses\",...] [include_unsafe] )\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"    (string) A json array of Firo addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) Firo address\n"
            "      ,...\n"
            "    ]\n"
            "4. include_unsafe (bool, optional, default=true) Include outputs that are not safe to spend\n"
            "                  because they come from unconfirmed untrusted transactions or unconfirmed\n"
            "                  replacement transactions (cases where we are less sure that a conflicting\n"
            "                  transaction won't be mined).\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",          (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",    (string) the Firo address\n"
            "    \"account\" : \"account\",    (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\",   (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction output amount in " + CURRENCY_UNIT + "\n"
            "    \"confirmations\" : n,      (numeric) The number of confirmations\n"
            "    \"redeemScript\" : n        (string) The redeemScript if scriptPubKey is P2SH\n"
            "    \"spendable\" : xxx,        (bool) Whether we have the private keys to spend this output\n"
            "    \"solvable\" : xxx          (bool) Whether we know how to spend this output, ignoring the lack of keys\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
        );

    int nMinDepth = 1;
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    set<CBitcoinAddress> setAddress;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Firo address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    bool include_unsafe = true;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    UniValue results(UniValue::VARR);
    vector<COutput> vecOutputs;
    assert(pwallet != NULL);
    LOCK2(cs_main, pwallet->cs_wallet);
    pwallet->AvailableCoins(vecOutputs, !include_unsafe, NULL, true);
    BOOST_FOREACH(const COutput& out, vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (setAddress.size() && (!fValidAddress || !setAddress.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));

        if (fValidAddress) {
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString()));

            if (pwallet->mapAddressBook.count(address)) {
                entry.push_back(Pair("account", pwallet->mapAddressBook[address].name));
            }

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
                }
            }
        }

        entry.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
        entry.push_back(Pair("amount", ValueFromAmount(out.tx->tx->vout[out.i].nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        entry.push_back(Pair("spendable", out.fSpendable));
        entry.push_back(Pair("solvable", out.fSolvable));
        results.push_back(entry);
    }

    return results;
}

UniValue fundrawtransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                            "fundrawtransaction \"hexstring\" ( options )\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add at most one change output to the outputs.\n"
                            "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
                            "2. options                 (object, optional)\n"
                            "   {\n"
                            "     \"changeAddress\"          (string, optional, default pool address) The Firo address to receive the change\n"
                            "     \"changePosition\"         (numeric, optional, default random) The index of the change output\n"
                            "     \"includeWatching\"        (boolean, optional, default false) Also select inputs which are watch only\n"
                            "     \"lockUnspents\"           (boolean, optional, default false) Lock selected unspent outputs\n"
                            "     \"reserveChangeKey\"       (boolean, optional, default true) Reserves the change output key from the keypool\n"
                            "     \"feeRate\"                (numeric, optional, default not set: makes wallet determine the fee) Set a specific feerate (" + CURRENCY_UNIT + " per KB)\n"
                            "     \"subtractFeeFromOutputs\" (array, optional) A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.\n"
                            "                                  [vout_index,...]\n"
                            "   }\n"
                            "                         for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR));

    CTxDestination changeAddress = CNoDestination();
    int changePosition = -1;
    bool includeWatching = false;
    bool lockUnspents = false;
    bool reserveChangeKey = true;
    CFeeRate feeRate = CFeeRate(0);
    bool overrideEstimatedFeerate = false;
    UniValue subtractFeeFromOutputs;
    set<int> setSubtractFeeFromOutputs;

    if (request.params.size() > 1) {
      if (request.params[1].type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        includeWatching = request.params[1].get_bool();
      }
      else {
        RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VOBJ));

        UniValue options = request.params[1];

        RPCTypeCheckObj(options,
            {
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"reserveChangeKey", UniValueType(UniValue::VBOOL)},
                {"feeRate", UniValueType()}, // will be checked below
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
            },
            true, true);

        if (options.exists("changeAddress")) {
            CBitcoinAddress address(options["changeAddress"].get_str());

            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "changeAddress must be a valid Firo address");

            changeAddress = address.Get();
        }

        if (options.exists("changePosition"))
            changePosition = options["changePosition"].get_int();

        if (options.exists("includeWatching"))
            includeWatching = options["includeWatching"].get_bool();

        if (options.exists("lockUnspents"))
            lockUnspents = options["lockUnspents"].get_bool();

        if (options.exists("reserveChangeKey"))
            reserveChangeKey = options["reserveChangeKey"].get_bool();

        if (options.exists("feeRate"))
        {
            feeRate = CFeeRate(AmountFromValue(options["feeRate"]));
            overrideEstimatedFeerate = true;
        }

        if (options.exists("subtractFeeFromOutputs"))
            subtractFeeFromOutputs = options["subtractFeeFromOutputs"].get_array();
      }
    }

    // parse hex string from parameter
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (tx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > tx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        if (pos >= int(tx.vout.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        setSubtractFeeFromOutputs.insert(pos);
    }

    CAmount nFeeOut;
    string strFailReason;

    if (!pwallet->FundTransaction(tx, nFeeOut, overrideEstimatedFeerate, feeRate, changePosition, strFailReason, includeWatching, lockUnspents, setSubtractFeeFromOutputs, reserveChangeKey, changeAddress)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(tx)));
    result.push_back(Pair("changepos", changePosition));
    result.push_back(Pair("fee", ValueFromAmount(nFeeOut)));

    return result;
}

UniValue regeneratemintpool(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw runtime_error(
                "regeneratemintpool\n"
                "\nIf issues exist with the keys that map to mintpool entries in the DB, this function corrects them.\n"
                "\nExamples:\n"
                + HelpExampleCli("regeneratemintpool", "")
                + HelpExampleRpc("regeneratemintpool", "")
            );

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    if (!pwallet->IsHDSeedAvailable() || !pwallet->zwallet) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Can only regenerate mintpool on a HD-enabled wallet.");
    }

    CWalletDB walletdb(pwallet->strWalletFile);
    vector<std::pair<uint256, MintPoolEntry>> listMintPool = walletdb.ListMintPool();
    std::vector<std::pair<uint256, GroupElement>> serialPubcoinPairs = walletdb.ListSerialPubcoinPairs();

    // <hashPubcoin, hashSerial>
    std::pair<uint256,uint256> nIndexes;

    uint256 oldHashSerial;
    uint256 oldHashPubcoin;

    bool reindexRequired = false;

    for (auto& mintPoolPair : listMintPool){
        oldHashPubcoin = mintPoolPair.first;
        bool hasSerial = pwallet->zwallet->GetSerialForPubcoin(serialPubcoinPairs, oldHashPubcoin, oldHashSerial);

        MintPoolEntry entry = mintPoolPair.second;
        nIndexes = pwallet->zwallet->RegenerateMintPoolEntry(walletdb, get<0>(entry),get<1>(entry),get<2>(entry));

        if(nIndexes.first != oldHashPubcoin){
            walletdb.EraseMintPoolPair(oldHashPubcoin);
            reindexRequired = true;
        }

        if(!hasSerial || nIndexes.second != oldHashSerial){
            walletdb.ErasePubcoin(oldHashSerial);
            reindexRequired = true;
        }
    }

    if(reindexRequired)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Mintpool issue corrected. Please shutdown firo and restart with -reindex flag.");

    return true;
}

//[firo]: zerocoin section
// zerocoin section

UniValue listunspentmintzerocoins(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw runtime_error(
                "listunspentmintzerocoins [minconf=1] [maxconf=9999999] \n"
                        "Returns array of unspent transaction outputs\n"
                        "with between minconf and maxconf (inclusive) confirmations.\n"
                        "Results are an array of Objects, each of which has:\n"
                        "{txid, vout, scriptPubKey, amount, confirmations}");

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();

    int nMaxDepth = 9999999;
    if (request.params.size() > 1)
        nMaxDepth = request.params[1].get_int();

    UniValue results(UniValue::VARR);
    vector <COutput> vecOutputs;
    assert(pwallet != NULL);
    pwallet->ListAvailableCoinsMintCoins(vecOutputs, false);
    LogPrintf("vecOutputs.size()=%s\n", vecOutputs.size());
    BOOST_FOREACH(const COutput &out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64_t nValue = out.tx->tx->vout[out.i].nValue;
        const CScript &pk = out.tx->tx->vout[out.i].scriptPubKey;
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        results.push_back(entry);
    }

    return results;
}

UniValue listunspentsigmamints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw runtime_error(
                "listunspentsigmamints [minconf=1] [maxconf=9999999] \n"
                        "Returns array of unspent transaction outputs\n"
                        "with between minconf and maxconf (inclusive) confirmations.\n"
                        "Results are an array of Objects, each of which has:\n"
                        "{txid, vout, scriptPubKey, amount, confirmations}");

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    EnsureSigmaWalletIsAvailable();

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();

    int nMaxDepth = 9999999;
    if (request.params.size() > 1)
        nMaxDepth = request.params[1].get_int();

    UniValue results(UniValue::VARR);
    vector <COutput> vecOutputs;
    assert(pwallet != NULL);
    pwallet->ListAvailableSigmaMintCoins(vecOutputs, false);
    LogPrintf("vecOutputs.size()=%s\n", vecOutputs.size());
    BOOST_FOREACH(const COutput &out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64_t nValue = out.tx->tx->vout[out.i].nValue;
        const CScript &pk = out.tx->tx->vout[out.i].scriptPubKey;
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        results.push_back(entry);
    }

    return results;
}

UniValue listunspentlelantusmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2) {
        throw runtime_error(
            "listunspentsigmamints [minconf=1] [maxconf=9999999] \n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}");
    }

    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
            "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    EnsureLelantusWalletIsAvailable();

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();

    int nMaxDepth = 9999999;
    if (request.params.size() > 1)
        nMaxDepth = request.params[1].get_int();

    UniValue results(UniValue::VARR);
    vector <COutput> vecOutputs;
    assert(pwallet != NULL);
    pwallet->ListAvailableLelantusMintCoins(vecOutputs, false);
    LogPrintf("vecOutputs.size()=%s\n", vecOutputs.size());
    BOOST_FOREACH(const COutput &out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64_t nValue = out.tx->tx->vout[out.i].nValue;
        const CScript &pk = out.tx->tx->vout[out.i].scriptPubKey;
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        results.push_back(entry);
    }

    return results;
}

UniValue mint(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "mint amount\n"
            "\nAutomatically choose denominations to mint by amount."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to mint, must be a multiple of 0.05\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("mint", "0.15")
            + HelpExampleCli("mint", "100.9")
            + HelpExampleRpc("mint", "0.15")
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureSigmaWalletIsAvailable();

    // Ensure Sigma mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!sigma::IsSigmaAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not active");
    }

    CAmount nAmount = AmountFromValue(request.params[0]);
    LogPrintf("rpcWallet.mint() denomination = %s, nAmount = %d \n", request.params[0].getValStr(), nAmount);

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

    std::vector<sigma::PrivateCoin> privCoins;

    const auto& sigmaParams = sigma::Params::get_default();
    std::transform(mints.begin(), mints.end(), std::back_inserter(privCoins),
        [sigmaParams](const sigma::CoinDenomination& denom) -> sigma::PrivateCoin {
            return sigma::PrivateCoin(sigmaParams, denom);
        });
    vector<CHDMint> vDMints;
    auto vecSend = CWallet::CreateSigmaMintRecipients(privCoins, vDMints);

    CWalletTx wtx;
    std::string strError = pwallet->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

UniValue mintlelantus(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "mintlelantus amount\n"
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to mint, must be not less than 0.05\n"
                "\nResult:\n"
                "\"transactionid\"  (string) The transaction id.\n"
                "\nExamples:\n"
                + HelpExampleCli("mintlelantus", "0.15")
                + HelpExampleCli("mintlelantus", "100.9")
                + HelpExampleRpc("mintlelantus", "0.15")
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureLelantusWalletIsAvailable();

    // Ensure Lelantus mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    CAmount nAmount = AmountFromValue(request.params[0]);
    LogPrintf("rpcWallet.mintlelantus() nAmount = %d \n", nAmount);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<CHDMint> mints;
    std::string strError = pwallet->MintAndStoreLelantus(nAmount, wtxAndFee, mints);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    UniValue result(UniValue::VARR);
    for(const auto& wtx : wtxAndFee) {
        result.push_back(wtx.first.GetHash().GetHex());
    }

    return result;
}

UniValue autoMintlelantus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "This function automatically mints all unspent transparent funds\n"
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureLelantusWalletIsAvailable();

    // Ensure Lelantus mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<CHDMint> mints;
    std::string strError = pwallet->MintAndStoreLelantus(0, wtxAndFee, mints, true);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    UniValue result(UniValue::VARR);
    for(const auto& wtx : wtxAndFee) {
        result.push_back(wtx.first.GetHash().GetHex());
    }

    return result;
}

UniValue mintzerocoin(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error("mintzerocoin <amount>(1,10,25,50,100)\n" + HelpRequiringPassphrase(pwallet));

    EnsureZerocoinMintIsAllowed();

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (request.params[0].get_real() == 1.0) {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 10.0) {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 25.0) {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 50.0) {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 100.0) {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = AmountFromValue(request.params[0]);
    } else {
        throw runtime_error("mintzerocoin <amount>(1,10,25,50,100)\n");
    }
    LogPrintf("rpcWallet.mintzerocoin() denomination = %s, nAmount = %s \n", denomination, nAmount);


    // Always use modulus v2
    libzerocoin::Params *zcParams = ZCParamsV2;

    // The following constructor does all the work of minting a brand
    // new zerocoin. It stores all the private values inside the
    // PrivateCoin object. This includes the coin secrets, which must be
    // stored in a secure location (wallet) at the client.
    libzerocoin::PrivateCoin newCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
    // Get a copy of the 'public' portion of the coin. You should
    // embed this into a Zerocoin 'MINT' transaction along with a series
    // of currency inputs totaling the assigned value of one zerocoin.
    libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();

    // Validate
    if (pubCoin.validate()) {
        CScript scriptSerializedCoin =
                CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

        if (pwallet->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        // Wallet comments
        CWalletTx wtx;
        string strError = pwallet->MintZerocoin(scriptSerializedCoin, nAmount, wtx);

        if (strError != "")
            throw JSONRPCError(RPC_WALLET_ERROR, strError);

        CWalletDB walletdb(pwallet->strWalletFile);
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
        pwallet->NotifyZerocoinChanged(pwallet, zerocoinTx.value.GetHex(), "New (" + std::to_string(zerocoinTx.denomination) + " mint)", CT_NEW);
        walletdb.WriteZerocoinEntry(zerocoinTx);

        return wtx.GetHash().GetHex();
    } else {
        return "";
    }

}

UniValue mintmanyzerocoin(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() == 0 || request.params.size() % 2 != 0 || request.params.size() > 10)
        throw runtime_error(
                "mintmanyzerocoin <denomination>(1,10,25,50,100), numberOfMints, <denomination>(1,10,25,50,100), numberOfMints, ... }\n"
                + HelpRequiringPassphrase(pwallet)
                + "\nMint 1 or more zerocoins in a single transaction. Amounts must be of denominations specified.\n"
                + "Specify each denomination followed by the number of them to mint, for all denominations desired.\n"
                + "Total amount for all must be less than " + to_string(ZC_MINT_LIMIT) + ".  \n"
                "\nArguments:\n"
                "1. \"denomination\"             (integer, required) zerocoin denomination\n"
                "2. \"numberOfMints\"            (integer, required) amount of mints for chosen denomination\n"
                "\nExamples:\nThe first example mints denomination 1, one time, for a total FIRO valuation of 1.\nThe next example mints denomination 25, ten times, and denomination 50, five times, for a total FIRO valuation of 500.\n"
                    + HelpExampleCli("mintmanyzerocoin", "1 1")
                    + HelpExampleCli("mintmanyzerocoin", "25 10 50 5")
        );

    EnsureZerocoinMintIsAllowed();

    UniValue sendTo(UniValue::VOBJ);

    for(size_t i=0; i<request.params.size(); i+=2){
        string denomination = request.params[i].get_str();
        string amount = request.params[i+1].get_str();
        sendTo.push_back(Pair(denomination, stoi(amount)));
    }

    if(!ValidMultiMint(pwallet, sendTo)){
        throw JSONRPCError(RPC_WALLET_ERROR, "Insufficient funds/mint inputs out of range");
    }

    int64_t denominationInt = 0;
    libzerocoin::CoinDenomination denomination;
    // Always use modulus v2
    libzerocoin::Params *zcParams = ZCParamsV2;

    vector<CRecipient> vecSend;
    vector<libzerocoin::PrivateCoin> privCoins;
    CWalletTx wtx;

    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& denominationStr, keys){

        denominationInt = stoi(denominationStr.c_str());

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
                    "denomination must be one of (1,10,25,50,100)\n");
        }


        int64_t amount = sendTo[denominationStr].get_int();

        LogPrintf("rpcWallet.mintmanyzerocoin() denomination = %s, nAmount = %s \n", denominationStr, amount);


        if(amount < 0){
                throw runtime_error(
                    "amounts must be greater than 0.\n");
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
                newCoin = libzerocoin::PrivateCoin(zcParams, denomination, ZEROCOIN_TX_VERSION_2);
                pubCoin = newCoin.getPublicCoin();
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

    string strError = pwallet->MintAndStoreZerocoin(vecSend, privCoins, wtx);

    if (strError != "")
        throw runtime_error(strError);

    return wtx.GetHash().GetHex();
}

UniValue spendzerocoin(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                "spendzerocoin <amount>(1,10,25,50,100) (\"firoaddress\")\n"
                + HelpRequiringPassphrase(pwallet) +
				"\nArguments:\n"
				"1. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. currently options are following 1, 10, 25, 50 and 100 only\n"
				"2. \"firoaddress\"  (string, optional) The Firo address to send to third party.\n"
				"\nExamples:\n"
				            + HelpExampleCli("spendzerocoin", "10 \"a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (request.params[0].get_real() == 1.0) {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 10.0) {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 25.0) {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 50.0) {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = AmountFromValue(request.params[0]);
    } else if (request.params[0].get_real() == 100.0) {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = AmountFromValue(request.params[0]);
    } else {
        throw runtime_error(
                "spendzerocoin <amount>(1,10,25,50,100) (\"firoaddress\")\n");
    }

    CBitcoinAddress address;
    string thirdPartyaddress = "";
    if (request.params.size() > 1){
    	// Address
    	thirdPartyaddress = request.params[1].get_str();
    	address = CBitcoinAddress(request.params[1].get_str());
		 if (!address.IsValid())
			 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
    }

    EnsureWalletIsUnlocked(pwallet);

    // Wallet comments
    CWalletTx wtx;
    CBigNum coinSerial;
    uint256 txHash;
    CBigNum zcSelectedValue;
    bool zcSelectedIsUsed;

    string strError = pwallet->SpendZerocoin(thirdPartyaddress, nAmount, denomination, wtx, coinSerial, txHash, zcSelectedValue,
                                                 zcSelectedIsUsed);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();

}

UniValue spendmanyzerocoin(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

        if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
                "spendmanyzerocoin \"{\"address\":\"<third party address or blank for internal>\", \"denominations\": [{\"value\":(1,10,25,50,100), \"amount\":<>}, {\"value\":(1,10,25,50,100), \"amount\":<>},...]}\"\n"
                + HelpRequiringPassphrase(pwallet)
                + "\nSpend multiple zerocoins in a single transaction. Amounts must be of denominations specified.\n"
                "\nArguments:\n"
                "1. \"address: \"             (object, required) A string specifying the address to send to. If left blank, will spend to a wallet address. \n"
                    " denominations: "
                    "    [\n"
                    "    {"
                    "      \"value\": ,   (numeric) The numeric value must be one of (1,10,25,50,100)\n"
                    "      \"amount\" :,  (numeric or string) The amount of spends of this value.\n"
                    "    }"
                    "    ,...\n"
                    "    ]\n"
                "\nExamples:\n"
                    + HelpExampleCli("spendmanyzerocoin", "\"{\\\"address\\\":\\\"TXYb6pEWBDcxQvTxbFQ9sEV1c3rWUPGW3v\\\", \\\"denominations\\\": [{\\\"value\\\":1, \\\"amount\\\":1}, {\\\"value\\\":10, \\\"amount\\\":1}]}\"")
                    + HelpExampleCli("spendmanyzerocoin", "\"{\\\"address\\\":\\\"\\\", \\\"denominations\\\": [{\\\"value\\\":1, \\\"amount\\\":2}]}\"")
        );

    UniValue data = request.params[0].get_obj();

    LOCK2(cs_main, pwallet->cs_wallet);

    int64_t value = 0;
    int64_t amount = 0;
    libzerocoin::CoinDenomination denomination;
    std::vector<std::pair<int64_t, libzerocoin::CoinDenomination>> denominations;
    UniValue addressUni(UniValue::VOBJ);

    UniValue inputs = find_value(data, "denominations");
    if(inputs.isNull()){
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }

    addressUni = find_value(data, "address");
    if(addressUni.isNull()){
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");
    }
    std::string addressStr = addressUni.get_str();

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
                    "spendmanyzerocoin <amount>(1,10,25,50,100) (\"firoaddress\")\n");
        }
        for(int64_t j=0; j<amount; j++){
            denominations.push_back(std::make_pair(value * COIN, denomination));
        }
    }

    string thirdPartyAddress = "";
    if (!(addressStr == "")){
        CBitcoinAddress address(addressStr);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
        thirdPartyAddress = addressStr;
    }

    EnsureWalletIsUnlocked(pwallet);

    // Wallet comments
    CWalletTx wtx;
    vector<CBigNum> coinSerials;
    uint256 txHash;
    vector<CBigNum> zcSelectedValues;
    string strError = "";

    // begin spend process
    CReserveKey reservekey(pwallet);

    if (pwallet->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SpendZerocoin() : %s", strError.c_str());
        return strError;
    }

    strError = pwallet->SpendMultipleZerocoin(thirdPartyAddress, denominations, wtx, coinSerials, txHash, zcSelectedValues, false);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

UniValue spendmany(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
                "spendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
                "\nSpend multiple zerocoins and remint changes in a single transaction by specify addresses and amount for each address."
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
                "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
                "    {\n"
                "      \"address\":amount   (numeric or string) The Firo address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
                "      ,...\n"
                "    }\n"
                "3. minconf                 (numeric, optional, default=6) NOT IMPLEMENTED. Only use the balance confirmed at least this many times.\n"
                "4. \"comment\"             (string, optional) A comment\n"
                "5. subtractfeefromamount   (string, optional) A json array with addresses.\n"
                "                           The fee will be equally deducted from the amount of each selected address.\n"
                "                           Those recipients will receive less firos than you enter in their corresponding amount field.\n"
                "                           If no addresses are specified here, the sender pays the fee.\n"
                "    [\n"
                "      \"address\"            (string) Subtract fee from this address\n"
                "      ,...\n"
                "    ]\n"
                "\nResult:\n"
                "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                "                                    the number of addresses.\n"
                "\nExamples:\n"
                "\nSend two amounts to two different addresses:\n"
                + HelpExampleCli("spendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
                "\nSend two amounts to two different addresses and subtract fee from amount:\n"
                + HelpExampleCli("spendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"")
        );

    if (!sigma::IsSigmaAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not active");
    }

    EnsureSigmaWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Only account "" have sigma coins.
    std::string strAccount = AccountFromValue(request.params[0]);
    if (!strAccount.empty())
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    UniValue sendTo = request.params[1].get_obj();

    CWalletTx wtx;
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    std::unordered_set<std::string> subtractFeeFromAmountSet;
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (request.params.size() > 4) {
        subtractFeeFromAmount = request.params[4].get_array();
        for (int i = subtractFeeFromAmount.size(); i--;) {
            subtractFeeFromAmountSet.insert(subtractFeeFromAmount[i].get_str());
        }
    }

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    auto keys = sendTo.getKeys();
    if (keys.size() <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Required at least an address to send");
    }

    for (const auto& strAddr : keys) {
        CBitcoinAddress address(strAddr);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address: " + strAddr);

        if (!setAddress.insert(address).second)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicated address: " + strAddr);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[strAddr]);
        if (nAmount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        }
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount =
            subtractFeeFromAmountSet.find(strAddr) != subtractFeeFromAmountSet.end();

        vecSend.push_back({scriptPubKey, nAmount, fSubtractFeeFromAmount});
    }

    EnsureWalletIsUnlocked(pwallet);

    CAmount nFeeRequired = 0;

    try {
        pwallet->SpendSigma(vecSend, wtx, nFeeRequired);
    }
    catch (const InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
    }
    catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    return wtx.GetHash().GetHex();
}

UniValue joinsplit(const JSONRPCRequest& request) {

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                "joinsplit {\"address\":amount,...} ([\"address\",...] )\n"
                "\nSpend lelantus and mint in one transaction, you need at least provide one of 1-st or 3-rd arguments."
                + HelpRequiringPassphrase(pwallet) + "\n"
                "\nArguments:\n"
                "1. \"amounts\"             (string, optional) A json object with addresses and amounts\n"
                "    {\n"
                "      \"address\":amount   (numeric or string) The Firo address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
                "      ,...\n"
                "    }\n"
                "2. subtractfeefromamount   (string, optional) A json array with addresses.\n"
                "                           The fee will be equally deducted from the amount of each selected address.\n"
                "                           Those recipients will receive less firos than you enter in their corresponding amount field.\n"
                "                           If no addresses are specified here, the sender pays the fee.\n"
                "    [\n"
                "      \"address\"            (string) Subtract fee from this address\n"
                "      ,...\n"
                "    ]\n"
                "3. output mints            (numeric, optional) A json object with amounts to mint\n"
                "    {\n"
                "      \"mint\"\n"
                "      ,...\n"
                "    }\n"
                "\nResult:\n"
                "\"transactionid\"          (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                "                                    the number of addresses.\n"
                "\nExamples:\n"
                "\nSend two amounts to two different addresses:\n"
                + HelpExampleCli("joinsplit", "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
                "\nSend two amounts to two different addresses and subtract fee from amount:\n"
                + HelpExampleCli("joinsplit", "\"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"\"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"")
        );

    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    EnsureLelantusWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);


    UniValue sendTo = request.params[0].get_obj();
    UniValue mintAmounts;
    if(request.params.size() >= 3) {
        try {
                mintAmounts = request.params[2].get_obj();
        } catch (std::runtime_error const &) {
            //may be empty
        }
    }

    std::unordered_set<std::string> subtractFeeFromAmountSet;
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (request.params.size() > 2) {
        try {
            subtractFeeFromAmount = request.params[1].get_array();
        }  catch (std::runtime_error const &) {
            //may be empty
        }
        for (int i = subtractFeeFromAmount.size(); i--;) {
            subtractFeeFromAmountSet.insert(subtractFeeFromAmount[i].get_str());
        }
    }

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;
    std::vector<CAmount> vMints;

    CAmount totalAmount = 0;

    auto keys = sendTo.getKeys();
    std::vector<UniValue> mints = mintAmounts.empty() ? std::vector<UniValue>() : mintAmounts.getValues();

    if(keys.empty() && mints.empty())
        throw JSONRPCError(RPC_TYPE_ERROR, "You have to provide at least public addressed or amount to mint");

    for (const auto& strAddr : keys) {
        CBitcoinAddress address(strAddr);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address: " + strAddr);

        if (!setAddress.insert(address).second)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, duplicated address: " + strAddr);

        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[strAddr]);
        if (nAmount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        }
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount =
                subtractFeeFromAmountSet.find(strAddr) != subtractFeeFromAmountSet.end();

        vecSend.push_back({scriptPubKey, nAmount, fSubtractFeeFromAmount});
    }

    for(const auto& mint : mints) {
        auto val = mint.get_int64();
        if (!lelantus::IsAvailableToMint(val) || val <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount to mint is invalid.\n");
        }

        vMints.push_back(val);
    }

    EnsureWalletIsUnlocked(pwallet);

    CWalletTx wtx;

    try {
        pwallet->JoinSplitLelantus(vecSend, vMints, wtx);
    }
    catch (const InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
    }
    catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    return wtx.GetHash().GetHex();
}

UniValue resetmintzerocoin(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
                "resetmintzerocoin"
                + HelpRequiringPassphrase(pwallet));

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    walletdb.ListPubCoin(listPubcoin);

    BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, listPubcoin){
        if (zerocoinItem.randomness != 0 && zerocoinItem.serialNumber != 0) {
            CZerocoinEntry zerocoinTx;
            zerocoinTx.IsUsed = false;
            zerocoinTx.denomination = zerocoinItem.denomination;
            zerocoinTx.value = zerocoinItem.value;
            zerocoinTx.serialNumber = zerocoinItem.serialNumber;
            zerocoinTx.nHeight = -1;
            zerocoinTx.randomness = zerocoinItem.randomness;
            zerocoinTx.ecdsaSecretKey = zerocoinItem.ecdsaSecretKey;
            walletdb.WriteZerocoinEntry(zerocoinTx);
        }
    }

    return NullUniValue;
}

UniValue resetsigmamint(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
                "resetsigmamint"
                + HelpRequiringPassphrase(pwallet));

    EnsureSigmaWalletIsAvailable();

    std::vector <CMintMeta> listMints;
    CWalletDB walletdb(pwallet->strWalletFile);
    listMints = pwallet->zwallet->GetTracker().ListMints(false, false);

    BOOST_FOREACH(CMintMeta &mint, listMints) {
        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), false, dMint)){
            continue;
        }
        dMint.SetUsed(false);
        dMint.SetHeight(-1);
        pwallet->zwallet->GetTracker().Add(walletdb, dMint, true);
    }

    return NullUniValue;
}

UniValue resetlelantusmint(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
                "resetlelantusmint"
                + HelpRequiringPassphrase(pwallet));

    EnsureLelantusWalletIsAvailable();

    std::vector <CLelantusMintMeta> listMints;
    CWalletDB walletdb(pwallet->strWalletFile);
    listMints = pwallet->zwallet->GetTracker().ListLelantusMints(false, false);

    BOOST_FOREACH(const CLelantusMintMeta& mint, listMints) {
        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), true, dMint)) {
            continue;
        }
        dMint.SetUsed(false);
        dMint.SetHeight(-1);
        pwallet->zwallet->GetTracker().AddLelantus(walletdb, dMint, true);
    }

    return NullUniValue;
}

UniValue listmintzerocoins(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
                "listmintzerocoins <all>(false/true)\n"
                        "\nArguments:\n"
                        "1. <all> (boolean, optional) false (default) to return own mintzerocoins. true to return every mintzerocoins.\n"
                        "\nResults are an array of Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    bool fAllStatus = false;
    if (request.params.size() > 0) {
        fAllStatus = request.params[0].get_bool();
    }

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    walletdb.ListPubCoin(listPubcoin);
    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, listPubcoin) {
        if (fAllStatus || zerocoinItem.IsUsed || (zerocoinItem.randomness != 0 && zerocoinItem.serialNumber != 0)) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", zerocoinItem.id));
            entry.push_back(Pair("IsUsed", zerocoinItem.IsUsed));
            entry.push_back(Pair("denomination", zerocoinItem.denomination));
            entry.push_back(Pair("value", zerocoinItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", zerocoinItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", zerocoinItem.nHeight));
            entry.push_back(Pair("randomness", zerocoinItem.randomness.GetHex()));
            results.push_back(entry);
        }
    }

    return results;
}

UniValue listsigmamints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
                "listsigmamints <all>(false/true)\n"
                "\nArguments:\n"
                "1. <all> (boolean, optional) false (default) to return own mintzerocoins. true to return every mintzerocoins.\n"
                "\nResults are an array of Objects, each of which has:\n"
                "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    EnsureSigmaWalletIsAvailable();

    bool fAllStatus = false;
    if (request.params.size() > 0) {
        fAllStatus = request.params[0].get_bool();
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    list <CSigmaEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    listPubcoin = pwallet->zwallet->GetTracker().MintsAsSigmaEntries(false, false);
    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CSigmaEntry &zerocoinItem, listPubcoin) {
        if (fAllStatus || zerocoinItem.IsUsed || (zerocoinItem.randomness != uint64_t(0) && zerocoinItem.serialNumber != uint64_t(0))) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", zerocoinItem.id));
            entry.push_back(Pair("IsUsed", zerocoinItem.IsUsed));
            entry.push_back(Pair("denomination", zerocoinItem.get_denomination_value()));
            entry.push_back(Pair("value", zerocoinItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", zerocoinItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", zerocoinItem.nHeight));
            entry.push_back(Pair("randomness", zerocoinItem.randomness.GetHex()));
            results.push_back(entry);
        }
    }

    return results;
}

UniValue listlelantusmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
                "listlelantusmints <all>(false/true)\n"
                "\nArguments:\n"
                "1. <all> (boolean, optional) false (default) to return own listlelantusmints. true to return every listlelantusmints.\n"
                "\nResults are an array of Objects, each of which has:\n"
                "{id, IsUsed, amount, value, serialNumber, nHeight, randomness}");

    EnsureLelantusWalletIsAvailable();

    bool fAllStatus = false;
    if (request.params.size() > 0) {
        fAllStatus = request.params[0].get_bool();
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    list <CLelantusEntry> listCoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    listCoin = pwallet->zwallet->GetTracker().MintsAsLelantusEntries(false, false);
    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CLelantusEntry &lelantusItem, listCoin) {
        if (fAllStatus || lelantusItem.IsUsed || (lelantusItem.randomness != uint64_t(0) && lelantusItem.serialNumber != uint64_t(0))) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", lelantusItem.id));
            entry.push_back(Pair("isUsed", lelantusItem.IsUsed));
            entry.push_back(Pair("amount", lelantusItem.amount));
            entry.push_back(Pair("value", lelantusItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", lelantusItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", lelantusItem.nHeight));
            entry.push_back(Pair("randomness", lelantusItem.randomness.GetHex()));
            results.push_back(entry);
        }
    }

    return results;
}


UniValue listpubcoins(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
                "listpubcoins <all>(1/10/25/50/100)\n"
                        "\nArguments:\n"
                        "1. <all> (int, optional) 1,10,25,50,100 (default) to return all pubcoin with denomination. empty to return all pubcoin.\n"
                        "\nResults are an array of Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    int denomination = -1;
    if (request.params.size() > 0) {
        denomination = request.params[0].get_int();
    }

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    walletdb.ListPubCoin(listPubcoin);
    UniValue results(UniValue::VARR);
    listPubcoin.sort(CompID);

    BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, listPubcoin) {
        if (zerocoinItem.id > 0 && (denomination < 0 || zerocoinItem.denomination == denomination)) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", zerocoinItem.id));
            entry.push_back(Pair("IsUsed", zerocoinItem.IsUsed));
            entry.push_back(Pair("denomination", zerocoinItem.denomination));
            entry.push_back(Pair("value", zerocoinItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", zerocoinItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", zerocoinItem.nHeight));
            entry.push_back(Pair("randomness", zerocoinItem.randomness.GetHex()));
            results.push_back(entry);
        }
    }

    return results;
}

UniValue listsigmapubcoins(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    std::string help_message =
        "listsigmapubcoins <all>(0.05/0.1/0.5/1/10/25/100)\n"
            "\nArguments:\n"
            "1. <all> (string, optional) 0.05, 0.1, 0.5, 1, 10, 25, 100 (default) to return all sigma public coins with given denomination. empty to return all pubcoin.\n"
            "\nResults are an array of Objects, each of which has:\n"
            "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}";
    if (request.fHelp || request.params.size() > 1) {
        throw runtime_error(help_message);
    }

    EnsureSigmaWalletIsAvailable();

    sigma::CoinDenomination denomination;
    bool filter_by_denom = false;
    if (request.params.size() > 0) {
        filter_by_denom = true;
        if (!sigma::StringToDenomination(request.params[0].get_str(), denomination)) {
            throw runtime_error(help_message);
        }
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    list<CSigmaEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    listPubcoin = pwallet->zwallet->GetTracker().MintsAsSigmaEntries(false, false);
    UniValue results(UniValue::VARR);
    listPubcoin.sort(CompSigmaHeight);

    auto state = sigma::CSigmaState::GetState();
    BOOST_FOREACH(const CSigmaEntry &sigmaItem, listPubcoin) {
        sigma::PublicCoin coin(sigmaItem.value, sigmaItem.get_denomination());
        int height, id;
        std::tie(height, id) = state->GetMintedCoinHeightAndId(coin);
        if (id > 0 &&
            (!filter_by_denom || sigmaItem.get_denomination() == denomination)) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", id));
            entry.push_back(Pair("IsUsed", sigmaItem.IsUsed));
            entry.push_back(Pair("denomination", sigmaItem.get_string_denomination()));
            entry.push_back(Pair("value", sigmaItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", sigmaItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", height));
            entry.push_back(Pair("randomness", sigmaItem.randomness.GetHex()));
            results.push_back(entry);
        }
    }

    return results;
}

UniValue setmintzerocoinstatus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
                "setmintzerocoinstatus \"coinserial\" <isused>(true/false)\n"
                        "Set mintzerocoin IsUsed status to True or False\n"
                        "Results are an array of one or no Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    CBigNum coinSerial;
    coinSerial.SetHex(request.params[0].get_str());

    bool fStatus = true;
    fStatus = request.params[1].get_bool();

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    walletdb.ListPubCoin(listPubcoin);

    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, listPubcoin) {
        if (zerocoinItem.serialNumber != 0) {
            LogPrintf("zerocoinItem.serialNumber = %s\n", zerocoinItem.serialNumber.GetHex());
            if (zerocoinItem.serialNumber == coinSerial) {
                LogPrintf("setmintzerocoinstatus Found!\n");
                CZerocoinEntry zerocoinTx;
                zerocoinTx.id = zerocoinItem.id;
                zerocoinTx.IsUsed = fStatus;
                zerocoinTx.denomination = zerocoinItem.denomination;
                zerocoinTx.value = zerocoinItem.value;
                zerocoinTx.serialNumber = zerocoinItem.serialNumber;
                zerocoinTx.nHeight = zerocoinItem.nHeight;
                zerocoinTx.randomness = zerocoinItem.randomness;
                zerocoinTx.ecdsaSecretKey = zerocoinItem.ecdsaSecretKey;
                const std::string& isUsedDenomStr = zerocoinTx.IsUsed
                        ? "Used (" + std::to_string(zerocoinTx.denomination) + " mint)"
                        : "New (" + std::to_string(zerocoinTx.denomination) + " mint)";
                pwallet->NotifyZerocoinChanged(pwallet, zerocoinTx.value.GetHex(), isUsedDenomStr, CT_UPDATED);
                walletdb.WriteZerocoinEntry(zerocoinTx);

                if (!fStatus) {
                    // erase zerocoin spend entry
                    CZerocoinSpendEntry spendEntry;
                    spendEntry.coinSerial = coinSerial;
                    walletdb.EraseCoinSpendSerialEntry(spendEntry);
                }

                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("id", zerocoinTx.id));
                entry.push_back(Pair("IsUsed", zerocoinTx.IsUsed));
                entry.push_back(Pair("denomination", zerocoinTx.denomination));
                entry.push_back(Pair("value", zerocoinTx.value.GetHex()));
                entry.push_back(Pair("serialNumber", zerocoinTx.serialNumber.GetHex()));
                entry.push_back(Pair("nHeight", zerocoinTx.nHeight));
                entry.push_back(Pair("randomness", zerocoinTx.randomness.GetHex()));
                results.push_back(entry);
                break;
            }
        }
    }

    return results;
}

UniValue setsigmamintstatus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
                "setsigmamintstatus \"coinserial\" <isused>(true/false)\n"
                "Set mintsigma IsUsed status to True or False\n"
                "Results are an array of one or no Objects, each of which has:\n"
                "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    EnsureSigmaWalletIsAvailable();

    Scalar coinSerial;
    coinSerial.SetHex(request.params[0].get_str());

    bool fStatus = true;
    fStatus = request.params[1].get_bool();

    EnsureWalletIsUnlocked(pwallet);

    std::vector <CMintMeta> listMints;
    CWalletDB walletdb(pwallet->strWalletFile);
    listMints = pwallet->zwallet->GetTracker().ListMints(false, false);

    UniValue results(UniValue::VARR);

    BOOST_FOREACH(CMintMeta &mint, listMints) {
        CSigmaEntry zerocoinItem;
        if(!pwallet->GetMint(mint.hashSerial, zerocoinItem))
            continue;

        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), false, dMint)){
            continue;
        }

        if (zerocoinItem.serialNumber != uint64_t(0)) {
            LogPrintf("zerocoinItem.serialNumber = %s\n", zerocoinItem.serialNumber.GetHex());
            if (zerocoinItem.serialNumber == coinSerial) {
                LogPrintf("setmintzerocoinstatus Found!\n");

                const std::string& isUsedDenomStr =
                    fStatus
                    ? "Used (" + std::to_string((double)zerocoinItem.get_denomination_value() / COIN) + " mint)"
                    : "New (" + std::to_string((double)zerocoinItem.get_denomination_value() / COIN) + " mint)";
                pwallet->NotifyZerocoinChanged(pwallet, zerocoinItem.value.GetHex(), isUsedDenomStr, CT_UPDATED);

                if(!mint.isDeterministic){
                    zerocoinItem.IsUsed = fStatus;
                    pwallet->zwallet->GetTracker().Add(walletdb, zerocoinItem, true);
                }else{
                    dMint.SetUsed(fStatus);
                    pwallet->zwallet->GetTracker().Add(walletdb, dMint, true);
                }

                if (!fStatus) {
                    // erase zerocoin spend entry
                    CSigmaSpendEntry spendEntry;
                    spendEntry.coinSerial = coinSerial;
                    walletdb.EraseCoinSpendSerialEntry(spendEntry);
                }

                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("id", zerocoinItem.id));
                entry.push_back(Pair("IsUsed", fStatus));
                entry.push_back(Pair("denomination", zerocoinItem.get_denomination_value()));
                entry.push_back(Pair("value", zerocoinItem.value.GetHex()));
                entry.push_back(Pair("serialNumber", zerocoinItem.serialNumber.GetHex()));
                entry.push_back(Pair("nHeight", zerocoinItem.nHeight));
                entry.push_back(Pair("randomness", zerocoinItem.randomness.GetHex()));
                results.push_back(entry);
                break;
            }
        }
    }

    return results;
}

UniValue setlelantusmintstatus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
                "setlelantusmintstatus \"coinserial\" <isused>(true/false)\n"
                "Set lelantus mint IsUsed status to True or False\n"
                "Results are an array of one or no Objects, each of which has:\n"
                "{id, IsUsed, amount, value, serialNumber, nHeight, randomness}");

    EnsureLelantusWalletIsAvailable();

    Scalar coinSerial;
    coinSerial.SetHex(request.params[0].get_str());

    bool fStatus = true;
    fStatus = request.params[1].get_bool();

    EnsureWalletIsUnlocked(pwallet);

    std::vector <CLelantusMintMeta> listMints;
    listMints = pwallet->zwallet->GetTracker().ListLelantusMints(false, false, false);
    CWalletDB walletdb(pwallet->strWalletFile);

    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CLelantusMintMeta& mint, listMints) {
        CLelantusEntry lelantusItem;
        if(!pwallet->GetMint(mint.hashSerial, lelantusItem))
            continue;

        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), true, dMint)){
            continue;
        }

        if (!lelantusItem.serialNumber.isZero()) {
            LogPrintf("lelantusItem.serialNumber = %s\n", lelantusItem.serialNumber.GetHex());
            if (lelantusItem.serialNumber == coinSerial) {
                LogPrintf("setmintzerocoinstatus Found!\n");

                const std::string& isUsedAmountStr =
                        fStatus
                        ? "Used (" + std::to_string((double)lelantusItem.amount / COIN) + " mint)"
                        : "New (" + std::to_string((double)lelantusItem.amount / COIN) + " mint)";
                pwallet->NotifyZerocoinChanged(pwallet, lelantusItem.value.GetHex(), isUsedAmountStr, CT_UPDATED);

                dMint.SetUsed(fStatus);
                pwallet->zwallet->GetTracker().AddLelantus(walletdb, dMint, true);

                if (!fStatus) {
                    // erase lelantus spend entry
                    CLelantusSpendEntry spendEntry;
                    spendEntry.coinSerial = coinSerial;
                    walletdb.EraseLelantusSpendSerialEntry(spendEntry);
                }

                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("id", lelantusItem.id));
                entry.push_back(Pair("isUsed", fStatus));
                entry.push_back(Pair("amount", lelantusItem.amount));
                entry.push_back(Pair("value", lelantusItem.value.GetHex()));
                entry.push_back(Pair("serialNumber", lelantusItem.serialNumber.GetHex()));
                entry.push_back(Pair("nHeight", lelantusItem.nHeight));
                entry.push_back(Pair("randomness", lelantusItem.randomness.GetHex()));
                results.push_back(entry);
                break;
            }
        }
    }

    return results;
}

UniValue listsigmaspends(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                "listsigmaspends\n"
                "Return up to \"count\" saved sigma spend transactions\n"
                "\nArguments:\n"
                "1. count            (numeric) The number of transactions to return, <=0 means no limit\n"
                "2. onlyunconfirmed  (bool, optional, default=false) If true return only unconfirmed transactions\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"txid\": \"transactionid\",      (string) The transaction hash\n"
                "    \"confirmations\": n,             (numeric) The number of confirmations for the transaction\n"
                "    \"abandoned\": xxx,               (bool) True if the transaction was already abandoned\n"
                "    \"spends\": \n"
                "    [\n"
                "      {\n"
                "        \"denomination\": d,            (string) Denomination\n"
                "        \"spendid\": id,                (numeric) Spend group id\n"
                "        \"serial\": \"s\",              (string) Serial number of the coin\n"
                "      }\n"
                "    ]\n"
                "    \"re-mints\": \n"
                "    [\n"
                "      {\n"
                "        \"denomination\": \"s\",        (string) Denomination\n"
                "        \"value\": \"s\",               (string) value\n"
                "      }\n"
                "    ]\n"
                "  }\n"
                "]\n");

    EnsureSigmaWalletIsAvailable();

    int  count = request.params[0].get_int();
    bool fOnlyUnconfirmed = request.params.size()>=2 && request.params[1].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue ret(UniValue::VARR);
    const CWallet::TxItems& txOrdered = pwallet->wtxOrdered;

    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin();
         it != txOrdered.rend();
         ++it) {
        CWalletTx *const pwtx = (*it).second.first;

        if (!pwtx || !pwtx->tx->IsSigmaSpend())
            continue;

        UniValue entry(UniValue::VOBJ);

        int confirmations = pwtx->GetDepthInMainChain();
        if (confirmations > 0 && fOnlyUnconfirmed)
            continue;

        entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
        entry.push_back(Pair("confirmations", confirmations));
        entry.push_back(Pair("abandoned", pwtx->isAbandoned()));

        UniValue spends(UniValue::VARR);
        BOOST_FOREACH(const CTxIn &txin, pwtx->tx->vin) {
            // For sigma public coin group id is prevout.n.
            int pubcoinId = txin.prevout.n;

            // NOTE(martun): +1 on the next line stands for 1 byte in which the opcode of
            // OP_SIGMASPEND is written. In zerocoin you will see +4 instead,
            // because the size of serialized spend is also written, probably in 3 bytes.
            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::Params* zcParams = sigma::Params::get_default();
            sigma::CoinSpend spend(zcParams, serializedCoinSpend);

            UniValue spendEntry(UniValue::VOBJ);
            spendEntry.push_back(Pair("denomination",
                                 sigma::DenominationToString(spend.getDenomination())));
            spendEntry.push_back(Pair("spendid", pubcoinId));
            spendEntry.push_back(Pair("serial", spend.getCoinSerialNumber().GetHex()));
            spends.push_back(spendEntry);
        }

        entry.push_back(Pair("spends", spends));

        UniValue remints(UniValue::VARR);
        BOOST_FOREACH(const CTxOut &txout, pwtx->tx->vout) {
            if (txout.scriptPubKey.empty() || !txout.scriptPubKey.IsSigmaMint()) {
                continue;
            }
            sigma::CoinDenomination denomination;
            IntegerToDenomination(txout.nValue, denomination);

            UniValue remintEntry(UniValue::VOBJ);
            remintEntry.push_back(Pair(
                "denomination", sigma::DenominationToString(denomination)));
            remintEntry.push_back(Pair(
                "value", sigma::ParseSigmaMintScript(txout.scriptPubKey).tostring()));
            remints.push_back(remintEntry);
        }

        entry.push_back(Pair("remints", remints));
        ret.push_back(entry);

        if (count > 0 && (int)ret.size() >= count)
            break;
    }

    return ret;
}

UniValue listlelantusjoinsplits(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                "listlelantusjoinsplits\n"
                "Return up to \"count\" saved lelantus joinsplit transactions\n"
                "\nArguments:\n"
                "1. count            (numeric) The number of transactions to return, <=0 means no limit\n"
                "2. onlyunconfirmed  (bool, optional, default=false) If true return only unconfirmed transactions\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"txid\": \"transactionid\",      (string) The transaction hash\n"
                "    \"confirmations\": n,             (numeric) The number of confirmations for the transaction\n"
                "    \"abandoned\": xxx,               (bool) True if the transaction was already abandoned\n"
                "    \"joinsplits\": \n"
                "    [\n"
                "      {\n"
                "        \"spendid\": id,                (numeric) Spend group id\n"
                "        \"serial\": \"s\",              (string) Serial number of the coin\n"
                "      }\n"
                "    ]\n"
                "  }\n"
                "]\n");

    EnsureLelantusWalletIsAvailable();

    int  count = request.params[0].get_int();
    bool fOnlyUnconfirmed = request.params.size()>=2 && request.params[1].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue ret(UniValue::VARR);
    const CWallet::TxItems& txOrdered = pwallet->wtxOrdered;

    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin();
         it != txOrdered.rend();
         ++it) {
        CWalletTx *const pwtx = (*it).second.first;

        if (!pwtx || !pwtx->tx->IsLelantusJoinSplit())
            continue;

        UniValue entry(UniValue::VOBJ);

        int confirmations = pwtx->GetDepthInMainChain();
        if (confirmations > 0 && fOnlyUnconfirmed)
            continue;

        entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
        entry.push_back(Pair("confirmations", confirmations));
        entry.push_back(Pair("abandoned", pwtx->isAbandoned()));

        UniValue spends(UniValue::VARR);
        std::unique_ptr<lelantus::JoinSplit> joinsplit;
        try {
            joinsplit = lelantus::ParseLelantusJoinSplit(pwtx->tx->vin[0]);
        } catch (std::invalid_argument&) {
            continue;
        }

        std::vector<Scalar> spentSerials = joinsplit->getCoinSerialNumbers();
        std::vector<uint32_t> ids = joinsplit->getCoinGroupIds();

        if(spentSerials.size() != ids.size()) {
            continue;
        }

        for(size_t i = 0; i < spentSerials.size(); i++) {
            UniValue spendEntry(UniValue::VOBJ);
            spendEntry.push_back(Pair("spendid", int64_t(ids[i])));
            spendEntry.push_back(Pair("serial", spentSerials[i].GetHex()));
            spends.push_back(spendEntry);
        }

        entry.push_back(Pair("spent_coins", spends));
        ret.push_back(entry);

        if (count > 0 && (int)ret.size() >= count)
            break;
    }

    return ret;
}

UniValue listspendzerocoins(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
                "listspendzerocoins\n"
                "Return up to \"count\" saved spend transactions\n"
                "\nArguments:\n"
                "1. count            (numeric) The number of transactions to return, <=0 means no limit\n"
                "2. onlyunconfirmed  (bool, optional, default=false) If true return only unconfirmed transactions\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"txid\": \"transactionid\",      (string) The transaction hash\n"
                "    \"denomination\": d,            (numeric) Denomination\n"
                "    \"spendid\": id,                (numeric) Spend group id\n"
                "    \"version\": \"v\",               (string) Spend version (1.0, 1.5 or 2.0)\n"
                "    \"modversion\": mv,             (numeric) Modulus version (1 or 2)\n"
                "    \"serial\": \"s\",                (string) Serial number of the coin\n"
                "    \"abandoned\": xxx,             (bool) True if the transaction was already abandoned\n"
                "    \"confirmations\": n,           (numeric) The number of confirmations for the transaction\n"
                "  }\n"
                "]\n");

    int  count = request.params[0].get_int();
    bool fOnlyUnconfirmed = request.params.size()>=2 && request.params[1].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue ret(UniValue::VARR);
    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
        CWalletTx *const pwtx = (*it).second.first;

        if (!pwtx || !pwtx->tx->IsZerocoinSpend() || pwtx->tx->vin.size() != 1)
            continue;

        UniValue entry(UniValue::VOBJ);

        int confirmations = pwtx->GetDepthInMainChain();
        if (confirmations > 0 && fOnlyUnconfirmed)
            continue;

        entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
        entry.push_back(Pair("confirmations", confirmations));
        entry.push_back(Pair("abandoned", pwtx->isAbandoned()));

        const CTxIn &txin = pwtx->tx->vin[0];
        int pubcoinId = txin.nSequence;
        bool fModulusV2 = pubcoinId >= ZC_MODULUS_V2_BASE_ID;
        if (fModulusV2)
            pubcoinId -= ZC_MODULUS_V2_BASE_ID;

        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                        (const char *)&*txin.scriptSig.end(),
                                        SER_NETWORK, PROTOCOL_VERSION);
        libzerocoin::CoinSpend spend(fModulusV2 ? ZCParamsV2 : ZCParams, serializedCoinSpend);
        int spendVersion = spend.getVersion();

        entry.push_back(Pair("denomination", (int)spend.getDenomination()));
        entry.push_back(Pair("spendid", pubcoinId));
        entry.push_back(Pair("modversion", fModulusV2 ? 2 : 1));
        entry.push_back(Pair("version", spendVersion==ZEROCOIN_TX_VERSION_1 ? "1.0" :
                                         (spendVersion==ZEROCOIN_TX_VERSION_1_5 ? "1.5" : "2.0")));
        entry.push_back(Pair("serial", spend.getCoinSerialNumber().GetHex()));

        ret.push_back(entry);

        if (count > 0 && (int)ret.size() >= count)
            break;
    }

    return ret;
}

UniValue remintzerocointosigma(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "remintzerocointosigma <denomination>(1,10,25,50,100)\n"
            +HelpRequiringPassphrase(pwallet) +
            "\nConvert zerocoin mint to sigma mint.\n"
            "\nArguments:\n"
            "1. \"denomination\"          (integer, required) existing zerocoin mint denomination\n"
        );

    EnsureSigmaWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);
    libzerocoin::CoinDenomination denomination;
    switch (request.params[0].get_int()) {
        case 1:
        case 10:
        case 25:
        case 50:
        case 100:
            denomination = (libzerocoin::CoinDenomination)request.params[0].get_int();
            break;

        default:
            throw runtime_error("Incorrect denomination\n");
    }

    EnsureWalletIsUnlocked(pwallet);
    std::string stringError;
    CWalletTx wtx;

    if (!pwallet->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, denomination, &wtx))
        throw JSONRPCError(RPC_WALLET_ERROR, stringError);

    return wtx.GetHash().GetHex();
}

UniValue removetxmempool(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
                "removetxmempool <txid>\n"
                + HelpRequiringPassphrase(pwallet));

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    LOCK(cs_main);
    {
        LOCK(mempool.cs);
        if (mempool.exists(hash)) {
            LogPrintf("[Ooops], Uncomplete function\n");
//            CTransaction tx;
//            tx = mempool.lookup(hash);
//            mempool.remove(tx);
            return NullUniValue;
        }
    }

    return NullUniValue;
}

UniValue removetxwallet(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error("removetxwallet <txid>\n" + HelpRequiringPassphrase(pwallet));

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    pwallet->EraseFromWallet(hash);
    return NullUniValue;
}



extern UniValue dumpprivkey_firo(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet_firo(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);

// Calculate the size of the transaction assuming all signatures are max size
// Use DummySignatureCreator, which inserts 72 byte signatures everywhere.
// TODO: re-use this in CWallet::CreateTransaction (right now
// CreateTransaction uses the constructed dummy-signed tx to do a priority
// calculation, but we should be able to refactor after priority is removed).
// NOTE: this requires that all inputs must be in mapWallet (eg the tx should
// be IsAllFromMe).
int64_t CalculateMaximumSignedTxSize(CWallet * const pwallet, const CTransaction &tx)
{
    CMutableTransaction txNew(tx);
    std::vector<pair<CWalletTx *, unsigned int>> vCoins;
    // Look up the inputs.  We should have already checked that this transaction
    // IsAllFromMe(ISMINE_SPENDABLE), so every input should already be in our
    // wallet, with a valid index into the vout array.
    for (auto& input : tx.vin) {
        const auto mi = pwallet->mapWallet.find(input.prevout.hash);
        assert(mi != pwallet->mapWallet.end() && input.prevout.n < mi->second.tx->vout.size());
        vCoins.emplace_back(make_pair(&(mi->second), input.prevout.n));
    }
    if (!pwallet->DummySignTx(txNew, vCoins)) {
        // This should never happen, because IsAllFromMe(ISMINE_SPENDABLE)
        // implies that we can sign for every input.
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction contains inputs that cannot be signed");
    }
    return GetVirtualTransactionSize(txNew);
}

UniValue bumpfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw runtime_error(
            "bumpfee \"txid\" ( options ) \n"
            "\nBumps the fee of an opt-in-RBF transaction T, replacing it with a new transaction B.\n"
            "An opt-in RBF transaction with the given txid must be in the wallet.\n"
            "The command will pay the additional fee by decreasing (or perhaps removing) its change output.\n"
            "If the change output is not big enough to cover the increased fee, the command will currently fail\n"
            "instead of adding new inputs to compensate. (A future implementation could improve this.)\n"
            "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
            "By default, the new fee will be calculated automatically using estimatefee.\n"
            "The user can specify a confirmation target for estimatefee.\n"
            "Alternatively, the user can specify totalFee, or use RPC setpaytxfee to set a higher fee rate.\n"
            "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
            "returned by getnetworkinfo) to enter the node's mempool.\n"
            "\nArguments:\n"
            "1. txid                  (string, required) The txid to be bumped\n"
            "2. options               (object, optional)\n"
            "   {\n"
            "     \"confTarget\"        (numeric, optional) Confirmation target (in blocks)\n"
            "     \"totalFee\"          (numeric, optional) Total fee (NOT feerate) to pay, in satoshis.\n"
            "                         In rare cases, the actual fee paid might be slightly higher than the specified\n"
            "                         totalFee if the tx change output has to be removed because it is too close to\n"
            "                         the dust threshold.\n"
            "     \"replaceable\"       (boolean, optional, default true) Whether the new transaction should still be\n"
            "                         marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
            "                         be left unchanged from the original. If false, any input sequence numbers in the\n"
            "                         original transaction that were less than 0xfffffffe will be increased to 0xfffffffe\n"
            "                         so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
            "                         still be replacable in practice, for example if it has unconfirmed ancestors which\n"
            "                         are replaceable).\n"
            "   }\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\":    \"value\",   (string)  The id of the new transaction\n"
            "  \"origfee\":  n,         (numeric) Fee of the replaced transaction\n"
            "  \"fee\":      n,         (numeric) Fee of the new transaction\n"
            "  \"errors\":  [ str... ] (json array of strings) Errors encountered during processing (may be empty)\n"
            "}\n"
            "\nExamples:\n"
            "\nBump the fee, get the new transaction\'s txid\n" +
            HelpExampleCli("bumpfee", "<txid>"));
    }

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VSTR)(UniValue::VOBJ));
    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    // retrieve the original tx from the wallet
    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    CWalletTx& wtx = pwallet->mapWallet[hash];

    if (pwallet->HasWalletSpend(hash)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction has descendants in the wallet");
    }

    {
        LOCK(mempool.cs);
        auto it = mempool.mapTx.find(hash);
        if (it != mempool.mapTx.end() && it->GetCountWithDescendants() > 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction has descendants in the mempool");
        }
    }

    if (wtx.GetDepthInMainChain() != 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction has been mined, or is conflicted with a mined transaction");
    }

    if (!SignalsOptInRBF(wtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction is not BIP 125 replaceable");
    }

    if (wtx.mapValue.count("replaced_by_txid")) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Cannot bump transaction %s which was already bumped by transaction %s", hash.ToString(), wtx.mapValue.at("replaced_by_txid")));
    }

    // check that original tx consists entirely of our inputs
    // if not, we can't bump the fee, because the wallet has no way of knowing the value of the other inputs (thus the fee)
    if (!pwallet->IsAllFromMe(wtx, ISMINE_SPENDABLE)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction contains inputs that don't belong to this wallet");
    }

    // figure out which output was change
    // if there was no change output or multiple change outputs, fail
    int nOutput = -1;
    for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
        if (pwallet->IsChange(wtx.tx->GetHash(), wtx.tx->vout[i])) {
            if (nOutput != -1) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Transaction has multiple change outputs");
            }
            nOutput = i;
        }
    }
    if (nOutput == -1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction does not have a change output");
    }

    // Calculate the expected size of the new transaction.
    int64_t txSize = GetVirtualTransactionSize(*(wtx.tx));
    const int64_t maxNewTxSize = CalculateMaximumSignedTxSize(pwallet, *wtx.tx);

    // optional parameters
    bool specifiedConfirmTarget = false;
    int newConfirmTarget = nTxConfirmTarget;
    CAmount totalFee = 0;
    bool replaceable = true;
    if (request.params.size() > 1) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"confTarget", UniValueType(UniValue::VNUM)},
                {"totalFee", UniValueType(UniValue::VNUM)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
            },
            true, true);

        if (options.exists("confTarget") && options.exists("totalFee")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confTarget and totalFee options should not both be set. Please provide either a confirmation target for fee estimation or an explicit total fee for the transaction.");
        } else if (options.exists("confTarget")) {
            specifiedConfirmTarget = true;
            newConfirmTarget = options["confTarget"].get_int();
            if (newConfirmTarget <= 0) { // upper-bound will be checked by estimatefee/smartfee
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid confTarget (cannot be <= 0)");
            }
        } else if (options.exists("totalFee")) {
            totalFee = options["totalFee"].get_int64();
            CAmount requiredFee = CWallet::GetRequiredFee(maxNewTxSize);
            if (totalFee < requiredFee ) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("Insufficient totalFee (cannot be less than required fee %s)",
                                             FormatMoney(requiredFee)));
            }
        }

        if (options.exists("replaceable")) {
            replaceable = options["replaceable"].get_bool();
        }
    }

    // calculate the old fee and fee-rate
    CAmount nOldFee = wtx.GetDebit(ISMINE_SPENDABLE) - wtx.tx->GetValueOut();
    CFeeRate nOldFeeRate(nOldFee, txSize);
    CAmount nNewFee;
    CFeeRate nNewFeeRate;
    // The wallet uses a conservative WALLET_INCREMENTAL_RELAY_FEE value to
    // future proof against changes to network wide policy for incremental relay
    // fee that our node may not be aware of.
    CFeeRate walletIncrementalRelayFee = CFeeRate(WALLET_INCREMENTAL_RELAY_FEE);
    if (::incrementalRelayFee > walletIncrementalRelayFee) {
        walletIncrementalRelayFee = ::incrementalRelayFee;
    }

    if (totalFee > 0) {
        CAmount minTotalFee = nOldFeeRate.GetFee(maxNewTxSize) + ::incrementalRelayFee.GetFee(maxNewTxSize);
        if (totalFee < minTotalFee) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Insufficient totalFee, must be at least %s (oldFee %s + incrementalFee %s)",
                                                                FormatMoney(minTotalFee), FormatMoney(nOldFeeRate.GetFee(maxNewTxSize)), FormatMoney(::incrementalRelayFee.GetFee(maxNewTxSize))));
        }
        nNewFee = totalFee;
        nNewFeeRate = CFeeRate(totalFee, maxNewTxSize);
    } else {
        // if user specified a confirm target then don't consider any global payTxFee
        if (specifiedConfirmTarget) {
            nNewFee = CWallet::GetMinimumFee(maxNewTxSize, newConfirmTarget, mempool, CAmount(0));
        }
        // otherwise use the regular wallet logic to select payTxFee or default confirm target
        else {
            nNewFee = CWallet::GetMinimumFee(maxNewTxSize, newConfirmTarget, mempool);
        }

        nNewFeeRate = CFeeRate(nNewFee, maxNewTxSize);

        // New fee rate must be at least old rate + minimum incremental relay rate
        // walletIncrementalRelayFee.GetFeePerK() should be exact, because it's initialized
        // in that unit (fee per kb).
        // However, nOldFeeRate is a calculated value from the tx fee/size, so
        // add 1 satoshi to the result, because it may have been rounded down.
        if (nNewFeeRate.GetFeePerK() < nOldFeeRate.GetFeePerK() + 1 + walletIncrementalRelayFee.GetFeePerK()) {
            nNewFeeRate = CFeeRate(nOldFeeRate.GetFeePerK() + 1 + walletIncrementalRelayFee.GetFeePerK());
            nNewFee = nNewFeeRate.GetFee(maxNewTxSize);
        }
    }

    // Check that in all cases the new fee doesn't violate maxTxFee
     if (nNewFee > maxTxFee) {
         throw JSONRPCError(RPC_WALLET_ERROR,
                            strprintf("Specified or calculated fee %s is too high (cannot be higher than maxTxFee %s)",
                                      FormatMoney(nNewFee), FormatMoney(maxTxFee)));
     }

    // check that fee rate is higher than mempool's minimum fee
    // (no point in bumping fee if we know that the new tx won't be accepted to the mempool)
    // This may occur if the user set TotalFee or paytxfee too low, if fallbackfee is too low, or, perhaps,
    // in a rare situation where the mempool minimum fee increased significantly since the fee estimation just a
    // moment earlier. In this case, we report an error to the user, who may use totalFee to make an adjustment.
    CFeeRate minMempoolFeeRate = mempool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
    if (nNewFeeRate.GetFeePerK() < minMempoolFeeRate.GetFeePerK()) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("New fee rate (%s) is less than the minimum fee rate (%s) to get into the mempool. totalFee value should to be at least %s or settxfee value should be at least %s to add transaction.", FormatMoney(nNewFeeRate.GetFeePerK()), FormatMoney(minMempoolFeeRate.GetFeePerK()), FormatMoney(minMempoolFeeRate.GetFee(maxNewTxSize)), FormatMoney(minMempoolFeeRate.GetFeePerK())));
    }

    // Now modify the output to increase the fee.
    // If the output is not large enough to pay the fee, fail.
    CAmount nDelta = nNewFee - nOldFee;
    assert(nDelta > 0);
    CMutableTransaction tx(*(wtx.tx));
    CTxOut* poutput = &(tx.vout[nOutput]);
    if (poutput->nValue < nDelta) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Change output is too small to bump the fee");
    }

    // If the output would become dust, discard it (converting the dust to fee)
    poutput->nValue -= nDelta;
    if (poutput->nValue <= poutput->GetDustThreshold(::dustRelayFee)) {
        LogPrint("rpc", "Bumping fee and discarding dust output\n");
        nNewFee += poutput->nValue;
        tx.vout.erase(tx.vout.begin() + nOutput);
    }

    // Mark new tx not replaceable, if requested.
    if (!replaceable) {
        for (auto& input : tx.vin) {
            if (input.nSequence < 0xfffffffe) input.nSequence = 0xfffffffe;
        }
    }

    // sign the new tx
    CTransaction txNewConst(tx);
    int nIn = 0;
    for (auto& input : tx.vin) {
        std::map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(input.prevout.hash);
        assert(mi != pwallet->mapWallet.end() && input.prevout.n < mi->second.tx->vout.size());
        const CScript& scriptPubKey = mi->second.tx->vout[input.prevout.n].scriptPubKey;
        const CAmount& amount = mi->second.tx->vout[input.prevout.n].nValue;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(pwallet, &txNewConst, nIn, amount, SIGHASH_ALL), scriptPubKey, sigdata)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
        }
        UpdateTransaction(tx, nIn, sigdata);
        nIn++;
    }

    // commit/broadcast the tx
    CReserveKey reservekey(pwallet);
    CWalletTx wtxBumped(pwallet, MakeTransactionRef(std::move(tx)));
    wtxBumped.mapValue = wtx.mapValue;
    wtxBumped.mapValue["replaces_txid"] = hash.ToString();
    wtxBumped.vOrderForm = wtx.vOrderForm;
    wtxBumped.strFromAccount = wtx.strFromAccount;
    wtxBumped.fTimeReceivedIsTxTime = true;
    wtxBumped.fFromMe = true;
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxBumped, reservekey, g_connman.get(), state)) {
        // NOTE: CommitTransaction never returns false, so this should never happen.
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason()));
    }

    UniValue vErrors(UniValue::VARR);
    if (state.IsInvalid()) {
        // This can happen if the mempool rejected the transaction.  Report
        // what happened in the "errors" response.
        vErrors.push_back(strprintf("Error: The transaction was rejected: %s", FormatStateMessage(state)));
    }

    // mark the original tx as bumped
    if (!pwallet->MarkReplaced(wtx.GetHash(), wtxBumped.GetHash())) {
        // TODO: see if JSON-RPC has a standard way of returning a response
        // along with an exception. It would be good to return information about
        // wtxBumped to the caller even if marking the original transaction
        // replaced does not succeed for some reason.
        vErrors.push_back("Error: Created new bumpfee transaction but could not mark the original transaction as replaced.");
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("txid", wtxBumped.GetHash().GetHex()));
    result.push_back(Pair("origfee", ValueFromAmount(nOldFee)));
    result.push_back(Pair("fee", ValueFromAmount(nNewFee)));
    result.push_back(Pair("errors", vErrors));

    return result;
}

/******************************************************************************/

UniValue listpcodes(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw runtime_error(
            "listpcodes  \n"
            "Lists all existing payment codes with labels. \n"
            "Example:\n" +
            HelpExampleCli("listpcodes", ""));
    }
    UniValue result(UniValue::VARR);
    for(std::tuple<bip47::CPaymentCode, std::string, CBitcoinAddress> const & info : pwallet->ListPcodes()) {
        UniValue r(UniValue::VOBJ);
        r.push_back(Pair("Pcode", std::get<0>(info).toString()));
        r.push_back(Pair("Label",std::get<1>(info)));
        r.push_back(Pair("NotifAddr",std::get<2>(info).ToString()));
        result.push_back(r);
    }
    return result;
}

UniValue generatepcode(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    std::function<void()> help = []()
    {
        throw runtime_error(
            "generatepcode  \"label\"\n"
            "Generates a new labeled BIP47 payment code. \n"
            "The label should be unique and non-empty. \n"
            "Example:\n" +
            HelpExampleCli("generatepaymentcode", "<label>"));
    };

    if (request.fHelp || request.params.size() < 1 or request.params.size() > 2) {
        help();
    }

    UniValue result;
    std::string const label = request.params[0].get_str();
    if (label.empty()) {
        help();
    }

    std::vector<std::tuple<bip47::CPaymentCode, std::string, CBitcoinAddress>>  const pcodes = pwallet->ListPcodes();
    if (std::find_if(pcodes.begin(), pcodes.end(), [&label](std::tuple<bip47::CPaymentCode, std::string, CBitcoinAddress> const & pcode){ return  std::get<1>(pcode) == label; }) != pcodes.end()) {
        help();
    }

    result.setStr(pwallet->GeneratePcode(label).toString());
    return result;
}

namespace {
void SendNotificationTx(CWallet * const pwallet, bip47::CPaymentChannel const & pchannel, CWalletTx& wtxNew)
{
    CAmount curBalance = pwallet->GetBalance();

    if (curBalance < bip47::NotificationTxValue)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    CBitcoinAddress const notifAddr = pchannel.getTheirPcode().getNotificationAddress();

    // Parse Zcoin address
    CScript scriptPubKey = GetScriptForDestination(notifAddr.Get());

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    vecSend.push_back({scriptPubKey, bip47::NotificationTxValue, false});
    CScript opReturnScript = CScript() << OP_RETURN << std::vector<unsigned char>(80);
    vecSend.push_back({opReturnScript, 0, false});

    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    if (wtxNew.tx->vin.size() == 0)
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot select inputs for the notification tx");

    CCoinsViewCache view(pcoinsTip);
    const Coin coin = view.AccessCoin(wtxNew.tx->vin[0].prevout);
    const CTxOut &prevout = coin.out;

    CTxDestination dest;
    CKey prevoutKey;
    CKeyID keyID;
    if (!ExtractDestination(prevout.scriptPubKey, dest) || !CBitcoinAddress(dest).GetKeyID(keyID) || !pwallet->GetKey(keyID , prevoutKey))
        throw std::runtime_error("Cannot get the prevout key.");

    bip47::Bytes const pcode = pchannel.getMaskedPayload(wtxNew.tx->vin[0].prevout, prevoutKey);
    opReturnScript = CScript() << OP_RETURN << pcode;
    vecSend[1].scriptPubKey = opReturnScript;

    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    LogBip47("Sending pcode: %s to naddress: %s\n", pchannel.getMyPcode().toString(), notifAddr.ToString());

    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

void SendNotificationTxLelantus(CWallet * const pwallet, bip47::CPaymentChannel const & pchannel, CWalletTx& wtxNew)
{
    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    CBitcoinAddress const notifAddr = pchannel.getTheirPcode().getNotificationAddress();

    std::vector<CRecipient> recipients;
    std::vector<CAmount> newMints;

    CRecipient receiver;
    receiver.scriptPubKey = GetScriptForDestination(notifAddr.Get());
    receiver.nAmount = bip47::NotificationTxValue;
    receiver.fSubtractFeeFromAmount = false;

    recipients.emplace_back(receiver);
    CScript opReturnScript = CScript() << OP_RETURN << std::vector<unsigned char>(80); // Passing empty array to calc fees
    recipients.push_back({opReturnScript, 0, false});

    try {
        std::vector<CLelantusEntry> spendCoins;
        std::vector<CSigmaEntry> sigmaSpendCoins;
        std::vector<CHDMint> mintCoins;
        CAmount fee;

        wtxNew = pwallet->CreateLelantusJoinSplitTransaction(recipients, fee, newMints, spendCoins, sigmaSpendCoins, mintCoins, nullptr,
                [&pchannel](CTxOut & out, LelantusJoinSplitBuilder const & builder) {
                    if(out.scriptPubKey[0] == OP_RETURN) {
                        CKey spendPrivKey;
                        spendPrivKey.Set(builder.spendCoins[0].ecdsaSecretKey.begin(), builder.spendCoins[0].ecdsaSecretKey.end(), false);
                        CDataStream ds(SER_NETWORK, 0);
                        ds << builder.spendCoins[0].serialNumber;
                        bip47::Bytes const pcode = pchannel.getMaskedPayload((unsigned char const *)ds.vch.data(), ds.vch.size(), spendPrivKey);
                        out.scriptPubKey = CScript() << OP_RETURN << pcode;
                    }
                });

        if (!sigmaSpendCoins.empty())
            throw std::runtime_error(std::string("It looks like you have unspent Sigma coins in your wallet. Using Sigma coins for BIP47 is not supported. Please spend your Sigma coins before establishing a BIP47 channel."));

        if (spendCoins.empty())
            throw std::runtime_error(std::string("Cannot create a Lelantus spend to address: " + notifAddr.ToString()).c_str());

        pwallet->CommitLelantusTransaction(wtxNew, spendCoins, sigmaSpendCoins, mintCoins);
        LogBip47("Paymentcode %s was sent to notification address: %s\n", pchannel.getMyPcode().toString().c_str(), notifAddr.ToString().c_str() );
    }
    catch (const InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, std::string(e.what())+" Please check your Lelantus balance is grear than " + std::to_string(1.0 * bip47::NotificationTxValue / COIN));
    }
    catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
}
}

UniValue setupchannel(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "setupchannel \"paymentcode\"\n"
            "\nSets up a payment channel for the payment code. Sends a notification transaction to the payment code notification address.\n"
            "It __will__ use Lelantus facilities to send the notification tx. The tx cost is " + std::to_string(1.0 * bip47::NotificationTxValue / COIN ) + " for the JoinSplit tx + fees\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"paymentcode\"  (string, required) The payment code to send to.\n"
            "\nResult:\n"
            "\"txid\"                  (string) The notification transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("setupchannel", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\"")
        );

    bip47::CPaymentCode theirPcode(request.params[0].get_str());

    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not activated yet");
    }

    EnsureLelantusWalletIsAvailable();

    EnsureWalletIsUnlocked(pwallet);

    LOCK2(cs_main, pwallet->cs_wallet);

    bip47::CPaymentChannel pchannel = pwallet->SetupPchannel(theirPcode);

    CWalletTx wtx;

    SendNotificationTxLelantus(pwallet, pchannel, wtx);

    return wtx.GetHash().GetHex();
}

UniValue sendtopcode(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw runtime_error(
            "sendtopcode \"paymentcode\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given payment code.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"paymentcode\"  (string, required) The payment code to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\", 0.1, \"donation\", \"seans outpost\"")
        );

    bip47::CPaymentCode theirPcode(request.params[0].get_str());

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    LOCK2(cs_main, pwallet->cs_wallet);

    CBitcoinAddress address = pwallet->GetNextAddress(theirPcode);

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 4)
        fSubtractFeeFromAmount = request.params[4].get_bool();

    EnsureWalletIsUnlocked(pwallet);

    SendMoney(pwallet, address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    return wtx.GetHash().GetHex();
}

/******************************************************************************/

extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);
extern UniValue importmulti(const JSONRPCRequest& request);

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
    //  --------------------- ------------------------    -----------------------    ----------
    { "rawtransactions",    "fundrawtransaction",       &fundrawtransaction,       false,  {"hexstring","options"} },
    { "hidden",             "resendwallettransactions", &resendwallettransactions, true,   {} },
    { "wallet",             "abandontransaction",       &abandontransaction,       false,  {"txid"} },
    { "wallet",             "addmultisigaddress",       &addmultisigaddress,       true,   {"nrequired","keys","account"} },
    { "wallet",             "addwitnessaddress",        &addwitnessaddress,        true,   {"address"} },
    { "wallet",             "backupwallet",             &backupwallet,             true,   {"destination"} },
    { "wallet",             "bumpfee",                  &bumpfee,                  true,   {"txid", "options"} },
    { "wallet",             "dumpprivkey",              &dumpprivkey_firo,        true,   {"address"}  },
    { "wallet",             "dumpwallet",               &dumpwallet_firo,         true,   {"filename"} },
    { "wallet",             "encryptwallet",            &encryptwallet,            true,   {"passphrase"} },
    { "wallet",             "getaccountaddress",        &getaccountaddress,        true,   {"account"} },
    { "wallet",             "getaccount",               &getaccount,               true,   {"address"} },
    { "wallet",             "getaddressesbyaccount",    &getaddressesbyaccount,    true,   {"account"} },
    { "wallet",             "getbalance",               &getbalance,               false,  {"account","minconf","include_watchonly"} },
    { "wallet",             "getnewaddress",            &getnewaddress,            true,   {"account"} },
    { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      true,   {} },
    { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     false,  {"account","minconf"} },
    { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     false,  {"address","minconf"} },
    { "wallet",             "gettransaction",           &gettransaction,           false,  {"txid","include_watchonly"} },
    { "wallet",             "getunconfirmedbalance",    &getunconfirmedbalance,    false,  {} },
    { "wallet",             "getwalletinfo",            &getwalletinfo,            false,  {} },
    { "wallet",             "importmulti",              &importmulti,              true,   {"requests","options"} },
    { "wallet",             "importprivkey",            &importprivkey,            true,   {"privkey","label","rescan"} },
    { "wallet",             "importwallet",             &importwallet,             true,   {"filename"} },
    { "wallet",             "importaddress",            &importaddress,            true,   {"address","label","rescan","p2sh"} },
    { "wallet",             "importprunedfunds",        &importprunedfunds,        true,   {"rawtransaction","txoutproof"} },
    { "wallet",             "importpubkey",             &importpubkey,             true,   {"pubkey","label","rescan"} },
    { "wallet",             "keypoolrefill",            &keypoolrefill,            true,   {"newsize"} },
    { "wallet",             "listaccounts",             &listaccounts,             false,  {"minconf","include_watchonly"} },
    { "wallet",             "listaddressgroupings",     &listaddressgroupings,     false,  {} },
    { "wallet",             "listaddressbalances",      &listaddressbalances,      false,  {"minamount"} },
    { "wallet",             "listlockunspent",          &listlockunspent,          false,  {} },
    { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    false,  {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    false,  {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",           &listsinceblock,           false,  {"blockhash","target_confirmations","include_watchonly"} },
    { "wallet",             "listtransactions",         &listtransactions,         false,  {"account","count","skip","include_watchonly"} },
    { "wallet",             "listunspent",              &listunspent,              false,  {"minconf","maxconf","addresses","include_unsafe"} },
    { "wallet",             "lockunspent",              &lockunspent,              true,   {"unlock","transactions"} },
    { "wallet",             "move",                     &movecmd,                  false,  {"fromaccount","toaccount","amount","minconf","comment"} },
    { "wallet",             "sendfrom",                 &sendfrom,                 false,  {"fromaccount","toaddress","amount","minconf","comment","comment_to"} },
    { "wallet",             "sendmany",                 &sendmany,                 false,  {"fromaccount","amounts","minconf","comment","subtractfeefrom"} },
    { "wallet",             "sendtoaddress",            &sendtoaddress,            false,  {"address","amount","comment","comment_to","subtractfeefromamount"} },
    { "wallet",             "setaccount",               &setaccount,               true,   {"address","account"} },
    { "wallet",             "settxfee",                 &settxfee,                 true,   {"amount"} },
    { "wallet",             "signmessage",              &signmessage,              true,   {"address","message"} },
    { "wallet",             "walletlock",               &walletlock,               true,   {} },
    { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   true,   {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletpassphrase",         &walletpassphrase,         true,   {"passphrase","timeout"} },
    { "wallet",             "removeprunedfunds",        &removeprunedfunds,        true,   {"txid"} },

    { "wallet",             "listunspentmintzerocoins", &listunspentmintzerocoins, false },
    { "wallet",             "listunspentsigmamints",    &listunspentsigmamints,    false },
    { "wallet",             "listunspentlelantusmints", &listunspentlelantusmints, false },
    { "wallet",             "mint",                     &mint,                     false },
    { "wallet",             "mintlelantus",             &mintlelantus,             false },
    { "wallet",             "autoMintlelantus",         &autoMintlelantus,         false },
    { "wallet",             "mintzerocoin",             &mintzerocoin,             false },
    { "wallet",             "mintmanyzerocoin",         &mintmanyzerocoin,         false },
    { "wallet",             "spendzerocoin",            &spendzerocoin,            false },
    { "wallet",             "spendmanyzerocoin",        &spendmanyzerocoin,        false },
    { "wallet",             "spendmany",                &spendmany,                false },
    { "wallet",             "joinsplit",                &joinsplit,                false },
    { "wallet",             "resetmintzerocoin",        &resetmintzerocoin,        false },
    { "wallet",             "resetsigmamint",           &resetsigmamint,           false },
    { "wallet",             "resetlelantusmint",        &resetlelantusmint,        false },
    { "wallet",             "setmintzerocoinstatus",    &setmintzerocoinstatus,    false },
    { "wallet",             "setsigmamintstatus",       &setsigmamintstatus,       false },
    { "wallet",             "setlelantusmintstatus",    &setlelantusmintstatus,    false },
    { "wallet",             "listmintzerocoins",        &listmintzerocoins,        false },
    { "wallet",             "listsigmamints",           &listsigmamints,           false },
    { "wallet",             "listpubcoins",             &listpubcoins,             false },
    { "wallet",             "listsigmapubcoins",        &listsigmapubcoins,        false },
    { "wallet",             "listlelantusmints",        &listlelantusmints,        false },

    { "wallet",             "setmininput",              &setmininput,              false },
    { "wallet",             "regeneratemintpool",       &regeneratemintpool,       false },
    { "wallet",             "removetxmempool",          &removetxmempool,          false },
    { "wallet",             "removetxwallet",           &removetxwallet,           false },
    { "wallet",             "listspendzerocoins",       &listspendzerocoins,       false },
    { "wallet",             "listsigmaspends",          &listsigmaspends,          false },
    { "wallet",             "listlelantusjoinsplits",   &listlelantusjoinsplits,   false },
    { "wallet",             "remintzerocointosigma",    &remintzerocointosigma,    false },

    //bip47
    { "bip47",              "generatepcode",            &generatepcode,            false },
    { "bip47",              "setupchannel",             &setupchannel,             false },
    { "bip47",              "sendtopcode",              &sendtopcode,              false },
    { "bip47",              "listpcodes",               &listpcodes,               false }
};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    if (GetBoolArg("-disablewallet", false))
        return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
