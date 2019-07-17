// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "core_io.h"
#include "init.h"
#include "main.h"
#include "zerocoin.h"
#include "zerocoin_v3.h"
#include "../sigma/coinspend.h"
#include "net.h"
#include "netbase.h"
#include "policy/rbf.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet.h"
#include "walletdb.h"
#include "hdmint/tracker.h"
#include "znode-sync.h"
#include "zerocoin.h"
#include "walletexcept.h"

#include <znode-payments.h>

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

std::string HelpRequiringPassphrase()
{
    return pwalletMain && pwalletMain->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(bool avoidException)
{
    if (!pwalletMain)
    {
        if (!avoidException)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
        else
            return false;
    }
    return true;
}

void EnsureSigmaWalletIsAvailable()
{
    if (!zwalletMain) {
        throw JSONRPCError(RPC_WALLET_ERROR, "sigma mint/spend is not allowed for legacy wallet");
    }
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

bool ValidMultiMint(const UniValue& data){
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

    return ((totalValue <= pwalletMain->GetBalance()) &&
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

UniValue getnewaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress ( \"account\" )\n"
            "\nReturns a new zcoin address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "\nResult:\n"
            "\"zcoinaddress\"    (string) The new zcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, strAccount, "receive");

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CPubKey pubKey;
    if (!pwalletMain->GetAccountPubkey(pubKey, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return CBitcoinAddress(pubKey.GetID());
}

UniValue getaccountaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current zcoin address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"zcoinaddress\"   (string) The account zcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    UniValue ret(UniValue::VSTR);

    ret = GetAccountAddress(strAccount).ToString();
    return ret;
}


UniValue getrawchangeaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getrawchangeaddress\n"
            "\nReturns a new zcoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    CReserveKey reservekey(pwalletMain);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    CKeyID keyID = vchPubKey.GetID();

    return CBitcoinAddress(keyID).ToString();
}


UniValue setaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount \"zcoinaddress\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"  (string, required) The zcoin address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"tabby\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwalletMain, address.Get()))
    {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwalletMain->mapAddressBook.count(address.Get()))
        {
            string strOldAccount = pwalletMain->mapAddressBook[address.Get()].name;
            if (address == GetAccountAddress(strOldAccount))
                GetAccountAddress(strOldAccount, true);
        }
        pwalletMain->SetAddressBook(address.Get(), strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount \"zcoinaddress\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"  (string, required) The zcoin address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
            + HelpExampleRpc("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");

    string strAccount;
    map<CTxDestination, CAddressBookData>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.name.empty())
        strAccount = (*mi).second.name;
    return strAccount;
}

UniValue setmininput(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
                "setmininput <amount>\n"
                        "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64_t nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nMinimumInputValue = nAmount;
    return true;
}


UniValue getaddressesbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"  (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"zcoinaddress\"  (string) a zcoin address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

static void SendMoney(const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwalletMain->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse Zcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwalletMain->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");
}

UniValue sendtoaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendtoaddress \"zcoinaddress\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"zcoinaddress\"  (string, required) The zcoin address to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");

    // Amount
    CAmount nAmount = AmountFromValue(params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && !params[2].isNull() && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (params.size() > 4)
        fSubtractFeeFromAmount = params[4].get_bool();

    EnsureWalletIsUnlocked();

    SendMoney(address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"zcoinaddress\",     (string) The zcoin address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) The account (DEPRECATED)\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    map<CTxDestination, CAmount> balances = pwalletMain->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings())
    {
        UniValue jsonGrouping(UniValue::VARR);
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second.name);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage \"zcoinaddress\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"  (string, required) The zcoin address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", \"my message\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue getreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress \"zcoinaddress\" ( minconf )\n"
            "\nReturns the total amount received by the given bitcoinaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"zcoinaddress\"  (string, required) The zcoin address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 0") +
            "\nThe amount with at least 6 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\", 6")
       );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // zcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");
    CScript scriptPubKey = GetScriptForDestination(address.Get());
    if (!IsMine(*pwalletMain, scriptPubKey))
        return ValueFromAmount(0);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress = pwalletMain->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return ValueFromAmount(nAmount);
}


UniValue getbalance(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "getbalance ( \"account\" minconf includeWatchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, optional) DEPRECATED. The selected account, or \"*\" for entire wallet. It may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and "getbalance * 1 true" should return the same number
        CAmount nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!CheckFinalTx(wtx) || wtx.GetBlocksToMaturity() > 0 || wtx.GetDepthInMainChain() < 0)
                continue;

            CAmount allFee;
            string strSentAccount;
            list<COutputEntry> listReceived;
            list<COutputEntry> listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                BOOST_FOREACH(const COutputEntry& r, listReceived)
                    nBalance += r.amount;
            }
            BOOST_FOREACH(const COutputEntry& s, listSent)
                nBalance -= s.amount;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    CAmount nBalance = pwalletMain->GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

UniValue getunconfirmedbalance(const UniValue &params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 0)
        throw runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ValueFromAmount(pwalletMain->GetUnconfirmedBalance());
}


UniValue movecmd(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. minconf           (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    if (!pwalletMain->AccountMove(strFrom, strTo, nAmount, strComment))
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}


UniValue sendfrom(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 3 || params.size() > 6)
        throw runtime_error(
            "sendfrom \"fromaccount\" \"tozcoinaddress\" amount ( minconf \"comment\" \"comment-to\" )\n"
            "\nDEPRECATED (use sendtoaddress). Sent an amount from an account to a zcoin address."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "2. \"tozcoinaddress\"  (string, required) The zcoin address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment-to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"transactionid\"        (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("sendfrom", "\"\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");
    CAmount nAmount = AmountFromValue(params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && !params[4].isNull() && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && !params[5].isNull() && !params[5].get_str().empty())
        wtx.mapValue["to"]      = params[5].get_str();

    EnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = pwalletMain->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    SendMoney(address.Get(), nAmount, false, wtx);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The zcoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefromamount   (string, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
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
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 1 \"\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendmany", "\"\", \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\", 6, \"testing\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = AccountFromValue(params[0]);
    UniValue sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 4)
        subtractFeeFromAmount = params[4].get_array();

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+name_);

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

    EnsureWalletIsUnlocked();

    // Check funds
    CAmount nBalance = pwalletMain->GetAccountBalance(strAccount, nMinDepth, ISMINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

// Defined in rpc/misc.cpp
extern CScript _createmultisig_redeemScript(const UniValue& params);

UniValue addmultisigaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet.\n"
            "Each key is a zcoin address or hex-encoded public key.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keysobject\"   (string, required) A json array of zcoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"  (string) zcoin address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"      (string, optional) DEPRECATED. An account to assign the addresses to.\n"

            "\nResult:\n"
            "\"zcoinaddress\"  (string) A zcoin address associated with the keys.\n"

            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBook(innerID, strAccount, "send");
    return CBitcoinAddress(innerID).ToString();
}

class Witnessifier : public boost::static_visitor<bool>
{
public:
    CScriptID result;

    bool operator()(const CNoDestination &dest) const { return false; }

    bool operator()(const CKeyID &keyID) {
        CPubKey pubkey;
        if (pwalletMain) {
            CScript basescript = GetScriptForDestination(keyID);
            isminetype typ;
            typ = IsMine(*pwalletMain, basescript, SIGVERSION_WITNESS_V0);
            if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
                return false;
            CScript witscript = GetScriptForWitness(basescript);
            pwalletMain->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }

    bool operator()(const CScriptID &scriptID) {
        CScript subscript;
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)) {
            int witnessversion;
            std::vector<unsigned char> witprog;
            if (subscript.IsWitnessProgram(witnessversion, witprog)) {
                result = scriptID;
                return true;
            }
            isminetype typ;
            typ = IsMine(*pwalletMain, subscript, SIGVERSION_WITNESS_V0);
            if (typ != ISMINE_SPENDABLE && typ != ISMINE_WATCH_SOLVABLE)
                return false;
            CScript witscript = GetScriptForWitness(subscript);
            pwalletMain->AddCScript(witscript);
            result = CScriptID(witscript);
            return true;
        }
        return false;
    }
};

UniValue addwitnessaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 1)
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

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address");

    Witnessifier w;
    CTxDestination dest = address.Get();
    bool ret = boost::apply_visitor(w, dest);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Public key or redeemscript not known to wallet, or the key is uncompressed");
    }

    pwalletMain->SetAddressBook(w.result, "", "receive");

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

UniValue ListReceived(const UniValue& params, bool fByAccounts)
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
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !CheckFinalTx(wtx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwalletMain, address);
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
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CAddressBookData)& item, pwalletMain->mapAddressBook)
    {
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
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
            item.fIsWatchonly = fIsWatchonly;
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
                BOOST_FOREACH(const uint256& item, (*it).second.txids)
                {
                    transactions.push_back(item.GetHex());
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

UniValue listreceivedbyaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listreceivedbyaddress ( minconf includeempty includeWatchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf       (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty  (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"                (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ListReceived(params, false);
}

UniValue listreceivedbyaccount(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. includeempty (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n"

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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    return ListReceived(params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest, CBitcoinAddress &addr)
{
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
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
            if(involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & ISMINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination, addr);
            if (wtx.IsZerocoinSpend() || wtx.IsSigmaSpend() || wtx.IsZerocoinRemint()) {
                entry.push_back(Pair("category", "spend"));
            }
            else if (wtx.IsZerocoinMint() || wtx.IsSigmaMint()) {
                entry.push_back(Pair("category", "mint"));
            }
            else {
                entry.push_back(Pair("category", "send"));
            }
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name));
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
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination].name;
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if(involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & ISMINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination, addr);
                if (wtx.IsCoinBase())
                {
                    int txHeight = chainActive.Height() - wtx.GetDepthInMainChain();
                    CScript payee;

                    mnpayments.GetBlockPayee(txHeight, payee);
                    //compare address of payee to addr.
                    CTxDestination payeeDest;
                    ExtractDestination(payee, payeeDest);
                    CBitcoinAddress payeeAddr(payeeDest);
                    if(addr.ToString() == payeeAddr.ToString()){
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
                if (pwalletMain->mapAddressBook.count(r.destination))
                    entry.push_back(Pair("label", account));
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

UniValue listtransactions(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 4)
        throw runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"zcoinaddress\",    (string) The zcoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable).\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
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
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered;

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
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

// This for supporting casino. Ask Reuben if you need more information.
UniValue listtransactionsfrom(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 4)
        throw runtime_error(
            "listtransactions ( \"account\" count from includeWatchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. from           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. includeWatchonly (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"zcoinaddress\",    (string) The zcoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable).\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx            (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
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
            "    \"label\": \"label\"        (string) A comment for the address/transaction, if any\n"
            "    \"otheraccount\": \"accountname\",  (string) For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered;

    if (txOrdered.size() < static_cast<unsigned>(nFrom)) {
        return ret;
    }

    auto it = txOrdered.begin();
    std::advance(it, nFrom);

    for (int cnt = 0; (it != txOrdered.end()) && (cnt < nCount); it++, cnt++) {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);
    }

    return ret;
}

UniValue listaccounts(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listaccounts ( minconf includeWatchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    map<string, CAmount> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, pwalletMain->mapAddressBook) {
        if (IsMine(*pwalletMain, entry.first) & includeWatchonly) // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
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
                if (pwalletMain->mapAddressBook.count(r.destination))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.destination].name] += r.amount;
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const list<CAccountingEntry> & acentries = pwalletMain->laccentries;
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    BOOST_FOREACH(const PAIRTYPE(string, CAmount)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue listsinceblock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp)
        throw runtime_error(
            "listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted\n"
            "\nArguments:\n"
            "1. \"blockhash\"   (string, optional) The block hash to list transactions since\n"
            "2. target-confirmations:    (numeric, optional) The confirmations required, must be 1 or more\n"
            "3. includeWatchonly:        (bool, optional, default=false) Include transactions to watchonly addresses (see 'importaddress')"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"zcoinaddress\",    (string) The zcoin address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (params.size() > 0)
    {
        uint256 blockId;

        blockId.SetHex(params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListTransactions(tx, "*", 0, true, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue gettransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "gettransaction \"txid\" ( includeWatchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "2. \"includeWatchonly\"    (bool, optional, default=false) Whether to include watchonly addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\"  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",  (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"zcoinaddress\",   (string) The zcoin address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash];

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    string strHex = EncodeHexTx(static_cast<CTransaction>(wtx), RPCSerializationFlags());
    entry.push_back(Pair("hex", strHex));

    return entry;
}

UniValue abandontransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    if (!pwalletMain->AbandonTransaction(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");

    return NullUniValue;
}


UniValue backupwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strDest = params[0].get_str();
    if (!pwalletMain->BackupWallet(strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return NullUniValue;
}


UniValue keypoolrefill(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)params[0].get_int();
    }

    EnsureWalletIsUnlocked();
    pwalletMain->TopUpKeyPool(kpSize);

    if (pwalletMain->GetKeyPoolSize() < kpSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending zcoins\n"
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwalletMain->TopUpKeyPool();

    int64_t nSleepTime = params[1].get_int64();
    LOCK(cs_nWalletUnlockTime);
    nWalletUnlockTime = GetTime() + nSleepTime;
    RPCRunLater("lockwallet", boost::bind(LockWallet, pwalletMain), nSleepTime);

    return NullUniValue;
}


UniValue walletpassphrasechange(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return NullUniValue;
}


UniValue walletlock(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return NullUniValue;
}


UniValue encryptwallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
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
            + HelpExampleCli("signmessage", "\"zcoinaddress\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; zcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue lockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (params.size() == 1)
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL));
    else
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VBOOL)(UniValue::VARR));

    bool fUnlock = params[0].get_bool();

    if (params.size() == 1) {
        if (fUnlock)
            pwalletMain->UnlockAllCoins();
        return true;
    }

    UniValue outputs = params[1].get_array();
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
            pwalletMain->UnlockCoin(outpt);
        else
            pwalletMain->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 0)
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

    LOCK2(cs_main, pwalletMain->cs_wallet);

    vector<COutPoint> vOutpts;
    pwalletMain->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or string, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("settxfee", "0.00000001 XZC")
            + HelpExampleRpc("settxfee", "0.00000001 XZC")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(params[0]);

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 0)
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
            "  \"hdmasterkeyid\": \"<hash160>\", (string) the Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwalletMain->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwalletMain->GetImmatureBalance())));
    obj.push_back(Pair("txcount",       (int)pwalletMain->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
    CKeyID masterKeyID = pwalletMain->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull())
         obj.push_back(Pair("hdmasterkeyid", masterKeyID.GetHex()));
    return obj;
}

UniValue resendwallettransactions(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 0)
        throw runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::vector<uint256> txids = pwalletMain->ResendWalletTransactionsBefore(GetTime());
    UniValue result(UniValue::VARR);
    BOOST_FOREACH(const uint256& txid, txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listunspent ( minconf maxconf  [\"address\",...] )\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"    (string) A json array of zcoin addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) zcoin address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",          (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",    (string) the zcoin address\n"
            "    \"account\" : \"account\",    (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\",   (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction amount in " + CURRENCY_UNIT + "\n"
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

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    set<CBitcoinAddress> setAddress;
    if (params.size() > 2) {
        UniValue inputs = params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid zcoin address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    UniValue results(UniValue::VARR);
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);
    LOCK2(cs_main, pwalletMain->cs_wallet);
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true);
    BOOST_FOREACH(const COutput& out, vecOutputs) {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        CTxDestination address;
        const CScript& scriptPubKey = out.tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (setAddress.size() && (!fValidAddress || !setAddress.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));

        if (fValidAddress) {
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString()));

            if (pwalletMain->mapAddressBook.count(address))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }

        entry.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
        entry.push_back(Pair("amount", ValueFromAmount(out.tx->vout[out.i].nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        entry.push_back(Pair("spendable", out.fSpendable));
        entry.push_back(Pair("solvable", out.fSolvable));
        results.push_back(entry);
    }

    return results;
}

UniValue fundrawtransaction(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
                            "fundrawtransaction \"hexstring\" ( options )\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add one change output to the outputs.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
                            "2. options               (object, optional)\n"
                            "   {\n"
                            "     \"changeAddress\"     (string, optional, default pool address) The zcoin address to receive the change\n"
                            "     \"changePosition\"    (numeric, optional, default random) The index of the change output\n"
                            "     \"includeWatching\"   (boolean, optional, default false) Also select inputs which are watch only\n"
                            "     \"lockUnspents\"      (boolean, optional, default false) Lock selected unspent outputs\n"
                            "     \"feeRate\"           (numeric, optional, default not set: makes wallet determine the fee) Set a specific feerate (" + CURRENCY_UNIT + " per KB)\n"
                            "   }\n"
                            "                         for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}\n"
                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\"hex\"             \n"
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

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));

    CTxDestination changeAddress = CNoDestination();
    int changePosition = -1;
    bool includeWatching = false;
    bool lockUnspents = false;
    CFeeRate feeRate = CFeeRate(0);
    bool overrideEstimatedFeerate = false;

    if (params.size() > 1) {
      if (params[1].type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        includeWatching = params[1].get_bool();
      }
      else {
        RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VOBJ));

        UniValue options = params[1];

        RPCTypeCheckObj(options,
            {
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"feeRate", UniValueType()}, // will be checked below
            },
            true, true);

        if (options.exists("changeAddress")) {
            CBitcoinAddress address(options["changeAddress"].get_str());

            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "changeAddress must be a valid zcoin address");

            changeAddress = address.Get();
        }

        if (options.exists("changePosition"))
            changePosition = options["changePosition"].get_int();

        if (options.exists("includeWatching"))
            includeWatching = options["includeWatching"].get_bool();

        if (options.exists("lockUnspents"))
            lockUnspents = options["lockUnspents"].get_bool();

        if (options.exists("feeRate"))
        {
            feeRate = CFeeRate(AmountFromValue(options["feeRate"]));
            overrideEstimatedFeerate = true;
        }
      }
    }

    // parse hex string from parameter
    CTransaction origTx;
    if (!DecodeHexTx(origTx, params[0].get_str(), true))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    if (origTx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > origTx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    CMutableTransaction tx(origTx);
    CAmount nFeeOut;
    string strFailReason;

    if(!pwalletMain->FundTransaction(tx, nFeeOut, overrideEstimatedFeerate, feeRate, changePosition, strFailReason, includeWatching, lockUnspents, changeAddress))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(tx)));
    result.push_back(Pair("changepos", changePosition));
    result.push_back(Pair("fee", ValueFromAmount(nFeeOut)));

    return result;
}

//[zcoin]: zerocoin section
// zerocoin section

UniValue listunspentmintzerocoins(const UniValue &params, bool fHelp) {
    if (fHelp || params.size() > 2)
        throw runtime_error(
                "listunspentmintzerocoins [minconf=1] [maxconf=9999999] \n"
                        "Returns array of unspent transaction outputs\n"
                        "with between minconf and maxconf (inclusive) confirmations.\n"
                        "Results are an array of Objects, each of which has:\n"
                        "{txid, vout, scriptPubKey, amount, confirmations}");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    UniValue results(UniValue::VARR);
    vector <COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->ListAvailableCoinsMintCoins(vecOutputs, false);
    LogPrintf("vecOutputs.size()=%s\n", vecOutputs.size());
    BOOST_FOREACH(const COutput &out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64_t nValue = out.tx->vout[out.i].nValue;
        const CScript &pk = out.tx->vout[out.i].scriptPubKey;
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        results.push_back(entry);
    }

    return results;
}

UniValue listunspentsigmamints(const UniValue &params, bool fHelp) {
    if (fHelp || params.size() > 2)
        throw runtime_error(
                "listunspentsigmamints [minconf=1] [maxconf=9999999] \n"
                        "Returns array of unspent transaction outputs\n"
                        "with between minconf and maxconf (inclusive) confirmations.\n"
                        "Results are an array of Objects, each of which has:\n"
                        "{txid, vout, scriptPubKey, amount, confirmations}");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");

    EnsureSigmaWalletIsAvailable();

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM)(UniValue::VARR));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    UniValue results(UniValue::VARR);
    vector <COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->ListAvailableSigmaMintCoins(vecOutputs, false);
    LogPrintf("vecOutputs.size()=%s\n", vecOutputs.size());
    BOOST_FOREACH(const COutput &out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        int64_t nValue = out.tx->vout[out.i].nValue;
        const CScript &pk = out.tx->vout[out.i].scriptPubKey;
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash()) {
            CTxDestination address;
            if (ExtractDestination(pk, address)) {
                const CScriptID &hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount", ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        results.push_back(entry);
    }

    return results;
}

UniValue mint(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp)) {
        return NullUniValue;
    }

    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "mint amount\n"
            "\nAutomatically choose denominations to mint by amount."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to mint, must be a multiple of 0.05\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("mint", "0.15")
            + HelpExampleCli("mint", "100.9")
            + HelpExampleRpc("mint", "0.15")
        );

    EnsureWalletIsUnlocked();
    EnsureSigmaWalletIsAvailable();

    // Ensure Sigma mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!sigma::IsSigmaAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not activated yet");
    }

    CAmount nAmount = AmountFromValue(params[0]);
    LogPrintf("rpcWallet.mint() denomination = %s, nAmount = %d \n", params[0].getValStr(), nAmount);

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
    std::string strError = pwalletMain->MintAndStoreSigma(vecSend, privCoins, vDMints, wtx);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

UniValue mintzerocoin(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error("mintzerocoin <amount>(1,10,25,50,100)\n" + HelpRequiringPassphrase());

    EnsureZerocoinMintIsAllowed();

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (params[0].get_real() == 1.0) {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 10.0) {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 25.0) {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 50.0) {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 100.0) {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = AmountFromValue(params[0]);
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

        if (pwalletMain->IsLocked())
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

        // Wallet comments
        CWalletTx wtx;
        bool isSigmaMint = false;
        string strError = pwalletMain->MintZerocoin(scriptSerializedCoin, nAmount, isSigmaMint, wtx);

        if (strError != "")
            throw JSONRPCError(RPC_WALLET_ERROR, strError);

        CWalletDB walletdb(pwalletMain->strWalletFile);
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
        pwalletMain->NotifyZerocoinChanged(pwalletMain, zerocoinTx.value.GetHex(), "New (" + std::to_string(zerocoinTx.denomination) + " mint)", CT_NEW);
        walletdb.WriteZerocoinEntry(zerocoinTx);

        return wtx.GetHash().GetHex();
    } else {
        return "";
    }

}

UniValue mintmanyzerocoin(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() == 0 || params.size() % 2 != 0 || params.size() > 10)
        throw runtime_error(
                "mintmanyzerocoin <denomination>(1,10,25,50,100), numberOfMints, <denomination>(1,10,25,50,100), numberOfMints, ... }\n"
                + HelpRequiringPassphrase()
                + "\nMint 1 or more zerocoins in a single transaction. Amounts must be of denominations specified.\n"
                + "Specify each denomination followed by the number of them to mint, for all denominations desired.\n"
                + "Total amount for all must be less than " + to_string(ZC_MINT_LIMIT) + ".  \n"
                "\nArguments:\n"
                "1. \"denomination\"             (integer, required) zerocoin denomination\n"
                "2. \"numberOfMints\"            (integer, required) amount of mints for chosen denomination\n"
                "\nExamples:\nThe first example mints denomination 1, one time, for a total XZC valuation of 1.\nThe next example mints denomination 25, ten times, and denomination 50, five times, for a total XZC valuation of 500.\n"
                    + HelpExampleCli("mintmanyzerocoin", "1 1")
                    + HelpExampleCli("mintmanyzerocoin", "25 10 50 5")
        );

    EnsureZerocoinMintIsAllowed();

    UniValue sendTo(UniValue::VOBJ);

    for(size_t i=0; i<params.size(); i+=2){
        string denomination = params[i].get_str();
        string amount = params[i+1].get_str();
        sendTo.push_back(Pair(denomination, stoi(amount)));
    }

    if(!ValidMultiMint(sendTo)){
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

    string strError = pwalletMain->MintAndStoreZerocoin(vecSend, privCoins, wtx);

    if (strError != "")
        throw runtime_error(strError);

    return wtx.GetHash().GetHex();
}

UniValue spendzerocoin(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
                "spendzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n"
                + HelpRequiringPassphrase() +
				"\nArguments:\n"
				"1. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. currently options are following 1, 10, 25, 50 and 100 only\n"
				"2. \"zcoinaddress\"  (string, optional) The zcoin address to send to third party.\n"
				"\nExamples:\n"
				            + HelpExampleCli("spendzerocoin", "10 \"a1kCCGddf5pMXSipLVD9hBG2MGGVNaJ15U\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (params[0].get_real() == 1.0) {
        denomination = libzerocoin::ZQ_LOVELACE;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 10.0) {
        denomination = libzerocoin::ZQ_GOLDWASSER;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 25.0) {
        denomination = libzerocoin::ZQ_RACKOFF;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 50.0) {
        denomination = libzerocoin::ZQ_PEDERSEN;
        nAmount = AmountFromValue(params[0]);
    } else if (params[0].get_real() == 100.0) {
        denomination = libzerocoin::ZQ_WILLIAMSON;
        nAmount = AmountFromValue(params[0]);
    } else {
        throw runtime_error(
                "spendzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
    }

    CBitcoinAddress address;
    string thirdPartyaddress = "";
    if (params.size() > 1){
    	// Address
    	thirdPartyaddress = params[1].get_str();
    	address = CBitcoinAddress(params[1].get_str());
		 if (!address.IsValid())
			 throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address");
    }

    EnsureWalletIsUnlocked();

    // Wallet comments
    CWalletTx wtx;
    CBigNum coinSerial;
    uint256 txHash;
    CBigNum zcSelectedValue;
    bool zcSelectedIsUsed;

    string strError = pwalletMain->SpendZerocoin(thirdPartyaddress, nAmount, denomination, wtx, coinSerial, txHash, zcSelectedValue,
                                                 zcSelectedIsUsed);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();

}

UniValue spendallzerocoin(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() >= 1)
        throw runtime_error(
                "spendallzerocoin\n"
                "\nAutomatically spends all zerocoin mints to self\n" );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    bool hasUnspendableMints = false;

    string strError;
    bool result = pwalletMain->SpendOldMints(strError);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    else if(strError == "" && !result)
        hasUnspendableMints = true;

    return  hasUnspendableMints;
}

UniValue spendmanyzerocoin(const UniValue& params, bool fHelp) {

        if (fHelp || params.size() != 1)
        throw runtime_error(
                "spendmanyzerocoin \"{\"address\":\"<third party address or blank for internal>\", \"denominations\": [{\"value\":(1,10,25,50,100), \"amount\":<>}, {\"value\":(1,10,25,50,100), \"amount\":<>},...]}\"\n"
                + HelpRequiringPassphrase()
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

    UniValue data = params[0].get_obj();

    LOCK2(cs_main, pwalletMain->cs_wallet);

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
                    "spendmanyzerocoin <amount>(1,10,25,50,100) (\"zcoinaddress\")\n");
        }
        for(int64_t j=0; j<amount; j++){
            denominations.push_back(std::make_pair(value * COIN, denomination));
        }
    }

    string thirdPartyAddress = "";
    if (!(addressStr == "")){
        CBitcoinAddress address(addressStr);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Zcoin address");
        thirdPartyAddress = addressStr;
    }

    EnsureWalletIsUnlocked();

    // Wallet comments
    CWalletTx wtx;
    vector<CBigNum> coinSerials;
    uint256 txHash;
    vector<CBigNum> zcSelectedValues;
    string strError = "";

    // begin spend process
    CReserveKey reservekey(pwalletMain);

    if (pwalletMain->IsLocked()) {
        strError = "Error: Wallet locked, unable to create transaction!";
        LogPrintf("SpendZerocoin() : %s", strError.c_str());
        return strError;
    }

    strError = pwalletMain->SpendMultipleZerocoin(thirdPartyAddress, denominations, wtx, coinSerials, txHash, zcSelectedValues, false);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

UniValue spendmany(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw std::runtime_error(
                "spendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
                "\nSpend multiple zerocoins and remint changes in a single transaction by specify addresses and amount for each address."
                + HelpRequiringPassphrase() + "\n"
                "\nArguments:\n"
                "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
                "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
                "    {\n"
                "      \"address\":amount   (numeric or string) The zcoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
                "      ,...\n"
                "    }\n"
                "3. minconf                 (numeric, optional, default=6) NOT IMPLEMENTED. Only use the balance confirmed at least this many times.\n"
                "4. \"comment\"             (string, optional) A comment\n"
                "5. subtractfeefromamount   (string, optional) A json array with addresses.\n"
                "                           The fee will be equally deducted from the amount of each selected address.\n"
                "                           Those recipients will receive less zcoins than you enter in their corresponding amount field.\n"
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
        throw JSONRPCError(RPC_WALLET_ERROR, "Sigma is not activated yet");
    }

    EnsureSigmaWalletIsAvailable();

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Only account "" have sigma coins.
    std::string strAccount = AccountFromValue(params[0]);
    if (!strAccount.empty())
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    UniValue sendTo = params[1].get_obj();

    CWalletTx wtx;
    if (params.size() > 3 && !params[3].isNull() && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    std::unordered_set<std::string> subtractFeeFromAmountSet;
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 4) {
        subtractFeeFromAmount = params[4].get_array();
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
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid zcoin address: " + strAddr);

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

    EnsureWalletIsUnlocked();

    CAmount nFeeRequired = 0;

    try {
        pwalletMain->SpendSigma(vecSend, wtx, nFeeRequired);
    }
    catch (const InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
    }
    catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    return wtx.GetHash().GetHex();
}

UniValue resetmintzerocoin(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "resetmintzerocoin"
                + HelpRequiringPassphrase());

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
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

UniValue resetsigmamint(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() != 0)
        throw runtime_error(
                "resetsigmamint"
                + HelpRequiringPassphrase());

    EnsureSigmaWalletIsAvailable();

    std::vector <CMintMeta> listMints;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listMints = zwalletMain->GetTracker().ListMints(false, false);

    BOOST_FOREACH(CMintMeta &mint, listMints) {
        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), dMint)){
            continue;
        }
        dMint.SetUsed(false);
        dMint.SetHeight(-1);
        zwalletMain->GetTracker().Add(dMint, true);
    }

    return NullUniValue;
}

UniValue listmintzerocoins(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "listmintzerocoins <all>(false/true)\n"
                        "\nArguments:\n"
                        "1. <all> (boolean, optional) false (default) to return own mintzerocoins. true to return every mintzerocoins.\n"
                        "\nResults are an array of Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    bool fAllStatus = false;
    if (params.size() > 0) {
        fAllStatus = params[0].get_bool();
    }

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
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

UniValue listsigmamints(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() > 1)
        throw runtime_error(
                "listsigmamints <all>(false/true)\n"
                "\nArguments:\n"
                "1. <all> (boolean, optional) false (default) to return own mintzerocoins. true to return every mintzerocoins.\n"
                "\nResults are an array of Objects, each of which has:\n"
                "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    EnsureSigmaWalletIsAvailable();

    bool fAllStatus = false;
    if (params.size() > 0) {
        fAllStatus = params[0].get_bool();
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked();

    list <CSigmaEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listPubcoin = zwalletMain->GetTracker().MintsAsZerocoinEntries(false, false);
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


UniValue listpubcoins(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "listpubcoins <all>(1/10/25/50/100)\n"
                        "\nArguments:\n"
                        "1. <all> (int, optional) 1,10,25,50,100 (default) to return all pubcoin with denomination. empty to return all pubcoin.\n"
                        "\nResults are an array of Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    int denomination = -1;
    if (params.size() > 0) {
        denomination = params[0].get_int();
    }

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
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

UniValue listsigmapubcoins(const UniValue& params, bool fHelp) {

    std::string help_message =
        "listsigmapubcoins <all>(0.05/0.1/0.5/1/10/25/100)\n"
            "\nArguments:\n"
            "1. <all> (string, optional) 0.05, 0.1, 0.5, 1, 10, 25, 100 (default) to return all sigma public coins with given denomination. empty to return all pubcoin.\n"
            "\nResults are an array of Objects, each of which has:\n"
            "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}";
    if (fHelp || params.size() > 1) {
        throw runtime_error(help_message);
    }

    EnsureSigmaWalletIsAvailable();

    sigma::CoinDenomination denomination;
    bool filter_by_denom = false;
    if (params.size() > 0) {
        filter_by_denom = true;
        if (!sigma::StringToDenomination(params[0].get_str(), denomination)) {
            throw runtime_error(help_message);
        }
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked();

    list<CSigmaEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listPubcoin = zwalletMain->GetTracker().MintsAsZerocoinEntries(false, false);
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

UniValue setmintzerocoinstatus(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
                "setmintzerocoinstatus \"coinserial\" <isused>(true/false)\n"
                        "Set mintzerocoin IsUsed status to True or False\n"
                        "Results are an array of one or no Objects, each of which has:\n"
                        "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    CBigNum coinSerial;
    coinSerial.SetHex(params[0].get_str());

    bool fStatus = true;
    fStatus = params[1].get_bool();

    list <CZerocoinEntry> listPubcoin;
    CWalletDB walletdb(pwalletMain->strWalletFile);
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
                pwalletMain->NotifyZerocoinChanged(pwalletMain, zerocoinTx.value.GetHex(), isUsedDenomStr, CT_UPDATED);
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

UniValue setsigmamintstatus(const UniValue& params, bool fHelp) {

    if (fHelp || params.size() != 2)
        throw runtime_error(
                "setsigmamintstatus \"coinserial\" <isused>(true/false)\n"
                "Set mintsigma IsUsed status to True or False\n"
                "Results are an array of one or no Objects, each of which has:\n"
                "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    EnsureSigmaWalletIsAvailable();

    Scalar coinSerial;
    coinSerial.SetHex(params[0].get_str());

    bool fStatus = true;
    fStatus = params[1].get_bool();

    EnsureWalletIsUnlocked();

    std::vector <CMintMeta> listMints;
    CWalletDB walletdb(pwalletMain->strWalletFile);
    listMints = zwalletMain->GetTracker().ListMints(false, false);

    UniValue results(UniValue::VARR);

    BOOST_FOREACH(CMintMeta &mint, listMints) {
        CSigmaEntry zerocoinItem;
        if(!pwalletMain->GetMint(mint.hashSerial, zerocoinItem))
            continue;

        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), dMint)){
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
                pwalletMain->NotifyZerocoinChanged(pwalletMain, zerocoinItem.value.GetHex(), isUsedDenomStr, CT_UPDATED);

                if(!mint.isDeterministic){
                    zerocoinItem.IsUsed = fStatus;
                    zwalletMain->GetTracker().Add(zerocoinItem, true);
                }else{
                    dMint.SetUsed(fStatus);
                    zwalletMain->GetTracker().Add(dMint, true);
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

UniValue listsigmaspends(const UniValue &params, bool fHelp) {

    if (fHelp || params.size() < 1 || params.size() > 2)
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

    int  count = params[0].get_int();
    bool fOnlyUnconfirmed = params.size()>=2 && params[1].get_bool();

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VARR);
    const CWallet::TxItems& txOrdered = pwalletMain->wtxOrdered;

    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin();
         it != txOrdered.rend();
         ++it) {
        CWalletTx *const pwtx = (*it).second.first;

        if (!pwtx || !pwtx->IsSigmaSpend())
            continue;

        UniValue entry(UniValue::VOBJ);

        int confirmations = pwtx->GetDepthInMainChain();
        if (confirmations > 0 && fOnlyUnconfirmed)
            continue;

        entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
        entry.push_back(Pair("confirmations", confirmations));
        entry.push_back(Pair("abandoned", pwtx->isAbandoned()));

        UniValue spends(UniValue::VARR);
        BOOST_FOREACH(const CTxIn &txin, pwtx->vin) {
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
        BOOST_FOREACH(const CTxOut &txout, pwtx->vout) {
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

UniValue listspendzerocoins(const UniValue &params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 2)
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

    int  count = params[0].get_int();
    bool fOnlyUnconfirmed = params.size()>=2 && params[1].get_bool();

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VARR);
    const CWallet::TxItems & txOrdered = pwalletMain->wtxOrdered;

    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
        CWalletTx *const pwtx = (*it).second.first;

        if (!pwtx || !pwtx->IsZerocoinSpend() || pwtx->vin.size() != 1)
            continue;

        UniValue entry(UniValue::VOBJ);

        int confirmations = pwtx->GetDepthInMainChain();
        if (confirmations > 0 && fOnlyUnconfirmed)
            continue;

        entry.push_back(Pair("txid", pwtx->GetHash().GetHex()));
        entry.push_back(Pair("confirmations", confirmations));
        entry.push_back(Pair("abandoned", pwtx->isAbandoned()));

        const CTxIn &txin = pwtx->vin[0];
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

UniValue remintzerocointosigma(const UniValue &params, bool fHelp) {

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "remintzerocointosigma <denomination>(1,10,25,50,100)\n"
            +HelpRequiringPassphrase() +
            "\nConvert zerocoin mint to sigma mint.\n"
            "\nArguments:\n"
            "1. \"denomination\"          (integer, required) existing zerocoin mint denomination\n"
        );

    EnsureSigmaWalletIsAvailable();

    LOCK2(cs_main, pwalletMain->cs_wallet);
    libzerocoin::CoinDenomination denomination;
    switch (params[0].get_int()) {
        case 1:
        case 10:
        case 25:
        case 50:
        case 100:
            denomination = (libzerocoin::CoinDenomination)params[0].get_int();
            break;

        default:
            throw runtime_error("Incorrect denomination\n");
    }

    EnsureWalletIsUnlocked();
    std::string stringError;
    CWalletTx wtx;

    if (!pwalletMain->CreateZerocoinToSigmaRemintModel(stringError, ZEROCOIN_TX_VERSION_2, denomination, &wtx))
        throw JSONRPCError(RPC_WALLET_ERROR, stringError);

    return wtx.GetHash().GetHex();
}

UniValue removetxmempool(const UniValue &params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "removetxmempool <txid>\n"
                + HelpRequiringPassphrase());

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (pwalletMain->IsLocked())
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

UniValue removetxwallet(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error("removetxwallet <txid>\n" + HelpRequiringPassphrase());

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    pwalletMain->EraseFromWallet(hash);
    return NullUniValue;
}



extern UniValue dumpprivkey_zcoin(const UniValue& params, bool fHelp); // in rpcdump.cpp
extern UniValue importprivkey(const UniValue& params, bool fHelp);
extern UniValue importaddress(const UniValue& params, bool fHelp);
extern UniValue importpubkey(const UniValue& params, bool fHelp);
extern UniValue dumpwallet_zcoin(const UniValue& params, bool fHelp);
extern UniValue importwallet(const UniValue& params, bool fHelp);
extern UniValue importprunedfunds(const UniValue& params, bool fHelp);
extern UniValue removeprunedfunds(const UniValue& params, bool fHelp);

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
    //  --------------------- ------------------------    -----------------------    ----------
    { "rawtransactions",    "fundrawtransaction",       &fundrawtransaction,       false },
    { "hidden",             "resendwallettransactions", &resendwallettransactions, true  },
    { "wallet",             "abandontransaction",       &abandontransaction,       false },
    { "wallet",             "addmultisigaddress",       &addmultisigaddress,       true  },
    { "wallet",             "addwitnessaddress",        &addwitnessaddress,        true  },
    { "wallet",             "backupwallet",             &backupwallet,             true  },
    { "wallet",             "dumpprivkey",              &dumpprivkey_zcoin,        true  },
    { "wallet",             "dumpwallet",               &dumpwallet_zcoin,         true  },
    { "wallet",             "encryptwallet",            &encryptwallet,            true  },
    { "wallet",             "getaccountaddress",        &getaccountaddress,        true  },
    { "wallet",             "getaccount",               &getaccount,               true  },
    { "wallet",             "getaddressesbyaccount",    &getaddressesbyaccount,    true  },
    { "wallet",             "getbalance",               &getbalance,               false },
    { "wallet",             "getnewaddress",            &getnewaddress,            true  },
    { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      true  },
    { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     false },
    { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     false },
    { "wallet",             "gettransaction",           &gettransaction,           false },
    { "wallet",             "getunconfirmedbalance",    &getunconfirmedbalance,    false },
    { "wallet",             "getwalletinfo",            &getwalletinfo,            false },
    { "wallet",             "importprivkey",            &importprivkey,            true  },
    { "wallet",             "importwallet",             &importwallet,             true  },
    { "wallet",             "importaddress",            &importaddress,            true  },
    { "wallet",             "importprunedfunds",        &importprunedfunds,        true  },
    { "wallet",             "importpubkey",             &importpubkey,             true  },
    { "wallet",             "keypoolrefill",            &keypoolrefill,            true  },
    { "wallet",             "listaccounts",             &listaccounts,             false },
    { "wallet",             "listaddressgroupings",     &listaddressgroupings,     false },
    { "wallet",             "listlockunspent",          &listlockunspent,          false },
    { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    false },
    { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    false },
    { "wallet",             "listsinceblock",           &listsinceblock,           false },
    { "wallet",             "listtransactions",         &listtransactions,         false },
    { "hidden",             "listtransactionsfrom",     &listtransactionsfrom,     false },
    { "wallet",             "listunspent",              &listunspent,              false },
    { "wallet",             "lockunspent",              &lockunspent,              true  },
    { "wallet",             "move",                     &movecmd,                  false },
    { "wallet",             "sendfrom",                 &sendfrom,                 false },
    { "wallet",             "sendmany",                 &sendmany,                 false },
    { "wallet",             "sendtoaddress",            &sendtoaddress,            false },
    { "wallet",             "setaccount",               &setaccount,               true  },
    { "wallet",             "settxfee",                 &settxfee,                 true  },
    { "wallet",             "signmessage",              &signmessage,              true  },
    { "wallet",             "walletlock",               &walletlock,               true  },
    { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   true  },
    { "wallet",             "walletpassphrase",         &walletpassphrase,         true  },
    { "wallet",             "removeprunedfunds",        &removeprunedfunds,        true  },
    { "wallet",             "setmininput",              &setmininput,              false },
    { "wallet",             "listunspentmintzerocoins", &listunspentmintzerocoins, false },
    { "wallet",             "listunspentsigmamints",    &listunspentsigmamints,    false },
    { "wallet",             "mint",                     &mint,                     false },
    { "wallet",             "mintzerocoin",             &mintzerocoin,             false },
    { "wallet",             "mintmanyzerocoin",         &mintmanyzerocoin,         false },
    { "wallet",             "spendzerocoin",            &spendzerocoin,            false },
    { "wallet",             "spendmanyzerocoin",        &spendmanyzerocoin,        false },
    { "wallet",             "spendmany",                &spendmany,                false },
    { "wallet",             "resetmintzerocoin",        &resetmintzerocoin,        false },
    { "wallet",             "resetsigmamint",           &resetsigmamint,           false },
    { "wallet",             "setmintzerocoinstatus",    &setmintzerocoinstatus,    false },
    { "wallet",             "setsigmamintstatus",       &setsigmamintstatus,       false },
    { "wallet",             "listmintzerocoins",        &listmintzerocoins,        false },
    { "wallet",             "listsigmamints",           &listsigmamints,           false },
    { "wallet",             "listpubcoins",             &listpubcoins,             false },
    { "wallet",             "listsigmapubcoins",        &listsigmapubcoins,        false },


    { "wallet",             "removetxmempool",          &removetxmempool,          false },
    { "wallet",             "removetxwallet",           &removetxwallet,           false },
    { "wallet",             "listspendzerocoins",       &listspendzerocoins,       false },
    { "wallet",             "listsigmaspends",          &listsigmaspends,          false },
    { "wallet",             "spendallzerocoin",         &spendallzerocoin,         false },
    { "wallet",             "remintzerocointosigma",    &remintzerocointosigma,    false }
};

void RegisterWalletRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
