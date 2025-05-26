// Copyright (c) 2010 Satoshi Nakamoto// Copyright (c) 2016-2019 The Firo Core developers
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
#include "sigma.h"
#include "lelantus.h"
#include "llmq/quorums_instantsend.h"
#include "llmq/quorums_chainlocks.h"
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
#include "walletexcept.h"
#include "masternode-payments.h"
#include "lelantusjoinsplitbuilder.h"
#include "bip47/paymentchannel.h"
#include "bip47/account.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp>

#include <univalue.h>

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

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

void EnsureSparkWalletIsAvailable()
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
    std::vector<std::string> keys = data.getKeys();
    CAmount totalValue = 0;
    int totalInputs = 0;
    int denomination;
    int64_t amount;
    BOOST_FOREACH(const std::string& denominationStr, keys){
        denomination = std::stoi(denominationStr.c_str());
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
    bool fLLMQLocked = llmq::quorumInstantSendManager->IsLocked(wtx.GetHash());
    bool chainlock = false;
    if (confirms > 0) {
        chainlock = llmq::chainLocksHandler->HasChainLock(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.hashBlock);
    }
    entry.push_back(Pair("confirmations", confirms));
    entry.push_back(Pair("instantlock", fLLMQLocked));
    entry.push_back(Pair("chainlock", chainlock));
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

    BOOST_FOREACH(const PAIRTYPE(std::string,std::string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

std::string AccountFromValue(const UniValue& value)
{
    std::string strAccount = value.get_str();
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
        throw std::runtime_error(
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
    std::string strAccount;
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

UniValue getnewexchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error("");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key or use existing one and convert it to exchange address format
    CKeyID keyID;
    if (request.params.size() == 0) {
        CPubKey newKey;
        if (!pwallet->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        keyID = newKey.GetID();
        pwallet->SetAddressBook(keyID, "", "receive");
    }
    else {
        // out of four tx destinations types only CKeyID (P2PKH) is supported here
        class CTxDestinationVisitor : public boost::static_visitor<CKeyID> {
        public:
            CTxDestinationVisitor() {}
            CKeyID operator() (const CNoDestination&) const {return CKeyID();}
            CKeyID operator() (const CKeyID& keyID) const {return keyID;}
            CKeyID operator() (const CExchangeKeyID&) const {return CKeyID();}
            CKeyID operator() (const CScriptID&) const {return CKeyID();}
        };

        CBitcoinAddress existingKey(request.params[0].get_str());
        if (!existingKey.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Firo address");
        }

        keyID = boost::apply_visitor(CTxDestinationVisitor(), existingKey.Get());
        if (keyID.IsNull()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Must be P2PKH address");
        }
    }

    CBitcoinAddress newAddress;
    newAddress.SetExchange(keyID);

    pwallet->SetAddressBook(newAddress.Get(), "", "receive");

    return newAddress.ToString();
}

CBitcoinAddress GetAccountAddress(CWallet * const pwallet, std::string strAccount, bool bForceNew=false)
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
        throw std::runtime_error(
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
    std::string strAccount = AccountFromValue(request.params[0]);

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
        throw std::runtime_error(
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
        throw std::runtime_error(
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

    std::string strAccount;
    if (request.params.size() > 1)
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, address.Get())) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(address.Get())) {
            std::string strOldAccount = pwallet->mapAddressBook[address.Get()].name;
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
        throw std::runtime_error(
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

    std::string strAccount;
    std::map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(address.Get());
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}

UniValue setmininput(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
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
        throw std::runtime_error(
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

    std::string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second.name;
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
    std::vector<CRecipient> vecSend;
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (std::set<CTxDestination> grouping : pwallet->GetAddressGroupings()) {
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
        throw std::runtime_error(
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

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

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

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue proveprivatetxown(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "proveprivatetxown \"txid\" \"message\"\n"
                "\nCreated a proof by signing the message with private key of each spent coin."
                + HelpRequiringPassphrase(pwallet) + "\n"
                                                     "\nArguments:\n"
                                                     "1. \"strTxId\"  (string, required) Txid, in which we spend lelantus coins.\n"
                                                     "2. \"message\"         (string, required) The message to create a signature of.\n"
                                                     "\nResult:\n"
                                                     "\"proof\"          (string) The signatures of the message encoded in base 64\n"
                                                     "\nExamples:\n"
                                                     "\nUnlock the wallet for 30 seconds\n"
                + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
                "\nCreate the signature\n"
                + HelpExampleCli("proveprivatetxown", "\"34df0ec7bcc8a2bda2c0df41ac560172d974c56ffc9adc0e2377d0fc54b4e8f9 \" \"my message\"") +
                "\nVerify the signature\n"
                + HelpExampleCli("verifyprivatetxown", "\"34df0ec7bcc8a2bda2c0df41ac560172d974c56ffc9adc0e2377d0fc54b4e8f9 \" \"proof\" \"my message\"") +
                "\nAs json rpc\n"
                + HelpExampleRpc("proveprivatetxown", "\"34df0ec7bcc8a2bda2c0df41ac560172d974c56ffc9adc0e2377d0fc54b4e8f9 \", \"my message\"")
        );

    EnsureLelantusWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string strTxId = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    uint256 txid = uint256S(strTxId);
    std::vector<unsigned char> vchSig = pwallet->ProvePrivateTxOwn(txid, strMessage);

    if (vchSig.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Something went wrong, may be you are not the owner of provided tx");

    return EncodeBase64(&vchSig[0], vchSig.size());
}


UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "getreceivedbyaddress \"firoaddress\" ( minconf addlocked )\n"
            "\nReturns the total amount received by the given firoaddress in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"firoaddress\"  (string, required) The Firo address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. addlocked           (bool, optional, default=false) Whether to include transactions locked via InstantSend.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 0") +
            "\nThe amount with at least 2 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 2") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", 2")
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
    bool fAddLocked = (request.params.size() > 2 && request.params[2].get_bool());

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
                if ((wtx.GetDepthInMainChain() >= nMinDepth) || (fAddLocked && wtx.IsLockedByLLMQInstantSend()))
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

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "getreceivedbyaccount \"account\" ( minconf addlocked )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. addlocked      (bool, optional, default=false) Whether to include transactions locked via InstantSend.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 2 confirmation, very safe\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 2") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 2")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (request.params.size() > 1)
        nMinDepth = request.params[1].get_int();
    bool fAddLocked = (request.params.size() > 2 && request.params[2].get_bool());

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

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
                if ((wtx.GetDepthInMainChain() >= nMinDepth) || (fAddLocked && wtx.IsLockedByLLMQInstantSend()))
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

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
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
            "4. addlocked      (bool, optional, default=false) Whether to include the value of transactions locked via InstantSend in the wallet's balance.\n"
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

    bool fAddLocked = (request.params.size() > 3 && request.params[3].get_bool());

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account, fAddLocked));
}

UniValue getprivatebalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getprivatebalance\n"
            "\nReturns  private balance.\n"
            "Private balance is the sum of all confirmed sigma/lelantus mints which are created by the wallet.\n"
            "\nResult:\n"
            "amount              (numeric) The confirmed private balance in " + CURRENCY_UNIT + ".\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet\n"
            + HelpExampleCli("getprivatebalance", "")
            + HelpExampleRpc("getprivatebalance", "")
        );

    EnsureLelantusWalletIsAvailable();
    LOCK2(cs_main, pwallet->cs_wallet);

    return  ValueFromAmount(pwallet->GetPrivateBalance().first + pwallet->sparkWallet->getAvailableBalance());
}

UniValue gettotalbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }


    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "gettotalbalance\n"
            "\nReturns total (transparent + private) balance.\n"
            "Transparent balance is the sum of coin amounts received as utxo.\n"
            "Private balance is the sum of all confirmed sigma/lelantus/spark mints which are created by the wallet.\n"
            "\nResult:\n"
            "amount              (numeric) The total balance in " + CURRENCY_UNIT + " for the wallet.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet\n"
            + HelpExampleCli("gettotalbalance", "")
            + HelpExampleRpc("gettotalbalance", "")
        );

    EnsureLelantusWalletIsAvailable();
    EnsureSparkWalletIsAvailable();
    LOCK2(cs_main, pwallet->cs_wallet);


    return  ValueFromAmount(pwallet->GetBalance() + pwallet->GetPrivateBalance().first + pwallet->sparkWallet->getAvailableBalance());
}

UniValue getunconfirmedbalance(const JSONRPCRequest &request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
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
        throw std::runtime_error(
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
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 2 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strFrom = AccountFromValue(request.params[0]);
    std::string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (request.params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    std::string strComment;
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
        throw std::runtime_error(
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
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 2 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 2 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 2, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
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
        throw std::runtime_error(
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

    std::string strAccount = AccountFromValue(request.params[0]);
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

    std::set<CBitcoinAddress> setAddress;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    BOOST_FOREACH(const std::string& name_, keys)
    {
        CBitcoinAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Firo address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+name_);
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
    std::string strFailReason;
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
        std::string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" )\n"
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
        throw std::runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount;
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

    bool operator()(const CExchangeKeyID &/*keyID*/) {
        // can't witnessify this
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
        std::string msg = "addwitnessaddress \"address\"\n"
            "\nAdd a witness address for a script (with pubkey or redeemscript known).\n"
            "It returns the witness script.\n"

            "\nArguments:\n"
            "1. \"address\"       (string, required) An address known to the wallet\n"

            "\nResult:\n"
            "\"witnessaddress\",  (string) The value of the new address (P2SH of witness script).\n"
            "}\n"
        ;
        throw std::runtime_error(msg);
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
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts, bool fAddLocked)
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
    std::map<CBitcoinAddress, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if ((nDepth < nMinDepth) && !(fAddLocked && wtx.IsLockedByLLMQInstantSend()))
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
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> mapAccountTally;
    for (const std::pair<CBitcoinAddress, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CBitcoinAddress& address = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
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
            _item.nConf = std::min(_item.nConf, nConf);
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
        for (std::map<std::string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
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
        throw std::runtime_error(
            "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"
            "4. addlocked         (bool, optional, default=false) Whether to include transactions locked via InstantSend.\n"


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
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    bool fAddLocked = (request.params.size() > 3 && request.params[3].get_bool());

    return ListReceived(pwallet, request.params, false, fAddLocked);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"
            "4. addlocked         (bool, optional, default=false) Whether to include transactions locked via InstantSend.\n"

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
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true, true")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    bool fAddLocked = (request.params.size() > 3 && request.params[3].get_bool());

    return ListReceived(pwallet, request.params, true, fAddLocked);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest, CBitcoinAddress &addr)
{
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(CWallet * const pwallet, const CWalletTx& wtx, const std::string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    CBitcoinAddress addr;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
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

            CSparkOutputTx output;
            if (wtx.tx->IsSparkTransaction()) {
                const CTxOut& txout = wtx.tx->vout[s.vout];
                if (txout.scriptPubKey.IsSparkMintType()) {
                    if(pwallet->GetSparkOutputTx(txout.scriptPubKey, output)) {
                        entry.push_back(Pair("address", output.address));
                    }
                }
            }

            if (wtx.tx->HasNoRegularInputs()) {
                entry.push_back(Pair("category", "spend"));
            }
            else if (wtx.tx->IsZerocoinMint() || wtx.tx->IsSigmaMint() || wtx.tx->IsLelantusMint() || wtx.tx->IsSparkMint()) {
                entry.push_back(Pair("category", "mint"));
            }
            else if (wtx.tx->IsSpatsMint()) {
                entry.push_back(Pair("category", "spatsmint"));
            }
            else {
                entry.push_back(Pair("category", "send"));
            }

            if (!output.address.empty())
                entry.push_back(Pair("amount", ValueFromAmount(-output.amount)));
            else
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
    if (listReceived.size() > 0 && ((wtx.GetDepthInMainChain() >= nMinDepth) || wtx.IsLockedByLLMQInstantSend()))
    {
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            std::string account;
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

                    bool its_znode_payment = false;
                    if (!fSkipMnpayoutCheck) {
                        std::vector<CTxOut> voutMasternodePaymentsRet;
                        mnpayments.GetBlockTxOuts(txHeight, GetTime(), CAmount(), voutMasternodePaymentsRet);
                        //compare address of payee to addr.
                        for(CTxOut const & out : voutMasternodePaymentsRet) {
                            CTxDestination payeeDest;
                            ExtractDestination(out.scriptPubKey, payeeDest);
                            CBitcoinAddress payeeAddr(payeeDest);

                            if(addr.ToString() == payeeAddr.ToString()) {
                                its_znode_payment = true;
                            }
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

void AcentryToJSON(const CAccountingEntry& acentry, const std::string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == std::string("*"));

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
        throw std::runtime_error(
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
            "                                         transation conflicts with the block chain\n"
            "    \"instantlock\" : true|false, (bool) Current transaction lock state. Available for 'send' and 'receive' category of transactions.\n"
            "    \"chainlock\" : true|false, (bool) The state of the corresponding block chainlock\n"
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

    std::string strAccount = "*";
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

    std::vector<UniValue> arrTmp = ret.getValues();

    std::vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    std::vector<UniValue>::iterator last = arrTmp.begin();
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
        throw std::runtime_error(
            "listaccounts ( minconf include_watchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. include_watchonly   (bool, optional, default=false) Include balances in watch-only addresses (see 'importaddress')\n"
            "3. addlocked           (bool, optional, default=false) Whether to include transactions locked via InstantSend.\n"
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
            "\nList account balances for 2 or more confirmations\n"
            + HelpExampleCli("listaccounts", "2") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("listaccounts", "2")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (request.params.size() > 0)
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(request.params.size() > 1)
        if(request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;
    bool fAddLocked = (request.params.size() > 2 && request.params[2].get_bool());
    std::map<std::string, CAmount> mapAccountBalances;
    for (const std::pair<CTxDestination, CAddressBookData>& entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
        }
    }

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        CAmount nFee;
        std::string strSentAccount;
        std::list<COutputEntry> listReceived;
        std::list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const COutputEntry& s, listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if ((nDepth >= nMinDepth) || (fAddLocked && wtx.IsLockedByLLMQInstantSend()))
        {
            BOOST_FOREACH(const COutputEntry& r, listReceived)
                if (pwallet->mapAddressBook.count(r.destination)) {
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                }
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const std::list<CAccountingEntry> & acentries = pwallet->laccentries;
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    BOOST_FOREACH(const PAIRTYPE(std::string, CAmount)& accountBalance, mapAccountBalances) {
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
        throw std::runtime_error(
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
            "    \"instantlock\" : true|false, (bool) Current transaction lock state. Available for 'send' and 'receive' category of transactions.\n"
            "    \"chainlock\" : true|false, (bool) The state of the corresponding block chainlock\n"
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
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid blockhash");
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
        throw std::runtime_error(
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
            "  \"instantlock\" : true|false, (bool) Current transaction lock state\n"
            "  \"chainlock\" : true|false, (bool) The state of the corresponding block chainlock\n"
            "  \"confirmations\" : n,     (numeric) The number of blockchain confirmations\n"
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
    if (wtx.tx->vin[0].IsLelantusJoinSplit()) {
        try {
            nFee = (0 - lelantus::ParseLelantusJoinSplit(*wtx.tx)->getFee());
        }
        catch (const std::exception &) {
            // do nothing
        }
    } else if (wtx.tx->IsSparkSpend()) {
        try {
            nFee = (0 - spark::ParseSparkSpend(*wtx.tx).getFee());
        }
        catch (const std::exception &) {
            // do nothing
        }
    }

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));

    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    std::string strHex = EncodeHexTx(static_cast<CTransaction>(wtx), RPCSerializationFlags());
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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

    std::string strDest = request.params[0].get_str();
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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

        std::string txid = find_value(o, "txid").get_str();
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
        throw std::runtime_error(
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

    std::vector<COutPoint> vOutpts;
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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
        throw std::runtime_error(
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

    std::set<CBitcoinAddress> setAddress;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Firo address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    bool include_unsafe = true;
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
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
        throw std::runtime_error(
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
    std::set<int> setSubtractFeeFromOutputs;

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
    std::string strFailReason;

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
        throw std::runtime_error(
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
    std::vector<std::pair<uint256, MintPoolEntry>> listMintPool = walletdb.ListMintPool();
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
        nIndexes = pwallet->zwallet->RegenerateMintPoolEntry(walletdb, std::get<0>(entry),std::get<1>(entry),std::get<2>(entry));

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

//[firo]: sigma/lelantus section

UniValue listunspentsigmamints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
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
    std::vector <COutput> vecOutputs;
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
        throw std::runtime_error(
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
    std::vector <COutput> vecOutputs;
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

UniValue listunspentsparkmints(const std::pair<Scalar, Scalar>& identifier, const CWallet* pwallet)
{
    UniValue results(UniValue::VARR);
    std::list<CSparkMintMeta> coins = pwallet->sparkWallet->GetAvailableSparkCoins(identifier);

    LogPrintf("coins.size()=%s\n", coins.size());
    BOOST_FOREACH(const auto& coin, coins)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", coin.txid.GetHex()));
        entry.push_back(Pair("nHeight", coin.nHeight));
        entry.push_back(Pair("memo", coin.memo));

        CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
        serialized << coin.coin;
        CScript script;
        // opcode is inserted as 1 byte according to file script/script.h
        script << OP_SPARKMINT;
        script.insert(script.end(), serialized.begin(), serialized.end());
        entry.push_back(Pair("scriptPubKey", HexStr(script.begin(), script.end())));
        entry.push_back(Pair("amount", ValueFromAmount(coin.v)));
        entry.push_back(Pair("coin", (coin.coin.getHash().GetHex())));
        results.push_back(entry);
    }

    return results;
}

UniValue listunspentsparkmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
                "listunspentsparkmints \n"
                "Returns array of unspent mint coins, only spark base assets\n"
                "Results are an array of Objects, each of which has:\n"
                "{txid, nHeight, memo, scriptPubKey, amount}");
    }

    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    EnsureSparkWalletIsAvailable();
    assert(pwallet != NULL);

    std::pair<Scalar, Scalar> identifier = std::make_pair(Scalar(uint64_t(0)), Scalar(uint64_t(0)));
    return listunspentsparkmints(identifier, pwallet);
}

UniValue listunspentspatsmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
                "listunspentsparkmints \n"
                "\nArguments:\n"
                "1. a       (numeric) .\n"
                "2. iota    (numeric) .\n"
                "Returns array of unspent mints coins, all assets by identifier\n"
                "Results are an array of Objects, each of which has:\n"
                "{txid, nHeight, memo, scriptPubKey, amount}");
    }

    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    EnsureSparkWalletIsAvailable();

    UniValue results(UniValue::VARR);;
    assert(pwallet != NULL);

    Scalar a(uint64_t(request.params[0].get_int()));
    Scalar iota(uint64_t(request.params[0].get_int()));

    std::pair<Scalar, Scalar> identifier = std::make_pair(a, iota);
    return listunspentsparkmints(identifier, pwallet);
}

UniValue listsparkmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "listsparkmints \n"
                "Returns array of mint coins\n"
                "Results are an array of Objects, each of which has:\n"
                "{txid, nHeight, nId, isUsed, lTagHash, memo, scriptPubKey, amount}");
    }

    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }

    EnsureSparkWalletIsAvailable();


    UniValue results(UniValue::VARR);;
    assert(pwallet != NULL);

    std::unordered_map<uint256, CSparkMintMeta> coins_ = pwallet->sparkWallet->getMintMap();

    // sort the result so you can easily compare when testing
    std::vector<std::pair<uint256, CSparkMintMeta> > coins(coins_.begin(), coins_.end());
    sort(coins.begin(), coins.end(),
         [](decltype(coins)::const_reference m1, decltype(coins)::const_reference m2)->bool {
             CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
             ds1 << m1;
             ds2 << m2;
             return ds1.str() < ds2.str();
         });

    BOOST_FOREACH(const auto& coin, coins)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", coin.second.txid.GetHex()));
        entry.push_back(Pair("nHeight", coin.second.nHeight));
        entry.push_back(Pair("nId", coin.second.nId));
        entry.push_back(Pair("isUsed", coin.second.isUsed));
        entry.push_back(Pair("lTagHash", coin.first.GetHex()));
        entry.push_back(Pair("memo", SanitizeString(coin.second.memo)));
        entry.push_back(Pair("a", coin.second.a.GetHex()));
        entry.push_back(Pair("iota", coin.second.iota.GetHex()));

        CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
        serialized << pwallet->sparkWallet->getCoinFromMeta(coin.second);
        CScript script;
        // opcode is inserted as 1 byte according to file script/script.h
        script << OP_SPARKMINT;
        script.insert(script.end(), serialized.begin(), serialized.end());
        entry.push_back(Pair("scriptPubKey", HexStr(script.begin(), script.end())));
        entry.push_back(Pair("amount", ValueFromAmount(coin.second.v)));
        results.push_back(entry);
    }

    return results;
}

UniValue getsparkdefaultaddress(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "getsparkdefaultaddress \n"
                "Returns first spark address in encoded form\n"
                "Result is a string object.");
    }

    EnsureSparkWalletIsAvailable();

    assert(pwallet != NULL);

    spark::Address address = pwallet->sparkWallet->getDefaultAddress();
    unsigned char network = spark::GetNetworkType();
    UniValue result(UniValue::VARR);
    result.push_back(address.encode(network));
    return result;
}

UniValue getnewsparkaddress(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "getnewsparkaddress \n"
                "Returns new spark address in encoded form\n"
                "Result is a string object.");
    }

    EnsureSparkWalletIsAvailable();

    assert(pwallet != NULL);

    spark::Address address = pwallet->sparkWallet->generateNewAddress();
    unsigned char network = spark::GetNetworkType();

    pwallet->SetSparkAddressBook(address.encode(network), "", "receive");

    UniValue result(UniValue::VARR);
    result.push_back(address.encode(network));
    return result;
}

UniValue getallsparkaddresses(const JSONRPCRequest& request) {
    CWallet *const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "getallsparkaddresses \n"
                "Returns array  spark address in encoded form\n"
                "Results are an array of Objects, each of which has:\n"
                "{diversifier and address}");
    }

    EnsureSparkWalletIsAvailable();

    assert(pwallet != NULL);

    std::unordered_map<int32_t, spark::Address> addresses = pwallet->sparkWallet->getAllAddresses();
    unsigned char network = spark::GetNetworkType();
    UniValue results(UniValue::VOBJ);
    for (auto &itr : addresses) {

        results.push_back(Pair(std::to_string(itr.first), itr.second.encode(network)));
    }
    return results;
}


UniValue listsparkspends(const JSONRPCRequest& request) {
    CWallet *const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "listsparkspends \n"
                "Returns array  spark spends\n"
                "Results are an array of Objects, each of which has:\n"
                "{txid, lTagHash, lTag and amount}");
    }

    EnsureSparkWalletIsAvailable();
    assert(pwallet != NULL);

    std::list<CSparkSpendEntry> spends = pwallet->sparkWallet->ListSparkSpends();

    UniValue results(UniValue::VARR);
    for (auto &itr : spends) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", itr.hashTx.GetHex()));
        entry.push_back(Pair("lTagHash", itr.lTagHash.GetHex()));
        entry.push_back(Pair("lTag", itr.lTag.GetHex()));
        entry.push_back(Pair("amount", itr.amount));
        results.push_back(entry);
    }
    return results;
}

UniValue getsparkbalance(const JSONRPCRequest& request) {
    CWallet *const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "getsparkbalance \n"
                "Returns spark balance\n"
                "Results are an array three Objects:\n"
                "{availableBalance, unconfirmedBalance, and fullBalance}");
    }

    EnsureSparkWalletIsAvailable();
    assert(pwallet != NULL);

    UniValue results(UniValue::VOBJ);
    results.push_back(Pair("availableBalance",pwallet->sparkWallet->getAvailableBalance()));
    results.push_back(Pair("unconfirmedBalance",pwallet->sparkWallet->getUnconfirmedBalance()));
    results.push_back(Pair("fullBalance",pwallet->sparkWallet->getFullBalance()));

    return results;
}

UniValue getsparkaddressbalance(const JSONRPCRequest& request) {
    CWallet *const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
                "getsparkaddressbalance \n"
                "Returns spark address balance\n"
                "Results are an array three Objects:\n"
                "{availableBalance, unconfirmedBalance, and fullBalance}");
    }

    EnsureSparkWalletIsAvailable();
    assert(pwallet != NULL);

    std::string strAddress = request.params[0].get_str();
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    spark::Address address(params);
    unsigned char coinNetwork;
    try {
        coinNetwork = address.decode(strAddress);
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Spark address: ")+strAddress);
    }

    if (coinNetwork != network)
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid address, wrong network type: ")+strAddress);


    UniValue results(UniValue::VOBJ);
    results.push_back(Pair("availableBalance: ",pwallet->sparkWallet->getAddressAvailableBalance(address)));
    results.push_back(Pair("unconfirmedBalance: ",pwallet->sparkWallet->getAddressUnconfirmedBalance(address)));
    results.push_back(Pair("fullBalance: ",pwallet->sparkWallet->getAddressFullBalance(address)));

    return results;
}

UniValue resetsparkmints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "resetsparkmints"
                + HelpRequiringPassphrase(pwallet) + "\nResets all your Spark mints' status to unsued and unconfirmed. To make it valid again, you have to rescan or reindex.\n"
                                                     "WARNING: Run this only for testing and if you fully understand what it does.\n");

    EnsureSparkWalletIsAvailable();

    std::vector<CSparkMintMeta> listMints;
    CWalletDB walletdb(pwallet->strWalletFile);
    listMints = pwallet->sparkWallet->ListSparkMints();

    BOOST_FOREACH(CSparkMintMeta& mint, listMints) {
        mint.isUsed = false;
        mint.nHeight = -1;
        pwallet->sparkWallet->updateMint(mint, walletdb);
    }

    return NullUniValue;
}

UniValue setsparkmintstatus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "setsparkmintstatus \"lTagHash\" <isused>(true/false)\n"
                "Set mintIsUsed status to True or False");

    EnsureSparkWalletIsAvailable();

    uint256 lTagHash;
    lTagHash.SetHex(request.params[0].get_str());

    bool fStatus = true;
    fStatus = request.params[1].get_bool();

    EnsureWalletIsUnlocked(pwallet);
    CWalletDB walletdb(pwallet->strWalletFile);
    CSparkMintMeta coinMeta = pwallet->sparkWallet->getMintMeta(lTagHash);

    if (coinMeta != CSparkMintMeta()) {
        coinMeta.isUsed = fStatus;
        pwallet->sparkWallet->updateMint(coinMeta, walletdb);
    }

    return NullUniValue;
}

UniValue mintspark(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() == 0 || request.params.size() > 2)
        throw std::runtime_error(
            "mintspark {\"address\":{amount,memo...}}\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
                                                 "\nArguments:\n"
                                                 "    {\n"
                                                 "      \"address\":amount   (numeric or string) The Spark address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT +
                                                 " is the value\n"
                                                 "      ,...\n"
                                                 "    }\n"
                                                 "\nResult:\n"
                                                 "\"txid\" (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                                                "                                    the number of addresses.\n"
                                                "\nExamples:\n"
                                                "\nSend two amounts to two different spark addresses:\n"
            + HelpExampleCli("mintspark", "\"{\\\"sr1xtw3yd6v4ghgz873exv2r5nzfwryufxjzzz4xr48gl4jmh7fxml4568xr0nsdd7s4l5as2h50gakzjqrqpm7yrecne8ut8ylxzygj8klttsgm37tna4jk06acl2azph0dq4yxdqqgwa60\\\":{\\\"amount\\\":0.01, \\\"memo\\\":\\\"test_memo\\\"},\\\"sr1x7gcqdy670l2v4p9h2m4n5zgzde9y6ht86egffa0qrq40c6z329yfgvu8vyf99tgvnq4hwshvfxxhfzuyvz8dr3lt32j70x8l34japg73ca4w6z9x7c7ryd2gnafg9eg3gpr90gtunraw\\\":{\\\"amount\\\":0.01, \\\"memo\\\":\\\"\\\"}}\"") +
            "\nSend two amounts to two different spark addresses setting memo:\n"
            + HelpExampleRpc("mintspark", "\"{\"sr1xtw3yd6v4ghgz873exv2r5nzfwryufxjzzz4xr48gl4jmh7fxml4568xr0nsdd7s4l5as2h50gakzjqrqpm7yrecne8ut8ylxzygj8klttsgm37tna4jk06acl2azph0dq4yxdqqgwa60\":{\"amount\":1},\\\"sr1x7gcqdy670l2v4p9h2m4n5zgzde9y6ht86egffa0qrq40c6z329yfgvu8vyf99tgvnq4hwshvfxxhfzuyvz8dr3lt32j70x8l34japg73ca4w6z9x7c7ryd2gnafg9eg3gpr90gtunraw\":{\"amount\":0.01, \"memo\":\"test_memo2\"}}\"")
        );
    EnsureWalletIsUnlocked(pwallet);
    EnsureSparkWalletIsAvailable();

    // Ensure spark mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    UniValue sendTo = request.params[0].get_obj();

    std::vector<std::string> keys = sendTo.getKeys();
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();

    std::vector<spark::MintedCoinData> outputs;
    BOOST_FOREACH(const std::string& name_, keys)
    {
        spark::Address address(params);
        unsigned char coinNetwork;
        try {
            coinNetwork = address.decode(name_);
        } catch (const std::exception &) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Spark address: ")+name_);
        }

        if (coinNetwork != network)
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid address, wrong network type: ")+name_);
        UniValue amountAndMemo = sendTo[name_].get_obj();

        CAmount nAmount(0);
        if (amountAndMemo.exists("amount"))
            nAmount = AmountFromValue(amountAndMemo["amount"]);
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no amount: ")+name_);

        std::string memo = "";
        if (amountAndMemo.exists("memo"))
            memo = amountAndMemo["memo"].get_str();

        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        LogPrintf("rpcWallet.mintSpark() nAmount = %d \n", nAmount);

        spark::MintedCoinData data;
        data.address = address;
        data.memo = memo;
        data.v = nAmount;
        outputs.push_back(data);
    }
    bool subtractFeeFromAmount = false;
    if (request.params.size() > 1)
        subtractFeeFromAmount = request.params[1].get_bool();
    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::string strError = pwallet->MintAndStoreSpark(outputs, wtxAndFee, subtractFeeFromAmount);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    UniValue result(UniValue::VARR);
    for(const auto& wtx : wtxAndFee) {
        result.push_back(wtx.first.GetHash().GetHex());
    }

    return result;
}

UniValue mintspats(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "mintspats \"address\":{amount,memo...}\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
                                                 "\nArguments:\n"
                                                 " \"address\"   (string) The Spark address\n"
                                                 " \"memo\"   (string) memo\n"
                                                 " \"amount\"   (numeric) amount to mint\n"
                                                 " \"a\"   (numeric)\n"
                                                 " \"iota\"   (numeric)\n"
                                                 "\nResult:\n"
                                                 "\"txid\" (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                                                "                                    the number of addresses.\n"
                                                "\nExamples:\n"
                                                "\nSend two amounts to two different spark addresses:\n"
            + HelpExampleCli("mintspats", "\"\\\"sr1xtw3yd6v4ghgz873exv2r5nzfwryufxjzzz4xr48gl4jmh7fxml4568xr0nsdd7s4l5as2h50gakzjqrqpm7yrecne8ut8ylxzygj8klttsgm37tna4jk06acl2azph0dq4yxdqqgwa60\\\":{\\\"amount\\\":0.01, \\\"a\\\":1,\\\"iota\\\":1,\\\"memo\\\":\\\"test_memo\\\"}\"")
            + HelpExampleRpc("mintspats", "\"\"sr1xtw3yd6v4ghgz873exv2r5nzfwryufxjzzz4xr48gl4jmh7fxml4568xr0nsdd7s4l5as2h50gakzjqrqpm7yrecne8ut8ylxzygj8klttsgm37tna4jk06acl2azph0dq4yxdqqgwa60\":{\"amount\":1, \\\"a\\\":1,\\\"iota\\\":1,}\"")
        );
    EnsureWalletIsUnlocked(pwallet);
    EnsureSparkWalletIsAvailable();

    // Ensure spats mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!spark::IsSpatsStarted()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spats is not activated yet");
    }

    std::string str_addr = request.params[0].get_str();
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    spark::Address address(params);
    unsigned char coinNetwork;
    try {
        coinNetwork = address.decode(str_addr);
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Spark address: ")+str_addr);
    }

    UniValue data = request.params[1].get_obj();
    spark::MintedCoinData output;
    CAmount nAmount(0);
    if (data.exists("amount"))
        nAmount = AmountFromValue(data["amount"]);
    else
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no amount"));

    std::string memo = "";
    if (data.exists("memo"))
        memo = data["memo"].get_str();

    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    LogPrintf("rpcWallet.mintspats() nAmount = %d \n", nAmount);

    output.address = address;
    output.memo = memo;
    output.v = nAmount;

    if (data.exists("a"))
        output.a = Scalar(uint64_t(data["memo"].get_int()));
    else
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("a is not specified"));

    if (data.exists("iota"))
        output.iota = Scalar(uint64_t(data["iota"].get_int()));
    else
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("iota is not specified"));


    CWalletTx wtx;
    try {
        wtx = pwallet->MintAndStoreSpats({output, address});
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spats creation failed.");
    }

    return wtx.GetHash().GetHex();
}

UniValue automintspark(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "automintspark\n"
                "This function automatically mints all unspent transparent funds to Spark.\n"
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureSparkWalletIsAvailable();

    // Ensure spark mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<spark::MintedCoinData> outputs;
    std::string strError = pwallet->MintAndStoreSpark(outputs, wtxAndFee, true, true);

    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    UniValue result(UniValue::VARR);
    for(const auto& wtx : wtxAndFee) {
        result.push_back(wtx.first.GetHash().GetHex());
    }

    return result;
}

UniValue spendspark(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "spendspark {\"address\":{amount,subtractfee...}, \"address\":{amount,memo,subtractfee...}}\n"
                + HelpRequiringPassphrase(pwallet) + "\n"
                                                     "\nArguments:\n"
                                                     "{\n"
                                                     "  \"address\":amount (numeric or string), memo (string,only for private, not required), subtractfee (bool), a (numeric), iota (numeric) The Spark address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
                                                     "  ,...\n"
                                                     " }\n"
                                                     "\nResult:\n"
                                                     "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
                                                     "                                    the number of addresses.\n"
                                                     "\nExamples:\n"
                                                     "\nSend an amount to transparent address:\n"
                 + HelpExampleCli("spendspark", "\"{\\\"TR1FW48J6ozpRu25U8giSDdTrdXXUYau7U\\\":{\\\"amount\\\":0.01, \\\"subtractFee\\\": false}}\"") +
                 "\nSend an amount to a transparent address and two different private addresses:\n"
                 + HelpExampleCli("spendspark", "\"{\\\"TR1FW48J6ozpRu25U8giSDdTrdXXUYau7U\\\":{\\\"amount\\\":0.01, \\\"subtractFee\\\": false}, \\\"sr1hk87wuh660mss6vnxjf0syt4p6r6ptew97de3dvz698tl7p5p3w7h4m4hcw74mxnqhtz70r7gyydcx6pmkfmnew9q4z0c0muga3sd83h786znjx74ccsjwm284aswppqf2jd0sssendlj\\\":{\\\"amount\\\":0.01, \\\"memo\\\":\\\"test_memo\\\", \\\"subtractFee\\\": false},\\\"sr1x7gcqdy670l2v4p9h2m4n5zgzde9y6ht86egffa0qrq40c6z329yfgvu8vyf99tgvnq4hwshvfxxhfzuyvz8dr3lt32j70x8l34japg73ca4w6z9x7c7ryd2gnafg9eg3gpr90gtunraw\\\":{\\\"amount\\\":0.01, \\\"subtractFee\\\": false}}\"") +
                 "\nSend two amounts to two different transparent addresses and two different private addresses:\n"
                 + HelpExampleRpc("spendspark", "\"{\"TR1FW48J6ozpRu25U8giSDdTrdXXUYau7U\":{\"amount\":0.01, \"subtractFee\": false},\"TuzUyNtTznSNnT2rPXG6Mk7hHG8Svuuoci\":{\"amount\":0.01, \"subtractFee\": true}, \"sr1hk87wuh660mss6vnxjf0syt4p6r6ptew97de3dvz698tl7p5p3w7h4m4hcw74mxnqhtz70r7gyydcx6pmkfmnew9q4z0c0muga3sd83h786znjx74ccsjwm284aswppqf2jd0sssendlj\":{\"amount\":0.01, \"memo\":\"\", \"subtractFee\": false},\"sr1x7gcqdy670l2v4p9h2m4n5zgzde9y6ht86egffa0qrq40c6z329yfgvu8vyf99tgvnq4hwshvfxxhfzuyvz8dr3lt32j70x8l34japg73ca4w6z9x7c7ryd2gnafg9eg3gpr90gtunraw\":{\"amount\":0.01, \"memo\":\"test_memo\", \"subtractFee\": false}}\"")
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureSparkWalletIsAvailable();

    // Ensure spark mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    std::vector<CRecipient> recipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients;
    std::vector<spark::OutputCoinData> spatsRecipients;

    UniValue sendTo = request.params[0].get_obj();
    std::vector<std::string> keys = sendTo.getKeys();
    const spark::Params* params = spark::Params::get_default();
    std::set<CBitcoinAddress> setAddress;
    unsigned char network = spark::GetNetworkType();

    BOOST_FOREACH(const std::string& name_, keys)
    {
        spark::Address sAddress(params);
        unsigned char coinNetwork;
        bool isSparkAddress;
        try {
            unsigned char coinNetwork = sAddress.decode(name_);
            isSparkAddress = true;
            if (coinNetwork != network)
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid address, wrong network type: ")+name_);
        } catch (const std::exception &) {
            isSparkAddress = false;
        }

        if (isSparkAddress) {
            UniValue amountAndMemo = sendTo[name_].get_obj();
            CAmount nAmount(0);
            if (amountAndMemo.exists("amount"))
                nAmount = AmountFromValue(amountAndMemo["amount"]);
            else
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no amount: ")+name_);

            if (nAmount <= 0)
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

            std::string memo = "";
            if (amountAndMemo.exists("memo"))
                memo = amountAndMemo["memo"].get_str();

            bool subtractFee = false;
            if (amountAndMemo.exists("subtractFee"))
                subtractFee = amountAndMemo["subtractFee"].get_bool();
            else
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no subtractFee: ")+name_);

            if (nAmount <= 0)
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
            LogPrintf("rpcWallet.mintSpark() nAmount = %d \n", nAmount);

            spark::OutputCoinData data;
            data.address = sAddress;
            data.memo = memo;
            data.v = nAmount;

            if (amountAndMemo.exists("a"))
                 data.a = Scalar(uint64_t(amountAndMemo["memo"].get_int()));

            if (amountAndMemo.exists("iota"))
                data.iota = Scalar(uint64_t(amountAndMemo["subtractFee"].get_int()));
            if (data.a != Scalar(uint64_t(0)) || data.iota != Scalar(uint64_t(0)))
                spatsRecipients.push_back(data);
            else
                privateRecipients.push_back(std::make_pair(data, subtractFee));
            continue;
        }

        CBitcoinAddress address(name_);
        if (address.IsValid()) {
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   std::string("Invalid parameter, duplicated address: ") + name_);
            setAddress.insert(address);

            CScript scriptPubKey = GetScriptForDestination(address.Get());

            UniValue amountObj = sendTo[name_].get_obj();
            CAmount nAmount(0);
            if (amountObj.exists("amount"))
                nAmount = AmountFromValue(amountObj["amount"]);
            else
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no amount: ") + name_);
            if (nAmount <= 0)
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

            bool fSubtractFeeFromAmount = false;
            if (amountObj.exists("subtractFee"))
                fSubtractFeeFromAmount = amountObj["subtractFee"].get_bool();
            else
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters, no subtractFee: ") + name_);

            CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
            recipients.push_back(recipient);

            continue;
        }

        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Firo address: ") + name_);
    }

    CAmount fee;
    CWalletTx wtx;
    try {
        wtx = pwallet->SpendAndStoreSpark(recipients, privateRecipients, spatsRecipients, fee);
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark spend creation failed.");
    }

    return wtx.GetHash().GetHex();
}

UniValue lelantustospark(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
                "lelantustospark \n"
                "Takes all your lelantus mints, spends all to transparent layer, takes all that UTX's and mints to Spark");
    }

    if (!lelantus::IsLelantusGraceFulPeriod()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus spends are not allowed anymore");
    }


    EnsureWalletIsUnlocked(pwallet);
    EnsureSparkWalletIsAvailable();

    assert(pwallet != NULL);
    std::string strFailReason = "";
    bool passed = false;
    try {
        passed = pwallet->LelantusToSpark(strFailReason);
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed!");
    }
    if (!passed || strFailReason != "")
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus to Spark failed. " + strFailReason);

    return NullUniValue;
}

UniValue identifysparkcoins(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "identifysparkcoins \"txHash\"\n"
                "Identifies coins in transaction, and adds into wallet if yours");

    EnsureSparkWalletIsAvailable();

    uint256 txHash;
    txHash.SetHex(request.params[0].get_str());

    CTransactionRef tx;
    uint256 hashBlock;
    GetTransaction(txHash, tx,  Params().GetConsensus(), hashBlock);
    CWalletDB walletdb(pwallet->strWalletFile);

    UniValue results(UniValue::VOBJ);
    results.push_back(Pair("Old availableBalance",pwallet->sparkWallet->getAvailableBalance()));
    results.push_back(Pair("Old unconfirmedBalance",pwallet->sparkWallet->getUnconfirmedBalance()));
    results.push_back(Pair("Old fullBalance",pwallet->sparkWallet->getFullBalance()));

    if (tx->IsSparkTransaction()) {
        auto coins =  spark::GetSparkMintCoins(*tx);
        uint256 txHash = tx->GetHash();
        pwallet->sparkWallet->UpdateMintState(coins, txHash, walletdb);
    }

    results.push_back(Pair("availableBalance",pwallet->sparkWallet->getAvailableBalance()));
    results.push_back(Pair("unconfirmedBalance",pwallet->sparkWallet->getUnconfirmedBalance()));
    results.push_back(Pair("fullBalance",pwallet->sparkWallet->getFullBalance()));

    return results;
}

UniValue getsparkcoinaddr(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "getsparkcoinaddr \"txHash\"\n"
                "Returns all spark outputs to you, address memo and amount for each");

    EnsureSparkWalletIsAvailable();

    uint256 txHash;
    txHash.SetHex(request.params[0].get_str());

    CTransactionRef tx;
    uint256 hashBlock;
    GetTransaction(txHash, tx,  Params().GetConsensus(), hashBlock);

    UniValue results(UniValue::VARR);;
    assert(pwallet != NULL);

    std::unordered_map<uint256, CSparkMintMeta> coins = pwallet->sparkWallet->getMintMap();
    unsigned char network = spark::GetNetworkType();

    for (const auto& coin : coins)
    {
        if (txHash == coin.second.txid) {
            spark::Address address = pwallet->sparkWallet->getAddress(coin.second.i);
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("address", address.encode(network)));
            entry.push_back(Pair("memo", SanitizeString(coin.second.memo)));
            entry.push_back(Pair("amount", ValueFromAmount(coin.second.v)));
            results.push_back(entry);
        }
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
    std::vector<CHDMint> vDMints;
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
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not active");
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
                "autoMintlelantus\n"
                "This function automatically mints all unspent transparent funds to Lelantus.\n"
        );

    EnsureWalletIsUnlocked(pwallet);
    EnsureLelantusWalletIsAvailable();

    // Ensure Lelantus mints is already accepted by network so users will not lost their coins
    // due to other nodes will treat it as garbage data.
    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not active");
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

UniValue spendmany(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
                "spendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] )\n"
                "\nSpend multiple coins and remint changes in a single transaction by specify addresses and amount for each address."
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

    if (!lelantus::IsLelantusGraceFulPeriod()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus spends are not allowed anymore");
    }

    EnsureLelantusWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);


    UniValue sendTo = request.params[0].get_obj();

    std::unordered_set<std::string> subtractFeeFromAmountSet;
    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (request.params.size() > 1) {
        try {
            subtractFeeFromAmount = request.params[1].get_array();
        }  catch (std::runtime_error const &) {
            //may be empty
        }
        for (int i = subtractFeeFromAmount.size(); i--;) {
            subtractFeeFromAmountSet.insert(subtractFeeFromAmount[i].get_str());
        }
    }

    UniValue mintAmounts;
    if(request.params.size() > 2) {
        try {
                mintAmounts = request.params[2].get_obj();
        } catch (std::runtime_error const &) {
            //may be empty
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

UniValue resetsigmamint(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
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
        throw std::runtime_error(
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

UniValue listsigmamints(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
                "listsigmamints <all>(false/true)\n"
                "\nArguments:\n"
                "1. <all> (boolean, optional) false (default) to return own mints. true to return every mints.\n"
                "\nResults are an array of Objects, each of which has:\n"
                "{id, IsUsed, denomination, value, serialNumber, nHeight, randomness}");

    EnsureSigmaWalletIsAvailable();

    bool fAllStatus = false;
    if (request.params.size() > 0) {
        fAllStatus = request.params[0].get_bool();
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    std::list <CSigmaEntry> listPubcoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    listPubcoin = pwallet->zwallet->GetTracker().MintsAsSigmaEntries(false, false);
    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CSigmaEntry &sigmaItem, listPubcoin) {
        if (fAllStatus || sigmaItem.IsUsed || (sigmaItem.randomness != uint64_t(0) && sigmaItem.serialNumber != uint64_t(0))) {
            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("id", sigmaItem.id));
            entry.push_back(Pair("IsUsed", sigmaItem.IsUsed));
            entry.push_back(Pair("denomination", sigmaItem.get_denomination_value()));
            entry.push_back(Pair("value", sigmaItem.value.GetHex()));
            entry.push_back(Pair("serialNumber", sigmaItem.serialNumber.GetHex()));
            entry.push_back(Pair("nHeight", sigmaItem.nHeight));
            entry.push_back(Pair("randomness", sigmaItem.randomness.GetHex()));
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
        throw std::runtime_error(
                "listlelantusmints <all>(false/true)\n"
                "\nArguments:\n"
                "1. <all> (boolean, optional) false (default) to return real listlelantusmints. true to return every listlelantusmints.\n"
                "\nResults are an array of Objects, each of which has:\n"
                "{id, IsUsed, amount, value, serialNumber, nHeight, randomness}");

    EnsureLelantusWalletIsAvailable();

    bool fAllStatus = false;
    if (request.params.size() > 0) {
        fAllStatus = request.params[0].get_bool();
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    std::list <CLelantusEntry> listCoin;
    CWalletDB walletdb(pwallet->strWalletFile);
    listCoin = pwallet->zwallet->GetTracker().MintsAsLelantusEntries(false, false);
    UniValue results(UniValue::VARR);

    BOOST_FOREACH(const CLelantusEntry &lelantusItem, listCoin) {
        if ((fAllStatus || lelantusItem.amount != uint64_t(0)) && (lelantusItem.IsUsed || (lelantusItem.randomness != uint64_t(0) && lelantusItem.serialNumber != uint64_t(0)))) {
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
        throw std::runtime_error(help_message);
    }

    EnsureSigmaWalletIsAvailable();

    sigma::CoinDenomination denomination;
    bool filter_by_denom = false;
    if (request.params.size() > 0) {
        filter_by_denom = true;
        if (!sigma::StringToDenomination(request.params[0].get_str(), denomination)) {
            throw std::runtime_error(help_message);
        }
    }

    // Mint secret data encrypted in wallet
    EnsureWalletIsUnlocked(pwallet);

    std::list<CSigmaEntry> listPubcoin;
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

UniValue setsigmamintstatus(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
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
        CSigmaEntry sigmaItem;
        if(!pwallet->GetMint(mint.hashSerial, sigmaItem))
            continue;

        CHDMint dMint;
        if (!walletdb.ReadHDMint(mint.GetPubCoinValueHash(), false, dMint)){
            continue;
        }

        if (sigmaItem.serialNumber != uint64_t(0)) {
            LogPrintf("sigmaItem.serialNumber = %s\n", sigmaItem.serialNumber.GetHex());
            if (sigmaItem.serialNumber == coinSerial) {
                LogPrintf("setmintsigmastatus Found!\n");

                const std::string& isUsedDenomStr =
                    fStatus
                    ? "Used (" + std::to_string((double)sigmaItem.get_denomination_value() / COIN) + " mint)"
                    : "New (" + std::to_string((double)sigmaItem.get_denomination_value() / COIN) + " mint)";
                pwallet->NotifyZerocoinChanged(pwallet, sigmaItem.value.GetHex(), isUsedDenomStr, CT_UPDATED);

                if(!mint.isDeterministic){
                    sigmaItem.IsUsed = fStatus;
                    pwallet->zwallet->GetTracker().Add(walletdb, sigmaItem, true);
                }else{
                    dMint.SetUsed(fStatus);
                    pwallet->zwallet->GetTracker().Add(walletdb, dMint, true);
                }

                if (!fStatus) {
                    // erase sigma spend entry
                    CSigmaSpendEntry spendEntry;
                    spendEntry.coinSerial = coinSerial;
                    walletdb.EraseCoinSpendSerialEntry(spendEntry);
                }

                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("id", sigmaItem.id));
                entry.push_back(Pair("IsUsed", fStatus));
                entry.push_back(Pair("denomination", sigmaItem.get_denomination_value()));
                entry.push_back(Pair("value", sigmaItem.value.GetHex()));
                entry.push_back(Pair("serialNumber", sigmaItem.serialNumber.GetHex()));
                entry.push_back(Pair("nHeight", sigmaItem.nHeight));
                entry.push_back(Pair("randomness", sigmaItem.randomness.GetHex()));
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
        throw std::runtime_error(
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
                LogPrintf("setmintlelantusstatus Found!\n");

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
        throw std::runtime_error(
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
            // OP_SIGMASPEND is written.
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
        throw std::runtime_error(
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
            joinsplit = lelantus::ParseLelantusJoinSplit(*pwtx->tx);
        } catch (const std::exception &) {
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

UniValue removetxmempool(const JSONRPCRequest& request) {
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
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
            CTransactionRef tx;
            tx = txpools.get(hash);
            txpools.removeRecursive(*tx);
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
        throw std::runtime_error("removetxwallet <txid>\n" + HelpRequiringPassphrase(pwallet));

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
    std::vector<std::pair<CWalletTx *, unsigned int>> vCoins;
    // Look up the inputs.  We should have already checked that this transaction
    // IsAllFromMe(ISMINE_SPENDABLE), so every input should already be in our
    // wallet, with a valid index into the vout array.
    for (auto& input : tx.vin) {
        const auto mi = pwallet->mapWallet.find(input.prevout.hash);
        assert(mi != pwallet->mapWallet.end() && input.prevout.n < mi->second.tx->vout.size());
        vCoins.emplace_back(std::make_pair(&(mi->second), input.prevout.n));
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
        throw std::runtime_error(
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
/*                                                                            */
/*                              BIP47                                         */
/*                                                                            */
/******************************************************************************/

UniValue listrapaddresses(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    auto help = []() {
        throw std::runtime_error(
            "listrapaddresses verbose \n"
            "Lists all existing receiving RAP addresses with labels. \n"
            "verbose: (bool, optional) - displays all used and next(unused) addresses for each RAP address,\n"
            "\t\tas well as all sending RAP addresses with addresses.\n"
            "Example:\n" +
            HelpExampleCli("listrapaddresses true", ""));
    };

    if (request.fHelp || request.params.size() > 1) {
        help();
    }
    bool verbose = false;
    if (request.params.size() == 1)
        try {
            verbose = request.params[0].getBool();
        } catch (...) {
            help();
        }

    UniValue result(UniValue::VARR);

    if (!verbose) {
        std::vector<bip47::CPaymentCodeDescription> descriptions;
        {
            LOCK(pwallet->cs_wallet);
            descriptions = pwallet->ListPcodes();
        }
        for(bip47::CPaymentCodeDescription const & info : descriptions) {
            UniValue r(UniValue::VOBJ);
            r.push_back(Pair("RAPaddr", std::get<1>(info).toString()));
            r.push_back(Pair("Label",std::get<2>(info)));
            r.push_back(Pair("NotificationAddr",std::get<3>(info).ToString()));
            result.push_back(r);
        }
        return result;
    }

    {
        UniValue r(UniValue::VOBJ);
        LOCK(pwallet->cs_wallet);
        pwallet->GetBip47Wallet()->enumerateReceivers(
            [&result](bip47::CAccountReceiver const & receiver)->bool {
                UniValue r(UniValue::VOBJ);
                r.push_back(Pair("MyRAPaddr", receiver.getMyPcode().toString()));
                r.push_back(Pair("Label", receiver.getLabel()));
                r.push_back(Pair("NotificationAddr",receiver.getMyNotificationAddress().ToString()));
                size_t n = 0;
                for(bip47::CPaymentChannel const & pchannel : receiver.getPchannels()) {
                    r.push_back(Pair(std::string("TheirRapAddr"), pchannel.getTheirPcode().toString()));
                    n = 0;
                    for(bip47::MyAddrContT::value_type const & addr: pchannel.generateMyUsedAddresses()) {
                        r.push_back(Pair(std::string("MyUsed") + std::to_string(n++), addr.first.ToString()));
                    }
                    n = 0;
                    for(bip47::MyAddrContT::value_type const & addr: pchannel.generateMyNextAddresses()) {
                        r.push_back(Pair(std::string("MyNext") + std::to_string(n++), addr.first.ToString()));
                    }
                }
                result.push_back(r);
                return true;
            }
        );
    }
    {
        UniValue r(UniValue::VOBJ);
        LOCK(pwallet->cs_wallet);
        pwallet->GetBip47Wallet()->enumerateSenders(
            [&result](bip47::CAccountSender  const & sender)->bool {
                UniValue r(UniValue::VOBJ);
                r.push_back(Pair("TheirRapAddr", sender.getTheirPcode().toString()));
                r.push_back(Pair("NotificationTxid", sender.getNotificationTxId().ToString()));
                size_t n = 0;
                for(bip47::TheirAddrContT::value_type const & addr : sender.getTheirUsedAddresses())
                    r.push_back(Pair(std::string("TheirUsed") + std::to_string(n++), addr.ToString()));
                r.push_back(Pair(std::string("TheirNext") + std::to_string(n), sender.getTheirNextSecretAddress().ToString()));
                result.push_back(r);
                return true;
            }
        );
    }
    return result;
}

UniValue createrapaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    std::function<void()> help = []()
    {
        throw std::runtime_error(
            "createrapaddress  \"label\"\n"
            "Creates a new labeled RAP address. \n"
            "The label should be unique and non-empty. \n"
            "Example:\n" +
            HelpExampleCli("createrapaddress", "<label>"));
    };

    if (request.fHelp || request.params.size() < 1 or request.params.size() > 2) {
        help();
    }

    UniValue result;
    std::string const label = request.params[0].get_str();
    if (label.empty()) {
        help();
    }

    std::vector<bip47::CPaymentCodeDescription> pcodes;
    {
        LOCK(pwallet->cs_wallet);
        pcodes = pwallet->ListPcodes();
    }
    if (std::find_if(pcodes.begin(), pcodes.end(), [&label](bip47::CPaymentCodeDescription const & pcode){ return  std::get<2>(pcode) == label; }) != pcodes.end()) {
        help();
    }

    LOCK(pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    result.setStr(pwallet->GeneratePcode(label).toString());
    return result;
}

UniValue setupchannel(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "setupchannel \"RapAddress\"\n"
            "\nSets up a payment channel for the RAP address. Sends a notification transaction to the RAP address notification address.\n"
            "It __will__ use Lelantus facilities to send the notification tx. The tx cost is " + std::to_string(1.0 * bip47::NotificationTxValue / COIN ) + " for the JoinSplit tx + fees\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"RapAddress\"  (string, required) The RAP address to send to.\n"
            "\nResult:\n"
            "\"txid\"                  (string) The notification transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("setupchannel", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\"")
        );

    bip47::CPaymentCode theirPcode(request.params[0].get_str());

    if (!lelantus::IsLelantusAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Lelantus is not active");
    }

    EnsureLelantusWalletIsAvailable();

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    try {
        CWalletTx wtx = pwallet->PrepareAndSendNotificationTx(theirPcode);
        return wtx.GetHash().GetHex();

    }
    catch (InsufficientFunds const & e)
    {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, std::string(e.what())+" Please check your Lelantus balance is greater than " + std::to_string(1.0 * bip47::NotificationTxValue / COIN));
    }
    catch (std::runtime_error const & e)
    {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
}

UniValue sendtorapaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            "sendtorapaddress \"RapAddress\" amount ( \"comment\" \"comment-to\" subtractfeefromamount )\n"
            "\nSend an amount to a given RAP address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"RapAddress\"  (string, required) The RAP address to send to.\n"
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
            + HelpExampleCli("sendtorapaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1")
            + HelpExampleCli("sendtorapaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtorapaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtorapaddress", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\", 0.1, \"donation\", \"seans outpost\"")
        );

    bip47::CPaymentCode theirPcode(request.params[0].get_str());

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    CBitcoinAddress address = pwallet->GetTheirNextAddress(theirPcode);

    // Wallet comments
    CWalletTx wtx;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (request.params.size() > 3 && !request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (request.params.size() > 4)
        fSubtractFeeFromAmount = request.params[4].get_bool();

    SendMoney(pwallet, address.Get(), nAmount, fSubtractFeeFromAmount, wtx);

    pwallet->GenerateTheirNextAddress(theirPcode);

    return wtx.GetHash().GetHex();
}

UniValue setusednumber(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw std::runtime_error(
            "setusednumber \"RapAddress\" number\n"
            "\nIncrease the number of used addresses for a RAP address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"paymentcode\"  (string, required) The RAP address.\n"
            "2. \"number\"       (int32_t, required) The number of used addresses which a RAP address will have after this call.\n"
            "                                        If the current number of used addresses is greater than the provides, the call has no effect."
            "\nResult:\n"
            "\"numberOfUsed\"    (int32_t) The number of used addresses after the call.\n"
            "\nExamples:\n"
            + HelpExampleCli("setusednumber", "\"PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA\" 20")
        );

    bip47::CPaymentCode pcode(request.params[0].get_str());
    size_t const number = ParseInt32V(request.params[1], "number");

    boost::optional<bip47::CPaymentCodeDescription> pcodeDesc;
    {
        LOCK(pwallet->cs_wallet);
        pcodeDesc = pwallet->FindPcode(pcode);
    }

    if(!pcodeDesc)
        throw std::runtime_error("RAP address not found: " + pcode.toString());

    if(std::get<4>(*pcodeDesc) == bip47::CPaymentCodeSide::Receiver)
            EnsureWalletIsUnlocked(pwallet);

    LOCK2(cs_main, pwallet->cs_wallet);

    size_t numberOfUsed = pwallet->SetUsedAddressNumber(pcode, number);

    return UniValue(int(numberOfUsed));
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
    { "wallet",             "getbalance",               &getbalance,               false,  {"account","minconf","include_watchonly","addlocked"} },
    { "wallet",             "getprivatebalance",        &getprivatebalance,        false,  {} },
    { "wallet",             "gettotalbalance",          &gettotalbalance,          false,  {} },
    { "wallet",             "getnewaddress",            &getnewaddress,            true,   {"account"} },
    { "hidden",             "getnewexchangeaddress",    &getnewexchangeaddress,    true, {} },
    { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      true,   {} },
    { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     false,  {"account","minconf","addlocked"} },
    { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     false,  {"address","minconf","addlocked"} },
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
    { "wallet",             "listaccounts",             &listaccounts,             false,  {"minconf","include_watchonly","addlocked"} },
    { "wallet",             "listaddressgroupings",     &listaddressgroupings,     false,  {} },
    { "wallet",             "listaddressbalances",      &listaddressbalances,      false,  {"minamount"} },
    { "wallet",             "listlockunspent",          &listlockunspent,          false,  {} },
    { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    false,  {"minconf","include_empty","include_watchonly","addlocked"} },
    { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    false,  {"minconf","include_empty","include_watchonly","addlocked"} },
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
    { "wallet",             "proveprivatetxown",        &proveprivatetxown,        true,   {"txid","message"} },
    { "wallet",             "walletlock",               &walletlock,               true,   {} },
    { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   true,   {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletpassphrase",         &walletpassphrase,         true,   {"passphrase","timeout"} },
    { "wallet",             "removeprunedfunds",        &removeprunedfunds,        true,   {"txid"} },

    { "wallet",             "listunspentsigmamints",    &listunspentsigmamints,    false },
    { "wallet",             "listunspentlelantusmints", &listunspentlelantusmints, false },
    { "wallet",             "mint",                     &mint,                     false },
    { "wallet",             "mintlelantus",             &mintlelantus,             false },
    { "wallet",             "autoMintlelantus",         &autoMintlelantus,         false },
    { "wallet",             "spendmany",                &spendmany,                false },
    { "wallet",             "joinsplit",                &joinsplit,                false },
    { "wallet",             "resetsigmamint",           &resetsigmamint,           false },
    { "wallet",             "resetlelantusmint",        &resetlelantusmint,        false },
    { "wallet",             "setsigmamintstatus",       &setsigmamintstatus,       false },
    { "wallet",             "setlelantusmintstatus",    &setlelantusmintstatus,    false },
    { "wallet",             "listsigmamints",           &listsigmamints,           false },
    { "wallet",             "listsigmapubcoins",        &listsigmapubcoins,        false },
    { "wallet",             "listlelantusmints",        &listlelantusmints,        false },

    { "wallet",             "setmininput",              &setmininput,              false },
    { "wallet",             "regeneratemintpool",       &regeneratemintpool,       false },
    { "wallet",             "removetxmempool",          &removetxmempool,          false },
    { "wallet",             "removetxwallet",           &removetxwallet,           false },
    { "wallet",             "listsigmaspends",          &listsigmaspends,          false },
    { "wallet",             "listlelantusjoinsplits",   &listlelantusjoinsplits,   false },

    //spark
    { "wallet",             "listunspentsparkmints",  &listunspentsparkmints,  false },
    { "wallet",             "listunspentspatsmints",  &listunspentspatsmints,  false },
    { "wallet",             "listsparkmints",         &listsparkmints,         false },
    { "wallet",             "listsparkspends",        &listsparkspends,        false },
    { "wallet",             "getsparkdefaultaddress", &getsparkdefaultaddress, false },
    { "wallet",             "getallsparkaddresses",   &getallsparkaddresses,   false },
    { "wallet",             "getnewsparkaddress",     &getnewsparkaddress,     false },
    { "wallet",             "getsparkbalance",        &getsparkbalance,        false },
    { "wallet",             "getsparkaddressbalance", &getsparkaddressbalance, false },
    { "wallet",             "resetsparkmints",        &resetsparkmints,        false },
    { "wallet",             "setsparkmintstatus",     &setsparkmintstatus,     false },
    { "wallet",             "mintspark",              &mintspark,              false },
    { "wallet",             "mintspats",              &mintspats,              false },
    { "wallet",             "automintspark",          &automintspark,          false },
    { "wallet",             "spendspark",             &spendspark,             false },
    { "wallet",             "lelantustospark",        &lelantustospark,        false },
    { "wallet",             "identifysparkcoins",     &identifysparkcoins,     false },
    { "wallet",             "getsparkcoinaddr",       &getsparkcoinaddr,       false },


    //bip47
    { "bip47",              "createrapaddress",         &createrapaddress,         true },
    { "bip47",              "setupchannel",             &setupchannel,             true },
    { "bip47",              "sendtorapaddress",         &sendtorapaddress,         true },
    { "bip47",              "listrapaddresses",         &listrapaddresses,         true },
    { "bip47",              "setusednumber",            &setusednumber,            true }
};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    if (GetBoolArg("-disablewallet", false))
        return;

    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
