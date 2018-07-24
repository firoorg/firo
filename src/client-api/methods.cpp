// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "client-api/server.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.cpp"
#include <stdint.h>
#include <client-api/protocol.h>

#include <univalue.h>

#include <boost/thread/thread.hpp> // boost::thread::interrupt

using namespace std;

UniValue getBlockHeight(const string strHash)
{
    LOCK(cs_main);

    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (mapBlockIndex.count(hash) == 0)
        return -1;

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    return pblockindex->nHeight;
}

void APIWalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex)); //TODO check to see if this is blockheight or npt
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
        entry.push_back(Pair("blockheight", getBlockHeight(wtx.hashBlock.GetHex())));
    } else {
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void ListAPITransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    CBitcoinAddress addr;
    string addrStr;
    CTxOut txout;

    UniValue address(UniValue::VOBJ);
    UniValue total(UniValue::VOBJ);
    UniValue txid(UniValue::VOBJ);

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
        {
            UniValue entry(UniValue::VOBJ);
            uint256 txid = wtx.GetHash();
            MaybePushAddress(entry, s.destination, addr);
            if (addr.Set(s.destination))
                addrStr = addr.ToString();
                entry.push_back(Pair("address", addr.ToString()));
            if(wtx.IsZerocoinMint(txout)){
                    entry.push_back(Pair("category", "mint"));
                    addrStr = "ZEROCOIN_MINT";
                    entry.push_back(Pair("address", addrStr));
                    if(pwalletMain){
                        entry.push_back(Pair("used", pwalletMain->IsMintFromTxOutUsed(txout)));
                    }
                }
            else if(wtx.IsZerocoinSpend()){
                    entry.push_back(Pair("category", "spend"));
                }
            else {
                entry.push_back(Pair("category", "send"));
            }
            UniValue amount = ValueFromAmount(s.amount);
            entry.push_back(Pair("amount", amount));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name));
            entry.push_back(Pair("fee", ValueFromAmount(nFee)));
            WalletTxToJSON(wtx, entry);

            if(!ret[addrStr].isNull()){
                address = ret[addrStr];
            }
            else {
                address.clear();
            }

            if(!address["total"].isNull()){
                total = address["total"];
            }
            else {
                total.clear();
            }

            if(!total["sent"].isNull()){
                UniValue totalSent = find_value(total, "sent");
                UniValue newTotal = totalSent.get_int() + amount.get_int();
                total.replace("sent", newTotal);
            }
            else{
                entry.push_back(Pair("sent", amount.get_int()));
            }
            address.replace("total", total);
            address.replace(txid.GetHex(), entry);

            ret.replace(addrStr, address);
        }
    }

    // Received
    // if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    // {
    //     BOOST_FOREACH(const COutputEntry& r, listReceived)
    //     {
    //         string account;
    //         if (pwalletMain->mapAddressBook.count(r.destination))
    //             account = pwalletMain->mapAddressBook[r.destination].name;
    //         if (fAllAccounts || (account == strAccount))
    //         {
    //             UniValue entry(UniValue::VOBJ);
    //             uint256 txid = wtx.GetHash();
    //             MaybePushAddress(entry, r.destination, addr);
    //             if (wtx.IsCoinBase())
    //             {
    //                 int txHeight = chainActive.Height() - wtx.GetDepthInMainChain();
    //                 CScript payee;

    //                 mnpayments.GetBlockPayee(txHeight, payee);
    //                 //compare address of payee to addr. 
    //                 CTxDestination payeeDest;
    //                 ExtractDestination(payee, payeeDest);
    //                 CBitcoinAddress payeeAddr(payeeDest);
    //                 if(addr.ToString() == payeeAddr.ToString()){
    //                     entry.push_back(Pair("category", "znode"));
    //                 }
    //                 else if (wtx.GetDepthInMainChain() < 1)
    //                     entry.push_back(Pair("category", "orphan"));
    //                 else
    //                     entry.push_back(Pair("category", "mined"));
    //             }
    //             else if(wtx.IsZerocoinSpend()){
    //                 entry.push_back(Pair("category", "spend"));
    //             }
    //             else {
    //                 entry.push_back(Pair("category", "receive"));
    //             }
    //             UniValue amount = ValueFromAmount(r.amount);
    //             entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
    //             if (pwalletMain->mapAddressBook.count(r.destination))
    //                 entry.push_back(Pair("label", account));
    //             WalletTxToJSON(wtx, entry);

    //             if(!ret[addrStr]["total"]["sent"].isNull()){
    //                 UniValue totalSent = ret[addrStr]["total"]["sent"];
    //                 ret[addrStr]["total"]["sent"] = totalSent.get_int() + amount.get_int();
    //             }
    //             else{
    //                 ret[addrStr]["total"]["sent"] = amount.get_int();
    //             }

    //             ret[addrStr][txid.GetHex()] = entry;
    //         }
    //     }
    // }
}

UniValue apistatus(const UniValue& data, bool fHelp)
{
    LogPrintf("API status called.");
    return true;
}
UniValue lockwallet(const UniValue& data, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    if (pwalletMain->IsCrypted() && (data.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletunlock again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but lockwallet was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return true;
}

UniValue unlockwallet(const UniValue& data, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in data[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make data[0] mlock()'d to begin with.

    LogPrintf("getting values \n");
    vector<UniValue> values = data.getValues();
    LogPrintf("values size: %s\n", to_string(values.size()));
    

    UniValue auth = find_value(data, "auth");
    UniValue password = find_value(data, "password");

    LogPrintf("valtype: %s\n", password.type());

    strWalletPass = password.get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else //TODO length error
        throw runtime_error(
            "walletunlock <passphrase>\n"
            "Stores the wallet decryption key in memory.");

    pwalletMain->TopUpKeyPool();

    return true;
}

//TODO remove params, add genesis block hash
UniValue getstatewallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

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
            ListAPITransactions(tx, "*", 0, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

static const CAPICommand commands[] =
{ //  type                  collection     actor (function)        authPort  authPassphrase
  //  --------------------- ------------ -----------------------  ---------- --------------
    { "get",         "apistatus",       &apistatus,              false,    false  },
    { "modify",      "lockwallet",      &lockwallet,             true,     false  },
    { "modify",      "unlockwallet",    &unlockwallet,           true,     false  }
};

void RegisterAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
