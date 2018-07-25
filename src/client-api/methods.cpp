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
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
        entry.push_back(Pair("blockheight", getBlockHeight(wtx.hashBlock.GetHex())));
    } 

    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void ListAPITransactions(const CWalletTx& wtx, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    CBitcoinAddress addr;
    string addrStr;
    CTxOut txout;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    // Sent
    if ((!listSent.empty() || nFee != 0))
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
        {   
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue categories(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            uint256 txid = wtx.GetHash();
            if (addr.Set(s.destination)){
                addrStr = addr.ToString();
            }

            string category;
            
            if(wtx.IsZerocoinMint(txout)){
                category = "mint";
                addrStr = "ZEROCOIN_MINT";
                if(pwalletMain){
                    entry.push_back(Pair("used", pwalletMain->IsMintFromTxOutUsed(txout)));
                }
            }
            else if(wtx.IsZerocoinSpend()){
                category = "spend";                
            }
            else {
                category = "send";
            }
            entry.push_back(Pair("category", category));
            entry.push_back(Pair("address", addrStr));

            CAmount amount = ValueFromAmount(s.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));
            if (pwalletMain->mapAddressBook.count(s.destination))
                entry.push_back(Pair("label", pwalletMain->mapAddressBook[s.destination].name));
            entry.push_back(Pair("fee", ValueFromAmount(nFee).get_real() * COIN));
            APIWalletTxToJSON(wtx, entry);


            if(!ret[addrStr].isNull()){
                address = ret[addrStr];
            }

            if(!address["total"].isNull()){
                total = address["total"];
            }

            if(!address["txids"].isNull()){
                txids = address["txids"];
            }

            if(!txids[category].isNull()){
                categories = txids[category];
            }

            if(!total["sent"].isNull()){
                UniValue totalSent = find_value(total, "sent");
                UniValue newTotal = totalSent.get_real() + amount;
                total.replace("sent", newTotal);
            }
            else{
                total.push_back(Pair("sent", amount));
            }
            categories.replace(txid.GetHex(), entry);
            txids.replace(category, categories);
            address.replace("total", total);
            address.replace("txids", txids);
            ret.replace(addrStr, address);
        }
    }

    //Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= 0)
    {
       // LogPrintf("api: in list received \n");
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue categories(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            string account;
            if (pwalletMain->mapAddressBook.count(r.destination)){
                account = pwalletMain->mapAddressBook[r.destination].name;
            }

            uint256 txid = wtx.GetHash();
            string category;
            if (addr.Set(r.destination)){
                addrStr = addr.ToString();
                entry.push_back(Pair("address", addr.ToString()));
            }
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
                    category = "znode";
                }
                else if (wtx.GetDepthInMainChain() < 1)
                    category = "orphan";
                else
                    category = "mined";
            }
            else if(wtx.IsZerocoinSpend()){
                category = "spend";
            }
            else {
                category = "receive";
            }
            entry.push_back(Pair("category", category));

            CAmount amount = ValueFromAmount(r.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));
            if (pwalletMain->mapAddressBook.count(r.destination))
                entry.push_back(Pair("label", account));

            APIWalletTxToJSON(wtx, entry);

            if(!ret[addrStr].isNull()){
                address = ret[addrStr];
            }

            if(!address["total"].isNull()){
                total = address["total"];
            }

            if(!address["txids"].isNull()){
                txids = address["txids"];
            }

            if(!txids[category].isNull()){
                categories = txids[category];
            }

            if(!total["balance"].isNull()){
                UniValue totalBalance = find_value(total, "balance");
                UniValue newTotal = totalBalance.get_real() + amount;
                total.replace("balance", newTotal);
            }
            else{
                total.push_back(Pair("balance", amount));
            }
            
            categories.replace(txid.GetHex(), entry);
            txids.replace(category, categories);
            address.replace("total", total);
            address.replace("txids", txids);

            ret.replace(addrStr, address);
        }
    }
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

UniValue statewallet(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;


    uint256 blockId;

    blockId.SetHex(chainActive[0]->GetBlockHash().ToString()); //set genesis block hash
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end())
        pindex = it->second;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VOBJ);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth)
            ListAPITransactions(tx, transactions, filter);
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("addresses", transactions));

    return ret;
}

static const CAPICommand commands[] =
{ //  type                  collection     actor (function)        authPort  authPassphrase
  //  --------------------- ------------ -----------------------  ---------- --------------
    { "get",         "apistatus",       &apistatus,              false,    false  },
    { "modify",      "lockwallet",      &lockwallet,             true,     false  },
    { "modify",      "unlockwallet",    &unlockwallet,           true,     false  },
    { "initial",     "statewallet",     &statewallet,            true,     false  },
};

void RegisterAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
