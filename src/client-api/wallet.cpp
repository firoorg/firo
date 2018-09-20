// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "znode-payments.h"
#include "rpc/server.h"
#include "util.h"
#include "wallet/wallet.h"
#include "client-api/server.h"
#include "client-api/send.h"
#include <client-api/protocol.h>
#include <univalue.h>

namespace fs = boost::filesystem;
using namespace std::chrono;
using namespace std;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

UniValue getTxMetadataEntry(string txid, string address, CAmount amount){
    fs::path const &path = CreateTxMetadataFile();

    // get data as ifstream
    std::ifstream txMetadataIn(path.string());

    // parse as std::string
    std::string txMetadataStr((std::istreambuf_iterator<char>(txMetadataIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    UniValue txMetadataUni(UniValue::VOBJ);
    UniValue txMetadataData(UniValue::VOBJ);
    txMetadataUni.read(txMetadataStr);

    if(!txMetadataUni["data"].isNull()){
        txMetadataData = txMetadataUni["data"];
    }
    UniValue entryPointer(UniValue::VOBJ);
    UniValue entry(UniValue::VOBJ);
    entryPointer = find_value(find_value(txMetadataData, txid), address);

    if(!entryPointer.isNull()){
        entry = entryPointer.get_obj();
        LogPrintf("entry: %s\n", entry.write());
        return entry;
    }

    return NullUniValue;
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONAPIError(API_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

vector<string> GetMyAccountNames()
{    
    LOCK2(cs_main, pwalletMain->cs_wallet);

    isminefilter includeWatchonly = ISMINE_SPENDABLE;

    vector<string> accounts;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, pwalletMain->mapAddressBook) {
        if (IsMine(*pwalletMain, entry.first) & includeWatchonly) // This address belongs to me
            accounts.push_back(entry.second.name);
    }
    return accounts;
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

CAmount getLockUnspentAmount()
{
    LOCK2(cs_main, pwalletMain->cs_wallet);

    CTransaction tx;
    uint256 hashBlock;
    uint256 hash;
    vector<COutPoint> vOutpts;
    CAmount total = 0;

    pwalletMain->ListLockedCoins(vOutpts);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        uint256 hash = outpt.hash;
        if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

        total += tx.vout[outpt.n].nValue;
    }

    return total;
}

UniValue getInitialTimestamp(string hash){
    fs::path const &path = CreateTxTimestampFile();

    // get data as ifstream
    std::ifstream TxTimestampIn(path.string());

    // parse as std::string
    std::string TxTimestampStr((std::istreambuf_iterator<char>(TxTimestampIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    UniValue TxTimestampUni(UniValue::VOBJ);
    TxTimestampUni.read(TxTimestampStr);

    UniValue TxTimestampData(UniValue::VOBJ);
    if(!TxTimestampUni["data"].isNull()){
        TxTimestampData = TxTimestampUni["data"];
    }

    UniValue firstSeenAt = find_value(TxTimestampData,hash);
    if(firstSeenAt.isNull()){
        return NullUniValue;
    }
    return firstSeenAt;
}

UniValue setInitialTimestamp(string hash){
    fs::path const &path = CreateTxTimestampFile();

    // get data as ifstream
    std::ifstream TxTimestampIn(path.string());

    // parse as std::string
    std::string TxTimestampStr((std::istreambuf_iterator<char>(TxTimestampIn)), std::istreambuf_iterator<char>());

    // finally as UniValue
    UniValue TxTimestampUni(UniValue::VOBJ);
    TxTimestampUni.read(TxTimestampStr);

    UniValue TxTimestampData(UniValue::VOBJ);
    if(!TxTimestampUni["data"].isNull()){
        TxTimestampData = TxTimestampUni["data"];
    }

    if(!find_value(TxTimestampData,hash).isNull()){
        return find_value(TxTimestampData,hash);
    }

    milliseconds secs = duration_cast< milliseconds >(
     system_clock::now().time_since_epoch()
    );
    UniValue firstSeenAt = secs.count();

    TxTimestampData.push_back(Pair(hash, firstSeenAt));

    if(!TxTimestampUni.replace("data", TxTimestampData)){
        throw runtime_error("Could not replace key/value pair.");
    }

    //write back UniValue
    std::ofstream TxTimestampOut(path.string());

    TxTimestampOut << TxTimestampUni.write(4,0) << endl;

    return firstSeenAt;


}

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
    string hash = wtx.GetHash().GetHex();
    if (confirms > 0)
    {
        entry.push_back(Pair("blockHash", wtx.hashBlock.GetHex()));
        UniValue blocktime = mapBlockIndex[wtx.hashBlock]->GetBlockTime();
        entry.push_back(Pair("blockTime", blocktime));
        entry.push_back(Pair("blockHeight", getBlockHeight(wtx.hashBlock.GetHex())));
        UniValue timestamp = getInitialTimestamp(hash);
        if(timestamp.isNull()) timestamp = blocktime;
        entry.push_back(Pair("firstSeenAt", timestamp));    
    }
    else {
        entry.push_back(Pair("firstSeenAt", setInitialTimestamp(hash)));
    }

    entry.push_back(Pair("txid", hash));

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

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    // Sent
    LogPrintf("listSent size: %s\n", listSent.size());
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
            
            if(wtx.vout[s.vout].scriptPubKey.IsZerocoinMint()){
                category = "mint";
                addrStr = "ZEROCOIN_MINT";
                if(pwalletMain){
                    entry.push_back(Pair("used", pwalletMain->IsMintFromTxOutUsed(wtx.vout[s.vout])));
                }
            }
            else if(wtx.vin[s.vout].IsZerocoinSpend()){
                category = "spendOut";                
            }
            else {
                category = "send";
            }
            entry.push_back(Pair("category", category));
            entry.push_back(Pair("address", addrStr));

            CAmount amount = ValueFromAmount(s.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));
            entry.push_back(Pair("fee", ValueFromAmount(nFee).get_real() * COIN));
            APIWalletTxToJSON(wtx, entry);

            UniValue txMetadata(UniValue::VOBJ);
            txMetadata = getTxMetadataEntry(txid.ToString(), addrStr, amount);
            if(!txMetadata.isNull()){
                string label = find_value(txMetadata, "label").get_str();
                entry.push_back(Pair("label", label));   
            }

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
                UniValue newTotal = totalSent.get_int64() + amount;
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
    LogPrintf("listReceived size: %s\n", listReceived.size());
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= 0)
    {
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
            else if(wtx.vin[r.vout].IsZerocoinSpend()){
                category = "spendIn";
            }
            else {
                category = "receive";
            }
            entry.push_back(Pair("category", category));

            CAmount amount = ValueFromAmount(r.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));

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
                UniValue newTotal = totalBalance.get_int64() + amount;
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

UniValue StateSinceBlock(UniValue& ret, std::string block){

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;

    blockId.SetHex(block); //set block hash
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end())
        pindex = it->second;

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VOBJ);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx tx = (*it).second;

        if (depth == -1 || tx.GetDepthInMainChain() <= depth)
            ListAPITransactions(tx, transactions, filter);
    }

    ret.push_back(Pair("addresses", transactions));

    return ret;
}

UniValue StateBlock(UniValue& ret, std::string block){

    LOCK2(cs_main, pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;

    blockId.SetHex(block); //set block hash
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end())
        pindex = it->second;

    if(!pindex){
        return false;
    }

    UniValue transactions(UniValue::VOBJ);

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
        CWalletTx wtx = (*it).second;
        CTransaction tx;
        uint256 hashBlock;

        GetTransaction(wtx.GetHash(), tx, Params().GetConsensus(), hashBlock, true);

        if(block==hashBlock.ToString()){
            ListAPITransactions(wtx, transactions, filter);
        }
    }

    ret.push_back(Pair("addresses", transactions));

    return ret;
}

UniValue statewallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    UniValue ret(UniValue::VOBJ);

    std::string genesisBlock = chainActive[0]->GetBlockHash().ToString();

    StateSinceBlock(ret, genesisBlock);

    return ret;
}

UniValue setpassphrase(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
{
    // encrypt's the wallet should be the wallet be unencrypted.
    // if already encrypted, it checks for a `newpassphrase` field, and updates the passphrase accordingly.
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);

    if (fHelp)
        return true;

    switch(type){
        case Update: {
            if(pwalletMain && pwalletMain->IsCrypted()){
                SecureString strOldWalletPass;
                strOldWalletPass.reserve(100);
                strOldWalletPass = find_value(auth, "passphrase").get_str().c_str();

                SecureString strNewWalletPass;
                strNewWalletPass.reserve(100);
                strNewWalletPass = find_value(auth, "newPassphrase").get_str().c_str();

                if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
                    throw runtime_error("");

                if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
                    throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

                return true;
            }
            else {
                throw JSONRPCError(API_WRONG_TYPE_CALLED, "Error: MODIFY type called, but wallet is unencrypted.");
            }
            break;
        }
        case Create: {
            if (pwalletMain->IsCrypted())
                throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

            SecureString strWalletPass;
            strWalletPass.reserve(100);
            strWalletPass = find_value(auth, "passphrase").get_str().c_str();

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
            break;
        }
        default: {
            throw JSONRPCError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
        }
    }
    return true;
}

UniValue lockwallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
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

UniValue unlockwallet(Type type, const UniValue& data, const UniValue& auth, bool fHelp)
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

    UniValue passphrase = find_value(auth, "passphrase");

    strWalletPass = passphrase.get_str().c_str();

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

UniValue balance(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    
    UniValue balanceObj(UniValue::VOBJ);
    UniValue totalObj(UniValue::VOBJ);
    UniValue xzcObj(UniValue::VOBJ);
    UniValue zerocoinObj(UniValue::VOBJ);

    // various balances
    CAmount xzcConfirmed = pwalletMain->GetBalance();
    CAmount xzcUnconfirmed = pwalletMain->GetUnconfirmedBalance();
    CAmount xzcLocked = getLockUnspentAmount();

    //get private confirmed
    CAmount zerocoinAll = 0;
    CAmount zerocoinConfirmed = 0;
    pwalletMain->GetAvailableMintCoinBalance(zerocoinConfirmed, true);
    pwalletMain->GetAvailableMintCoinBalance(zerocoinAll, false);

    //the difference of all and confirmed gives unconfirmed
    CAmount zerocoinUnconfirmed = zerocoinAll - zerocoinConfirmed; 

    // // We now have all base units, derive return values.
    CAmount total = xzcConfirmed + xzcUnconfirmed + xzcLocked + zerocoinAll;
    CAmount pending = total - xzcConfirmed - zerocoinConfirmed - xzcLocked;
    CAmount available = total - xzcLocked - xzcUnconfirmed - zerocoinUnconfirmed;

    
    totalObj.push_back(Pair("all", total));
    totalObj.push_back(Pair("pending", pending));
    totalObj.push_back(Pair("available", available));

    xzcObj.push_back(Pair("confirmed", xzcConfirmed));
    xzcObj.push_back(Pair("unconfirmed", xzcUnconfirmed));
    xzcObj.push_back(Pair("locked", xzcLocked));

    zerocoinObj.push_back(Pair("confirmed", zerocoinConfirmed));
    zerocoinObj.push_back(Pair("unconfirmed", zerocoinUnconfirmed));

    balanceObj.push_back(Pair("total", totalObj));
    balanceObj.push_back(Pair("xzc", xzcObj));
    balanceObj.push_back(Pair("zerocoin", zerocoinObj));

    return balanceObj;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "wallet",             "lockWallet",      &lockwallet,              true,      false,           false  },
    { "wallet",             "unlockWallet",    &unlockwallet,            true,      false,           false  },
    { "wallet",             "stateWallet",     &statewallet,             true,      false,           false  },
    { "wallet",             "setPassphrase",   &setpassphrase,           true,      false,           false  },
    { "wallet",             "balance",         &balance,                 true,      false,           false  }
    
};
void RegisterWalletAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
