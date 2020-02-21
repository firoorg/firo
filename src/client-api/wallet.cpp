// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "znode-payments.h"
#include "rpc/server.h"
#include "util.h"
#include "wallet/wallet.h"
#include "wallet/rpcwallet.h"
#include "client-api/server.h"
#include "client-api/send.h"
#include "client-api/sigma.h"
#include "client-api/protocol.h"
#include "client-api/wallet.h"
#include "coincontrol.h"
#include "univalue.h"
#include <fstream>
#include <boost/algorithm/string.hpp>

namespace fs = boost::filesystem;
using namespace boost::chrono;
using namespace std;

bool GetCoinControl(const UniValue& data, CCoinControl& cc) {
    if (find_value(data, "coinControl").isNull()) return false;
    UniValue uniValCC(UniValue::VOBJ);
    uniValCC = find_value(data, "coinControl");
    UniValue uniSelected(UniValue::VSTR);
    uniSelected = find_value(uniValCC, "selected");

    std::string selected = boost::algorithm::trim_copy(uniSelected.getValStr());
    if (selected.empty()) return false;

    std::vector<string> selectedKeys;
    boost::split(selectedKeys, selected, boost::is_any_of(":"));

    for(size_t i = 0; i < selectedKeys.size(); i++) {
        std::vector<string> splits;
        boost::split(splits, selectedKeys[i], boost::is_any_of("-"));
        if (splits.size() != 2) continue;

        uint256 hash;
        hash.SetHex(splits[0]);
        UniValue idx(UniValue::VNUM);
        idx.setNumStr(splits[1]);
        COutPoint op(hash, idx.get_int());
        cc.Select(op);
    }
    return true;
}

void GetSigmaBalance(CAmount& sigmaAll, CAmount& sigmaConfirmed) {
    auto coins = zwalletMain->GetTracker().ListMints(true, false, false);
    for (const auto& coin : coins) {
        // ignore spent coin
        if (coin.isUsed)
            continue;

        int64_t coinValue;
        DenominationToInteger(coin.denom, coinValue);

        sigmaAll += coinValue;
        if (coin.nHeight > 0
            && coin.nHeight + (ZC_MINT_CONFIRMATIONS-1) <= chainActive.Height())
            sigmaConfirmed += coinValue;
    }
}

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


CAmount getLockUnspentAmount()
{
    LOCK(pwalletMain->cs_wallet);

    CTransaction tx;
    uint256 hashBlock;
    uint256 hash;
    vector<COutPoint> vOutpts;
    CAmount total = 0;

    pwalletMain->ListLockedCoins(vOutpts);

    BOOST_FOREACH(COutPoint &outpt, vOutpts) {
        uint256 hash = outpt.hash;
        if (!GetTransaction(hash, tx, Params().GetConsensus(), hashBlock, true))
            continue;
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

void IsTxOutSpendable(const CWalletTx& wtx, const COutPoint& outPoint, UniValue& entry){
    if (pwalletMain->IsSpent(outPoint.hash, outPoint.n) ||
        (wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0) ||
        wtx.GetDepthInMainChain() <= 0)
        entry.push_back(Pair("spendable", false));

    else{
        entry.push_back(Pair("spendable", true));
        entry.push_back(Pair("locked", pwalletMain->IsLockedCoin(outPoint.hash, outPoint.n)));
    }
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
        if(timestamp.isNull()){ 
            timestamp = blocktime.get_int64() * 1000;
        }
        entry.push_back(Pair("firstSeenAt", timestamp));
    }
    else {
        entry.push_back(Pair("firstSeenAt", setInitialTimestamp(hash)));
    }

    entry.push_back(Pair("txid", hash));

    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void ListAPITransactions(const CWalletTx& wtx, UniValue& ret, const isminefilter& filter, bool getInputs)
{
    CAmount nFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    CBitcoinAddress addr;
    string addrStr;

    wtx.GetAPIAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    // Sent
    if ((!listSent.empty() || nFee != 0))
    {

        BOOST_FOREACH(const COutputEntry& s, listSent)
        {
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue totalCategory(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue vouts(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            uint256 txid = wtx.GetHash();
            if (addr.Set(s.destination)){
                addrStr = addr.ToString();
            }

            string category;
            string voutIndex = to_string(s.vout);
            
            // As outputs take preference, in the case of a Sigma-to-Sigma tx (ie. spend-to-mint), the category will be listed as "mint".
            if(wtx.vout[s.vout].scriptPubKey.IsSigmaMint()){
                category = "mint";
                addrStr = "MINT";
                if(pwalletMain->IsSigmaMintFromTxOutAvailable(wtx.vout[s.vout])){
                    entry.push_back(Pair("available", true));
                    COutPoint outPoint(wtx.GetHash(), s.vout);
                    IsTxOutSpendable(wtx, outPoint, entry);
                }else{
                    entry.push_back(Pair("available", false));
                }
            }
            else if((wtx.IsSigmaSpend())){
                // You can't mix spend and non-spend inputs, therefore it's valid to just check if the overall transaction is a spend.
                category = "spendOut";                
            }
            else {
                category = "send";
            }

            string categoryIndex = category + voutIndex;
            entry.push_back(Pair("category", category));
            entry.push_back(Pair("address", addrStr));
            entry.push_back(Pair("txIndex", s.vout));

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

            if(!txids[categoryIndex].isNull()){
                vouts = txids[categoryIndex];
            }

            if(!total[category].isNull()){
                totalCategory = total[category];
            }

            if(!totalCategory["sent"].isNull()){
                UniValue totalSent = find_value(totalCategory, "sent");
                UniValue newTotal = totalSent.get_int64() + amount;
                totalCategory.replace("sent", newTotal);
                total.replace(category, totalCategory);
            }
            else{
                totalCategory.push_back(Pair("sent", amount));
                total.replace(category, totalCategory);
            }
            vouts.replace(txid.GetHex(), entry);
            txids.replace(categoryIndex, vouts);
            address.replace("total", total);
            address.replace("txids", txids);
            ret.replace(addrStr, address);
        }
    }

    //Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= 0)
    {
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            UniValue address(UniValue::VOBJ);         
            UniValue total(UniValue::VOBJ);
            UniValue totalCategory(UniValue::VOBJ);
            UniValue txids(UniValue::VOBJ);
            UniValue vouts(UniValue::VOBJ);
            UniValue entry(UniValue::VOBJ);

            string account;
            if (pwalletMain->mapAddressBook.count(r.destination)){
                account = pwalletMain->mapAddressBook[r.destination].name;
            }

            uint256 txid = wtx.GetHash();
            string category;
            string voutIndex = to_string(r.vout);

            if (addr.Set(r.destination)){
                addrStr = addr.ToString();
                entry.push_back(Pair("address", addr.ToString()));
            }
            if (wtx.IsCoinBase())
            {
                int txHeight = getBlockHeight(wtx.hashBlock.GetHex()).get_int();
                if(txHeight == -1){
                    category = "coinbase";
                }
                else if(r.vout==1 && txHeight >= Params().GetConsensus().nZnodePaymentsStartBlock){
                    category = "znode";
                }
                else {
                    category = "mined";
                }
            }
            else if(wtx.IsSigmaSpend()){
                // You can't mix spend and non-spend inputs, therefore it's valid to just check if the overall transaction is a spend.
                category = "spendIn";
            } else {
                category = "receive";
            }
            string categoryIndex = category + voutIndex;
            entry.push_back(Pair("category", category));
            entry.push_back(Pair("txIndex", r.vout));

            CAmount amount = ValueFromAmount(r.amount).get_real() * COIN;
            entry.push_back(Pair("amount", amount));

            COutPoint outPoint(txid, r.vout);
            IsTxOutSpendable(wtx, outPoint, entry);

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

            if(!txids[categoryIndex].isNull()){
                vouts = txids[categoryIndex];
            }

            if(!total[category].isNull()){
                totalCategory = total[category];
            }

            if(!totalCategory["balance"].isNull()){
                UniValue totalBalance = find_value(totalCategory, "balance");
                UniValue newTotal = totalBalance.get_int64() + amount;
                totalCategory.replace("balance", newTotal);
                total.replace(category, totalCategory);
            }
            else{
                totalCategory.push_back(Pair("balance", amount));
                total.replace(category, totalCategory);
            }
            
            vouts.replace(txid.GetHex(), entry);
            txids.replace(categoryIndex, vouts);
            address.replace("total", total);
            address.replace("txids", txids);

            ret.replace(addrStr, address);
        }
    }

    if(getInputs){
        UniValue listInputs(UniValue::VARR);
        if (!find_value(ret, "inputs").isNull()) {
            listInputs = find_value(ret, "inputs");
        }
        if (!wtx.IsSigmaSpend()) {
            BOOST_FOREACH(const CTxIn& in, wtx.vin) {
                UniValue entry(UniValue::VOBJ);
                entry.push_back(Pair("txid", in.prevout.hash.ToString()));
                entry.push_back(Pair("index", to_string(in.prevout.n)));
                listInputs.push_back(entry);
            }
        }else {
            COutPoint outpoint;
            CMintMeta meta;
            Scalar zcSpendSerial;
            uint256 spentSerialHash;

            BOOST_FOREACH(const CTxIn& in, wtx.vin) {
                UniValue entry(UniValue::VOBJ);

                zcSpendSerial = sigma::GetSigmaSpendSerialNumber(wtx, in);
                spentSerialHash = primitives::GetSerialHash(zcSpendSerial);

                if(!zwalletMain->GetTracker().GetMetaFromSerial(spentSerialHash, meta))
                    continue;

                if(!sigma::GetOutPoint(outpoint, meta.GetPubCoinValue()))
                    continue;

                entry.push_back(Pair("txid", outpoint.hash.ToString()));
                entry.push_back(Pair("index", to_string(outpoint.n)));
                listInputs.push_back(entry);
            }
        }
        ret.replace("inputs", listInputs);
    }        
}

UniValue StateSinceBlock(UniValue& ret, std::string block){

    LOCK(pwalletMain->cs_wallet);

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
            ListAPITransactions(tx, transactions, filter, true);
    }

    ret.push_back(Pair("addresses", transactions));

    return ret;
}

UniValue StateBlock(UniValue& ret, std::string blockhash){

    LOCK(pwalletMain->cs_wallet);

    CBlockIndex *pindex = NULL;
    isminefilter filter = ISMINE_SPENDABLE;

    uint256 blockId;

    blockId.SetHex(blockhash); //set block hash
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end())
        pindex = it->second;

    if(!pindex){
        return false;
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, pindex, Params().GetConsensus())){
        LogPrintf("can't read block from disk.\n");
    }

    UniValue transactions(UniValue::VOBJ);
    BOOST_FOREACH(const CTransaction&tx, block.vtx)
    {
        const CWalletTx *wtx = pwalletMain->GetWalletTx(tx.GetHash());
        if(wtx){
            ListAPITransactions(*(wtx), transactions, filter, true);
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

    LOCK(pwalletMain->cs_wallet);

    if (fHelp)
        return true;

    switch(type){
        case Update: {
            if(pwalletMain && pwalletMain->IsCrypted()){
                SecureString strOldWalletPass;
                SecureString strNewWalletPass;
                strOldWalletPass.reserve(100);
                strNewWalletPass.reserve(100);
                try{
                    strOldWalletPass = find_value(auth, "passphrase").get_str().c_str();
                    strNewWalletPass = find_value(auth, "newPassphrase").get_str().c_str();

                }catch(const std::exception& e){
                    throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
                }

                if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
                    throw runtime_error("");

                if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
                    throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

                return true;
            }
            else {
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "Error: Update type called, but wallet is unencrypted.");
            }
            break;
        }
        case Create: {
            if (pwalletMain->IsCrypted())
                throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

            SecureString strWalletPass;
            strWalletPass.reserve(100);

            try{
                strWalletPass = find_value(auth, "passphrase").get_str().c_str();

            }catch(const std::exception& e){
                throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
            }

            if (strWalletPass.length() < 1)
                throw runtime_error(
                    "encryptwallet <passphrase>\n"
                    "Encrypts the wallet with <passphrase>.");

            if (!pwalletMain->EncryptWallet(strWalletPass))
                throw JSONAPIError(API_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

            // BDB seems to have a bad habit of writing old data into
            // slack space in .dat files; that is bad if the old data is
            // unencrypted private keys. So:
            StartShutdown();
            return "wallet encrypted; zcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";   
            break;
        }
        default: {
            throw JSONAPIError(API_TYPE_NOT_IMPLEMENTED, "Error: type does not exist for method called, or no type passed where method requires it.");
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

    LOCK(pwalletMain->cs_wallet);

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

    LOCK(pwalletMain->cs_wallet);

    if (!pwalletMain->IsCrypted())
        throw JSONAPIError(API_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but unlockwallet was called.");

    // Note that the walletpassphrase is stored in data[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make data[0] mlock()'d to begin with.

    try{
        strWalletPass = find_value(auth, "passphrase").get_str().c_str();

    }catch(const std::exception& e){
        throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
    }

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    }
    else //TODO length error
        throw JSONAPIError(API_WALLET_PASSPHRASE_INCORRECT, "The wallet passphrase entered was incorrect");

    pwalletMain->TopUpKeyPool();
    return true;
}

UniValue balance(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    if (!EnsureWalletIsAvailable(false))
        return NullUniValue;

    LOCK(pwalletMain->cs_wallet);
    
    UniValue balanceObj(UniValue::VOBJ);
    UniValue totalObj(UniValue::VOBJ);
    UniValue xzcObj(UniValue::VOBJ);
    UniValue sigmaObj(UniValue::VOBJ);

    // various balances
    CAmount xzcConfirmed = pwalletMain->GetBalance();
    CAmount xzcUnconfirmed = pwalletMain->GetUnconfirmedBalance();
    CAmount xzcLocked = getLockUnspentAmount();
    CAmount xzcImmature = pwalletMain->GetImmatureBalance();

    //get private confirmed
    CAmount sigmaAll = 0;
    CAmount sigmaConfirmed = 0;
    GetSigmaBalance(sigmaAll, sigmaConfirmed);

    //the difference of all and confirmed gives unconfirmed
    CAmount sigmaUnconfirmed = sigmaAll - sigmaConfirmed; 

    // // We now have all base units, derive return values.
    CAmount total = xzcConfirmed + xzcUnconfirmed + sigmaAll + xzcImmature;
    CAmount pending = total - xzcConfirmed - sigmaConfirmed;
    CAmount available = total - xzcLocked - xzcUnconfirmed - sigmaUnconfirmed - xzcImmature;
    
    totalObj.push_back(Pair("all", total));
    totalObj.push_back(Pair("pending", pending));
    totalObj.push_back(Pair("available", available));

    xzcObj.push_back(Pair("confirmed", xzcConfirmed));
    xzcObj.push_back(Pair("unconfirmed", xzcUnconfirmed));
    xzcObj.push_back(Pair("locked", xzcLocked));

    sigmaObj.push_back(Pair("confirmed", sigmaConfirmed));
    sigmaObj.push_back(Pair("unconfirmed", sigmaUnconfirmed));

    balanceObj.push_back(Pair("total", totalObj));
    balanceObj.push_back(Pair("public", xzcObj));
    balanceObj.push_back(Pair("private", sigmaObj));

    balanceObj.push_back(Pair("unspentMints", GetDenominations()));

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
