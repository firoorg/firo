// Copyright (c) 2018 Tadhg Riordan Zcoin Developer
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "validation.h"
#include "client-api/server.h"
#include "client-api/protocol.h"
#include "rpc/server.h"
#include "core_io.h"
#include "net.h"
#include "init.h"
#include "wallet/wallet.h"
#include "client-api/wallet.h"
#include "univalue.h"
#include "chain.h"
#include "txmempool.h"
#include "evo/deterministicmns.h"
#include "masternode-sync.h"

using namespace boost::chrono;

uint32_t AvgBlockTime(){
    uint32_t avgBlockTime;
    Consensus::Params nParams = Params().GetConsensus();
    if(chainActive.Tip()->nHeight >= nParams.nMTPFiveMinutesStartBlock)
        avgBlockTime = nParams.nPowTargetSpacingMTP;
    else
        avgBlockTime = nParams.nPowTargetSpacing;

    return avgBlockTime;
}

UniValue transaction(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    
    LOCK2(cs_main, pwalletMain->cs_wallet);

    //decode transaction
    UniValue ret(UniValue::VOBJ);
    CMutableTransaction transaction;
    if (!DecodeHexTx(transaction, find_value(data, "txRaw").get_str()))
        throw JSONAPIError(API_DESERIALIZATION_ERROR, "Error parsing or validating structure in raw format");

    const CWalletTx *wtx = pwalletMain->GetWalletTx(transaction.GetHash());
    if(wtx==NULL)
        throw JSONAPIError(API_INVALID_PARAMETER, "Invalid, missing or duplicate parameter");

    CWalletDB db(pwalletMain->strWalletFile);
    return FormatWalletTxForClientAPI(db, *wtx);
}


UniValue block(Type type, const UniValue& data, const UniValue& auth, bool fHelp){
    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string blockhash;
    try {
        blockhash = find_value(data, "hashBlock").get_str();
    } catch (const std::exception& e) {
        throw JSONAPIError(API_WRONG_TYPE_CALLED, "wrong key passed/value type for method");
    }

    uint256 blockId;
    blockId.SetHex(blockhash); //set block hash

    CBlockIndex *pindex;
    BlockMap::iterator it = mapBlockIndex.find(blockId);
    if (it != mapBlockIndex.end()) pindex = it->second;
    else return false;

    CBlock block;
    if(!ReadBlockFromDisk(block, pindex, Params().GetConsensus())){
        LogPrintf("can't read block from disk.\n");
    }

    CWalletDB db(pwalletMain->strWalletFile);
    UniValue transactions = UniValue::VARR;
    for (const CTransactionRef tx:block.vtx) {
        const CWalletTx *wtx = pwalletMain->GetWalletTx(tx->GetHash());
        if (wtx) transactions.push_back(FormatWalletTxForClientAPI(db, *wtx));
    }
    return transactions;
}

UniValue rebroadcast(Type type, const UniValue& data, const UniValue& auth, bool fHelp){

    UniValue ret(UniValue::VOBJ);
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash = uint256S(find_value(data, "txHash").get_str());
    CWalletTx *wtx = const_cast<CWalletTx*>(pwalletMain->GetWalletTx(hash));

    if (!wtx) {
        ret.push_back(Pair("result", false));
        ret.push_back(Pair("error", "Transaction cannot be found."));
        return ret;
    }

    if (wtx->GetDepthInMainChain() > 0) {
        ret.push_back(Pair("result", false));
        ret.push_back(Pair("error", "Transaction is already in chain"));
        return ret;
    }

    if (wtx->GetRequestCount() > 0) {
        ret.push_back(Pair("result", false));
        ret.push_back(Pair("error", "Transaction has already been requested to be rebroadcast"));
        return ret;
    }

    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t i=0; i<wtx->tx->vout.size() && !fHaveChain; i++) {
        if (view.HaveCoin(COutPoint(hash, i)))
            fHaveChain = true;
    }

    bool fHaveMempool = mempool.exists(hash);
    
    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        CValidationState state;
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, wtx->tx, false, &fMissingInputs, NULL, true, false, maxTxFee)){
            ret.push_back(Pair("result", false));
            ret.push_back(Pair("error", "Transaction not accepted to mempool"));
            return ret;
        }
    } else if (fHaveChain) {
        ret.push_back(Pair("result", false));
        ret.push_back(Pair("error", "transaction already in block chain"));
        return ret;
    }

    g_connman->RelayTransaction((CTransaction)*wtx);
    ret.push_back(Pair("result", true));
    return ret;
}

static const CAPICommand commands[] =
{ //  category              collection         actor (function)          authPort   authPassphrase   warmupOk
  //  --------------------- ------------       ----------------          -------- --------------   --------
    { "blockchain",         "block",           &block,                   true,      false,           false  },
    { "blockchain",         "rebroadcast",     &rebroadcast,             true,      false,           false  },
    { "blockchain",         "transaction",     &transaction,             true,      false,           false  }
    
};
void RegisterBlockchainAPICommands(CAPITable &tableAPI)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableAPI.appendCommand(commands[vcidx].collection, &commands[vcidx]);
}
