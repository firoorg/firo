// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "smartnode/smartnodepayments.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"

#include <algorithm>
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint64_t nLastBlockWeight = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = 0;

    if ((nHeight > 0) && (nHeight < 717499999)) {

         CScript FOUNDER_1_SCRIPT;
         CScript FOUNDER_2_SCRIPT;
         CScript FOUNDER_3_SCRIPT;
         CScript FOUNDER_4_SCRIPT;
         CScript FOUNDER_5_SCRIPT;

         if(!fTestNet && (GetAdjustedTime() > nStartRewardTime)){
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("Siim7T5zMH3he8xxtQzhmHs4CQSuMrCV1M").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("SW2FbVaBhU1Www855V37auQzGQd8fuLR9x").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("SPusYr5tUdUyRXevJg7pnCc9Sm4HEzaYZF").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("SU5bKb35xUV8aHG5dNarWHB3HBVjcCRjYo").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("SXun9XDHLdBhG4Yd1ueZfLfRpC9kZgwT1b").Get());
         }else if(!fTestNet && (GetAdjustedTime() <= nStartRewardTime)){
             throw std::runtime_error("CreateNewBlock() : Create new block too early");
         }else{
                FOUNDER_1_SCRIPT = GetScriptForDestination(CBitcoinAddress("TTpGqTr2PBeVx4vvNRJ9iTq4NwpTCbSSwy").Get());
                FOUNDER_2_SCRIPT = GetScriptForDestination(CBitcoinAddress("THypUznpFaDHaE7PS6yAc4pHNjC2BnWzUv").Get());
                FOUNDER_3_SCRIPT = GetScriptForDestination(CBitcoinAddress("TDJVZE5oCYYbJQyizU4FgB2KpnKVdebnxg").Get());
                FOUNDER_4_SCRIPT = GetScriptForDestination(CBitcoinAddress("TSziXCdaBcPk3Dt94BbTH9BZDH18K6sWsc").Get());
                FOUNDER_5_SCRIPT = GetScriptForDestination(CBitcoinAddress("TLn1PGAVccBBjF8JuhQmATCR8vxhmamJg8").Get());
         }


         if ((nHeight > 0) && (nHeight < 90000)) {
            // Take out amounts for budgets
            coinbaseTx.vout[0].nValue =-((int64_t)(0.95 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))));
            // And pay the budgets on each block
            coinbaseTx.vout.push_back(CTxOut((int64_t)(0.08 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))), CScript(FOUNDER_1_SCRIPT.begin(), FOUNDER_1_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut((int64_t)(0.08 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))), CScript(FOUNDER_2_SCRIPT.begin(), FOUNDER_2_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut((int64_t)(0.08 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))), CScript(FOUNDER_3_SCRIPT.begin(), FOUNDER_3_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut((int64_t)(0.15 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))), CScript(FOUNDER_4_SCRIPT.begin(), FOUNDER_4_SCRIPT.end())));
            coinbaseTx.vout.push_back(CTxOut((int64_t)(0.56 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))), CScript(FOUNDER_5_SCRIPT.begin(), FOUNDER_5_SCRIPT.end())));
         }
         if ((nHeight >= 90000) && (nHeight < HF_SMARTNODE_HEIGHT)) {
            // Take out amounts for budgets
            coinbaseTx.vout[0].nValue =-((int64_t)(0.95 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))));
            // And pay the budgets over 95 block rotation
            int blockRotation = nHeight - 95 * ((pindexPrev->nHeight+1)/95);
            int64_t reward = (int64_t)(0.95 * (GetBlockValue(nHeight, 0, pindexPrev->nTime)));
            if(blockRotation >= 0 && blockRotation <= 7){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_1_SCRIPT.begin(), FOUNDER_1_SCRIPT.end())));
            }
            if(blockRotation >= 8 && blockRotation <= 15){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_2_SCRIPT.begin(), FOUNDER_2_SCRIPT.end())));
            }
            if(blockRotation >= 16 && blockRotation <= 23){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_3_SCRIPT.begin(), FOUNDER_3_SCRIPT.end())));
            }
            if(blockRotation >= 24 && blockRotation <= 38){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_4_SCRIPT.begin(), FOUNDER_4_SCRIPT.end())));
            }
            if(blockRotation >= 39 && blockRotation <= 94){
                  coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_5_SCRIPT.begin(), FOUNDER_5_SCRIPT.end())));
            }
         }
         
         if ((nHeight >= HF_SMARTNODE_HEIGHT) && (nHeight < 717499999)) {
            // Take out amounts for budgets.
            coinbaseTx.vout[0].nValue =-((int64_t)(0.85 * (GetBlockValue(nHeight, 0, pindexPrev->nTime))));
            // And pay the budgets over 85 block rotation
            int blockRotation = nHeight - 85 * ((pindexPrev->nHeight+1)/85);
            int64_t reward = (int64_t)(0.85 * (GetBlockValue(nHeight, 0, pindexPrev->nTime)));
            if(blockRotation >= 0 && blockRotation <= 7){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_1_SCRIPT.begin(), FOUNDER_1_SCRIPT.end())));
            }
            if(blockRotation >= 8 && blockRotation <= 15){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_2_SCRIPT.begin(), FOUNDER_2_SCRIPT.end())));
            }
            if(blockRotation >= 16 && blockRotation <= 23){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_3_SCRIPT.begin(), FOUNDER_3_SCRIPT.end())));
            }
            if(blockRotation >= 24 && blockRotation <= 38){
               coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_4_SCRIPT.begin(), FOUNDER_4_SCRIPT.end())));
            }
            if(blockRotation >= 39 && blockRotation <= 84){
                  coinbaseTx.vout.push_back(CTxOut(reward, CScript(FOUNDER_5_SCRIPT.begin(), FOUNDER_5_SCRIPT.end())));
            }
            CAmount smartnodePayment = (int64_t)(0.1 * (GetBlockValue(nHeight, 0, pindexPrev->nTime)));
            // Take out amounts for SmartNode payments.
            coinbaseTx.vout[0].nValue -= smartnodePayment;
            // And pay the next SmartNode in line
            FillBlockPayments(coinbaseTx, nHeight, smartnodePayment, pblock->txoutSmartnode, pblock->voutSuperblock);
        }
    }

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SERIALIZED_SIZE - 1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    unsigned int COUNT_SPEND_ZC_TX = 0;
    unsigned int MAX_SPEND_ZC_TX_PER_BLOCK = 0;
    // if(fTestNet || nHeight > OLD_LIMIT_SPEND_TXS){
    //     MAX_SPEND_ZC_TX_PER_BLOCK = 1;
    // }
    // if(fTestNet || nHeight > SWITCH_TO_MORE_SPEND_TXS){
    //     MAX_SPEND_ZC_TX_PER_BLOCK = 5;
    // }

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = 2;//ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
        // -regtest only: allow overriding block.nVersion with
        // -blockversion=N to test forking scenarios
        if (chainparams.MineBlocksOnDemand())
            pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                  ? nMedianTimePast
                                  : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;

        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter)) {
                LogPrintf("skip, due to exist!\n");
                continue; // could have been added to the priorityBlock
            }

            const CTransaction& tx = iter->GetTx();
            LogPrintf("Trying to add tx=%s\n", tx.GetHash().ToString());

            bool fOrphan = false;
            BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else waitSet.insert(iter);
                LogPrintf("skip tx=%s, due to fOrphan=%s\n", tx.GetHash().ToString(), fOrphan);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }

            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    LogPrintf("stop due to size overweight", tx.GetHash().ToString());
                    LogPrintf("nBlockSize=%s\n", nBlockSize);
                    LogPrintf("nBlockMaxSize=%s\n", nBlockMaxSize);
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                LogPrintf("skip tx=%s\n", tx.GetHash().ToString());
                LogPrintf("nBlockSize=%s\n", nBlockSize);
                LogPrintf("nBlockMaxSize=%s\n", nBlockMaxSize);
                continue;
            }
            if (tx.IsCoinBase()) {
                LogPrintf("skip tx=%s, coinbase tx\n", tx.GetHash().ToString());
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff)) {
                LogPrintf("skip tx=%s, not IsFinalTx\n", tx.GetHash().ToString());
                continue;
            }

            if (tx.IsZerocoinSpend()) {
                LogPrintf("try to include zerocoinspend tx=%s\n", tx.GetHash().ToString());
                LogPrintf("COUNT_SPEND_ZC_TX =%s\n", COUNT_SPEND_ZC_TX);
                LogPrintf("MAX_SPEND_ZC_TX_PER_BLOCK =%s\n", MAX_SPEND_ZC_TX_PER_BLOCK);
                if (COUNT_SPEND_ZC_TX >= MAX_SPEND_ZC_TX_PER_BLOCK) {
                    continue;
                }

                //mempool.countZCSpend--;
                // Size limits
                unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

                LogPrintf("\n\n######################################\n");
                LogPrintf("nBlockMaxSize = %d\n", nBlockMaxSize);
                LogPrintf("nBlockSize = %d\n", nBlockSize);
                LogPrintf("nTxSize = %d\n", nTxSize);
                LogPrintf("nBlockSize + nTxSize  = %d\n", nBlockSize + nTxSize);
                LogPrintf("nBlockSigOpsCost  = %d\n", nBlockSigOpsCost);
                LogPrintf("GetLegacySigOpCount  = %d\n", GetLegacySigOpCount(tx));
                LogPrintf("######################################\n\n\n");

                if (nBlockSize + nTxSize >= nBlockMaxSize) {
                    LogPrintf("failed by sized\n");
                    continue;
                }

                // Legacy limits on sigOps:
                unsigned int nTxSigOps = GetLegacySigOpCount(tx);
                if (nBlockSigOpsCost + nTxSigOps >= MAX_BLOCK_SIGOPS_COST) {
                    LogPrintf("failed by sized\n");
                    continue;
                }

                int64_t nTxFees = 0;

                pblock->vtx.push_back(tx);
                pblocktemplate->vTxFees.push_back(nTxFees);
                pblocktemplate->vTxSigOpsCost.push_back(nTxSigOps);
                nBlockSize += nTxSize;
                ++nBlockTx;
                nBlockSigOpsCost += nTxSigOps;
                nFees += nTxFees;
                COUNT_SPEND_ZC_TX++;
                continue;
            }
            unsigned int nTxSigOps = iter->GetSigOpCost();
            LogPrintf("nTxSigOps=%s\n", nTxSigOps);
            LogPrintf("nBlockSigOps=%s\n", nBlockSigOps);
            LogPrintf("MAX_BLOCK_SIGOPS_COST=%s\n", MAX_BLOCK_SIGOPS_COST);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS_COST) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS_COST - 2) {
                    LogPrintf("stop due to cross fee\n", tx.GetHash().ToString());
                    break;
                }
                LogPrintf("skip tx=%s, nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS_COST\n", tx.GetHash().ToString());
                continue;
            }
            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOpsCost.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;
            LogPrintf("added to block=%s\n", tx.GetHash().ToString());
            if (fPrintPriority)
            {
                double dPriority = iter->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(tx.GetHash(), dPriority, dummy);
                LogPrintf("priority %.1f fee %s txid %s\n",
                          dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
            }

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Compute final coinbase transaction.
        //coinbaseTx.vout[0].nValue += nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
        //coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
        pblock->vtx[0] = coinbaseTx;
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
        pblock->nNonce         = 0;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOpsCost[0] = GetLegacySigOpCount(pblock->vtx[0]);
        pblock->vtx[0].vout[0].nValue += nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
        pblocktemplate->vTxFees[0] = -nFees;

        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }
    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}
