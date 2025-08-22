// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activemasternode.h"
#include "consensus/validation.h"
//#include "governance-classes.h"
#include "base58.h"
#include "script/standard.h"
#include "init.h"
#include "masternode-payments.h"
#include "masternode-sync.h"
#include "messagesigner.h"
#include "netfulfilledman.h"
#include "netmessagemaker.h"
#include "util.h"
#include "validation.h"

#include "evo/deterministicmns.h"

#include <string>

CMasternodePayments mnpayments;

bool IsOldBudgetBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet) {
    /*
    const Consensus::Params& consensusParams = Params().GetConsensus();
    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);

    if (nBlockHeight < consensusParams.nBudgetPaymentsStartBlock) {
        strErrorRet = strprintf("Incorrect block %d, old budgets are not activated yet", nBlockHeight);
        return false;
    }

    if (nBlockHeight >= consensusParams.nSuperblockStartBlock) {
        strErrorRet = strprintf("Incorrect block %d, old budgets are no longer active", nBlockHeight);
        return false;
    }

    // we are still using budgets, but we have no data about them anymore,
    // all we know is predefined budget cycle and window

    int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
    if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
       nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
        // NOTE: old budget system is disabled since 12.1
        if(masternodeSync.IsSynced()) {
            // no old budget blocks should be accepted here on mainnet,
            // testnet/devnet/regtest should produce regular blocks only
            LogPrint("gobject", "%s -- WARNING: Client synced but old budget system is disabled, checking block value against block reward\n", __func__);
            if(!isBlockRewardValueMet) {
                strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, old budgets are disabled",
                                        nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
            }
            return isBlockRewardValueMet;
        }
        // when not synced, rely on online nodes (all networks)
        LogPrint("gobject", "%s -- WARNING: Skipping old budget block value checks, accepting block\n", __func__);
        return true;
    }
    // LogPrint("gobject", "%s -- Block is not in budget cycle window, checking block value against block reward\n", __func__);
    if(!isBlockRewardValueMet) {
        strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, block is not in old budget cycle window",
                                nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
    }
    return isBlockRewardValueMet;
    */
   return true;
}

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Dash some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string& strErrorRet)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
   
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, int nTime, CAmount blockReward)
{
    if(fLiteMode) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        if(fDebug) LogPrintf("%s -- WARNING: Not enough data, skipping block payee checks\n", __func__);
        return true;
    }

    // we are still using budgets, but we have no data about them anymore,
    // we can only check masternode payments

    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Check for correct masternode payment
    if(mnpayments.IsTransactionValid(txNew, nBlockHeight, nTime, blockReward)) {
        LogPrint("mnpayments", "%s -- Valid znode payment at height %d: %s", __func__, nBlockHeight, txNew.ToString());
        return true;
    }

    LogPrintf("%s -- ERROR: Invalid znode payment detected at height %d: %s", __func__, nBlockHeight, txNew.ToString());
    return false;
}

void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, int nTime, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& /*voutSuperblockPaymentsRet*/)
{
    if (!mnpayments.GetMasternodeTxOuts(nBlockHeight, nTime, blockReward, voutMasternodePaymentsRet)) {
        LogPrint("mnpayments", "%s -- no znode to pay (MN list probably empty)\n", __func__);
    }

    txNew.vout.insert(txNew.vout.end(), voutMasternodePaymentsRet.begin(), voutMasternodePaymentsRet.end());
    //txNew.vout.insert(txNew.vout.end(), voutSuperblockPaymentsRet.begin(), voutSuperblockPaymentsRet.end());

    std::string voutMasternodeStr;
    for (const auto& txout : voutMasternodePaymentsRet) {
        // subtract MN payment from miner reward
        txNew.vout[0].nValue -= txout.nValue;
        if (!voutMasternodeStr.empty())
            voutMasternodeStr += ",";
        voutMasternodeStr += txout.ToString();
    }

    LogPrint("mnpayments", "%s -- nBlockHeight %d blockReward %lld voutMasternodePaymentsRet \"%s\" txNew %s", __func__,
                            nBlockHeight, blockReward, voutMasternodeStr, txNew.ToString());
}

std::string GetRequiredPaymentsString(int nBlockHeight, const CDeterministicMNCPtr &payee)
{
    std::string strPayee = "Unknown";
    if (payee) {
        CTxDestination dest;
        if (!ExtractDestination(payee->pdmnState->scriptPayout, dest))
            assert(false);
        strPayee = CBitcoinAddress(dest).ToString();
    }
    /*
    if (CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
        strPayee += ", " + CSuperblockManager::GetRequiredPaymentsString(nBlockHeight);
    }
    */
    return strPayee;
}

std::map<int, std::string> GetRequiredPaymentsStrings(int nStartHeight, int nEndHeight)
{
    std::map<int, std::string> mapPayments;

    if (nStartHeight < 1) {
        nStartHeight = 1;
    }

    LOCK(cs_main);
    int nChainTipHeight = chainActive.Height();

    bool doProjection = false;
    for(int h = nStartHeight; h < nEndHeight; h++) {
        if (h <= nChainTipHeight) {
            auto payee = deterministicMNManager->GetListForBlock(chainActive[h - 1]).GetMNPayee();
            mapPayments.emplace(h, GetRequiredPaymentsString(h, payee));
        } else {
            doProjection = true;
            break;
        }
    }
    if (doProjection) {
        auto projection = deterministicMNManager->GetListAtChainTip().GetProjectedMNPayees(nEndHeight - nChainTipHeight);
        for (size_t i = 0; i < projection.size(); i++) {
            auto payee = projection[i];
            int h = nChainTipHeight + 1 + i;
            mapPayments.emplace(h, GetRequiredPaymentsString(h, payee));
        }
    }

    return mapPayments;
}

/**
*   GetMasternodeTxOuts
*
*   Get masternode payment tx outputs
*/

bool CMasternodePayments::GetMasternodeTxOuts(int nBlockHeight, int nTime, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet) const
{
    // make sure it's not filled yet
    voutMasternodePaymentsRet.clear();

    if(!GetBlockTxOuts(nBlockHeight, nTime, blockReward, voutMasternodePaymentsRet)) {
        LogPrintf("CMasternodePayments::%s -- no payee for block at height %d (deterministic znode list empty)\n", __func__, nBlockHeight);
        return false;
    }

    for (const auto& txout : voutMasternodePaymentsRet) {
        CTxDestination address1;
        ExtractDestination(txout.scriptPubKey, address1);
        CBitcoinAddress address2(address1);

        LogPrintf("CMasternodePayments::%s -- Znode payment %lld to %s\n", __func__, txout.nValue, address2.ToString());
    }

    return true;
}

bool CMasternodePayments::GetBlockTxOuts(int nBlockHeight, int nTime, CAmount blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet) const
{
    voutMasternodePaymentsRet.clear();
    if (nBlockHeight == 0) {
        return false;
    }

    CAmount masternodeReward = GetMasternodePayment(nBlockHeight, nTime, blockReward);

    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = chainActive[nBlockHeight - 1];
    }
    uint256 proTxHash;
    auto dmnPayee = deterministicMNManager->GetListForBlock(pindex).GetMNPayee();
    if (!dmnPayee) {
        return false;
    }

    CAmount operatorReward = 0;
    if (dmnPayee->nOperatorReward != 0 && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
        // This calculation might eventually turn out to result in 0 even if an operator reward percentage is given.
        // This will however only happen in a few years when the block rewards drops very low.
        operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
        masternodeReward -= operatorReward;
    }

    if (masternodeReward > 0) {
        voutMasternodePaymentsRet.emplace_back(masternodeReward, dmnPayee->pdmnState->scriptPayout);
    }
    if (operatorReward > 0) {
        voutMasternodePaymentsRet.emplace_back(operatorReward, dmnPayee->pdmnState->scriptOperatorPayout);
    }

    return true;
}

// Is this masternode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CMasternodePayments::IsScheduled(const CDeterministicMNCPtr& dmnIn, int nNotBlockHeight) const
{
    auto projectedPayees = deterministicMNManager->GetListAtChainTip().GetProjectedMNPayees(8);
    for (const auto &dmn : projectedPayees) {
        if (dmn->proTxHash == dmnIn->proTxHash) {
            return true;
        }
    }
    return false;
}

bool CMasternodePayments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight, int nTime, CAmount blockReward) const
{
    if (!deterministicMNManager->IsDIP3Enforced(nBlockHeight)) {
        // can't verify historical blocks here
        return true;
    }

    std::vector<CTxOut> voutMasternodePayments;
    if (!GetBlockTxOuts(nBlockHeight, nTime, blockReward, voutMasternodePayments)) {
        LogPrintf("CMasternodePayments::%s -- ERROR failed to get payees for block at height %s\n", __func__, nBlockHeight);
        return true;
    }

    for (const auto& txout : voutMasternodePayments) {
        bool found = false;
        for (const auto& txout2 : txNew.vout) {
            if (txout == txout2) {
                found = true;
                break;
            }
        }
        if (!found) {
            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest))
                assert(false);
            LogPrintf("CMasternodePayments::%s -- ERROR failed to find expected payee %s in block at height %s\n", __func__, CBitcoinAddress(dest).ToString(), nBlockHeight);
            return false;
        }
    }
    return true;
}
