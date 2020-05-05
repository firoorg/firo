#include "notifyznodewarning.h"

#include "evo/deterministicmns.h"
#include "znode.h"
#include "chain.h"
#include "znodeconfig.h"
#include "znodeman.h"


#ifdef ENABLE_WALLET
#include "walletmodel.h"
#include "wallet/wallet.h"
#endif

#include <QMessageBox>
#include <QAbstractButton>

bool NotifyZnodeWarning::nConsidered = false;

void NotifyZnodeWarning::notify()
{
    QMessageBox msg;
    const Consensus::Params& params = ::Params().GetConsensus();
    float numBlocksToEnforcement = params.DIP0003EnforcementHeight - chainActive.Tip()->nHeight;
    float minutesToEnforcement = numBlocksToEnforcement * (params.nPowTargetSpacingMTP / 60);
    float daysDecimal = minutesToEnforcement / 60 / 24;
    float daysToEnforcement = floor(daysDecimal);
    float hoursToEnforcement = floor((daysDecimal > 0 ? (daysDecimal - daysToEnforcement) : 0) * 24);

    QString messageWarning = QString("WARNING: Legacy znodes detected. You should migrate to the new Znode layout before it becomes enforced (approximately %1 days and %2 hours). For details on how to migrate, go to https://zcoin.io/znode-migration")
    .arg(QString::number((int)daysToEnforcement, 10))
    .arg(QString::number((int)hoursToEnforcement, 10));
    msg.setText(messageWarning);
    msg.setIcon(QMessageBox::Warning);
    msg.exec();
    nConsidered = true;
}

bool NotifyZnodeWarning::shouldShow()
{
#ifdef ENABLE_WALLET
    if(nConsidered || // already fully considered warning
       znodeConfig.getCount() == 0 || // no legacy znodes detected
       !CZnode::IsLegacyWindow(chainActive.Tip()->nHeight) // outside of legacy window
       || !pwalletMain) // wallet not yet loaded
        return false;

    // get Znode entries.
    std::vector<COutPoint> vOutpts;
    bool nGotProReg = false;
    uint256 mnTxHash;
    int outputIndex;
    BOOST_FOREACH(CZnodeConfig::CZnodeEntry mne, znodeConfig.getEntries()) {
      
        CZnode* mn = mnodeman.Find(mne.getTxHash(), mne.getOutputIndex());
        // in the case that the Znode has dissapeared from the network, was never initialized, or it's outpoint has been spent (disabled Znode).
        if(mn==NULL || mn->IsOutpointSpent())
            continue;

        // So we have a valid legacy Znode. get ProReg transactions, look for the same collateral.
        if(!nGotProReg){
            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->ListProTxCoins(vOutpts);
            nGotProReg = true;
        }
        bool foundOutpoint = false;
        mnTxHash.SetHex(mne.getTxHash());
        outputIndex = boost::lexical_cast<unsigned int>(mne.getOutputIndex());
        COutPoint outpoint = COutPoint(mnTxHash, outputIndex);
        for (const auto& outpt : vOutpts) {
            if(outpt==outpoint){
                foundOutpoint = true;
                break;
            }
        }

        // if collateral not found, show warning.
        if(!foundOutpoint)
            return true;
    }

    // if we get to here, the warning will never be shown, and so is fully considered (All znodes ported or expired)
    nConsidered = true;
#endif
    return false;
}
