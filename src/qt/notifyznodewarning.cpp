#include "notifyznodewarning.h"

#include "evo/deterministicmns.h"
#include "znode.h"
#include "chain.h"
#include "znodeconfig.h"


#ifdef ENABLE_WALLET
#include "walletmodel.h"
#endif

#include <QMessageBox>
#include <QAbstractButton>

void NotifyZnodeWarning::notify()
{
    QMessageBox msg;
    const Consensus::Params& params = ::Params().GetConsensus();
    float numBlocksToEnforcement = params.DIP0003EnforcementHeight - chainActive.Tip()->nHeight;
    float minutesToEnforcement = numBlocksToEnforcement * (params.nPowTargetSpacing / 60);
    float daysDecimal = minutesToEnforcement / 60 / 24;
    float daysToEnforcement = floor(daysDecimal);
    float hoursToEnforcement = floor((daysToEnforcement > 0 ? (daysDecimal - daysToEnforcement) : 0) * 24);

    QString messageWarning = QString("WARNING: Legacy znodes detected. You should migrate to the new Znode layout before it becomes enforced (approximately %1% days and %2% hours. For details on how to migrate, go to zcoin.io/znodemigration").arg(QString::number((int)daysToEnforcement, 10)).arg(QString::number((int)hoursToEnforcement, 10));
    msg.setText(messageWarning);
    msg.setIcon(QMessageBox::Warning);
    msg.exec();
}

bool NotifyZnodeWarning::shouldShow()
{
#ifdef ENABLE_WALLET
    int numBlocks = chainActive.Tip()->nHeight;
    return znodeConfig.getCount() > 0 &&
       CDeterministicMNManager::IsDIP3Active(numBlocks) &&
       CZnode::IsLegacyWindow(numBlocks);
#endif
}
