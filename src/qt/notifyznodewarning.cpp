#include "notifyznodewarning.h"

#include "evo/deterministicmns.h"
#include "masternode-sync.h"
#include "chain.h"
#include "znodeconfig.h"
#include "warnings.h"
#include "validation.h"


#ifdef ENABLE_WALLET
#include "walletmodel.h"
#include "wallet/wallet.h"
#endif

bool NotifyZnodeWarning::nConsidered = false;

void NotifyZnodeWarning::notify()
{
    const Consensus::Params& params = ::Params().GetConsensus();
    float numBlocksToEnforcement = params.DIP0003EnforcementHeight - chainActive.Tip()->nHeight;
    float minutesToEnforcement = numBlocksToEnforcement * (params.nPowTargetSpacingMTP / 60);
    float daysDecimal = minutesToEnforcement / 60 / 24;
    float daysToEnforcement = floor(daysDecimal);
    float hoursToEnforcement = floor((daysDecimal > 0 ? (daysDecimal - daysToEnforcement) : 0) * 24);

    std::string strWarning = strprintf(_("WARNING: Legacy znodes detected. You should migrate to the new Znode layout before it becomes enforced (approximately %i days and %i hours). For details on how to migrate, go to https://zcoin.io/znode-migration"),
        (int)daysToEnforcement,
        (int)hoursToEnforcement);

    SetMiscWarning(strWarning);
    uiInterface.NotifyAlertChanged();
}

bool NotifyZnodeWarning::shouldShow()
{
#ifdef ENABLE_WALLET
#endif
    return false;
}
