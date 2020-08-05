#include "../lelantus.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "automintmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "lelantusmodel.h"

AutoMintModel::AutoMintModel(
    LelantusModel *_lelantusModel,
    OptionsModel *_optionsModel,
    CWallet *_wallet,
    QObject *parent) :
    QObject(parent),
    lelantusModel(_lelantusModel),
    optionsModel(_optionsModel),
    wallet(_wallet),
    autoMintState(AutoMintState::Disabled),
    checkPendingTxTimer(0),
    resetInitialSyncTimer(0),
    autoMintCheckTimer(0),
    initialSync(false)
{
    checkPendingTxTimer = new QTimer(this);
    checkPendingTxTimer->setSingleShot(true);

    resetInitialSyncTimer = new QTimer(this);
    resetInitialSyncTimer->setSingleShot(true);

    autoMintCheckTimer = new QTimer(this);
    autoMintCheckTimer->setSingleShot(false);

    if (optionsModel && optionsModel->getAutoAnonymize()) {
        QTimer::singleShot(5 * 1000, this, SLOT(startAutoMint()));
    }

    connect(checkPendingTxTimer, SIGNAL(timeout()), this, SLOT(checkPendingTransactions()));
    connect(resetInitialSyncTimer, SIGNAL(timeout()), this, SLOT(resetInitialSync()));
    connect(autoMintCheckTimer, SIGNAL(timeout()), this, SLOT(checkAutoMint()));

    connect(optionsModel, SIGNAL(autoAnonymizeChanged(bool)), this, SLOT(updateAutoMintOption(bool)));

    subscribeToCoreSignals();
}

AutoMintModel::~AutoMintModel()
{
    unsubscribeFromCoreSignals();

    disconnect(checkPendingTxTimer, SIGNAL(timeout()), this, SLOT(checkPendingTransactions()));

    delete resetInitialSyncTimer;
    delete checkPendingTxTimer;

    resetInitialSyncTimer = nullptr;
    checkPendingTxTimer = nullptr;
}

bool AutoMintModel::askingUser()
{
    return autoMintState == AutoMintState::WaitingForUserResponse;
}

void AutoMintModel::ackMintAll(AutoMintAck ack, CAmount minted, QString error)
{
    LOCK(lelantusModel->cs);
    if (ack == AutoMintAck::WaitUserToActive) {
        autoMintState = AutoMintState::WaitingUserToActivate;
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
        autoMintCheckTimer->stop();
    }
}

void AutoMintModel::checkAutoMint()
{
    // if lelantus is not allow or client is in initial syncing state then wait
    // except user force to check
    bool force = this->force;

    if (!force) {
        // check initialSync first to reduce main locking
        if (initialSync) {
            return;
        }

        bool allowed = lelantus::IsLelantusAllowed();
        if (!allowed) {
            return;
        }
    }

    {
        LOCK(lelantusModel->cs);

        if (fReindex) {
            return;
        }

        switch (autoMintState) {
        case AutoMintState::Disabled:
        case AutoMintState::WaitingIncomingFund:
            if (force) {
                break;
            }
            autoMintCheckTimer->stop();
            return;
        case AutoMintState::WaitingUserToActivate:
            // check activation status
            break;
        case AutoMintState::WaitingForUserResponse:
            return;
        default:
            throw std::runtime_error("Unknown auto mint state");
        }

        autoMintState = AutoMintState::WaitingForUserResponse;
    }

    lelantusModel->askUserToMint(force);
}

void AutoMintModel::setInitialSync()
{
    initialSync.store(true);
    resetInitialSyncTimer->stop();

    // wait 10 second if there are no new signal then reset flag
    resetInitialSyncTimer->start(10 * 1000);
}

void AutoMintModel::resetInitialSync()
{
    initialSync.store(false);
}

void AutoMintModel::startAutoMint(bool force)
{
    if (autoMintCheckTimer->isActive()) {
        if (!this->force && force) {
            this->force = force;
        }
        return;
    }

    CAmount mintable = 0;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        mintable = lelantusModel->getMintableAmount();
    }

    if (mintable > 0) {
        autoMintState = AutoMintState::WaitingUserToActivate;

        if (!this->force && force) {
            this->force = force;
        }

        autoMintCheckTimer->start(MODEL_UPDATE_DELAY);
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void AutoMintModel::checkPendingTransactions()
{
    LOCK2(cs_main, wallet->cs_wallet);
    LOCK(lelantusModel->cs);

    auto hasNew = false;
    for (auto const &tx : pendingTransactions) {
        if (!wallet->mapWallet.count(tx)) {
            continue;
        }

        auto const &wtx = wallet->mapWallet[tx];
        hasNew |= (wtx.GetAvailableCredit() - wtx.GetDebit(ISMINE_ALL)) > 0;

        if (hasNew) {
            break;
        }
    }

    pendingTransactions.clear();
    if (!hasNew) {
        return;
    }

    switch (autoMintState) {
    case AutoMintState::Disabled:
    case AutoMintState::WaitingUserToActivate:
    case AutoMintState::WaitingForUserResponse:
        return;
    case AutoMintState::WaitingIncomingFund:
        break;
    default:
        throw std::runtime_error("Unknown auto mint status");
    };

    autoMintState = AutoMintState::WaitingUserToActivate;
    startAutoMint();
}

void AutoMintModel::updateTransaction(uint256 hash)
{
    LOCK(lelantusModel->cs);

    checkPendingTxTimer->stop();
    checkPendingTxTimer->setSingleShot(true);

    pendingTransactions.push_back(hash);

    checkPendingTxTimer->start(10 * 1000); // 10 seconds
}

void AutoMintModel::updateAutoMintOption(bool enabled)
{
    LOCK(lelantusModel->cs);
    if (enabled) {
        if (autoMintState == AutoMintState::Disabled) {
            startAutoMint();
        }
    } else {
        // stop mint
        autoMintState = AutoMintState::Disabled;
    }
}

// Handlers for core signals
static void NotifyBlockTip(AutoMintModel *model, bool initialSync, const CBlockIndex *pIndex)
{
    Q_UNUSED(pIndex);
    if (initialSync) {
        QMetaObject::invokeMethod(
            model,
            "setInitialSync",
            Qt::QueuedConnection);
    }
}

static void NotifyTransactionChanged(
    AutoMintModel *model, CWallet *wallet, uint256 const &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(status);
    if (status == ChangeType::CT_NEW || status == ChangeType::CT_UPDATED) {
        QMetaObject::invokeMethod(
            model,
            "updateTransaction",
            Qt::QueuedConnection,
            Q_ARG(uint256, hash));
    }
}

void AutoMintModel::subscribeToCoreSignals()
{
    wallet->NotifyTransactionChanged.connect(
        boost::bind(NotifyTransactionChanged, this, _1, _2, _3));

    uiInterface.NotifyBlockTip.connect(boost::bind(
        NotifyBlockTip, this, _1, _2));
}

void AutoMintModel::unsubscribeFromCoreSignals()
{
    wallet->NotifyTransactionChanged.disconnect(
        boost::bind(NotifyTransactionChanged, this, _1, _2, _3));

    uiInterface.NotifyBlockTip.disconnect(boost::bind(
        NotifyBlockTip, this, _1, _2));
}