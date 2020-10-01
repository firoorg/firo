#include "../lelantus.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "automintmodel.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "lelantusmodel.h"

IncomingFundNotifier::IncomingFundNotifier(
    CWallet *_wallet, QObject *parent) :
    QObject(parent), wallet(_wallet), timer(0)
{
    timer = new QTimer(this);
    timer->setSingleShot(true);

    connect(timer,
        SIGNAL(timeout()),
        this,
        SLOT(check()),
        Qt::QueuedConnection);

    importTransactions();
    subscribeToCoreSignals();
}

IncomingFundNotifier::~IncomingFundNotifier()
{
    unsubscribeFromCoreSignals();

    delete timer;

    timer = nullptr;
}

void IncomingFundNotifier::newBlock()
{
    LOCK(cs);

    if (!txs.empty()) {
        resetTimer();
    }
}

void IncomingFundNotifier::pushTransaction(uint256 const &id)
{
    LOCK(cs);

    txs.push_back(id);
    resetTimer();
}

void IncomingFundNotifier::check()
{
    LOCK(cs);

    if (txs.empty()) {
        return;
    }

    CAmount credit = 0;
    std::vector<uint256> immatures;

    {
        LOCK2(cs_main, wallet->cs_wallet);
        while (!txs.empty()) {
            auto const &tx = txs.back();
            txs.pop_back();

            auto wtx = wallet->mapWallet.find(tx);
            if (wtx == wallet->mapWallet.end()) {
                continue;
            }

            credit += std::max(CAmount(0), wtx->second.GetAvailableCredit() - wtx->second.GetDebit(ISMINE_ALL));

            if (wtx->second.GetImmatureCredit() > 0) {
                immatures.push_back(tx);
            }
        }
    }

    for (auto const &tx : immatures) {
        txs.push_back(tx);
    }

    if (credit > 0) {
        Q_EMIT matureFund(credit);
    }
}

void IncomingFundNotifier::importTransactions()
{
    LOCK(cs);
    LOCK2(cs_main, wallet->cs_wallet);

    for (auto const &tx : wallet->mapWallet) {
        if (tx.second.GetAvailableCredit() > 0 || tx.second.GetImmatureCredit() > 0) {
            txs.push_back(tx.first);
        }
    }

    resetTimer();
}

void IncomingFundNotifier::resetTimer()
{
    timer->stop();
    timer->start(1000);
}

// Handlers for core signals
static void NotifyTransactionChanged(
    IncomingFundNotifier *model, CWallet *wallet, uint256 const &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(status);
    if (status == ChangeType::CT_NEW || status == ChangeType::CT_UPDATED) {
        QMetaObject::invokeMethod(
            model,
            "pushTransaction",
            Qt::QueuedConnection,
            Q_ARG(uint256, hash));
    }
}

static void IncomingFundNotifyBlockTip(
    IncomingFundNotifier *model, bool initialSync, const CBlockIndex *pIndex)
{
    Q_UNUSED(initialSync);
    Q_UNUSED(pIndex);
    QMetaObject::invokeMethod(
        model,
        "newBlock",
        Qt::QueuedConnection);
}

void IncomingFundNotifier::subscribeToCoreSignals()
{
    wallet->NotifyTransactionChanged.connect(boost::bind(
        NotifyTransactionChanged, this, _1, _2, _3));

    uiInterface.NotifyBlockTip.connect(
        boost::bind(IncomingFundNotifyBlockTip, this, _1, _2));
}

void IncomingFundNotifier::unsubscribeFromCoreSignals()
{
    wallet->NotifyTransactionChanged.disconnect(boost::bind(
        NotifyTransactionChanged, this, _1, _2, _3));

    uiInterface.NotifyBlockTip.disconnect(
        boost::bind(IncomingFundNotifyBlockTip, this, _1, _2));
}

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
    resetSyncingTimer(0),
    autoMintCheckTimer(0),
    syncing(false),
    notifier(0)
{
    resetSyncingTimer = new QTimer(this);
    resetSyncingTimer->setSingleShot(true);

    autoMintCheckTimer = new QTimer(this);
    autoMintCheckTimer->setSingleShot(false);

    connect(resetSyncingTimer, SIGNAL(timeout()), this, SLOT(resetSyncing()));
    connect(autoMintCheckTimer, SIGNAL(timeout()), this, SLOT(checkAutoMint()));

    notifier = new IncomingFundNotifier(wallet, this);

    connect(notifier, SIGNAL(matureFund(CAmount)), this, SLOT(startAutoMint()));

    connect(optionsModel, SIGNAL(autoAnonymizeChanged(bool)), this, SLOT(updateAutoMintOption(bool)));

    subscribeToCoreSignals();
}

AutoMintModel::~AutoMintModel()
{
    unsubscribeFromCoreSignals();

    delete resetSyncingTimer;
    delete autoMintCheckTimer;

    resetSyncingTimer = nullptr;
    autoMintCheckTimer = nullptr;
}

bool AutoMintModel::isAnonymizing() const
{
    return autoMintState == AutoMintState::Anonymizing;
}

void AutoMintModel::ackMintAll(AutoMintAck ack, CAmount minted, QString error)
{
    bool mint = false;
    {
        LOCK(lelantusModel->cs);
        if (autoMintState == AutoMintState::Disabled) {
            // Do nothing
            return;
        } else if (ack == AutoMintAck::WaitUserToActive) {
            autoMintState = AutoMintState::WaitingUserToActivate;
        } else if (ack == AutoMintAck::AskToMint) {
            autoMintState = AutoMintState::Anonymizing;
            autoMintCheckTimer->stop();
            mint = true;
        } else {
            autoMintState = AutoMintState::WaitingIncomingFund;
            autoMintCheckTimer->stop();
        }

        processAutoMintAck(ack, minted, error);
    }

    if (mint) {
        lelantusModel->mintAll(AutoMintMode::AutoMintAll);
    }
}

void AutoMintModel::checkAutoMint(bool force)
{
    // if lelantus is not allow or client is in initial syncing state then wait
    // except user force to check
    if (!force) {
        // check syncing first to reduce main locking
        if (syncing) {
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
            break;
        case AutoMintState::Anonymizing:
            return;
        default:
            throw std::runtime_error("Unknown auto mint state");
        }

        autoMintState = AutoMintState::Anonymizing;
    }

    Q_EMIT requireShowAutomintNotification();
}

void AutoMintModel::setSyncing()
{
    syncing.store(true);
    resetSyncingTimer->stop();

    // wait 2.5 seconds if there are no new signal then reset flag
    resetSyncingTimer->start(2500);
}

void AutoMintModel::resetSyncing()
{
    syncing.store(false);
}

void AutoMintModel::startAutoMint()
{
    if (autoMintCheckTimer->isActive()) {
        return;
    }

    if (!optionsModel->getAutoAnonymize()) {
        return;
    }

    CAmount mintable = 0;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        mintable = lelantusModel->getMintableAmount();
    }

    if (mintable > 0) {
        autoMintState = AutoMintState::WaitingUserToActivate;

        autoMintCheckTimer->start(MODEL_UPDATE_DELAY);
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void AutoMintModel::updateAutoMintOption(bool enabled)
{
    LOCK2(cs_main, wallet->cs_wallet);
    LOCK(lelantusModel->cs);

    if (enabled) {
        if (autoMintState == AutoMintState::Disabled) {
            startAutoMint();
        }
    } else {
        if (autoMintCheckTimer->isActive()) {
            autoMintCheckTimer->stop();
        }

        // stop mint
        autoMintState = AutoMintState::Disabled;

        Q_EMIT closeAutomintNotification();
    }
}

// Handlers for core signals
static void NotifyBlockTip(AutoMintModel *model, bool initialSync, const CBlockIndex *pIndex)
{
    Q_UNUSED(pIndex);
    Q_UNUSED(initialSync);
    QMetaObject::invokeMethod(
        model,
        "setSyncing",
        Qt::QueuedConnection);
}

void AutoMintModel::subscribeToCoreSignals()
{
    uiInterface.NotifyBlockTip.connect(
        boost::bind(NotifyBlockTip, this, _1, _2));
}

void AutoMintModel::unsubscribeFromCoreSignals()
{
    uiInterface.NotifyBlockTip.disconnect(
        boost::bind(NotifyBlockTip, this, _1, _2));
}

void AutoMintModel::processAutoMintAck(AutoMintAck ack, CAmount minted, QString error)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    msgParams.second = CClientUIInterface::MSG_WARNING;

    switch (ack)
    {
    case AutoMintAck::Success:
        msgParams.first = tr("Successfully anonymized %1")
            .arg(BitcoinUnits::formatWithUnit(optionsModel->getDisplayUnit(), minted));
        msgParams.second = CClientUIInterface::MSG_INFORMATION;
        break;
    case AutoMintAck::WaitUserToActive:
    case AutoMintAck::NotEnoughFund:
        return;
    case AutoMintAck::FailToMint:
        msgParams.first = tr("Fail to mint, %1").arg(error);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case AutoMintAck::FailToUnlock:
        msgParams.first = tr("Fail to unlock wallet");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    default:
        return;
    };

    Q_EMIT message(tr("Auto Anonymize"), msgParams.first, msgParams.second);
}