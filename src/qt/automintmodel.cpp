#include "../lelantus.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "automintmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "lelantusmodel.h"

#define WAITING_INCOMING_FUND_TIMEOUT 5 * 1000

IncomingFundNotifier::IncomingFundNotifier(
    CWallet *_wallet, QObject *parent) :
    QObject(parent), wallet(_wallet), timer(0), txs(4096)
{
    timer = new QTimer(this);

    connect(timer,
        SIGNAL(timeout()),
        this,
        SLOT(check()),
        Qt::QueuedConnection);

    timer->start(MODEL_UPDATE_DELAY);

    connect(this,
        SIGNAL(push(uint256)),
        this,
        SLOT(pushTransaction(uint256)),
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

void IncomingFundNotifier::pushTransaction(uint256 const &id)
{
    updateWaitUntil();
    txs.push(id);
}

void IncomingFundNotifier::check()
{
    if (QDateTime::currentDateTimeUtc() >= waitUntil || txs.empty()) {
        return;
    }

    CAmount credit = 0;
    std::vector<uint256> immutures;

    {
        LOCK2(cs_main, wallet->cs_wallet);
        uint256 tx;
        while (txs.pop(tx)) {
            auto wtx = wallet->mapWallet.find(tx);
            if (wtx == wallet->mapWallet.end()) {
                continue;
            }

            credit += (wtx->second.GetAvailableCredit()
                - wtx->second.GetDebit(ISMINE_ALL)) > 0;

            if (wtx->second.GetImmatureCredit() > 0) {
                immutures.push_back(tx);
            }
        }
    }

    for (auto const &tx : immutures) {
        txs.push(tx);
    }

    Q_EMIT matureFund(credit);
}

void IncomingFundNotifier::importTransactions()
{
    LOCK2(cs_main, wallet->cs_wallet);

    for (auto const &tx : wallet->mapWallet) {
        pushTransaction(tx.first);
    }
}

void IncomingFundNotifier::updateWaitUntil()
{
    waitUntil = QDateTime::currentDateTimeUtc().addMSecs(WAITING_INCOMING_FUND_TIMEOUT);
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

void IncomingFundNotifier::subscribeToCoreSignals()
{
    wallet->NotifyTransactionChanged.connect(boost::bind(
        NotifyTransactionChanged, this, _1, _2, _3));
}

void IncomingFundNotifier::unsubscribeFromCoreSignals()
{
    wallet->NotifyTransactionChanged.disconnect(boost::bind(
        NotifyTransactionChanged, this, _1, _2, _3));
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
    resetInitialSyncTimer(0),
    autoMintCheckTimer(0),
    initialSync(false),
    force(false),
    notifier(0)
{
    resetInitialSyncTimer = new QTimer(this);
    resetInitialSyncTimer->setSingleShot(true);

    autoMintCheckTimer = new QTimer(this);
    autoMintCheckTimer->setSingleShot(false);

    notifier = new IncomingFundNotifier(wallet, this);

    connect(resetInitialSyncTimer, SIGNAL(timeout()), this, SLOT(resetInitialSync()));
    connect(autoMintCheckTimer, SIGNAL(timeout()), this, SLOT(checkAutoMint()));

    connect(notifier, SIGNAL(matureFund(CAmount)), this, SLOT(startAutoMint()));

    connect(optionsModel,
        SIGNAL(autoAnonymizeChanged(bool)),
        this,
        SLOT(updateAutoMintOption(bool)));

    subscribeToCoreSignals();
}

AutoMintModel::~AutoMintModel()
{
    unsubscribeFromCoreSignals();

    delete resetInitialSyncTimer;
    delete autoMintCheckTimer;

    resetInitialSyncTimer = nullptr;
    autoMintCheckTimer = nullptr;
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

void AutoMintModel::updateAutoMintOption(bool enabled)
{
    LOCK2(cs_main, wallet->cs_wallet);
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