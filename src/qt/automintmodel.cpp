#include "../masternode-sync.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "automintmodel.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "sparkmodel.h"
#include "optionsmodel.h"

#include <boost/bind/bind.hpp>

IncomingFundNotifier::IncomingFundNotifier(
    CWallet *_wallet, QObject *parent) :
    QObject(parent), wallet(_wallet), timer(0), lastUpdateTime(0)
{
    timer = new QTimer(this);
    timer->setSingleShot(true);

    connect(timer, &QTimer::timeout, this, &IncomingFundNotifier::check, Qt::QueuedConnection);

    autoMintEnable = false;
    QMetaObject::invokeMethod(this, "importTransactions", Qt::QueuedConnection);
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

void IncomingFundNotifier::updateState(bool flag) {
    LOCK(cs);
    autoMintEnable = flag;
}

void IncomingFundNotifier::pushTransaction(uint256 const &id)
{
    LOCK(cs);
    txs.push_back(id);
    resetTimer();
}

void IncomingFundNotifier::check()
{
    CAmount credit = 0;
    std::vector<uint256> immatures;

    {
        TRY_LOCK(cs_main,lock_main);
        if (!lock_main)
            return;
        TRY_LOCK(cs, lock);
        if(!lock)
            return;
        TRY_LOCK(wallet->cs_wallet,lock_wallet);
        if (!lock_wallet)
            return;

        if (!autoMintEnable) {
            return;
        }

        // update only if there are transaction and last update was done more than 2 minutes ago, and in case it is first time
        if (txs.empty() || (lastUpdateTime!= 0 && (GetSystemTimeInSeconds() - lastUpdateTime <= 120))) {
            return;
        }
        lastUpdateTime = GetSystemTimeInSeconds();
        CCoinControl coinControl;
        coinControl.nCoinType = CoinType::ONLY_NOT1000IFMN;
        while (!txs.empty()) {
            auto const &tx = txs.back();
            txs.pop_back();

            auto wtx = wallet->mapWallet.find(tx);
            if (wtx == wallet->mapWallet.end()) {
                continue;
            }

            for (uint32_t i = 0; i != wtx->second.tx->vout.size(); i++) {
                coinControl.Select({wtx->first, i});
            }

            if (wtx->second.GetImmatureCredit() > 0) {
                immatures.push_back(tx);
            }
        }

        credit = pwalletMain->GetBalance(true);
        for (auto const &tx : immatures) {
            txs.push_back(tx);
        }
        if (credit > 0) {
            Q_EMIT matureFund(credit);
        }
    }
}

void IncomingFundNotifier::importTransactions()
{
    LOCK2(cs_main, cs);
    LOCK(wallet->cs_wallet);

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

AutoMintSparkModel::AutoMintSparkModel(
    SparkModel *_sparkModel,
    OptionsModel *_optionsModel,
    CWallet *_wallet,
    QObject *parent) :
    QObject(parent),
    sparkModel(_sparkModel),
    optionsModel(_optionsModel),
    wallet(_wallet),
    autoMintSparkState(AutoMintSparkState::Disabled),
    autoMintSparkCheckTimer(0),
    notifier(0)
{
    autoMintSparkCheckTimer = new QTimer(this);
    autoMintSparkCheckTimer->setSingleShot(false);

    connect(autoMintSparkCheckTimer, &QTimer::timeout, [this]{ checkAutoMintSpark(); });

    notifier = new IncomingFundNotifier(wallet, this);
    notifier->updateState(optionsModel->getAutoAnonymize());

    connect(notifier, &IncomingFundNotifier::matureFund, this, &AutoMintSparkModel::startAutoMintSpark);

    connect(optionsModel, &OptionsModel::autoAnonymizeChanged, this, &AutoMintSparkModel::updateAutoMintSparkOption);
}

AutoMintSparkModel::~AutoMintSparkModel()
{
    delete autoMintSparkCheckTimer;

    autoMintSparkCheckTimer = nullptr;
}

bool AutoMintSparkModel::isSparkAnonymizing() const
{
    return autoMintSparkState == AutoMintSparkState::Anonymizing;
}

void AutoMintSparkModel::ackMintSparkAll(AutoMintSparkAck ack, CAmount minted, QString error)
{
    bool mint = false;
    {
        TRY_LOCK(sparkModel->cs, lock);
        if(!lock)
            return;
        if (autoMintSparkState == AutoMintSparkState::Disabled) {
            // Do nothing
            return;
        } else if (ack == AutoMintSparkAck::WaitUserToActive) {
            autoMintSparkState = AutoMintSparkState::WaitingUserToActivate;
        } else if (ack == AutoMintSparkAck::AskToMint) {
            autoMintSparkState = AutoMintSparkState::Anonymizing;
            autoMintSparkCheckTimer->stop();
            mint = true;
        } else {
            autoMintSparkState = AutoMintSparkState::WaitingIncomingFund;
            autoMintSparkCheckTimer->stop();
        }

        processAutoMintSparkAck(ack, minted, error);
    }

    if (mint) {
        sparkModel->mintSparkAll(AutoMintSparkMode::AutoMintAll);
    }
}

void AutoMintSparkModel::checkAutoMintSpark(bool force)
{
    if (!force) {
        if (!masternodeSync.IsBlockchainSynced()) {
            return;
        }

        bool allowed = spark::IsSparkAllowed();
        if (!allowed) {
            return;
        }
    }

    {
        TRY_LOCK(sparkModel->cs, lock);
        if(!lock)
            return;

        if (fReindex) {
            return;
        }

        switch (autoMintSparkState) {
        case AutoMintSparkState::Disabled:
        case AutoMintSparkState::WaitingIncomingFund:
            if (force) {
                break;
            }
            autoMintSparkCheckTimer->stop();
            return;
        case AutoMintSparkState::WaitingUserToActivate:
            break;
        case AutoMintSparkState::Anonymizing:
            return;
        default:
            throw std::runtime_error("Unknown auto mint state");
        }

        autoMintSparkState = AutoMintSparkState::Anonymizing;
    }

    Q_EMIT requireShowAutomintSparkNotification();
}

void AutoMintSparkModel::startAutoMintSpark()
{
    if (autoMintSparkCheckTimer->isActive()) {
        return;
    }

    if (!optionsModel->getAutoAnonymize()) {
        return;
    }

    CAmount mintable = 0;
    {
        TRY_LOCK(cs_main,lock_main);
        if (!lock_main)
            return;
        TRY_LOCK(wallet->cs_wallet,lock_wallet);
        if (!lock_wallet)
            return;
        mintable = sparkModel->getMintableSparkAmount();
    }

    if (mintable > 0) {
        autoMintSparkState = AutoMintSparkState::WaitingUserToActivate;

        autoMintSparkCheckTimer->start(MODEL_UPDATE_DELAY);
    } else {
        autoMintSparkState = AutoMintSparkState::WaitingIncomingFund;
    }
}

void AutoMintSparkModel::updateAutoMintSparkOption(bool enabled)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;
    TRY_LOCK(sparkModel->cs, lock);
    if (!lock)
        return;

    notifier->updateState(enabled);

    if (enabled) {
        if (autoMintSparkState == AutoMintSparkState::Disabled) {
            startAutoMintSpark();
        }
    } else {
        if (autoMintSparkCheckTimer->isActive()) {
            autoMintSparkCheckTimer->stop();
        }

        // stop mint
        autoMintSparkState = AutoMintSparkState::Disabled;

        Q_EMIT closeAutomintSparkNotification();
    }
}

void AutoMintSparkModel::processAutoMintSparkAck(AutoMintSparkAck ack, CAmount minted, QString error)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    msgParams.second = CClientUIInterface::MSG_WARNING;

    switch (ack)
    {
    case AutoMintSparkAck::Success:
        msgParams.first = tr("Successfully anonymized %1")
            .arg(BitcoinUnits::formatWithUnit(optionsModel->getDisplayUnit(), minted));
        msgParams.second = CClientUIInterface::MSG_INFORMATION;
        break;
    case AutoMintSparkAck::WaitUserToActive:
    case AutoMintSparkAck::NotEnoughFund:
        return;
    case AutoMintSparkAck::FailToMint:
        msgParams.first = tr("Fail to mint, %1").arg(error);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case AutoMintSparkAck::FailToUnlock:
        msgParams.first = tr("Fail to unlock wallet");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    default:
        return;
    };

    Q_EMIT message(tr("Auto Anonymize"), msgParams.first, msgParams.second);
}