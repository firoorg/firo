#include "../validation.h"

#include "guiconstants.h"
#include "guiutil.h"
#include "lelantusmodel.h"

#include <QDateTime>
#include <QTimer>

#define POLLING_TIMEOUT 1000

// Handlers for core signals
static void NotifyTransactionChanged(
    LelantusModel *model, CWallet *wallet, uint256 const &hash, ChangeType status)
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

LelantusModel::LelantusModel(
    const PlatformStyle *platformStyle,
    CWallet *wallet,
    OptionsModel *optionsModel,
    QObject *parent)
    : QObject(parent),
    wallet(wallet),
    optionsModel(optionsModel)
{
    pollTimer = new QTimer(this);
    checkPendingTxTimer = new QTimer(this);

    QTimer::singleShot(20 * 1000, this, SLOT(start()));

    connect(pollTimer, SIGNAL(timeout()), this, SLOT(checkAutoMint()));
    connect(checkPendingTxTimer, SIGNAL(timeout()), this, SLOT(checkPendingTransactions()));

    subscribeToCoreSignals();
}

LelantusModel::~LelantusModel()
{
    delete pollTimer;
    delete checkPendingTxTimer;

    pollTimer = nullptr;
    checkPendingTxTimer = nullptr;

    unsubscribeFromCoreSignals();
}

OptionsModel* LelantusModel::getOptionsModel()
{
    return optionsModel;
}

void LelantusModel::subscribeToCoreSignals()
{
    wallet->NotifyTransactionChanged.connect(
        boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

void LelantusModel::unsubscribeFromCoreSignals()
{
    wallet->NotifyTransactionChanged.disconnect(
        boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

CAmount LelantusModel::getMintableAmount()
{
    std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->AvailableCoinsForLMint(valueAndUTXO, nullptr);
    }

    CAmount s = 0;
    for (auto const &val : valueAndUTXO) {
        s += val.first;
    }

    return s;
}

void LelantusModel::setupAutoMint()
{
    CAmount mintable = 0, immature;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        mintable = getMintableAmount();
        immature = wallet->GetImmatureBalance();
    }

    if (mintable > 0 || immature > 0) {
        autoMintState = AutoMintState::WaitingUserToActivate;
        startAutoMint();
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void LelantusModel::startAutoMint()
{
    LOCK(cs);
    pollTimer->start(MODEL_UPDATE_DELAY);
}

void LelantusModel::stopAutoMint()
{
    LOCK(cs);
    pollTimer->stop();
}

void LelantusModel::unlockWallet(SecureString const &passphase, size_t secs)
{
    LOCK(wallet->cs_wallet);
    wallet->Unlock(passphase);
}

void LelantusModel::lockWallet()
{
    LOCK(wallet->cs_wallet);
    wallet->Lock();
}

CAmount LelantusModel::mintAll()
{
    LOCK2(cs_main, wallet->cs_wallet);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<CHDMint> hdMints;

    auto str = wallet->MintAndStoreLelantus(0, wtxAndFee, hdMints, true);
    if (str != "") {
        throw std::runtime_error("Fail to mint all public balance, " + str);
    }

    CAmount s = 0;
    for (auto const &wtx : wtxAndFee) {
        for (auto const &out : wtx.first.tx->vout) {
            if (out.scriptPubKey.IsLelantusMint()) {
                s += out.nValue;
            }
        }
    }

    return s;
}

void LelantusModel::updateTransaction(uint256 hash)
{
    LOCK(cs);

    checkPendingTxTimer->stop();
    checkPendingTxTimer->setSingleShot(true);

    pendingTransactions.push_back(hash);

    checkPendingTxTimer->start(10 * 1000);
}

void LelantusModel::checkAutoMint()
{
    {
        LOCK(cs);

        if (fReindex) {
            return;
        }

        switch (autoMintState) {
        case AutoMintState::Disabled:
        case AutoMintState::WaitingIncomingFund:
            stopAutoMint();
            return;
        case AutoMintState::WaitingUserToActivate:
            // check activation status
            break;
        case AutoMintState::WaitingForUserResponse:
            return;
        default:
            throw std::runtime_error("Unknown auto mint state");
        }

        if (disableAutoMintUntil.isValid() &&
            QDateTime::currentDateTime() < disableAutoMintUntil) {
            return;
        }

        autoMintState = AutoMintState::WaitingForUserResponse;
        stopAutoMint();
    }
    Q_EMIT askUserToMint();
}

void LelantusModel::checkPendingTransactions()
{
    LOCK2(cs_main, wallet->cs_wallet);
    LOCK(cs);

    auto hasNew = false;
    for (auto const &tx : pendingTransactions) {
        if (!wallet->mapWallet.count(tx)) {
            continue;
        }

        auto const &wtx = wallet->mapWallet[tx];
        hasNew |= wtx.GetAvailableCredit() > 0 || wtx.GetImmatureCredit() > 0;

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

void LelantusModel::start()
{
    setupAutoMint();
}