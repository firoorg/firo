#include "../validation.h"

#include "guiconstants.h"
#include "guiutil.h"
#include "lelantusmodel.h"

#include <QDateTime>
#include <QTimer>

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
    checkPendingTxTimer = new QTimer(this);
    checkPendingTxTimer->setSingleShot(true);

    QTimer::singleShot(20 * 1000, this, SLOT(start()));

    connect(checkPendingTxTimer, SIGNAL(timeout()), this, SLOT(checkPendingTransactions()));

    subscribeToCoreSignals();
}

LelantusModel::~LelantusModel()
{
    delete checkPendingTxTimer;

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
    CAmount mintable = 0;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        mintable = getMintableAmount();
    }

    if (mintable > 0) {
        autoMintState = AutoMintState::WaitingUserToActivate;
        checkAutoMint();
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void LelantusModel::unlockWallet(SecureString const &passphase, size_t msecs)
{
    LOCK2(wallet->cs_wallet, cs);
    wallet->Unlock(passphase);

    QTimer::singleShot(msecs, this, SLOT(lock()));
}

void LelantusModel::lockWallet()
{
    LOCK2(wallet->cs_wallet, cs);
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

    checkPendingTxTimer->start(WaitingTime);
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

    askUserToMint();
}

void LelantusModel::askUserToMint()
{
    Q_EMIT askMintAll();
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
        hasNew |= wtx.GetAvailableCredit() > 0;

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
    checkAutoMint();
}

void LelantusModel::start()
{
    setupAutoMint();
}

void LelantusModel::ackMintAll(AutoMintAck ack, CAmount minted, QString error)
{
    LOCK(cs);
    if (ack == AutoMintAck::WaitUserToActive) {
        autoMintState = AutoMintState::WaitingUserToActivate;
        QTimer::singleShot(MODEL_UPDATE_DELAY, this, SLOT(askUserToMint()));
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void LelantusModel::lock()
{
    LOCK2(wallet->cs_wallet, cs);
    if (autoMintState == AutoMintState::WaitingForUserResponse) {
        QTimer::singleShot(MODEL_UPDATE_DELAY, this, SLOT(lock()));
        return;
    }

    if (wallet->IsCrypted() && !wallet->IsLocked()) {
        lockWallet();
    }
}
