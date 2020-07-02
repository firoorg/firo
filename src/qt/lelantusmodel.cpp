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
    pollTimer = new QTimer(this);
    QTimer::singleShot(30, this, SLOT(start()));

    subscribeToCoreSignals();
}

LelantusModel::~LelantusModel()
{
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
    CAmount mintable;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        mintable = getMintableAmount();
    }
    std::cout << "mintable : " << mintable << std::endl;

    connect(pollTimer, SIGNAL(timeout()), this, SLOT(checkAutoMint()));
    if (mintable > 0) {
        autoMintState = AutoMintState::WaitingUserToActivate;
        startAutoMint();
    } else {
        autoMintState = AutoMintState::WaitingIncomingFund;
    }
}

void LelantusModel::startAutoMint()
{
    LOCK(cs);
    pollTimer->start(1000);
}

void LelantusModel::resumeAutoMint(bool successToMint, QDateTime since)
{
    LOCK(cs);
    if (since.isValid()) {
        disableAutoMintUntil = since;
    }

    if (successToMint) {
        // success to mint then wait for new funds.
        autoMintState = AutoMintState::WaitingIncomingFund;
    } else {
        // fail to mint then wait user to back to screen and ask again.
        autoMintState = AutoMintState::WaitingUserToActivate;
    }

    pollTimer->start(1000);
}

void LelantusModel::stopAutoMint()
{
    LOCK(cs);
    pollTimer->stop();
}

CAmount LelantusModel::mintAll()
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    // TODO : dont use global
    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<CHDMint> hdMints;

    auto str = pwalletMain->MintAndStoreLelantus(0, wtxAndFee, hdMints, true);
}

void LelantusModel::updateTransaction(uint256 hash)
{
    {
        LOCK(cs);
        if (autoMintState == AutoMintState::Disabled) {
            return;
        }
    }

    bool newFund = false;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        if (!wallet->mapWallet.count(hash)) {
            return;
        }

        auto wtx = wallet->mapWallet[hash];
        newFund = wtx.GetAvailableCredit() > 0 || wtx.GetImmatureCredit() > 0;
    }

    if (!newFund) {
        return;
    }

    LOCK(cs);
    bool start = false;
    switch (autoMintState) {
    case AutoMintState::Disabled:
        return;
    case AutoMintState::WaitingUserToActivate:
    case AutoMintState::WaitingForUserResponse:
        break;
    case AutoMintState::WaitingIncomingFund:
        start = true;
        break;
    default:
        throw std::runtime_error("Unknown auto mint status");
    };

    auto t = QDateTime::currentDateTime();
    t = t.addSecs(10);
    if (!disableAutoMintUntil.isValid() || disableAutoMintUntil < t) {
        disableAutoMintUntil = t;
    }

    if (start) {
        autoMintState = AutoMintState::WaitingUserToActivate;
        startAutoMint();
    }
}

void LelantusModel::checkAutoMint()
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
    Q_EMIT askUserToMint();
}

void LelantusModel::start()
{
    setupAutoMint();
}