#include "../lelantus.h"
#include "../validation.h"

#include "automintmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "lelantusmodel.h"

#include <QDateTime>
#include <QTimer>

LelantusModel::LelantusModel(
    const PlatformStyle *platformStyle,
    CWallet *wallet,
    OptionsModel *optionsModel,
    QObject *parent)
    : QObject(parent),
    wallet(wallet)
{
    autoMintModel = new AutoMintModel(this, optionsModel, wallet, this);

    subscribeToCoreSignals();
}

LelantusModel::~LelantusModel()
{
    unsubscribeFromCoreSignals();

    delete autoMintModel;

    autoMintModel = nullptr;
}

void LelantusModel::askToMint()
{
    autoMintModel->userAskToMint();
}

CAmount LelantusModel::getMintableAmount()
{
    std::vector<std::pair<CAmount, std::vector<COutput>>> valueAndUTXO;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        pwalletMain->AvailableCoinsForLMint(valueAndUTXO, nullptr);
    }

    CAmount s = 0;
    for (auto const &val : valueAndUTXO) {
        s += val.first;
    }

    return s;
}

std::pair<CAmount, CAmount> LelantusModel::getPrivateBalance()
{
    size_t confirmed, unconfirmed;
    return getPrivateBalance(confirmed, unconfirmed);
}

std::pair<CAmount, CAmount> LelantusModel::getPrivateBalance(size_t &confirmed, size_t &unconfirmed)
{
    if (cached) {
        confirmed = this->confirmed;
        unconfirmed = this->unconfirmed;

        return {confirmedBalance, unconfirmedBalance};
    }

    confirmed = 0;
    unconfirmed = 0;
    confirmedBalance = 0;
    unconfirmedBalance = 0;

    auto zwallet = pwalletMain->zwallet.get();

    auto coins = zwallet->GetTracker().ListLelantusMints(true, false, false);
    for (auto const &c : coins) {

        if (c.isUsed || c.isArchived || !c.isSeedCorrect) {
            continue;
        }

        auto conf = c.nHeight > 0
            ? chainActive.Height() - c.nHeight + 1 : 0;

        if (conf >= ZC_MINT_CONFIRMATIONS) {
            confirmed++;
            confirmedBalance += c.amount;
        } else {
            unconfirmed++;
            unconfirmedBalance += c.amount;
        }
    }

    auto sigmaCoins = zwallet->GetTracker().ListMints(true, false, false);
    for (auto const &c : sigmaCoins) {

        if (c.isUsed || c.isArchived || !c.isSeedCorrect) {
            continue;
        }

        CAmount amount;
        if (!sigma::DenominationToInteger(c.denom, amount)) {
            throw std::runtime_error("Fail to get denomination value");
        }

        auto conf = c.nHeight > 0
            ? chainActive.Height() - c.nHeight + 1 : 0;

        if (conf >= ZC_MINT_CONFIRMATIONS) {
            confirmed++;
            confirmedBalance += amount;
        } else {
            unconfirmed++;
            unconfirmedBalance += amount;
        }
    }

    this->confirmed = confirmed;
    this->unconfirmed = unconfirmed;

    cached.store(true);

    return {confirmedBalance, unconfirmedBalance};
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
    LOCK(wallet->cs_wallet);

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

void LelantusModel::askUserToMint(bool userAsk)
{
    Q_EMIT askMintAll(userAsk);
}

void LelantusModel::ackMintAll(AutoMintAck ack, CAmount minted, QString error)
{
    autoMintModel->ackMintAll(ack, minted, error);
}

void LelantusModel::lock()
{
    LOCK2(wallet->cs_wallet, cs);
    if (autoMintModel->askingUser()) {
        QTimer::singleShot(MODEL_UPDATE_DELAY, this, SLOT(lock()));
        return;
    }

    if (wallet->IsCrypted() && !wallet->IsLocked()) {
        lockWallet();
    }
}

void LelantusModel::resetCached()
{
    cached.store(false);
}

static void NotifyZerocoinChanged(LelantusModel *model, CWallet *wallet, const std::string &pubCoin, const std::string &isUsed, ChangeType status)
{
    Q_UNUSED(pubCoin);
    Q_UNUSED(isUsed);
    Q_UNUSED(status);

    if (wallet->zwallet) {
        QMetaObject::invokeMethod(
            model,
            "resetCached",
            Qt::QueuedConnection);
    }
}

static void NotifyBlockTip(LelantusModel *model, bool initialSync, const CBlockIndex *pIndex)
{
    Q_UNUSED(pIndex);
    Q_UNUSED(initialSync);
    QMetaObject::invokeMethod(
        model,
        "resetCached",
        Qt::QueuedConnection);
}

void LelantusModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyZerocoinChanged.connect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));

    uiInterface.NotifyBlockTip.connect(boost::bind(NotifyBlockTip, this, _1, _2));
}

void LelantusModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyZerocoinChanged.disconnect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));

    uiInterface.NotifyBlockTip.disconnect(boost::bind(NotifyBlockTip, this, _1, _2));
}
