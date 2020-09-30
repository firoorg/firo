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
    autoMintModel(0),
    wallet(wallet)
{
    autoMintModel = new AutoMintModel(this, optionsModel, wallet, this);
}

LelantusModel::~LelantusModel()
{
    delete autoMintModel;

    autoMintModel = nullptr;
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

AutoMintModel* LelantusModel::getAutoMintModel()
{
    return autoMintModel;
}

std::pair<CAmount, CAmount> LelantusModel::getPrivateBalance()
{
    size_t confirmed, unconfirmed;
    return getPrivateBalance(confirmed, unconfirmed);
}

std::pair<CAmount, CAmount> LelantusModel::getPrivateBalance(size_t &confirmed, size_t &unconfirmed)
{
    std::pair<CAmount, CAmount> balance = {0, 0};

    confirmed = 0;
    unconfirmed = 0;

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
            balance.first += c.amount;
        } else {
            unconfirmed++;
            balance.second += c.amount;
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
            balance.first += amount;
        } else {
            unconfirmed++;
            balance.second += amount;
        }
    }

    return balance;
}

bool LelantusModel::unlockWallet(SecureString const &passphase, size_t msecs)
{
    LOCK2(wallet->cs_wallet, cs);
    if (!wallet->Unlock(passphase)) {
        return false;
    }

    QTimer::singleShot(msecs, this, SLOT(lock()));
    return true;
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

void LelantusModel::mintAll(AutoMintMode mode)
{
    Q_EMIT askMintAll(mode);
}

void LelantusModel::notifyUserToMint()
{
    Q_EMIT notifyAutomint();
}

void LelantusModel::ackMintAll(AutoMintAck ack, CAmount minted, QString error)
{
    autoMintModel->ackMintAll(ack, minted, error);
    if (ack == AutoMintAck::AskToMint) {
        mintAll(AutoMintMode::AutoMintAll);
    }
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
