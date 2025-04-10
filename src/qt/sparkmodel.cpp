#include "../lelantus.h"
#include "../validation.h"

#include "automintmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "sparkmodel.h"

#include <QDateTime>
#include <QTimer>


SparkModel::SparkModel(
    const PlatformStyle *platformStyle,
    CWallet *wallet,
    OptionsModel *optionsModel,
    QObject *parent)
    : QObject(parent),
    autoMintSparkModel(0),
    wallet(wallet)
{
    autoMintSparkModel = new AutoMintSparkModel(this, optionsModel, wallet, this);

    connect(this, &SparkModel::ackMintSparkAll, autoMintSparkModel, &AutoMintSparkModel::ackMintSparkAll);
}

SparkModel::~SparkModel()
{
    disconnect(this, &SparkModel::ackMintSparkAll, autoMintSparkModel, &AutoMintSparkModel::ackMintSparkAll);

    delete autoMintSparkModel;

    autoMintSparkModel = nullptr;
}

CAmount SparkModel::getMintableSparkAmount()
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

AutoMintSparkModel* SparkModel::getAutoMintSparkModel()
{
    return autoMintSparkModel;
}

std::pair<CAmount, CAmount> SparkModel::getSparkBalance()
{
    __firo_unused size_t confirmed, unconfirmed;
    return pwalletMain->GetSparkBalance();
}

bool SparkModel::unlockSparkWallet(SecureString const &passphase, size_t msecs)
{
    LOCK2(wallet->cs_wallet, cs);
    if (!wallet->Unlock(passphase)) {
        return false;
    }

    QTimer::singleShot(msecs, this, &SparkModel::lockSpark);
    return true;
}

void SparkModel::lockSparkWallet()
{
    LOCK2(wallet->cs_wallet, cs);
    wallet->Lock();
}

CAmount SparkModel::mintSparkAll()
{
    LOCK(wallet->cs_wallet);

    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFee;
    std::vector<spark::MintedCoinData> outputs;
    std::string strError = wallet->MintAndStoreSpark(outputs, wtxAndFee, true, true, true);
    if (strError != "") {
        throw std::runtime_error("Fail to mint all public balance, " + strError);
    }

    CAmount s = 0;
    bool ok = true;
    for (auto const &wtx : wtxAndFee) {
        for (auto const &out : wtx.first.tx->vout) {
            spark::Coin coin(spark::Params::get_default());
            try {
                spark::ParseSparkMintCoin(out.scriptPubKey, coin);
            } catch (std::invalid_argument&) {
                ok = false;
            }
            if (ok) {
                CSparkMintMeta mintMeta;
                coin.setSerialContext(spark::getSerialContext(* wtx.first.tx));
                if (pwalletMain->sparkWallet->getMintMeta(coin, mintMeta)) {
                    s += mintMeta.v;
                }
            }
        }
    }

    return s;
}

void SparkModel::mintSparkAll(AutoMintSparkMode mode)
{
    Q_EMIT askMintSparkAll(mode);
}

void SparkModel::sendAckMintSparkAll(AutoMintSparkAck ack, CAmount minted, QString error)
{
    Q_EMIT ackMintSparkAll(ack, minted, error);
}

void SparkModel::lockSpark()
{
    LOCK2(wallet->cs_wallet, cs);
    if (autoMintSparkModel->isSparkAnonymizing()) {
        QTimer::singleShot(MODEL_UPDATE_DELAY, this, &SparkModel::lockSpark);
        return;
    }

    if (wallet->IsCrypted() && !wallet->IsLocked()) {
        lockSparkWallet();
    }
}
