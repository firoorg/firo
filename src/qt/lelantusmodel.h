#ifndef ZCOIN_QT_LELANTUSMODEL_H
#define ZCOIN_QT_LELANTUSMODEL_H

#include "automintmodel.h"
#include "platformstyle.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QObject>

class LelantusModel : public QObject
{
    Q_OBJECT;

public:
    explicit LelantusModel(
        const PlatformStyle *platformStyle,
        CWallet *wallet,
        OptionsModel *optionsModel,
        QObject *parent = 0);

    ~LelantusModel();

public:
    void askToMint();
    CAmount getMintableAmount();
    AutoMintModel* getAutoMintModel();

    std::pair<CAmount, CAmount> getPrivateBalance();
    std::pair<CAmount, CAmount> getPrivateBalance(size_t &confirmed, size_t &unconfirmed);

    bool unlockWallet(SecureString const &passphase, size_t msecs);
    void lockWallet();

    CAmount mintAll();

    void ackMintAll(AutoMintAck ack, CAmount minted = 0, QString error = QString(""));

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askMintAll(bool userAsk);

public Q_SLOTS:
    void askUserToMint(bool userAsk = false);
    void lock();

    void resetCached();

private:
    std::atomic<bool> cached;
    size_t confirmed;
    size_t unconfirmed;
    CAmount confirmedBalance;
    CAmount unconfirmedBalance;

    AutoMintModel *autoMintModel;
    CWallet *wallet;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
};

#endif // ZCOIN_QT_LELANTUSMODEL_H