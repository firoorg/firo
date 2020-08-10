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

    std::pair<CAmount, CAmount> getPrivateBalance(bool includeSigma = true);
    std::pair<CAmount, CAmount> getPrivateBalance(size_t &confirmed, size_t &unconfirmed, bool includeSigma = true);

    void unlockWallet(SecureString const &passphase, size_t msecs);
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

private:
    AutoMintModel *autoMintModel;
    CWallet *wallet;
};

#endif // ZCOIN_QT_LELANTUSMODEL_H