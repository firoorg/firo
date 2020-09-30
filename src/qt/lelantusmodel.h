#ifndef ZCOIN_QT_LELANTUSMODEL_H
#define ZCOIN_QT_LELANTUSMODEL_H

#include "automintdialog.h"
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
    CAmount getMintableAmount();
    AutoMintModel* getAutoMintModel();

    std::pair<CAmount, CAmount> getPrivateBalance();
    std::pair<CAmount, CAmount> getPrivateBalance(size_t &confirmed, size_t &unconfirmed);

    bool unlockWallet(SecureString const &passphase, size_t msecs);
    void lockWallet();

    CAmount mintAll();

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askMintAll(AutoMintMode);
    void notifyAutomint();

public Q_SLOTS:
    void ackMintAll(AutoMintAck ack, CAmount minted = 0, QString error = QString(""));

    void mintAll(AutoMintMode);
    void notifyUserToMint();

    void lock();

private:
    AutoMintModel *autoMintModel;
    CWallet *wallet;
};

#endif // ZCOIN_QT_LELANTUSMODEL_H