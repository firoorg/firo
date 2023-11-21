#ifndef FIRO_QT_SPARKMODEL_H
#define FIRO_QT_SPARKMODEL_H

#include "automintdialog.h"
#include "automintmodel.h"
#include "platformstyle.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QObject>


class SparkModel : public QObject
{
    Q_OBJECT;

public:
    explicit SparkModel(
        const PlatformStyle *platformStyle,
        CWallet *wallet,
        OptionsModel *optionsModel,
        QObject *parent = 0);

    ~SparkModel();

public:
    CAmount getMintableSparkAmount();
    AutoMintSparkModel* getAutoMintSparkModel();

    std::pair<CAmount, CAmount> getSparkBalance();

    bool unlockSparkWallet(SecureString const &passphase, size_t msecs);
    void lockSparkWallet();

    CAmount mintSparkAll();

    void sendAckMintSparkAll(AutoMintSparkAck ack, CAmount minted = 0, QString error = QString());

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askMintSparkAll(AutoMintSparkMode);
    void ackMintSparkAll(AutoMintSparkAck ack, CAmount minted, QString error);

public Q_SLOTS:
    void mintSparkAll(AutoMintSparkMode);
    void lockSpark();

private:
    AutoMintSparkModel *autoMintSparkModel;
    CWallet *wallet;
};

#endif // FIRO_QT_SPARKMODEL_H