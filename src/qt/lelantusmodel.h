#ifndef ZCOIN_QT_LELANTUSMODEL_H
#define ZCOIN_QT_LELANTUSMODEL_H

#include "platformstyle.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QObject>

enum class AutoMintState : uint8_t {
    Disabled,
    WaitingIncomingFund,
    WaitingUserToActivate,
    WaitingForUserResponse
};

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
    mutable CCriticalSection cs;
    OptionsModel *getOptionsModel();
    CAmount getMintableAmount();

    void startAutoMint();
    void resumeAutoMint(
        bool successToMint,
        QDateTime until = QDateTime());

    void stopAutoMint();
    void unlockWallet(SecureString const &passphase, size_t secs);
    void lockWallet();

    CAmount mintAll();

private:
    OptionsModel *optionsModel;

    CWallet *wallet;

    QTimer *pollTimer;
    QTimer *startTimer;

    AutoMintState autoMintState = AutoMintState::Disabled;
    QDateTime disableAutoMintUntil;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void setupAutoMint();

Q_SIGNALS:
    void askUserToMint();

public Q_SLOTS:
    void checkAutoMint();

    void updateTransaction(uint256 hash);
    void start();
};

#endif // ZCOIN_QT_LELANTUSMODEL_H