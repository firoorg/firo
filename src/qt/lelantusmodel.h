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
    OptionsModel *getOptionsModel();
    CAmount getMintableAmount();

    void startAutoMint();
    void stopAutoMint();

    void unlockWallet(SecureString const &passphase, size_t secs);
    void lockWallet();

    CAmount mintAll();

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askUserToMint();

public Q_SLOTS:
    void checkPendingTransactions();
    void checkAutoMint();

    void updateTransaction(uint256 hash);
    void start();

private:
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void setupAutoMint();

private:
    OptionsModel *optionsModel;

    CWallet *wallet;

    QTimer *pollTimer;
    QTimer *startTimer;
    QTimer *checkPendingTxTimer;

    AutoMintState autoMintState = AutoMintState::Disabled;
    QDateTime disableAutoMintUntil;

    std::vector<uint256> pendingTransactions;
};

#endif // ZCOIN_QT_LELANTUSMODEL_H