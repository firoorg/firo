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

    void unlockWallet(SecureString const &passphase, size_t msecs);
    void lockWallet();

    CAmount mintAll();

    void ackMintAll(bool keepWaiting);

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askMintAll();

public Q_SLOTS:
    void askUserToMint();

    void checkPendingTransactions();
    void checkAutoMint();

    void updateTransaction(uint256 hash);
    void start();

    void lock();

private:
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void setupAutoMint();

private:
    AutoMintState autoMintState = AutoMintState::Disabled;
    QTimer *checkPendingTxTimer;
    OptionsModel *optionsModel;
    std::vector<uint256> pendingTransactions;
    CWallet *wallet;
};

#endif // ZCOIN_QT_LELANTUSMODEL_H