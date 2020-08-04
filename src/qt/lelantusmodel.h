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

enum class AutoMintAck : uint8_t {
    Success,
    WaitUserToActive,
    FailToMint,
    NotEnoughFund,
    UserReject
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

    void ackMintAll(AutoMintAck ack, CAmount minted = 0, QString error = QString(""));

public:
    mutable CCriticalSection cs;

Q_SIGNALS:
    void askMintAll(bool userAsk);

public Q_SLOTS:
    void askUserToMint(bool userAsk = false);

    void checkPendingTransactions();
    void checkAutoMint(bool force = false);

    void updateTransaction(uint256 hash);
    void resetInitialSync();
    void setInitialSync();
    void start();

    void lock();

    void updateAutoMintOption(bool);

private:
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void setupAutoMint();

private:
    static const size_t WaitingTime = 1 * 1000; // one second

private:
    AutoMintState autoMintState = AutoMintState::Disabled;
    QTimer *checkPendingTxTimer;
    QTimer *resetInitialSyncTimer;
    OptionsModel *optionsModel;
    std::atomic<bool> initialSync;
    std::vector<uint256> pendingTransactions;
    CWallet *wallet;
};

#endif // ZCOIN_QT_LELANTUSMODEL_H