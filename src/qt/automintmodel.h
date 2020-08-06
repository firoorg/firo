#ifndef ZCOIN_QT_AUTOMINTMODEL_H
#define ZCOIN_QT_AUTOMINTMODEL_H

#include "../amount.h"
#include "../uint256.h"

#include <QObject>
#include <QTimer>

class LelantusModel;
class OptionsModel;
class CWallet;

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

class AutoMintModel : public QObject
{
    Q_OBJECT;

public:
    explicit AutoMintModel(
        LelantusModel *lelantusModel,
        OptionsModel *optionsModel,
        CWallet *wallet,
        QObject *parent = 0);

    ~AutoMintModel();

public:
    bool askingUser();

public Q_SLOTS:
    void ackMintAll(AutoMintAck ack, CAmount minted, QString error);
    void checkAutoMint();

    void resetInitialSync();
    void setInitialSync();

    void triggerPendingTxChecking();

    void startAutoMint(bool force = false);

    void checkPendingTransactions();
    void updateTransaction(uint256 hash);

    void updateAutoMintOption(bool);

private:
    void importImmatureTransactions();

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

private:
    LelantusModel *lelantusModel;
    OptionsModel *optionsModel;
    CWallet *wallet;

    AutoMintState autoMintState;

    QTimer *checkPendingTxTimer;
    QTimer *resetInitialSyncTimer;
    QTimer *autoMintCheckTimer;

    std::atomic<bool> initialSync;
    std::atomic<bool> force;

    std::unordered_set<uint256> pendingTransactions;
};

#endif // ZCOIN_QT_AUTOMINTMODEL_H