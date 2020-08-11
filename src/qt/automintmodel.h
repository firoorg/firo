#ifndef ZCOIN_QT_AUTOMINTMODEL_H
#define ZCOIN_QT_AUTOMINTMODEL_H

#include "../amount.h"
#include "../ui_interface.h"
#include "../uint256.h"
#include "../validation.h"

#include <QDateTime>
#include <QObject>
#include <QTimer>

#include <mutex>
#include <queue>

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

class IncomingFundNotifier : public QObject
{
    Q_OBJECT;
public:
    explicit IncomingFundNotifier(CWallet *wallet, QObject *parent = 0);
    ~IncomingFundNotifier();

public Q_SLOTS:
    void newBlock();
    void pushTransaction(uint256 const &);
    void check();

Q_SIGNALS:
    void matureFund(CAmount);

private:
    void importTransactions();

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void resetTimer();

    CWallet *wallet;
    QTimer *timer;

    QDateTime waitUntil;
    std::queue<uint256> txs;
    mutable std::mutex txsMutex;
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
    void userAskToMint();

public Q_SLOTS:
    void ackMintAll(AutoMintAck ack, CAmount minted, QString error);
    void checkAutoMint(bool force = false);

    void resetSyncing();
    void setSyncing();

    void startAutoMint();

    void updateAutoMintOption(bool);

private:
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

private:
    LelantusModel *lelantusModel;
    OptionsModel *optionsModel;
    CWallet *wallet;

    AutoMintState autoMintState;

    QTimer *resetSyncingTimer;
    QTimer *autoMintCheckTimer;

    std::atomic<bool> syncing;

    IncomingFundNotifier *notifier;
};

#endif // ZCOIN_QT_AUTOMINTMODEL_H