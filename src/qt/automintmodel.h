#ifndef FIRO_QT_AUTOMINTMODEL_H
#define FIRO_QT_AUTOMINTMODEL_H

#include "../amount.h"
#include "../uint256.h"
#include "../validation.h"

#include "automintdialog.h"

#include <QDateTime>
#include <QObject>
#include <QTimer>

class SparkModel;
class OptionsModel;
class CWallet;

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
    void importTransactions();

Q_SIGNALS:
    void matureFund(CAmount);

private:
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void resetTimer();

    CWallet *wallet;
    QTimer *timer;

    std::vector<uint256> txs;
    mutable CCriticalSection cs;

    int64_t lastUpdateTime;
};

enum class AutoMintSparkState : uint8_t {
    Disabled,
    WaitingIncomingFund,
    WaitingUserToActivate,
    Anonymizing
};

enum class AutoMintSparkAck : uint8_t {
    AskToMint,
    Success,
    WaitUserToActive,
    FailToMint,
    NotEnoughFund,
    UserReject,
    FailToUnlock,
    Close
};

class AutoMintSparkModel : public QObject
{
    Q_OBJECT;

public:
    explicit AutoMintSparkModel(
        SparkModel *sparkModel,
        OptionsModel *optionsModel,
        CWallet *wallet,
        QObject *parent = 0);

    ~AutoMintSparkModel();

public:
    bool isSparkAnonymizing() const;

public Q_SLOTS:
    void ackMintSparkAll(AutoMintSparkAck ack, CAmount minted, QString error);
    void checkAutoMintSpark(bool force = false);

    void startAutoMintSpark();

    void updateAutoMintSparkOption(bool);

Q_SIGNALS:
    void message(const QString &title, const QString &message, unsigned int style);

    void requireShowAutomintSparkNotification();
    void closeAutomintSparkNotification();

private:
    void processAutoMintSparkAck(AutoMintSparkAck ack, CAmount minted, QString error);

private:
    SparkModel *sparkModel;
    OptionsModel *optionsModel;
    CWallet *wallet;

    AutoMintSparkState autoMintSparkState;

    QTimer *autoMintSparkCheckTimer;

    IncomingFundNotifier *notifier;
};

#endif // FIRO_QT_AUTOMINTMODEL_H