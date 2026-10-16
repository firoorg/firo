#ifndef FIRO_QT_BIP47SWEEPMODEL_H
#define FIRO_QT_BIP47SWEEPMODEL_H

#include <QObject>

class CWallet;

QT_BEGIN_NAMESPACE
class QThread;
class QTimer;
QT_END_NAMESPACE

/**
 * Looks for bip47 transactions on a thread of its own. The wallet is only locked for as long as
 * it takes to copy out what the scan reads; the scan itself runs on the copy.
 */
class Bip47ScanWorker : public QObject
{
    Q_OBJECT;

public:
    explicit Bip47ScanWorker(CWallet *wallet);

public Q_SLOTS:
    void scan();

Q_SIGNALS:
    void scanned(bool found);

private:
    CWallet *wallet;
};

/**
 * Checks a wallet once per run for funds left on its bip47 addresses, and tells the main window
 * to offer moving them away. A wallet with many transactions takes a noticeable while to go
 * through, so the check waits for the chain to be synced and then hands the work to a background
 * thread. The user can put the reminder away for good, which is remembered in the wallet.
 */
class Bip47SweepModel : public QObject
{
    Q_OBJECT;

public:
    explicit Bip47SweepModel(CWallet *wallet, QObject *parent = 0);
    ~Bip47SweepModel();

    /**
     * Starts waiting for the chain to be synced, and scans once it is. Does nothing if the user
     * has put the reminder away, or if the scan has already run in this session.
     */
    void start();

    /** Whether the scan has found anything. */
    bool hasBip47Transactions() const { return fFound; }

    /** Puts the reminder away for good. */
    void dismiss();

Q_SIGNALS:
    /** The wallet holds bip47 transactions and the user has not put the reminder away. */
    void bip47TransactionsFound();

    /** Asks the worker on the background thread to go through the wallet. */
    void startScan();

private Q_SLOTS:
    void checkChainSynced();
    void scanned(bool found);

private:
    CWallet *wallet;
    QThread *thread;
    QTimer *syncTimer;
    bool fStarted;
    bool fFound;
};

#endif // FIRO_QT_BIP47SWEEPMODEL_H
