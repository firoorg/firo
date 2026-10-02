#include "../masternode-sync.h"
#include "../validation.h"
#include "../wallet/wallet.h"

#include "bip47sweepmodel.h"

#include <QThread>
#include <QTimer>

/** How often the chain is asked whether it has caught up, in milliseconds. */
static int const SYNC_CHECK_DELAY = 5000;

Bip47ScanWorker::Bip47ScanWorker(CWallet *_wallet) :
    QObject(0), wallet(_wallet)
{
}

void Bip47ScanWorker::scan()
{
    /* Both steps run here rather than on the thread that asked for the scan: taking the snapshot
     * needs cs_wallet, and going through it takes long enough to be felt in the interface. */
    CBip47ScanSnapshot const snapshot = wallet->GetBip47ScanSnapshot();
    Q_EMIT scanned(CWallet::HasBip47Transactions(snapshot));
}

Bip47SweepModel::Bip47SweepModel(CWallet *_wallet, QObject *parent) :
    QObject(parent), wallet(_wallet), thread(0), syncTimer(0), fStarted(false), fFound(false)
{
    syncTimer = new QTimer(this);
    syncTimer->setInterval(SYNC_CHECK_DELAY);
    connect(syncTimer, &QTimer::timeout, this, &Bip47SweepModel::checkChainSynced);
}

Bip47SweepModel::~Bip47SweepModel()
{
    if (thread) {
        thread->quit();
        thread->wait();
    }
}

void Bip47SweepModel::start()
{
    if (fStarted || !wallet || !wallet->GetBip47Wallet())
        return;

    /* The reminder was put away in an earlier run, so there is nothing to scan for. */
    if (wallet->IsBip47SweepDismissed())
        return;

    fStarted = true;
    checkChainSynced();
    if (thread == 0)
        syncTimer->start();
}

void Bip47SweepModel::checkChainSynced()
{
    if (thread != 0)
        return;

    /* Scanning a chain that is still coming in would only have to be repeated, and the wallet is
     * busy with the blocks it is catching up on. */
    if (!masternodeSync.IsBlockchainSynced() || fReindex || fImporting)
        return;

    syncTimer->stop();

    Bip47ScanWorker *worker = new Bip47ScanWorker(wallet);
    thread = new QThread(this);
    worker->moveToThread(thread);

    connect(this, &Bip47SweepModel::startScan, worker, &Bip47ScanWorker::scan);
    connect(worker, &Bip47ScanWorker::scanned, this, &Bip47SweepModel::scanned);
    connect(thread, &QThread::finished, worker, &QObject::deleteLater, Qt::DirectConnection);

    thread->start();
    Q_EMIT startScan();
}

void Bip47SweepModel::scanned(bool found)
{
    fFound = found;

    thread->quit();
    thread->wait();
    thread->deleteLater();
    thread = 0;

    /* The user may have put the reminder away while the scan was running. */
    if (found && !wallet->IsBip47SweepDismissed())
        Q_EMIT bip47TransactionsFound();
}

void Bip47SweepModel::dismiss()
{
    wallet->SetBip47SweepDismissed(true);
}
