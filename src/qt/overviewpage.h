// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include "amount.h"
#include "uint256.h"

#include <QWidget>
#include <QPointer>
#include <memory>

#include "walletmodel.h"

#include <QMessageBox>
#include <QTimer>


class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QAction;
class QModelIndex;
class QProgressBar;
class QLabel;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void setConsolidationAction(QAction *action);
    void showOutOfSyncWarning(bool fShow);
    void UpdatePropertyBalance(unsigned int propertyId, uint64_t available, uint64_t reserved);

public Q_SLOTS:
    void on_anonymizeButton_clicked();
    void consolidateCoins();

    void setBalance(
        const CAmount& balance, 
        const CAmount& unconfirmedBalance,
        const CAmount& immatureBalance,
        const CAmount& watchOnlyBalance,
        const CAmount& watchUnconfBalance,
        const CAmount& watchImmatureBalance,
        const CAmount& privateBalance,
        const CAmount& unconfirmedPrivateBalance,
        const CAmount& anonymizableBalance);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();
    void gotoSendCoinsPage();
    void gotoReceiveCoinsPage();
private:
    bool canConsolidate() const;
    Ui::OverviewPage *ui;
    ClientModel *clientModel;
    QPointer<WalletModel> walletModel;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    CAmount currentPrivateBalance;
    CAmount currentUnconfirmedPrivateBalance;
    CAmount currentAnonymizableBalance;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;

    QTimer countDownTimer;
    int secDelay;
    QString migrationWindowClosesIn;
    QString blocksRemaining;
    QString migrateAmount;

    int privateBarSplitPercent_{0};
    QProgressBar *privateSplitProgress{nullptr};
    QWidget *activityEmptyState_{nullptr};
    QLabel *networkBadge_{nullptr};
    QLabel *emptyIcon_{nullptr};
    QLabel *emptyTitle_{nullptr};
    QLabel *emptyHint_{nullptr};
    QPointer<QAction> consolidationAction;

    void applyOverviewRedesign();
    void applyOverviewTheme();
    void addShadow(QWidget *w, int blurRadius = 18, int yOffset = 4, int alpha = 60);
    void updatePrivateTransparentSplitBar();
    void updateBalanceSplitLabels();
    void updateActivityEmptyState();
private Q_SLOTS:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void updateSparkAnonymizeRowVisibility();
    void showConsolidationResult(qulonglong remainingOutputs, bool anotherBatch);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
