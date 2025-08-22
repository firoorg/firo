// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include "amount.h"
#include "uint256.h"

#include <QWidget>
#include <memory>

#include "../spats/manager.hpp"

#include "walletmodel.h"

#include <QSettings>
#include <QMessageBox>
#include <QTimer>
#include <QResizeEvent>


class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget, public spats::UpdatesObserver
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);
    void UpdatePropertyBalance(unsigned int propertyId, uint64_t available, uint64_t reserved);
    void resizeEvent(QResizeEvent* event) override;

public Q_SLOTS:
    void on_anonymizeButton_clicked();
    void migrateClicked();
    void onRefreshClicked();

    void setBalance(
        const CAmount& balance,
        const CAmount& unconfirmedBalance,
        const CAmount& immatureBalance,
        const CAmount& watchOnlyBalance,
        const CAmount& watchUnconfBalance,
        const CAmount& watchImmatureBalance,
        const spats::Wallet::asset_balances_t& spats_balances,
        const CAmount& anonymizableBalance);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void enabledTorChanged();
    void outOfSyncWarningClicked();
    void spatsRegistryChangedSignal();
private:
    Ui::OverviewPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    spats::Wallet::asset_balances_t currentSpatsBalances_;
    CAmount currentAnonymizableBalance;

    QSettings settings;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;

    QTimer countDownTimer;
    int secDelay;
    QString migrationWindowClosesIn;
    QString blocksRemaining;
    QString migrateAmount;
    std::map<spats::universal_asset_id_t, spats::SparkAssetDisplayAttributes> spats_display_attributes_cache_;
    std::mutex spats_registry_change_affected_asset_ids_mutex_;
    asset_ids_set_t spats_registry_change_affected_asset_ids_;  // protected by spats_registry_change_affected_asset_ids_mutex_

    void displaySpatsBalances();
    const spats::SparkAssetDisplayAttributes* getSpatsDisplayAttributes(spats::universal_asset_id_t asset_id);
    void adjustTextSize(int width,int height);

    void process_spats_registry_changed(const admin_addresses_set_t &affected_asset_admin_addresses, const asset_ids_set_t &affected_asset_ids) override;

private Q_SLOTS:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void handleEnabledTorChanged();
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void countDown();
    void handleSpatsRegistryChangedSignal();
    
    void on_tableWidgetSparkBalances_contextMenuRequested(const QPoint &pos);
};

class MigrateLelantusToSparkDialog : public QMessageBox
{
    Q_OBJECT
private:
    bool clickedButton;
    WalletModel *model;
public:
    MigrateLelantusToSparkDialog(WalletModel *model);
    bool getClickedButton();

private Q_SLOTS:
    void onIgnoreClicked();
    void onMigrateClicked();
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
