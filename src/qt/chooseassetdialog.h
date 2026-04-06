// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CHOOSEASSETDIALOG_H
#define BITCOIN_QT_CHOOSEASSETDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <optional>

class PlatformStyle;

namespace Ui {
class ChooseAssetDialog;
}

/** One-line description for Send dialog / status (uses registry + balance map). */
QString FormatSpatsAssetSummary(const spats::Wallet::asset_balances_t& balances, spats::universal_asset_id_t id);

/** Compact picker for Spark / Spats assets (balances from wallet). */
class ChooseAssetDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ChooseAssetDialog(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~ChooseAssetDialog() override;

    void setWalletModel(WalletModel* model);
    void setPreselected(spats::universal_asset_id_t id);

    spats::universal_asset_id_t selectedAsset() const { return selected_; }

    /** Short label for the Send dialog (name + balance hint). */
    QString selectedSummary() const;

    void reloadAndApplyFilter();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private Q_SLOTS:
    void onSearchTextChanged(const QString& text);

private:
    void rebuildCardWidgets();
    void applyFilter(const QString& filter);
    static QString assetKeyString(spats::universal_asset_id_t id);
    static std::optional<spats::universal_asset_id_t> parseAssetKey(const QString& key);

    Ui::ChooseAssetDialog* ui;
    const PlatformStyle* platformStyle;
    WalletModel* model_;
    spats::universal_asset_id_t selected_;
    spats::Wallet::asset_balances_t balances_;
};

#endif // BITCOIN_QT_CHOOSEASSETDIALOG_H
