// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SENDTOPCODEDIALOG_H
#define BITCOIN_QT_SENDTOPCODEDIALOG_H

#include "guiutil.h"

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>

#include "walletmodel.h"
#include "bip47/paymentcode.h"

class OptionsModel;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class SendtoPcodeDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog for requesting payment of bitcoins */
class SendtoPcodeDialog : public QDialog
{
    Q_OBJECT

public:
    enum struct Result : int {
        cancelled = 0,
        addressSelected,
    };

    explicit SendtoPcodeDialog(QWidget *parent, std::string const & pcode, std::string const & label);
    ~SendtoPcodeDialog();

    void setModel(WalletModel *model);
    std::pair<Result, CBitcoinAddress> getResult() const;
    std::unique_ptr<WalletModel::UnlockContext> getUnlockContext();
    void close();

private:
    Ui::SendtoPcodeDialog *ui;
    WalletModel *model;
    std::shared_ptr<bip47::CPaymentCode> paymentCode;
    Result result;
    std::string label;
    uint256 notificationTxHash;
    CBitcoinAddress addressToUse;
    std::unique_ptr<WalletModel::UnlockContext> unlockContext;

    void setNotifTxId();
    void setUseAddr();
    void setLelantusBalance(CAmount const & amount, CAmount const & unconfirmedLelantusBalance);

private Q_SLOTS:
    void on_sendButton_clicked();
    void on_useButton_clicked();
    void on_cancelButton_clicked();
    void on_helpButton_clicked();
    void showEvent(QShowEvent* event);
    void onTransactionChanged(uint256 txHash);
    void onWindowShown();
    void onBalanceChanged(CAmount const &, CAmount const &, CAmount const &, CAmount const &, CAmount const &, CAmount const &, CAmount const &, CAmount const &, CAmount const &);
};

#endif /* SENDTOPCODEDIALOG_H */

