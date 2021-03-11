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

#include <experimental/any>

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

    explicit SendtoPcodeDialog(QWidget *parent, std::string const & pcode);
    ~SendtoPcodeDialog();

    void setModel(WalletModel *model);

    std::pair<Result, std::experimental::any> getResult() const;

public Q_SLOTS:

private:
    Ui::SendtoPcodeDialog *ui;
    WalletModel *model;
    std::shared_ptr<bip47::CPaymentCode> paymentCode;
    Result result;
    uint256 notificationTx;
    CBitcoinAddress addressToUse;

    void setTxUrl(uint256 const & txid);
    void setUseAddr();

private Q_SLOTS:
    void on_sendButton_clicked();
    void on_useButton_clicked();
    void on_cancelButton_clicked();
    void on_helpButton_clicked();
    void showEvent( QShowEvent* event );
};

#endif /* SENDTOPCODEDIALOG_H */

