// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CREATEPCODEDIALOG_H
#define BITCOIN_QT_CREATEPCODEDIALOG_H

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
    class CreatePcodeDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Dialog for requesting payment of bitcoins */
class CreatePcodeDialog : public QDialog
{
    Q_OBJECT

public:
    enum struct ColumnWidths : int {
        Number = 80,
        Label = 180,
        Pcode = 180
    };

    explicit CreatePcodeDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~CreatePcodeDialog();

    void setModel(WalletModel *model);

public Q_SLOTS:
    void clear();
    void reject();
    void accept();

protected:
    virtual void keyPressEvent(QKeyEvent *event);

private:
    Ui::CreatePcodeDialog *ui;
    GUIUtil::TableViewLastColumnResizingFixer *columnResizingFixer;
    WalletModel *model;
    QMenu *contextMenu;
    const PlatformStyle *platformStyle;
    SendCoinsRecipient recipient;

    QModelIndex selectedRow();
    void copyColumnToClipboard(int column);
    virtual void resizeEvent(QResizeEvent *event);

private Q_SLOTS:
    void on_createPcodeButton_clicked();
    void on_labelText_textChanged();
    void on_pcodesView_doubleClicked(const QModelIndex &index);
    void pcodesView_selectionChanged(QItemSelection const & selected, QItemSelection const & deselected);
    void on_showPcodeButton_clicked();
    void showMenu(const QPoint &point);
    void copyPcode();
    void copyNotificationAddr();
    void showQrcode();
};

#endif // BITCOIN_QT_CREATEPCODEDIALOG_H
