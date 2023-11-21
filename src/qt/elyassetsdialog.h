// Copyright (c) 2011-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ELYASSETSDIALOG_H
#define ELYASSETSDIALOG_H

#include "guiutil.h"

#include <QDialog>

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QMenu;
class QPoint;
class QResizeEvent;
class QString;
class QWidget;
QT_END_NAMESPACE

namespace Ui {
    class ElyAssetsDialog;
}

class ElyAssetsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ElyAssetsDialog(QWidget *parent = 0);
    ~ElyAssetsDialog();

    void setClientModel(ClientModel *model);
    void setWalletModel(WalletModel *model);
    void AddRow(const std::string& label, const std::string& address, const std::string& reserved, const std::string& available);
    void PopulateBalances(unsigned int propertyId);
    void UpdatePropSelector();

private:
    Ui::ElyAssetsDialog *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    QMenu *contextMenu;
    QMenu *contextMenuSummary;

    GUIUtil::TableViewLastColumnResizingFixer *borrowedColumnResizingFixer;
    virtual void resizeEvent(QResizeEvent *event);

public Q_SLOTS:
    void propSelectorChanged();
    void balancesUpdated();
    void reinitEly();

private Q_SLOTS:
    void contextualMenu(const QPoint &point);
    void balancesCopyCol0();
    void balancesCopyCol1();
    void balancesCopyCol2();
    void balancesCopyCol3();

Q_SIGNALS:
    /**  Fired when a message should be reported to the user */
    void message(const QString &title, const QString &message, unsigned int style);
};

#endif // ELYASSETSDIALOG_H
