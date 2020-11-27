// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_QT_LELANTUSCOINCONTROLDIALOG_H
#define ZCOIN_QT_LELANTUSCOINCONTROLDIALOG_H

#include "../amount.h"
#include "../script/standard.h"
#include "../wallet/coincontrol.h"

#include "walletmodel.h"

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidgetItem>

#define ASYMP_UTF8 "\xE2\x89\x88"

class CoinControlStorage : public QObject
{
    Q_OBJECT
public:
    CoinControlStorage();

public:
    QList<CAmount> payAmounts;
    CCoinControl coinControl;
    bool fSubtractFeeFromAmount;

public:
    void updateLabels(WalletModel*, QDialog*);
};

namespace Ui
{
    class CoinControlDialog;
}

class LelantusCoinControlDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LelantusCoinControlDialog(
        CoinControlStorage *storage,
        const PlatformStyle *platformStyle,
        QWidget *parent = 0);
    ~LelantusCoinControlDialog();

    void setModel(WalletModel *model);

    CoinControlStorage *storage;

private:
    Ui::CoinControlDialog *ui;
    WalletModel *model;
    int sortColumn;
    Qt::SortOrder sortOrder;

    QMenu *contextMenu;
    QTreeWidgetItem *contextMenuItem;
    QAction *copyTransactionHashAction;
    QAction *lockAction;
    QAction *unlockAction;

    const PlatformStyle *platformStyle;

    void sortView(int, Qt::SortOrder);
    void updateView();

    enum
    {
        COLUMN_CHECKBOX = 0,
        COLUMN_AMOUNT,
        COLUMN_LABEL,
        COLUMN_ADDRESS,
        COLUMN_DATE,
        COLUMN_CONFIRMATIONS,
        COLUMN_TXHASH,
        COLUMN_VOUT_INDEX,
    };
    friend class CCoinControlWidgetItem;

private Q_SLOTS:
    void showMenu(const QPoint &);
    void copyAmount();
    void copyLabel();
    void copyAddress();
    void copyTransactionHash();
    void lockCoin();
    void unlockCoin();
    void clipboardQuantity();
    void clipboardAmount();
    void clipboardFee();
    void clipboardAfterFee();
    void clipboardBytes();
    void clipboardLowOutput();
    void clipboardChange();
    void radioTreeMode(bool);
    void radioListMode(bool);
    void viewItemChanged(QTreeWidgetItem*, int);
    void headerSectionClicked(int);
    void buttonBoxClicked(QAbstractButton*);
    void buttonSelectAllClicked();
    void updateLabelLocked();
};

#endif // ZCOIN_QT_LELANTUSCOINCONTROLDIALOG_H
