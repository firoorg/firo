// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_RECEIVECOINSDIALOG_H
#define BITCOIN_QT_RECEIVECOINSDIALOG_H

#include "guiutil.h"

#include <QDialog>
#include <QHeaderView>
#include <QItemSelection>
#include <QKeyEvent>
#include <QMenu>
#include <QPoint>
#include <QVariant>
#include <QSortFilterProxyModel>
#include <QResizeEvent>

class OptionsModel;
class PlatformStyle;
class WalletModel;
class RecentRequestsFilterProxy;

namespace Ui {
    class ReceiveCoinsDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QComboBox;
class QHBoxLayout;
class QSortFilterProxyModel;
QT_END_NAMESPACE

/** Dialog for requesting payment of bitcoins */
class ReceiveCoinsDialog : public QDialog
{
    Q_OBJECT

public:
    enum AddressTypeEnum
    {
        Spark,
        Transparent,
        All
    };

    enum ColumnWidths {
        DATE_COLUMN_WIDTH = 130,
        LABEL_COLUMN_WIDTH = 120,
        AMOUNT_MINIMUM_COLUMN_WIDTH = 180,
        ADDRESSTYPE_COLUMN_WIDTH = 130,
        MINIMUM_COLUMN_WIDTH = 130
    };

    explicit ReceiveCoinsDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~ReceiveCoinsDialog();

    void setModel(WalletModel *model);
   
    void resizeEvent(QResizeEvent* event) override;
public Q_SLOTS:
    void clear();
    void reject();
    void accept();
    void chooseType(int idx);
    void displayCheckBox(int idx);

protected:
    virtual void keyPressEvent(QKeyEvent *event);

private:
    Ui::ReceiveCoinsDialog *ui;
    WalletModel *model;
    QMenu *contextMenu;
    const PlatformStyle *platformStyle;

    QModelIndex selectedRow();
    void copyColumnToClipboard(int column);
    RecentRequestsFilterProxy *recentRequestsProxyModel;
    void adjustTextSize(int width,int height);
private Q_SLOTS:
    void on_receiveButton_clicked();
    void on_showRequestButton_clicked();
    void on_removeRequestButton_clicked();
    void on_recentRequestsView_doubleClicked(const QModelIndex &index);
    void recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void updateDisplayUnit();
    void showMenu(const QPoint &point);
    void copyURI();
    void copyLabel();
    void copyMessage();
    void copyAmount();
};

class RecentRequestsFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit RecentRequestsFilterProxy(QObject *parent = 0);

    static const quint32 ALL_TYPES = 0xFFFFFFFF;

    static quint32 TYPE(int type) { return 1<<type; }

    void setTypeFilter(quint32 modes);

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex & source_parent) const;
    
private:
    quint32 typeFilter;
};

#endif // BITCOIN_QT_RECEIVECOINSDIALOG_H
