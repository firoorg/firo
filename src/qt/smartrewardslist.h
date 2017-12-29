// Copyright (c) 2011-2015 The Smartcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SMARTREWARDSLIST_H
#define BITCOIN_QT_SMARTREWARDSLIST_H

#include <QDialog>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;

namespace Ui {
    class SmartrewardsList;
}

QT_BEGIN_NAMESPACE
class QItemSelection;
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
class QTableView;
QT_END_NAMESPACE

/** SmartrewardsList Manager page widget */
class SmartrewardsList : public QWidget
{
    Q_OBJECT

public:
    explicit SmartrewardsList(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SmartrewardsList();

    void setModel(AddressTableModel *model);
    const QString &getReturnValue() const { return returnValue; }

private:
    Ui::SmartrewardsList *ui;
    AddressTableModel *model;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;

};
#endif // SMARTREWARDSLIST_H
