// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ADDRESSBOOKPAGE_H
#define BITCOIN_QT_ADDRESSBOOKPAGE_H

#include <QDialog>
#include <QSortFilterProxyModel>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;
class AddressBookFilterProxy;

namespace Ui {
    class AddressBookPage;
}

QT_BEGIN_NAMESPACE
class QItemSelection;
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
class QTableView;
QT_END_NAMESPACE

/** Widget that shows a list of sending or receiving addresses.
  */
class AddressBookPage : public QDialog
{
    Q_OBJECT

public:
    enum Tabs {
        SendingTab = 0,
        ReceivingTab = 1
    };

    enum Mode {
        ForSelection, /**< Open address book to pick address */
        ForEditing  /**< Open address book for editing */
    };

    enum AddressTypeEnum
    {
        Spark,
        Transparent,
        RAP
    };

    explicit AddressBookPage(const PlatformStyle *platformStyle, Mode mode, Tabs tab, QWidget *parent, bool isReused = true);
    ~AddressBookPage();

    void setModel(AddressTableModel *model);
    const QString &getReturnValue() const { return returnValue; }

public Q_SLOTS:
    void done(int retval);

private:
    Ui::AddressBookPage *ui;
    AddressTableModel *model;
    Mode mode;
    Tabs tab;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    AddressBookFilterProxy *fproxyModel;
    QMenu *contextMenu;
    QAction *copyAddressAction;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAddressToSelect;

private Q_SLOTS:
    /** Delete currently selected address entry */
    void on_deleteAddress_clicked();
    /** Create a new address for receiving coins and / or add a new address book entry */
    void on_newAddress_clicked();
    /** Copy address of currently selected address entry to clipboard */
    void on_copyAddress_clicked();
    /** Copy label of currently selected address entry to clipboard (no button) */
    void onCopyLabelAction();
    /** Edit currently selected address entry (no button) */
    void onEditAction();
    /** Export button clicked */
    void on_exportButton_clicked();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int /*end*/);

    void chooseAddressType(int idx);

Q_SIGNALS:
    void sendCoins(QString addr);
};

class AddressBookFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit AddressBookFilterProxy(QObject *parent = 0);

    // static const quint32 RECEIVE_TYPE = 0xFFFFFFFF;
    static const quint32 RECEIVE_TYPE = 8;

    static quint32 TYPE(int type) { return 1<<type; }

    void setTypeFilter(quint32 modes);

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex & source_parent) const;
    
private:
    quint32 typeFilter;
};

#endif // BITCOIN_QT_ADDRESSBOOKPAGE_H
