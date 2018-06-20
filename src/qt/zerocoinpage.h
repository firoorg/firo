// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ZEROCOINPAGE_H
#define BITCOIN_QT_ZEROCOINPAGE_H

#include <QWidget>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;

namespace Ui {
    class ZerocoinPage;
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
class ZerocoinPage : public QWidget
{
    Q_OBJECT

public:

    enum Mode {
        ForSelection, /**< Open address book to pick address */
        ForEditing  /**< Open address book for editing */
    };

    explicit ZerocoinPage(const PlatformStyle *platformStyle, Mode mode, QWidget *parent);
    ~ZerocoinPage();

    void setModel(AddressTableModel *model);
    const QString &getReturnValue() const { return returnValue; }

//public Q_SLOTS:
//    void done(int retval);

private:
    Ui::ZerocoinPage *ui;
    AddressTableModel *model;
    Mode mode;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newAddressToSelect;

private Q_SLOTS:
    /** Export button clicked */
    void on_exportButton_clicked();
    /** Zerocoin Mint clicked */
    void on_zerocoinMintButton_clicked();
    /** Zerocoin Spend clicked */
    void on_zerocoinSpendButton_clicked();
    /** Zerocoin Spend To Me checked */
    void zerocoinSpendToMeCheckBoxChecked(int);
//    void on_showQRCode_clicked();
    /** Set button states based on selected tab and selection */
//    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int /*end*/);

Q_SIGNALS:
    void sendCoins(QString addr);
};

#endif // BITCOIN_QT_ADDRESSBOOKPAGE_H
