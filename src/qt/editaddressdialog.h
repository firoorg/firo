// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_EDITADDRESSDIALOG_H
#define BITCOIN_QT_EDITADDRESSDIALOG_H

#include <QDialog>
#include <QAbstractItemModel>

class AddressTableModel;

namespace Ui {
    class EditAddressDialog;
}

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditAddressDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewReceivingAddress,
        NewSendingAddress,
        EditReceivingAddress,
        EditSendingAddress,
        NewPcode,
        EditPcode,
        NewSparkSendingAddress,
        EditSparkSendingAddress,
        NewSparkReceivingAddress,
        EditSparkReceivingAddress
    };

    explicit EditAddressDialog(Mode mode, QWidget *parent);
    ~EditAddressDialog();

    void setModel(AddressTableModel *model);
    void loadRow(int row);

    QString getAddress() const;
    void setAddress(const QString &address);

public Q_SLOTS:
    void accept() override;

private:
    bool saveCurrentRow();

    Ui::EditAddressDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    AddressTableModel *model;

    QString address;
};

#endif // BITCOIN_QT_EDITADDRESSDIALOG_H
