/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#ifndef MINTTOKENDIALOG_H
#define MINTTOKENDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <QRegExpValidator>
#include <QString>

class ClientModel;

namespace Ui
{
class MintTokenDialog;
}

class MintTokenDialog : public QWidget
{
    Q_OBJECT

public:
    explicit MintTokenDialog(QWidget* parent = nullptr);
    ~MintTokenDialog();

    void setClientModel(ClientModel* clientModel);
    void setModel(WalletModel* model);

    void clear();

public Q_SLOTS:
    void balancesUpdated();

private:
    Ui::MintTokenDialog* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    QRegExpValidator* divisibleQuantityValidator;
    QRegExpValidator* indivisibleQuantityValidator;

    void updateTokenComboBox();
    void updateAddressComboBox();
    void updateBalanceLabel();
    void updateAmountValidator();

private Q_SLOTS:
    void onMintButtonClicked();
    void onClearButtonClicked();
    void onAddressComboBoxChanged(int index);
    void onTokenComboBoxChanged(int index);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString& title, const QString& message, unsigned int style);
};

#endif // MINTTOKENDIALOG_H
