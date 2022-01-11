/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#ifndef MANAGETOKENDIALOG_H
#define MANAGETOKENDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <QRegExpValidator>
#include <QString>

class ClientModel;

namespace Ui
{
class ManageTokenDialog;
}

class ManageTokenDialog : public QWidget
{
    Q_OBJECT

public:
    explicit ManageTokenDialog(QWidget* parent = nullptr);
    ~ManageTokenDialog();

    void setClientModel(ClientModel* model);
    void setModel(WalletModel* model);

private:
    Ui::ManageTokenDialog* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
    QRegExpValidator* divisibleQuantityValidator;
    QRegExpValidator* indivisibleQuantityValidator;

    std::map<uint32_t, std::string> ownIdAddressMap;

    void clear();
    void updateAmountValidator();

private Q_SLOTS:
    void onIssueButtonClicked();
    void onClearButtonClicked();

    void issuerComboBoxChanged(int index);
    void updateOwnedTokens();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString& title, const QString& message, unsigned int style);
};

#endif // MANAGETOKENDIALOG_H
