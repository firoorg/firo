/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#ifndef ELYSIUMPRIVATESENDDIALOG_H
#define ELYSIUMPRIVATESENDDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <QRegExpValidator>

class ClientModel;

namespace Ui
{
class ElysiumPrivateSendDialog;
}

class ElysiumPrivateSendDialog : public QWidget
{
    Q_OBJECT

public:
    explicit ElysiumPrivateSendDialog(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~ElysiumPrivateSendDialog();

    void setClientModel(ClientModel* Model);
    void setWalletModel(WalletModel* model);

    void clear();

public Q_SLOTS:
    void onTokenComboBoxChanged(int index);
    void balancesUpdated();

private:
    Ui::ElysiumPrivateSendDialog* ui;
    const PlatformStyle* platformstyle;
    ClientModel* clientModel;
    WalletModel* walletModel;
    QRegExpValidator* divisibleQuantityValidator;
    QRegExpValidator* indivisibleQuantityValidator;

    std::map<uint32_t, uint64_t> balances;

    void updateTokenComboBox();
    void updateBalanceLabel();
    void updateAmountFieldValidators();

private Q_SLOTS:
    void onSendButtonClicked();
    void onClearButtonClicked();
    void onAddressBookButtonClicked();
    void onPasteButtonClicked();

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString& title, const QString& message, unsigned int style);
};

#endif // ELYSIUMPRIVATESENDDIALOG_H
