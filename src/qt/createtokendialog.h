/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#ifndef CREATETOKENDIALOG_H
#define CREATETOKENDIALOG_H

#include "walletmodel.h"

#include <QDialog>
#include <QRegExpValidator>
#include <QString>

class ClientModel;

namespace Ui
{
class CreateTokenDialog;
}

class CreateTokenDialog : public QWidget
{
    Q_OBJECT

public:
    explicit CreateTokenDialog(QWidget* parent = nullptr);
    ~CreateTokenDialog();

    void setClientModel(ClientModel* clientModel);
    void setModel(WalletModel* model);

    void clear();

private:
    Ui::CreateTokenDialog* ui;
    ClientModel* clientModel;
    WalletModel* model;
    QRegExpValidator* divisibleQuantityValidator;
    QRegExpValidator* indivisibleQuantityValidator;

    QString tempQuantity; // used to store quantity field text when disabling field for managed tokens

private Q_SLOTS:
    void onCreateButtonClicked();
    void onClearButtonClicked();

    void onDivisibleCheckBoxChanged(bool divisible);
    void onManagedCheckBoxChanged(bool managed);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString& title, const QString& message, unsigned int style);
};

#endif // CREATETOKENDIALOG_H
