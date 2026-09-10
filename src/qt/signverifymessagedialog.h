// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SIGNVERIFYMESSAGEDIALOG_H
#define BITCOIN_QT_SIGNVERIFYMESSAGEDIALOG_H

#include <QDialog>

class PlatformStyle;
class QLabel;
class WalletModel;

namespace Ui {
    class SignVerifyMessageDialog;
}

class SignVerifyMessageDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SignVerifyMessageDialog(const PlatformStyle *platformStyle, QWidget *parent);
    ~SignVerifyMessageDialog();

    void setModel(WalletModel *model);
    void setAddress_SM(const QString &address);
    void setAddress_VM(const QString &address);

    void showTab_SM(bool fShow);
    void showTab_VM(bool fShow);

protected:
    bool eventFilter(QObject *object, QEvent *event) override;

private:
    Ui::SignVerifyMessageDialog *ui;
    WalletModel *model;
    const PlatformStyle *platformStyle;

    /* Resolve "@name" Spark name notation in place to the address it points at. Input not
       using that notation is left alone. Returns false if the name is not registered. */
    bool resolveSparkAddress(QString &address) const;

    void setStatusStyle(QLabel* label, bool success);

    /* Size signatureOut_SM to its content: one line while empty, up to four for a long
       Spark ownership proof. */
    void adjustSignatureOutHeight();

private Q_SLOTS:
    /* sign message */
    void on_addressBookButton_SM_clicked();
    void on_pasteButton_SM_clicked();
    void on_signMessageButton_SM_clicked();
    void on_copySignatureButton_SM_clicked();
    void on_clearButton_SM_clicked();
    /* verify message */
    void on_addressBookButton_VM_clicked();
    void on_verifyMessageButton_VM_clicked();
    void on_clearButton_VM_clicked();
};

#endif // BITCOIN_QT_SIGNVERIFYMESSAGEDIALOG_H
