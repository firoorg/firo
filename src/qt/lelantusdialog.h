#ifndef ZCOIN_QT_LELANTUSDIALOG_H
#define ZCOIN_QT_LELANTUSDIALOG_H

#include "clientmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"

#include <QDialog>
#include <QWidget>

namespace Ui {
    class LelantusDialog;
}

class LelantusDialog : public QDialog
{
    Q_OBJECT

public:
    LelantusDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~LelantusDialog();

    void setClientModel(ClientModel *model);
    void setWalletModel(WalletModel *model);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

public Q_SLOTS:
    void clear();
    void accept();

    void setBalance(
        const CAmount& balance,
        const CAmount& unconfirmedBalance,
        const CAmount& immatureBalance,
        const CAmount& watchOnlyBalance,
        const CAmount& watchUnconfBalance,
        const CAmount& watchImmatureBalance,
        const CAmount& privateBalance,
        const CAmount& unconfirmedPrivateBalance,
        const CAmount& anonymizableBalance);

    void updateGlobalState();

private Q_SLOTS:
    void on_anonymizeButton_clicked();

private:
    void updateBalanceDisplay();

private:
    Ui::LelantusDialog *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    CAmount cachedPrivateBalance;
    CAmount cachedUnconfirmedPrivateBalance;
    CAmount cachedAnonymizableBalance;
};

#endif // ZCOIN_QT_LELANTUSDIALOG_H