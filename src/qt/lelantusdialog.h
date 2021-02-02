#ifndef FIRO_QT_LELANTUSDIALOG_H
#define FIRO_QT_LELANTUSDIALOG_H

#include "../script/standard.h"
#include "../wallet/coincontrol.h"

#include "clientmodel.h"
#include "platformstyle.h"
#include "lelantuscoincontroldialog.h"
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

    void updateDisplayUnit(int unit);
    void updateGlobalState();

private Q_SLOTS:
    void on_anonymizeButton_clicked();
    void on_buttonChooseFee_clicked();
    void on_buttonMinimizeFee_clicked();
    void coinControlFeatureChanged(bool);
    void coinControlButtonClicked();
    void coinControlChangeChecked(int);
    void coinControlChangeEdited(const QString &);
    void coinControlUpdateLabels();
    void coinControlClipboardQuantity();
    void coinControlClipboardAmount();
    void coinControlClipboardFee();
    void coinControlClipboardAfterFee();
    void coinControlClipboardBytes();
    void coinControlClipboardLowOutput();
    void coinControlClipboardChange();
    void setMinimumFee();
    void updateFeeSectionControls();
    void updateMinFeeLabel();
    void updateSmartFeeLabel();
    void updateGlobalFeeVariables();

private:
    void updateBalanceDisplay(int unit = -1);
    void processSendCoinsReturn(
        const WalletModel::SendCoinsReturn &sendCoinsReturn,
        const QString &msgArg = QString());

    CAmount getAmount(int unit = -1);
    void removeUnmatchedOutput(CCoinControl &coinControl);

    // fee configuration
    void minimizeFeeSection(bool fMinimize);
    void updateFeeMinimizedLabel();

private:
    Ui::LelantusDialog *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    CAmount cachedPrivateBalance;
    CAmount cachedUnconfirmedPrivateBalance;
    CAmount cachedAnonymizableBalance;

    bool fFeeMinimized;

    int currentUnit;

    // coin control
    CoinControlStorage coinControlStorage;
};

#endif // FIRO_QT_LELANTUSDIALOG_H