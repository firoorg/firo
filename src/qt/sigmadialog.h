#ifndef ZCOIN_QT_SIGMAPAGE_H
#define ZCOIN_QT_SIGMAPAGE_H

#include "addresstablemodel.h"
#include "clientmodel.h"
#include "platformstyle.h"
#include "sendcoinsentry.h"
#include "coincontroldialog.h"
#include <sigmacoincontroldialog.h>

#include <QWidget>

namespace Ui {
    class SigmaDialog;
    class BlankSigmaDialog;
}

class BlankSigmaDialog : public QDialog
{
    Q_OBJECT

public:
    BlankSigmaDialog();
    ~BlankSigmaDialog();

private:
    Ui::BlankSigmaDialog *ui;
};

class SigmaDialog : public QDialog
{
    Q_OBJECT

public:
    SigmaDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SigmaDialog();

    void setClientModel(ClientModel *model);
    void setWalletModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    void accept();
    SendCoinsEntry* addEntry();
    void coinControlFeatureChanged(bool);
    void updateTabsAndLabels();
    void coinControlUpdateLabels();
    void coinControlClipboardQuantity();
    void coinControlClipboardAmount();
    void coinControlClipboardFee();
    void coinControlClipboardAfterFee();
    void coinControlClipboardBytes();
    void coinControlClipboardPriority();
    void coinControlClipboardLowOutput();
    void coinControlClipboardChange();
    void coinControlButtonClicked();
    void coinControlChangeChecked(int);
    void coinControlChangeEdited(const QString &);
    void tabSelected();

private:
    Ui::SigmaDialog *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    bool isNewRecipientAllowed;
    const PlatformStyle *platformStyle;

    void processSpendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());

private Q_SLOTS:
    void numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, bool header);
    void on_mintButton_clicked();
    void on_sendButton_clicked();
    void removeEntry(SendCoinsEntry* entry);
    void updateAvailableToMintBalance(const CAmount& balance);
    void updateCoins(const std::vector<CMintMeta>& spendable, const std::vector<CMintMeta>& pending);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};

#endif // ZCOIN_QT_SIGMAPAGE_H
