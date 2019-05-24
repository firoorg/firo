#ifndef ZCOIN_QT_SIGMAPAGE_H
#define ZCOIN_QT_SIGMAPAGE_H

#include "addresstablemodel.h"
#include "clientmodel.h"
#include "platformstyle.h"
#include "sendcoinsentry.h"

#include <QWidget>

namespace Ui {
    class SigmaPage;
}

class SigmaPage : public QWidget
{
    Q_OBJECT

public:
    SigmaPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SigmaPage();

    void setClientModel(ClientModel *model);
    void setWalletModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    void accept();
    SendCoinsEntry* addEntry();
    void updateTabsAndLabels();

private:
    Ui::SigmaPage *ui;
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
    void updateCoins(const std::vector<CZerocoinEntryV3>& spendable, const std::vector<CZerocoinEntryV3>& pending);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};

#endif // ZCOIN_QT_SIGMAPAGE_H
