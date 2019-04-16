#ifndef ZCOIN_QT_SIGMAPAGE_H
#define ZCOIN_QT_SIGMAPAGE_H

#include <QWidget>

#include "addresstablemodel.h"
#include "sendcoinsentry.h"
#include "platformstyle.h"

namespace Ui {
    class SigmaPage;
}

class SigmaPage : public QWidget
{
    Q_OBJECT

public:
    SigmaPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SigmaPage();

    void setModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

public Q_SLOTS:
    void clear();
    SendCoinsEntry* addEntry();
    void updateTabsAndLabels();

private:
    Ui::SigmaPage *ui;
    WalletModel *model;
    bool isNewRecipientAllowed;
    const PlatformStyle *platformStyle;

    void processSpendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg = QString());

private Q_SLOTS:
    void on_sendButton_clicked();
    void removeEntry(SendCoinsEntry* entry);
    void updateCoins(const std::vector<CZerocoinEntryV3>& spendable, const std::vector<CZerocoinEntryV3>& pending);

Q_SIGNALS:
    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);
};

#endif // ZCOIN_QT_SIGMAPAGE_H
