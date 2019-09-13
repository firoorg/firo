#ifndef BITCOIN_QT_PAYMENTCODEPAGE_H
#define BITCOIN_QT_PAYMENTCODEPAGE_H

#include "primitives/transaction.h"
#include "platformstyle.h"
#include "sync.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>

class ClientModel;
class PlatformStyle;
class WalletModel;
class CWallet;

namespace Ui {
    class PaymentcodePage;
}


QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE


/** Paymentcode Manager page widget */
class PaymentcodePage : public QWidget
{
    Q_OBJECT

public:
    explicit PaymentcodePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~PaymentcodePage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

private:
    QMenu *contextMenu;
    int64_t nTimeFilterUpdated;
    bool fFilterUpdated;

public Q_SLOTS:


Q_SIGNALS:

private:
    Ui::PaymentcodePage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CWallet *wallet;

private Q_SLOTS:
    void showContextMenu(const QPoint &);
};
#endif // BITCOIN_QT_PAYMENTCODEPAGE_H
