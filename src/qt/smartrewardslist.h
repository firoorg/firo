#ifndef SMARTREWARDSLIST_H
#define SMARTREWARDSLIST_H

#include "primitives/transaction.h"
#include "platformstyle.h"
#include "sync.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>

namespace Ui {
    class SmartrewardsList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** SmartrewardsList Manager page widget */
class SmartrewardsList : public QWidget
{
    Q_OBJECT

public:
    explicit SmartrewardsList(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SmartrewardsList();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

Q_SIGNALS:

private:
    Ui::SmartrewardsList *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;

};
#endif // SMARTREWARDSLIST_H
