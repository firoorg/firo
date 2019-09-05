#include "paymentcodepage.h"
#include "ui_paymentcodepage.h"

#include "activeznode.h"
#include "clientmodel.h"
#include "init.h"
#include "guiutil.h"
#include "sync.h"
#include "wallet/wallet.h"
#include "walletmodel.h"

#include <QTimer>
#include <QMessageBox>


PaymentcodePage::PaymentcodePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PaymentcodePage),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);
    contextMenu = new QMenu();

}

PaymentcodePage::~PaymentcodePage()
{
    delete ui;
}

void PaymentcodePage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

void PaymentcodePage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void PaymentcodePage::showContextMenu(const QPoint &point)
{
    contextMenu->exec(QCursor::pos());
}