#include "smartrewardslist.h"
#include "ui_smartrewardslist.h"


#include "clientmodel.h"
#include "init.h"
#include "guiutil.h"
#include "../smartnode/activesmartnode.h"
#include "../smartnode/smartnodesync.h"
#include "../smartnode/smartnodeconfig.h"
#include "../smartnode/smartnodeman.h"
#include "sync.h"
#include "wallet/wallet.h"
#include "walletmodel.h"

#include <QTimer>
#include <QMessageBox>


SmartrewardsList::SmartrewardsList(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SmartrewardsList),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);
}

SmartrewardsList::~SmartrewardsList()
{
    delete ui;
}

void SmartrewardsList::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model) {
       return;
    }
}

void SmartrewardsList::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}
