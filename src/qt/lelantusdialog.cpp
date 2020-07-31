#include "ui_lelantusdialog.h"
#include "lelantusdialog.h"

LelantusDialog::LelantusDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LelantusDialog),
    clientModel(0),
    walletModel(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);
    setWindowTitle(tr("Lelantus"));
}

LelantusDialog::~LelantusDialog()
{
    delete ui;
}

void LelantusDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
}

void LelantusDialog::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;
}