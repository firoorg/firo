#include "notifymnemonic.h"
#include "ui_notifymnemonic.h"

#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "walletmodel.h"
#endif

#include <boost/filesystem.hpp>

#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>

NotifyMnemonic::NotifyMnemonic(QWidget *parent) :
        QDialog(parent),
        ui(new Ui::NotifyMnemonic)
{
    ui->setupUi(this);
}

NotifyMnemonic::~NotifyMnemonic()
{
    delete ui;
}

void NotifyMnemonic::notify()
{
    NotifyMnemonic notify;
    SecureString mnemonic;
    SecureString passphrase;
    pwalletMain->GetHDChain().GetMnemonic(mnemonic, passphrase);
    notify.ui->mnemonic->setText(mnemonic.c_str());
    if(notify.exec())
        return;
}
