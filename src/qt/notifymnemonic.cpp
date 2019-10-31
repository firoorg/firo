#include "notifymnemonic.h"
#include "ui_notifymnemonic.h"

#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "walletmodel.h"
#endif

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
#ifdef ENABLE_WALLET
    NotifyMnemonic notify;
    notify.setWindowIcon(QIcon(":icons/zcoin"));
    SecureString mnemonic;
    pwalletMain->GetMnemonicConatiner().GetMnemonic(mnemonic);
    notify.ui->mnemonic->setText(mnemonic.c_str());
    notify.exec();
#endif
}
