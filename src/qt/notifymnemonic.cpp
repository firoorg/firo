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
#include <QAbstractButton>

NotifyMnemonic::NotifyMnemonic(QWidget *parent) :
        QWizard(parent),
        ui(new Ui::NotifyMnemonic)
{
    ui->setupUi(this);
    disconnect(QWizard::button(QWizard::CancelButton), SIGNAL(clicked()), this, SLOT(reject()));
    connect(QWizard::button(QWizard::CancelButton), SIGNAL(clicked()), this, SLOT( cancelEvent()));
}

NotifyMnemonic::~NotifyMnemonic()
{
    delete ui;
}

void NotifyMnemonic::cancelEvent()
{
    if( QMessageBox::question( this, trUtf8( "Warning" ), trUtf8( "Are you sure you wish to proceed without confirming whether you have written down your seed words correctly?" ), QMessageBox::Yes, QMessageBox::No ) == QMessageBox::Yes ) {
        // allow cancel
        reject();
    }
}

void NotifyMnemonic::notify()
{
#ifdef ENABLE_WALLET
    SecureString mnemonic;
    pwalletMain->GetMnemonicContainer().GetMnemonic(mnemonic);
    NotifyMnemonic notify;
    notify.setWindowIcon(QIcon(":icons/zcoin"));
    notify.show();
    notify.ui->mnemonic->setText(mnemonic.c_str());
    notify.restart();
    while(true)
    {
        if(notify.exec())
        {
            std::string inputMnememonic = notify.ui->words->toPlainText().toStdString();
            std::string strMnemonic(mnemonic.begin(), mnemonic.end());
            if(inputMnememonic != strMnemonic) {
                notify.ui->errorMessage->setText("<font color='red'>Your entered words do not match, please press back to re-check your mnemonic.</font>");
                continue;
            }
            break;
        } else
            break;
    }
#endif
}
