#include "recover.h"
#include "ui_recover.h"

#include "guiutil.h"

#include "util.h"

#include "../wallet/wallet.h"
#include "../wallet/bip39.h"
#include "support/allocators/secure.h"

#include <boost/filesystem.hpp>

#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>

Recover::Recover(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Recover),
    thread(0)
{
    // load stylesheet
    GUIUtil::loadTheme();
    
    ui->setupUi(this);
    setCreateNew();
    thread = new QThread(this);

    connect(this, SIGNAL(stopThread()), thread, SLOT(quit()));
    thread->start();
}

Recover::~Recover()
{
    delete ui;
    /* Ensure thread is finished before it is deleted */
    Q_EMIT stopThread();
    thread->wait();
}

void Recover::setCreateNew()
{
    ui->createNew->setChecked(true);
    ui->textLabel2->setEnabled(false);
    ui->mnemonicWords->setEnabled(false);
    ui->mnemonicWords->clear();
    ui->use24->setChecked(true);
    ui->usePassphrase->setChecked(false);
    ui->textLabel3->setEnabled(false);
    ui->textLabel4->setEnabled(false);
    ui->mnemonicPassPhrase->setEnabled(false);
    ui->mnemonicPassPhrase2->setEnabled(false);
}

void Recover::on_createNew_clicked()
{
    setCreateNew();
}

void Recover::on_recoverExisting_clicked()
{
    ui->textLabel2->setEnabled(true);
    ui->mnemonicWords->setEnabled(true);
}

void Recover::on_usePassphrase_clicked()
{
    bool isChecked = ui->usePassphrase->isChecked();

    ui->textLabel3->setEnabled(isChecked);
    ui->textLabel4->setEnabled(isChecked);
    ui->mnemonicPassPhrase->setEnabled(isChecked);
    ui->mnemonicPassPhrase2->setEnabled(isChecked);

    ui->mnemonicPassPhrase->clear();
    ui->mnemonicPassPhrase2->clear();
}

bool Recover::askRecover(bool& newWallet)
{
    namespace fs = boost::filesystem;
    fs::path walletFile = GetDataDir(true) / GetArg("-wallet", DEFAULT_WALLET_DAT);

    if (!fs::exists(walletFile))
    {
        newWallet = true;
        Recover recover;
        recover.setWindowIcon(QIcon(":icons/firo"));
        while(true)
        {
            if(!recover.exec())
            {
                /* Cancel clicked */
                return false;
            } else {
                bool use12 = false;

                if(recover.ui->use12->isChecked()) {
                    use12 = true;
                }

                if(recover.ui->recoverExisting->isChecked()) {
                    newWallet = false;
                    std::string mnemonic = recover.ui->mnemonicWords->text().toStdString();
                    const char* str = mnemonic.c_str();
                    bool space = true;
                    int n = 0;

                    while (*str != '\0')
                    {
                        if (std::isspace(*str))
                        {
                            space = true;
                        }
                        else if (space)
                        {
                            n++;
                            space = false;
                        }
                        ++str;
                    }

                    if((n == 12 && !use12) || (n != 24 && n != 12) || (n != 12 && use12)) {
                        recover.ui->errorMessage->setText(tr("Wrong number of words. Please try again."));
                        continue;
                    }

                    if(mnemonic.empty()) {
                        recover.ui->errorMessage->setText("Mnemonic can't be empty.");
                        continue;
                    }

                    SecureString secmnemonic(mnemonic.begin(), mnemonic.end());
                    if(!Mnemonic::mnemonic_check(secmnemonic)){
                        recover.ui->errorMessage->setText(tr("Something went wrong. Please try again."));
                        continue;
                    }

                    SoftSetArg("-mnemonic", mnemonic);
                }

                if(recover.ui->usePassphrase->isChecked()) {
                    std::string mnemonicPassPhrase = recover.ui->mnemonicPassPhrase->text().toStdString();
                    std::string mnemonicPassPhrase2 = recover.ui->mnemonicPassPhrase2->text().toStdString();

                    if(mnemonicPassPhrase != mnemonicPassPhrase2) {
                        recover.ui->errorMessage->setText(tr("Passphrases don't match."));
                        continue;
                    }

                    if(mnemonicPassPhrase.empty()) {
                        recover.ui->errorMessage->setText(tr("Passphrase can't be empty."));
                        continue;
                    }

                    SoftSetArg("-mnemonicpassphrase", mnemonicPassPhrase);
                }

                if(use12)
                    SoftSetBoolArg("-use12", true);

                if(recover.ui->spinBoxPcodes->value() > 0)
                    SoftSetArg("-defaultpcodenumber", std::to_string(recover.ui->spinBoxPcodes->value()));

                break;
            }
        }
    }
    return true;
}