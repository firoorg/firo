#include "recover.h"
#include "ui_recover.h"

#include "guiutil.h"

#include "util.h"

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
    std::string dataDir = GetDataDir(false).string();
    if(dataDir.empty())
        throw std::runtime_error("Can't get data directory");

    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
    , testNet = GetOptBoolArg("-testnet");

    if (testNet && regTest && *testNet && *regTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (regTest && *regTest)
        dataDir += "/regtest";
    if (testNet && *testNet)
        dataDir += "/testnet3";

    dataDir += "/wallet.dat";

    if(!fs::exists(GUIUtil::qstringToBoostPath(QString::fromStdString(dataDir))))
    {
        newWallet = true;
        SoftSetBoolArg("-rescanmnemonic", true);
        Recover recover;
        recover.setWindowIcon(QIcon(":icons/zcoin"));
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
                        recover.ui->errorMessage->setText("<font color='red'>Wrong number of words. Please try again.</font>");
                        continue;
                    }

                    if(mnemonic.empty()) {
                        recover.ui->errorMessage->setText("<font color='red'>Mnemonic can't be empty.</font>");
                        continue;
                    }

                    SecureString secmnemonic(mnemonic.begin(), mnemonic.end());
                    if(!Mnemonic::mnemonic_check(secmnemonic)){
                        recover.ui->errorMessage->setText("<font color='red'>Something went wrong. Please try again.</font>");
                        continue;
                    }

                    SoftSetArg("-mnemonic", mnemonic);
                }

                if(recover.ui->usePassphrase->isChecked()) {
                    std::string mnemonicPassPhrase = recover.ui->mnemonicPassPhrase->text().toStdString();
                    std::string mnemonicPassPhrase2 = recover.ui->mnemonicPassPhrase2->text().toStdString();

                    if(mnemonicPassPhrase != mnemonicPassPhrase2) {
                        recover.ui->errorMessage->setText("<font color='red'>Passphrases don't match.</font>");
                        continue;
                    }

                    if(mnemonicPassPhrase.empty()) {
                        recover.ui->errorMessage->setText("<font color='red'>Passphrase can't be empty.</font>");
                        continue;
                    }

                    SoftSetArg("-mnemonicpassphrase", mnemonicPassPhrase);
                }

                if(use12)
                    SoftSetBoolArg("-use12", true);
                break;
            }
        }
    }
    return true;
}