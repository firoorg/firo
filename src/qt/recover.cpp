#include "recover.h"
#include "ui_recover.h"

#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "../wallet/wallet.h"
#endif // ENABLE_WALLET
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

    connect(this, &Recover::stopThread, thread, &QThread::quit);
    thread->start();

    ui->dateInput->setDisplayFormat("dd-MM-yyyy");
    ui->dateInput->setMinimumDate(QDate(2019, 12, 11));
}

Recover::~Recover()
{
    /* Ensure thread is finished before deleting ui */
    Q_EMIT stopThread();
    thread->wait();
    delete ui;
}

void Recover::setCreateNew()
{
    ui->createNew->setChecked(true);
    ui->textLabel2->setEnabled(false);
    ui->mnemonicWords->setEnabled(false);
    ui->mnemonicWords->clear();
    ui->dateInput->setEnabled(false);
    ui->dateInput->clear();
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
    ui->dateInput->setDisplayFormat("dd-MM-yyyy");
    ui->dateInput->setDate(QDate(2019, 12, 11));
}

void Recover::on_recoverExisting_clicked()
{
    ui->textLabel2->setEnabled(true);
    ui->mnemonicWords->setEnabled(true);
    ui->dateInput->setEnabled(true);
    ui->dateInput->setEnabled(true);
    ui->dateInput->setDisplayFormat("dd-MM-yyyy");
    ui->dateInput->setDate(ui->dateInput->minimumDate());
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
#ifdef ENABLE_WALLET
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
                    QByteArray mnemonicBytes = recover.ui->mnemonicWords->text().toUtf8();
                    QDate date = recover.ui->dateInput->date();
                    QDate newDate = date.addDays(-1);
                    recover.ui->dateInput->setDate(newDate);
                    SoftSetArg("-wcdate", recover.ui->dateInput->text().toStdString());
                    const char* str = mnemonicBytes.constData();
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
                        mnemonicBytes.fill('\0');
                        continue;
                    }

                    if(mnemonicBytes.isEmpty()) {
                        recover.ui->errorMessage->setText("Recovery seed phrase can't be empty.");
                        continue;
                    }

                    SecureString secmnemonic(mnemonicBytes.constData(), mnemonicBytes.constData() + mnemonicBytes.size());
                    mnemonicBytes.fill('\0');
                    if(!Mnemonic::mnemonic_check(secmnemonic)){
                        recover.ui->errorMessage->setText(tr("You have entered an invalid recovery seed phrase. Please double check the spelling and order."));
                        continue;
                    }

                    SoftSetArg("-mnemonic", std::string(secmnemonic.begin(), secmnemonic.end()));
                } else {
                    newWallet = true;
                    SoftSetBoolArg("-newwallet", newWallet);
                }

                if(recover.ui->usePassphrase->isChecked()) {
                    QByteArray passBytes1 = recover.ui->mnemonicPassPhrase->text().toUtf8();
                    QByteArray passBytes2 = recover.ui->mnemonicPassPhrase2->text().toUtf8();

                    if(passBytes1 != passBytes2) {
                        recover.ui->errorMessage->setText(tr("Passphrases don't match."));
                        passBytes1.fill('\0');
                        passBytes2.fill('\0');
                        continue;
                    }

                    if(passBytes1.isEmpty()) {
                        recover.ui->errorMessage->setText(tr("Passphrase can't be empty."));
                        continue;
                    }

                    SoftSetArg("-mnemonicpassphrase", std::string(passBytes1.constData(), passBytes1.size()));
                    passBytes1.fill('\0');
                    passBytes2.fill('\0');
                }

                if(use12)
                    SoftSetBoolArg("-use12", true);

                if(recover.ui->spinBoxPcodes->value() > 0)
                    SoftSetArg("-defaultrapaddressnumber", std::to_string(recover.ui->spinBoxPcodes->value()));

                break;
            }
        }
    }
#endif // ENABLE_WALLET
    return true;
}