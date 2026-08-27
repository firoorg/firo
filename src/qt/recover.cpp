#include "recover.h"
#include "ui_recover.h"

#include "guitheme.h"
#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "../wallet/wallet.h"
#endif // ENABLE_WALLET
#include "../wallet/bip39.h"
#include "support/allocators/secure.h"

#include <boost/filesystem.hpp>

#include <QCalendarWidget>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QPushButton>
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
    applyTheme();
    setCreateNew();
    thread = new QThread(this);

    connect(this, &Recover::stopThread, thread, &QThread::quit);
    thread->start();

    ui->dateInput->setDisplayFormat("dd-MM-yyyy");
    ui->dateInput->setMinimumDate(QDate(2019, 12, 11));
}

void Recover::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog#Recover { background: $BG; }
        QDialog#Recover QLabel { background: transparent; color: $INK; }
        QDialog#Recover QLabel#errorMessage { color: #E5484D; font-weight: 700; }
        QDialog#Recover QFrame { background: transparent; }
        QDialog#Recover QLineEdit,
        QDialog#Recover QDateEdit,
        QDialog#Recover QSpinBox {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
            selection-background-color: $WINE_DEEP;
            selection-color: #FFFFFF;
        }
        QDialog#Recover QLineEdit:focus,
        QDialog#Recover QDateEdit:focus,
        QDialog#Recover QSpinBox:focus {
            border: 1px solid $WINE;
        }
        QDialog#Recover QLineEdit:disabled,
        QDialog#Recover QDateEdit:disabled,
        QDialog#Recover QSpinBox:disabled {
            color: $INK_FAINT;
        }
        QDialog#Recover QRadioButton,
        QDialog#Recover QCheckBox {
            background: transparent;
            color: $INK;
        }
        QDialog#Recover QRadioButton:disabled,
        QDialog#Recover QCheckBox:disabled {
            color: $INK_FAINT;
        }
        QDialog#Recover QRadioButton::indicator:unchecked {
            image: url(:/images/radio_normal_light);
        }
        QDialog#Recover QRadioButton::indicator:checked {
            image: url(:/images/radio_checked_light);
        }
        QDialog#Recover QCheckBox::indicator:unchecked {
            image: url(:/images/checkbox_normal_light);
        }
        QDialog#Recover QCheckBox::indicator:checked {
            image: url(:/images/checkbox_checked_light);
        }
    )")));

    const QString primaryStyle = GUIUtil::primaryButtonStyle();
    const QString secondaryStyle = GUIUtil::secondaryButtonStyle();
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok))
        okButton->setStyleSheet(primaryStyle);
    if (QPushButton* cancelButton = ui->buttonBox->button(QDialogButtonBox::Cancel))
        cancelButton->setStyleSheet(secondaryStyle);

    if (QCalendarWidget* calendar = ui->dateInput->calendarWidget()) {
        calendar->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QCalendarWidget { background: $PANEL; border: 1px solid $BORDER; }
            #qt_calendar_navigationbar { background: $WINE; min-height: 42px; border: none; }
            #qt_calendar_prevmonth, #qt_calendar_nextmonth {
                background: transparent; border: none; width: 32px; height: 32px;
                border-radius: 8px; qproperty-iconSize: 14px 14px;
            }
            #qt_calendar_monthbutton, #qt_calendar_yearbutton {
                background: transparent; border: none; color: #FFFFFF;
                font-weight: 700; border-radius: 8px; padding: 4px 10px;
            }
            #qt_calendar_prevmonth:hover, #qt_calendar_nextmonth:hover,
            #qt_calendar_monthbutton:hover, #qt_calendar_yearbutton:hover {
                background: rgba(255,255,255,0.16);
            }
            #qt_calendar_calendarview {
                background: $PANEL; border: none; outline: none;
                gridline-color: transparent;
                selection-background-color: $WINE_DEEP; selection-color: #FFFFFF;
            }
            QCalendarWidget QWidget { alternate-background-color: $PANEL_SOFT; }
            QCalendarWidget QToolButton::menu-indicator { image: none; }
            QCalendarWidget QAbstractItemView:enabled {
                color: $INK; selection-background-color: $WINE_DEEP; selection-color: #FFFFFF;
            }
            QCalendarWidget QAbstractItemView:disabled { color: $INK_FAINT; }
            QCalendarWidget QMenu {
                background: $PANEL; color: $INK; border: 1px solid $BORDER;
            }
            QCalendarWidget QSpinBox {
                background: $PANEL; color: $INK; border: 1px solid $BORDER;
            }
        )")));
    }
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
                    std::string mnemonic = recover.ui->mnemonicWords->text().toStdString();
                    QDate date = recover.ui->dateInput->date();
                    QDate newDate = date.addDays(-1);
                    recover.ui->dateInput->setDate(newDate);
                    SoftSetArg("-wcdate", recover.ui->dateInput->text().toStdString());
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
                        recover.ui->errorMessage->setText("Recovery seed phrase can't be empty.");
                        continue;
                    }

                    SecureString secmnemonic(mnemonic.begin(), mnemonic.end());
                    if(!Mnemonic::mnemonic_check(secmnemonic)){
                        recover.ui->errorMessage->setText(tr("You have entered an invalid recovery seed phrase. Please double check the spelling and order."));
                        continue;
                    }

                    SoftSetArg("-mnemonic", mnemonic);
                } else {
                    newWallet = true;
                    SoftSetBoolArg("-newwallet", newWallet);
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
                    SoftSetArg("-defaultrapaddressnumber", std::to_string(recover.ui->spinBoxPcodes->value()));

                break;
            }
        }
    }
#endif // ENABLE_WALLET
    return true;
}
