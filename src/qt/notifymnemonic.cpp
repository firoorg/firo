#include "notifymnemonic.h"
#include "ui_notifymnemonic.h"

#include "guitheme.h"
#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "walletmodel.h"
#endif

#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>
#include <QAbstractButton>
#include <QDate>

NotifyMnemonic::NotifyMnemonic(QWidget *parent) :
        QWizard(parent),
        ui(new Ui::NotifyMnemonic)
{
    ui->setupUi(this);
    applyTheme();
    disconnect(QWizard::button(QWizard::CancelButton), &QAbstractButton::clicked, this, &QDialog::reject);
    connect(QWizard::button(QWizard::CancelButton), &QAbstractButton::clicked, this, &NotifyMnemonic::cancelEvent);
}

void NotifyMnemonic::applyTheme()
{
    GUIUtil::loadTheme();

    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QWizard#NotifyMnemonic { background: $BG; }
        QWizard#NotifyMnemonic QWizardPage { background: $BG; }
        QWizard#NotifyMnemonic QLabel { background: transparent; color: $INK; }
        QWizard#NotifyMnemonic QLabel#textLabel4 { color: $INK_FAINT; font-size: 11px; font-weight: 700; }
        QWizard#NotifyMnemonic QLabel#errorMessage { color: #E5484D; font-weight: 700; }
        QWizard#NotifyMnemonic QFrame#mnemonicBox {
            background: $WINE_TINT;
            border: 1.5px solid $WINE;
            border-radius: 16px;
        }
        QWizard#NotifyMnemonic QLabel#mnemonic {
            color: $INK;
            font-family: 'Menlo', 'Courier New', monospace;
            font-size: 13px;
        }
        QWizard#NotifyMnemonic QTextEdit {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
        }
    )")));

    if (QAbstractButton* nextButton = QWizard::button(QWizard::NextButton))
        nextButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    if (QAbstractButton* finishButton = QWizard::button(QWizard::FinishButton))
        finishButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    if (QAbstractButton* backButton = QWizard::button(QWizard::BackButton))
        backButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
    if (QAbstractButton* cancelButton = QWizard::button(QWizard::CancelButton))
        cancelButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
}

NotifyMnemonic::~NotifyMnemonic()
{
    delete ui;
}

void NotifyMnemonic::cancelEvent()
{
    if( QMessageBox::question( this, tr( "Warning" ), tr( "Are you sure you wish to proceed without confirming whether you have written down your seed words correctly?" ), QMessageBox::Yes, QMessageBox::No ) == QMessageBox::Yes ) {
        // allow cancel
        reject();
    }
}

QString getCurrentDate() {
    return QDate::currentDate().toString("dd-MM-yyyy");
}

void NotifyMnemonic::notify()
{
#ifdef ENABLE_WALLET
    SecureString mnemonic;
    pwalletMain->GetMnemonicContainer().GetMnemonic(mnemonic);
    NotifyMnemonic notify;
    notify.setWindowIcon(QIcon(":icons/firo"));
    notify.show();
    notify.ui->walletBirthDate->setText("Wallet creation date:  " + getCurrentDate());
    notify.ui->mnemonic->setText(mnemonic.c_str());
    notify.restart();
    while(true)
    {
        if(notify.exec())
        {
            std::string inputMnememonic = notify.ui->words->toPlainText().toStdString();
            std::string strMnemonic(mnemonic.begin(), mnemonic.end());
            if(inputMnememonic != strMnemonic) {
                notify.ui->errorMessage->setText("<font color='red'>" + tr("Your entered words do not match, please press back to re-check your mnemonic.") + "</font>");
                continue;
            }
            break;
        } else
            break;
    }
#endif
}
