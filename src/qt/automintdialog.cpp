#include "../validation.h"

#include "automintdialog.h"
#include "bitcoinunits.h"
#include "lelantusmodel.h"
#include "ui_automintdialog.h"

#include <QPushButton>
#include <QDebug>

AutoMintDialog::AutoMintDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutoMintDialog),
    model(0),
    lelantusModel(0),
    requiredPassphase(true)
{
    ENTER_CRITICAL_SECTION(cs_main);
    ENTER_CRITICAL_SECTION(pwalletMain->cs_wallet);

    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("Anonymize");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("Ask me later");
}

AutoMintDialog::~AutoMintDialog()
{
    if (lelantusModel) {
        LEAVE_CRITICAL_SECTION(lelantusModel->cs);
    }

    LEAVE_CRITICAL_SECTION(pwalletMain->cs_wallet);
    LEAVE_CRITICAL_SECTION(cs_main);
}

void AutoMintDialog::accept()
{
    ensureLelantusModel();

    if (requiredPassphase) {
        auto rawPassphase = ui->passEdit->text().toStdString();
        SecureString passphase(rawPassphase.begin(), rawPassphase.end());
        auto lock = ui->lockCheckBox->isChecked();

        lelantusModel->unlockWallet(passphase, lock ? 0 : 60 * 1000);
    }

    ui->warningLabel->setText(QString("Minting..."));
    ui->buttonBox->setVisible(false);
    ui->passEdit->setVisible(false);
    ui->passLabel->setVisible(false);
    ui->lockWarningLabel->setVisible(false);
    ui->lockCheckBox->setVisible(false);
    ui->warningLabel->repaint();

    try {
        auto minted = lelantusModel->mintAll();
        lelantusModel->ackMintAll(AutoMintAck::Success, minted);
    } catch (std::runtime_error const &e) {
        lelantusModel->ackMintAll(AutoMintAck::FailToMint, 0, e.what());
    }

    QDialog::accept();
}

int AutoMintDialog::exec()
{
    ensureLelantusModel();
    if (lelantusModel->getMintableAmount() <= 0) {
        lelantusModel->ackMintAll(AutoMintAck::NotEnoughFund);
        return 0;
    }

    return QDialog::exec();
}

void AutoMintDialog::reject()
{
    ensureLelantusModel();
    lelantusModel->ackMintAll(AutoMintAck::UserReject);
    QDialog::reject();
}

void AutoMintDialog::setModel(WalletModel *model)
{
    this->model = model;
    if (!this->model) {
        return;
    }

    lelantusModel = this->model->getLelantusModel();
    if (!lelantusModel) {
        return;
    }

    ENTER_CRITICAL_SECTION(lelantusModel->cs);

    if (this->model->getEncryptionStatus() != WalletModel::Locked) {
        ui->passLabel->setVisible(false);
        ui->passEdit->setVisible(false);
        ui->lockCheckBox->setVisible(false);

        ui->lockWarningLabel->setText(QString("Do you want to anonymize these funds?"));

        requiredPassphase = false;
    }
}

void AutoMintDialog::ensureLelantusModel()
{
    if (!lelantusModel) {
        throw std::runtime_error("Lelantus model is not set");
    }
}