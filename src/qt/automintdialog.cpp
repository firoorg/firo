#include "../validation.h"

#include "automintdialog.h"
#include "bitcoinunits.h"
#include "lelantusmodel.h"
#include "ui_automintdialog.h"

#include <QPushButton>

#define WAITING_TIME 5 * 60

AutoMintDialog::AutoMintDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutoMintDialog),
    model(0),
    lelantusModel(0)
{
    cs_main.lock();
    pwalletMain->cs_wallet.lock();

    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("Mint");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("Ask me later");
}

AutoMintDialog::~AutoMintDialog()
{
    if (lelantusModel) {
        lelantusModel->cs.unlock();
    }

    pwalletMain->cs_wallet.unlock();
    cs_main.unlock();
}

void AutoMintDialog::accept()
{
    ensureLelantusModel();

    ui->warningLabel->setText(QString("Minting..."));
    ui->buttonBox->setVisible(false);
    ui->passEdit->setVisible(false);
    ui->passLabel->setVisible(false);
    ui->warningLabel->repaint();

    lelantusModel->mintAll();

    auto t = QDateTime::currentDateTime();
    t = t.addSecs(WAITING_TIME);

    lelantusModel->resumeAutoMint(true, t);

    QDialog::accept();
}

int AutoMintDialog::exec()
{
    ensureLelantusModel();

    if (lelantusModel->getMintableAmount() == 0) {
        lelantusModel->resumeAutoMint(false);
        return 0;
    }

    return QDialog::exec();
}

void AutoMintDialog::reject()
{
    ensureLelantusModel();
    auto t = QDateTime::currentDateTime();
    t = t.addSecs(WAITING_TIME);

    lelantusModel->resumeAutoMint(false, t);

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

    lelantusModel->cs.lock();

    if (this->model->getEncryptionStatus() != WalletModel::Locked) {
        ui->passLabel->setVisible(false);
        ui->passEdit->setVisible(false);
    }

    {
        auto amount = lelantusModel->getMintableAmount();
        auto text = ui->warningLabel->text();
        text.replace("AMOUNT", BitcoinUnits::format(BitcoinUnit::BTC, amount));
        ui->warningLabel->setText(text);
    }
}

void AutoMintDialog::ensureLelantusModel()
{
    if (!lelantusModel) {
        throw std::runtime_error("Lelantus model is not set");
    }
}