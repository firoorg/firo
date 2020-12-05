#include "../validation.h"

#include "automintdialog.h"
#include "automintmodel.h"
#include "bitcoinunits.h"
#include "lelantusmodel.h"
#include "ui_automintdialog.h"

#include <QMessageBox>
#include <QPushButton>
#include <QDebug>

AutoMintDialog::AutoMintDialog(AutoMintMode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutoMintDialog),
    model(0),
    lelantusModel(0),
    requiredPassphase(true),
    progress(AutoMintProgress::Start),
    mode(mode)
{
    ENTER_CRITICAL_SECTION(cs_main);
    ENTER_CRITICAL_SECTION(pwalletMain->cs_wallet);

    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("Anonymize");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("Cancel");
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

    ui->buttonBox->setVisible(false);
    ui->passEdit->setVisible(false);
    ui->passLabel->setVisible(false);
    ui->lockWarningLabel->setVisible(false);
    ui->lockCheckBox->setVisible(false);

    if (requiredPassphase) {
        auto rawPassphase = ui->passEdit->text().toStdString();
        SecureString passphase(rawPassphase.begin(), rawPassphase.end());
        auto lock = ui->lockCheckBox->isChecked();

        progress = AutoMintProgress::Unlocking;
        repaint();

        if (!lelantusModel->unlockWallet(passphase, lock ? 0 : 60 * 1000)) {
            QMessageBox::critical(this, tr("Wallet unlock failed"),
                                  tr("The passphrase was incorrect."));
            return;
        }
    }

    progress = AutoMintProgress::Minting;
    repaint();

    AutoMintAck status;
    CAmount minted = 0;
    QString error;

    try {
        minted = lelantusModel->mintAll();
        status = AutoMintAck::Success;
    } catch (std::runtime_error const &e) {
        status = AutoMintAck::FailToMint;
        error = e.what();
    }

    QDialog::accept();

    lelantusModel->sendAckMintAll(status, minted, error);
}

int AutoMintDialog::exec()
{
    ensureLelantusModel();
    if (lelantusModel->getMintableAmount() <= 0) {
        lelantusModel->sendAckMintAll(AutoMintAck::NotEnoughFund);
        return 0;
    }

    return QDialog::exec();
}

void AutoMintDialog::reject()
{
    ensureLelantusModel();
    lelantusModel->sendAckMintAll(AutoMintAck::UserReject);
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
        ui->lockWarningLabel->setText(QString("Do you want to anonymize all transparent funds?"));

        requiredPassphase = false;
    }
}

void AutoMintDialog::paintEvent(QPaintEvent *event)
{
    QPainter painter;
    painter.begin(this);

    if (progress != AutoMintProgress::Start) {
        auto progressMessage = progress == AutoMintProgress::Unlocking ? "Unlocking wallet..." : "Anonymizing...";
        auto size = QFontMetrics(painter.font()).size(Qt::TextSingleLine, progressMessage);
        painter.drawText(
            (width() - size.width()) / 2,
            (height() - size.height()) / 2,
            QString(progressMessage));
    }

    QWidget::paintEvent(event);
    painter.end();
}

void AutoMintDialog::ensureLelantusModel()
{
    if (!lelantusModel) {
        throw std::runtime_error("Lelantus model is not set");
    }
}