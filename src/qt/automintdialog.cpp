#include "../validation.h"

#include "automintdialog.h"
#include "automintmodel.h"
#include "bitcoinunits.h"
#include "sparkmodel.h"
#include "ui_automintdialog.h"

#include <QMessageBox>
#include <QPushButton>
#include <QDebug>

AutoMintSparkDialog::AutoMintSparkDialog(AutoMintSparkMode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutoMintDialog),
    model(0),
    sparkModel(0),
    requiredPassphase(true),
    progress(AutoMintSparkProgress::Start),
    mode(mode)
{
    ENTER_CRITICAL_SECTION(cs_main);
    ENTER_CRITICAL_SECTION(pwalletMain->cs_wallet);

    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Anonymize"));
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Cancel"));
}

AutoMintSparkDialog::~AutoMintSparkDialog()
{
    if (sparkModel) {
        LEAVE_CRITICAL_SECTION(sparkModel->cs);
    }

    LEAVE_CRITICAL_SECTION(pwalletMain->cs_wallet);
    LEAVE_CRITICAL_SECTION(cs_main);
}

void AutoMintSparkDialog::accept()
{
    ensureSparkModel();

    ui->buttonBox->setVisible(false);
    ui->passEdit->setVisible(false);
    ui->passLabel->setVisible(false);
    ui->lockWarningLabel->setVisible(false);
    ui->lockCheckBox->setVisible(false);

    if (requiredPassphase) {
        auto rawPassphase = ui->passEdit->text().toStdString();
        SecureString passphase(rawPassphase.begin(), rawPassphase.end());
        auto lock = ui->lockCheckBox->isChecked();

        progress = AutoMintSparkProgress::Unlocking;
        repaint();

        if (!sparkModel->unlockSparkWallet(passphase, lock ? 0 : 60 * 1000)) {
            QMessageBox::critical(this, tr("Wallet unlock failed"),
                                  tr("The passphrase was incorrect."));
            QDialog::reject();
            return;
        }
    }

    progress = AutoMintSparkProgress::Minting;
    repaint();

    AutoMintSparkAck status;
    CAmount minted = 0;
    QString error;

    try {
        minted = sparkModel->mintSparkAll();
        status = AutoMintSparkAck::Success;
    } catch (std::runtime_error const &e) {
        status = AutoMintSparkAck::FailToMint;
        error = e.what();
        QMessageBox::critical(this, tr("Unable to generate mint"),
                              tr(error.toLocal8Bit().data()));
    }

    QDialog::accept();

    sparkModel->sendAckMintSparkAll(status, minted, error);
}

int AutoMintSparkDialog::exec()
{
    ensureSparkModel();
    if (sparkModel->getMintableSparkAmount() <= 0) {
        sparkModel->sendAckMintSparkAll(AutoMintSparkAck::NotEnoughFund);
        return 0;
    }

    return QDialog::exec();
}

void AutoMintSparkDialog::reject()
{
    ensureSparkModel();
    sparkModel->sendAckMintSparkAll(AutoMintSparkAck::UserReject);
    QDialog::reject();
}

void AutoMintSparkDialog::setModel(WalletModel *model)
{
    LOCK(sparkModel->cs);

    this->model = model;
    if (!this->model) {
        return;
    }

    sparkModel = this->model->getSparkModel();
    if (!sparkModel) {
        return;
    }

    CCriticalSectionLocker criticalLocker(sparkModel->cs);

    if (this->model->getEncryptionStatus() != WalletModel::Locked) {
        ui->passLabel->setVisible(false);
        ui->passEdit->setVisible(false);
        ui->lockCheckBox->setVisible(false);
        ui->lockWarningLabel->setText(QString(tr("Do you want to anonymize all transparent funds?")));

        requiredPassphase = false;
    }
}

void AutoMintSparkDialog::paintEvent(QPaintEvent *event)
{
    QPainter painter;
    painter.begin(this);

    if (progress != AutoMintSparkProgress::Start) {
        auto progressMessage = progress == AutoMintSparkProgress::Unlocking ? tr("Unlocking wallet...") : tr("Anonymizing...");
        auto size = QFontMetrics(painter.font()).size(Qt::TextSingleLine, progressMessage);
        painter.drawText(
            (width() - size.width()) / 2,
            (height() - size.height()) / 2,
            QString(progressMessage));
    }

    QWidget::paintEvent(event);
    painter.end();
}

void AutoMintSparkDialog::ensureSparkModel()
{
    if (!sparkModel) {
        throw std::runtime_error("Spark model is not set");
    }
}