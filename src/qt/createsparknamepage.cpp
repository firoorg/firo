#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"
#include "sendcoinsdialog.h"
#include "addresstablemodel.h"

#include "platformstyle.h"
#include "validation.h"
#include "compat_layer.h"

#include <QStyle>
#include <QMessageBox>

#define SEND_CONFIRM_DELAY   3

CreateSparkNamePage::CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateSparkNamePage)
{
    ui->setupUi(this);

    feeText = ui->feeTextLabel->text();
    ui->numberOfYearsEdit->setValue(1);
    ui->numberOfYearsEdit->setRange(1, 10);
    updateFee();
}

CreateSparkNamePage::~CreateSparkNamePage()
{
    delete ui;
}

void CreateSparkNamePage::setModel(WalletModel *model)
{
    this->model = model;

    connect(ui->sparkAddressEdit, &QLineEdit::textChanged,
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    connect(ui->sparkNameEdit,    &QLineEdit::textChanged,
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    connect(ui->numberOfYearsEdit, qOverload<int>(&QSpinBox::valueChanged),
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
}

void CreateSparkNamePage::on_generateButton_clicked()
{
    QString newSparkAddress = model->generateSparkAddress();
    ui->sparkAddressEdit->setText(newSparkAddress);
}

void CreateSparkNamePage::on_sparkNameEdit_textChanged(const QString &text)
{
    updateFee();
}

void CreateSparkNamePage::on_numberOfYearsEdit_valueChanged(int value)
{
    updateFee();
}

void CreateSparkNamePage::accept()
{
    if (!model->sparkNamesAllowed()) {
        QMessageBox::critical(this, tr("Error"), tr("Spark names are not yet allowed"));
        return;
    }
    QString sparkName = ui->sparkNameEdit->text();
    QString sparkAddress = ui->sparkAddressEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();
    QString additionalInfo = ui->additionalInfoEdit->toPlainText();
    QString strError;

    if (!model->validateSparkAddress(sparkAddress))
        QMessageBox::critical(this, tr("Error"), tr("Invalid spark address"));
    else if (!model->validateSparkNameData(sparkName, sparkAddress, additionalInfo, strError))
        QMessageBox::critical(this, tr("Error"), tr("Error details: ") + strError);
    else {
        if (CreateSparkNameTransaction(sparkName.toStdString(), sparkAddress.toStdString(), numberOfYears, additionalInfo.toStdString()))
            QDialog::accept();
    }
}

void CreateSparkNamePage::updateFee() {
    QString sparkName = ui->sparkNameEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();

    if (sparkName.isEmpty() || cmp::greater(sparkName.length(), CSparkNameManager::maximumSparkNameLength) || numberOfYears == 0 || numberOfYears > 10)
        ui->feeTextLabel->setText(feeText.arg("?"));
    else
        ui->feeTextLabel->setText(feeText.arg(QString::number(Params().GetConsensus().nSparkNamesFee[sparkName.length()]*numberOfYears)));
}

bool CreateSparkNamePage::CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo)
{
    try {
        LOCK(cs_main);
        LOCK(pwalletMain->cs_wallet);

        const auto &consensusParams = Params().GetConsensus();
        CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

        CSparkNameTxData sparkNameData;
        sparkNameData.nVersion = chainActive.Height() >= consensusParams.nSparkNamesV2StartBlock ? CSparkNameTxData::CURRENT_VERSION : 1;
        sparkNameData.operationType = (uint8_t)CSparkNameTxData::opRegister;
        sparkNameData.name = name;
        sparkNameData.sparkAddress = address;
        sparkNameData.additionalInfo = additionalInfo;
        sparkNameData.sparkNameValidityBlocks = numberOfYears*365*24*24;

        std::string strError;

        if (!sparkNameManager->ValidateSparkNameData(sparkNameData, strError)) {
            QMessageBox::critical(this, tr("Error validating spark name paramaeter"), strError.c_str());
            return false;
        }

        assert(!name.empty() && name.length() <= CSparkNameManager::maximumSparkNameLength);

        CAmount sparkNameFee = consensusParams.nSparkNamesFee[name.length()]*COIN*numberOfYears;
        FIRO_UNUSED CAmount txFee;

        WalletModelTransaction tx = model->initSparkNameTransaction(sparkNameFee);

        using UnlockContext = WalletModel::UnlockContext;
        std::unique_ptr<UnlockContext> ctx = std::unique_ptr<UnlockContext>(new UnlockContext(model->requestUnlock()));
        if (!ctx->isValid())
            return false;

        WalletModel::SendCoinsReturn prepareStatus = model->prepareSparkNameTransaction(tx, sparkNameData, sparkNameFee, nullptr);
        if (prepareStatus.status != WalletModel::StatusCode::OK) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to prepare spark name transaction"));
            return false;
        }

        QString formatted;
        QString questionString = tr("Are you sure you want to register spark name?");
        questionString.append(tr("  You are sending Firo from a Spark address to development fund transparent address."));

        SendConfirmationDialog confirmationDialog(tr("Confirm send coins for registering spark name"),
            questionString, SEND_CONFIRM_DELAY, this);
        confirmationDialog.exec();

        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if (retval != QMessageBox::Yes) {
            return false;
        }

        WalletModel::SendCoinsReturn sendStatus = model->spendSparkCoins(tx);
        if (sendStatus.status != WalletModel::StatusCode::OK) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to send spark name transaction"));
            return false;
        }

        if (model->getEncryptionStatus() != WalletModel::Unencrypted) {
            model->getAddressTableModel()->addRow(
                AddressTableModel::Send,
                QString::fromStdString(name),
                "",
                QString::fromStdString(address)
            );
        }
    }
    catch (const std::exception &) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to create spark name transaction"));
        return false;
    }

    return true;
}

void CreateSparkNamePage::checkSparkBalance()
{
    if (!model)
        return;

    QString sparkName = ui->sparkNameEdit->text();
    QString sparkAddress = ui->sparkAddressEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();

    if (sparkName.isEmpty() ||
        sparkName.length() > CSparkNameManager::maximumSparkNameLength ||
        !model->validateSparkAddress(sparkAddress)) {
        ui->balanceWarningLabel->clear();
        ui->balanceWarningLabel->setVisible(false);
        return;
    }

    CAmount requiredFee = Params().GetConsensus().nSparkNamesFee[sparkName.length()] * COIN * numberOfYears;
    CAmount available = model->getSparkBalance().first;

    if (available < requiredFee) {
        ui->balanceWarningLabel->setText(
            tr("⚠️ Not enough private funds to register this Spark name.")
        );
        ui->balanceWarningLabel->setVisible(true);
    } else {
        ui->balanceWarningLabel->clear();
        ui->balanceWarningLabel->setVisible(false);
    }
}
