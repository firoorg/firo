#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"
#include "sendcoinsdialog.h"
#include "addresstablemodel.h"

#include "guitheme.h"
#include "platformstyle.h"
#include "validation.h"
#include "sparkname.h"
#include "compat_layer.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QStyle>
#include <QMessageBox>
#include <QDateTime>
#include <QLocale>

#define SEND_CONFIRM_DELAY   3

CreateSparkNamePage::CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateSparkNamePage)
{
    ui->setupUi(this);

    feeText = ui->feeTextLabel->text();
    ui->numberOfYearsEdit->setValue(1);
    ui->numberOfYearsEdit->setRange(1, 15);
    updateFee();

    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));

    const QString captionStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 11px; font-weight: 700; }"));
    for (QLabel* caption : {ui->label_6, ui->label_2, ui->label_5, ui->label_3}) {
        caption->setStyleSheet(captionStyle);
    }
    ui->label->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; }")));
    ui->label_7->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 11px; font-weight: 700; }")));
    ui->feeTextLabel->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; }")));

    const QString fieldStyle = GUIUtil::themed(QStringLiteral(
        "QLineEdit, QTextEdit {"
        " background: $PANEL_SOFT;"
        " border: 1px solid $BORDER;"
        " border-radius: 10px;"
        " padding: 8px 12px;"
        " color: $INK;"
        "}"
        "QLineEdit:focus, QTextEdit:focus { border: 1px solid $WINE; }"));
    ui->sparkAddressEdit->setStyleSheet(fieldStyle);
    ui->sparkNameEdit->setStyleSheet(fieldStyle);
    ui->additionalInfoEdit->setStyleSheet(fieldStyle);

    ui->numberOfYearsEdit->setMinimumWidth(96);
    ui->numberOfYearsEdit->setAlignment(Qt::AlignCenter);
    ui->numberOfYearsEdit->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QSpinBox {"
        " background: $PANEL_SOFT; color: $INK;"
        " border: 1px solid $BORDER; border-radius: 10px;"
        " min-height: 34px;"
        "}"
        "QSpinBox:focus { border: 1px solid $WINE; }")));

    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle();
    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle();
    ui->generateButton->setStyleSheet(secondaryButtonStyle);
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setText(tr("Register"));
        okButton->setStyleSheet(primaryButtonStyle);
        GUIUtil::applyPrimaryButtonShadow(okButton);
    }
    if (QPushButton* cancelButton = ui->buttonBox->button(QDialogButtonBox::Cancel))
        cancelButton->setStyleSheet(secondaryButtonStyle);
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

void CreateSparkNamePage::setExtendMode(const QString &name, const QString &address)
{
    extendMode = true;
    ui->sparkNameEdit->setText(name);
    ui->sparkNameEdit->setEnabled(false);
    ui->sparkAddressEdit->setText(address);
    ui->sparkAddressEdit->setEnabled(false);
    ui->generateButton->setEnabled(false);
    try {
        ui->additionalInfoEdit->setPlainText(QString::fromStdString(
            CSparkNameManager::GetInstance()->GetSparkNameAdditionalData(name.toStdString())));
    } catch (const std::runtime_error&) {
        ui->additionalInfoEdit->clear();
    }
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok))
        okButton->setText(tr("Extend"));
    this->setWindowTitle(tr("Extend Spark Name"));
    updateFee();
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
        if (CreateSparkNameTransaction(sparkName.toStdString(), sparkAddress.toStdString(), numberOfYears, additionalInfo.toStdString())) {
            QMessageBox::information(
                this,
                tr("Transaction submitted"),
                extendMode
                    ? tr("The updated expiry will appear after the extension transaction is confirmed.")
                    : tr("The Spark Name will appear after the registration transaction is confirmed."));
            QDialog::accept();
        }
    }
}

void CreateSparkNamePage::updateFee() {
    QString sparkName = ui->sparkNameEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();

    if (sparkName.isEmpty() || cmp::greater(sparkName.length(), CSparkNameManager::maximumSparkNameLength) || numberOfYears == 0 || numberOfYears > 15) {
        ui->feeTextLabel->setText(feeText.arg("?"));
        return;
    }

    int fee = Params().GetConsensus().nSparkNamesFee[sparkName.length()] * numberOfYears;
    QString label;

    if (extendMode) {
        try {
            constexpr int nBlocksPerHour = 24;
            int newValidityBlocks = numberOfYears * 365 * 24 * nBlocksPerHour;

            LOCK(cs_main);
            int currentHeight = chainActive.Height();
            int currentExpirationHeight = CSparkNameManager::GetInstance()->GetSparkNameBlockHeight(
                CSparkNameManager::ToUpper(sparkName.toStdString()));

            int remainingBlocks = currentExpirationHeight - currentHeight;
            int totalValidityBlocks = newValidityBlocks + std::max(0, remainingBlocks);
            int blocksFromNow = totalValidityBlocks;

            QDateTime expirationDate = QDateTime::currentDateTime().addSecs(
                (qint64)blocksFromNow * 3600 / nBlocksPerHour);

            label = tr("Fee: %1 FIRO. New estimated expiration: %2")
                .arg(fee)
                .arg(QLocale::system().toString(expirationDate.date(), QLocale::LongFormat));
        } catch (const std::runtime_error&) {
            label = tr("Extension fee: %1 FIRO. The updated expiration estimate is unavailable.")
                .arg(fee);
        }
    } else {
        label = feeText.arg(QString::number(fee));
    }

    ui->feeTextLabel->setText(label);
}

bool CreateSparkNamePage::CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo)
{
    try {
        const auto &consensusParams = Params().GetConsensus();
        CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

        int nextBlockHeight;
        {
            LOCK(cs_main);
            nextBlockHeight = chainActive.Height() + 1;
        }

        CSparkNameTxData sparkNameData;
        sparkNameData.nVersion = nextBlockHeight >=
                consensusParams.nSparkNamesV2StartBlock
            ? CSparkNameTxData::CURRENT_VERSION
            : 1;
        sparkNameData.operationType = (uint8_t)CSparkNameTxData::opRegister;
        sparkNameData.name = name;
        sparkNameData.sparkAddress = address;
        sparkNameData.additionalInfo = additionalInfo;
        sparkNameData.sparkNameValidityBlocks = numberOfYears*365*24*24;

        std::string strError;

        if (!sparkNameManager->ValidateSparkNameData(sparkNameData, strError)) {
            QMessageBox::critical(this, tr("Error validating Spark Name parameter"), strError.c_str());
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

        WalletModel::SendCoinsReturn prepareStatus = model->prepareSparkNameTransaction(
            tx, sparkNameData, sparkNameFee, nullptr, nextBlockHeight);
        if (prepareStatus.status != WalletModel::StatusCode::OK) {
            QString errorText = extendMode
                ? tr("Failed to prepare the Spark Name extension transaction.")
                : tr("Failed to prepare the Spark Name registration transaction.");
            if (!prepareStatus.reasonCommitFailed.isEmpty())
                errorText.append(QStringLiteral("\n\n") + prepareStatus.reasonCommitFailed);
            QMessageBox::critical(
                this,
                tr("Error"),
                errorText);
            return false;
        }

        QString questionString = extendMode
            ? tr("Are you sure you want to extend this Spark Name?")
            : tr("Are you sure you want to register this Spark Name?");
        questionString.append(tr(" You are sending FIRO from a Spark address to the Spark Name fee address."));

        SendConfirmationDialog confirmationDialog(
            extendMode ? tr("Confirm Spark Name extension") : tr("Confirm Spark Name registration"),
            questionString, SEND_CONFIRM_DELAY, this);
        confirmationDialog.exec();

        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if (retval != QMessageBox::Yes) {
            return false;
        }

        WalletModel::SendCoinsReturn sendStatus = model->spendSparkCoins(tx);
        if (sendStatus.status != WalletModel::StatusCode::OK) {
            QString errorText = extendMode
                ? tr("Failed to submit the Spark Name extension transaction.")
                : tr("Failed to submit the Spark Name registration transaction.");
            if (!sendStatus.reasonCommitFailed.isEmpty())
                errorText.append(QStringLiteral("\n\n") + sendStatus.reasonCommitFailed);
            QMessageBox::critical(
                this,
                tr("Error"),
                errorText);
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
        QMessageBox::critical(
            this,
            tr("Error"),
            extendMode
                ? tr("Failed to extend the Spark Name.")
                : tr("Failed to register the Spark Name."));
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
            extendMode
                ? tr("⚠️ Not enough private funds to extend this Spark Name.")
                : tr("⚠️ Not enough private funds to register this Spark Name.")
        );
        ui->balanceWarningLabel->setVisible(true);
    } else {
        ui->balanceWarningLabel->clear();
        ui->balanceWarningLabel->setVisible(false);
    }
}
