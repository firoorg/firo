#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"
#include "sendcoinsdialog.h"

#include "guitheme.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "validation.h"
#include "sparkname.h"
#include "compat_layer.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QStyle>
#include <QMessageBox>
#include <QPointer>
#include <QDateTime>
#include <QLocale>
#include <QSignalBlocker>

#include <algorithm>
#include <cstdint>

#define SEND_CONFIRM_DELAY   3

namespace {

constexpr int64_t SPARK_NAME_BLOCKS_PER_YEAR = 365LL * 24 * 24;
constexpr int64_t MAXIMUM_SPARK_NAME_VALIDITY = 15 * SPARK_NAME_BLOCKS_PER_YEAR;

}

CreateSparkNamePage::CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateSparkNamePage)
{
    ui->setupUi(this);

    feeText = ui->feeTextLabel->text();
    ui->numberOfYearsEdit->setValue(1);
    ui->numberOfYearsEdit->setRange(1, 15);
    updateFee();

    ui->numberOfYearsEdit->setMinimumWidth(96);
    ui->numberOfYearsEdit->setAlignment(Qt::AlignCenter);
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setText(tr("Register"));
        GUIUtil::applyPrimaryButtonShadow(okButton);
    }

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &CreateSparkNamePage::applyTheme);
    applyTheme();
}

void CreateSparkNamePage::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QDialog { background: $BG; }"
        "QScrollArea { background: $BG; border: none; }"
        "QScrollArea > QWidget > QWidget { background: $BG; }")));

    const QString captionStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 12px; font-weight: 700; }"));
    for (QLabel* caption : {ui->label_6, ui->label_2, ui->label_5, ui->label_3}) {
        caption->setStyleSheet(captionStyle);
    }
    ui->label->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; }")));
    ui->label_7->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 12px; font-weight: 700; }")));
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
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok))
        okButton->setStyleSheet(primaryButtonStyle);
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
    QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok);
    if (okButton)
        okButton->setText(tr("Extend"));
    this->setWindowTitle(tr("Extend Spark Name"));

    try {
        CSparkNameManager* sparkNameManager = CSparkNameManager::GetInstance();
        ui->additionalInfoEdit->setPlainText(QString::fromStdString(
            sparkNameManager->GetSparkNameAdditionalData(name.toStdString())));

        int nextBlockHeight;
        {
            LOCK(cs_main);
            nextBlockHeight = chainActive.Height() + 1;
        }
        const int64_t expirationHeight = static_cast<int64_t>(
            sparkNameManager->GetSparkNameBlockHeight(
                CSparkNameManager::ToUpper(name.toStdString())));

        int maximumYears = 10;
        if (nextBlockHeight >= Params().GetConsensus().nSparkNamesV21StartBlock) {
            const int64_t remainingBlocks = std::max<int64_t>(
                0, expirationHeight - nextBlockHeight);
            const int64_t availableBlocks = std::max<int64_t>(
                0, MAXIMUM_SPARK_NAME_VALIDITY - remainingBlocks);
            maximumYears = static_cast<int>(availableBlocks / SPARK_NAME_BLOCKS_PER_YEAR);
        }

        {
            const QSignalBlocker blocker(ui->numberOfYearsEdit);
            if (maximumYears > 0) {
                ui->numberOfYearsEdit->setRange(1, maximumYears);
                ui->numberOfYearsEdit->setValue(
                    std::min(ui->numberOfYearsEdit->value(), maximumYears));
                ui->numberOfYearsEdit->setEnabled(true);
                extensionUnavailableReason.clear();
            } else {
                ui->numberOfYearsEdit->setRange(0, 0);
                ui->numberOfYearsEdit->setEnabled(false);
                extensionUnavailableReason =
                    tr("This Spark Name cannot be extended by a full year yet.");
            }
        }
    } catch (const std::runtime_error&) {
        ui->additionalInfoEdit->clear();
        const QSignalBlocker blocker(ui->numberOfYearsEdit);
        ui->numberOfYearsEdit->setRange(0, 0);
        ui->numberOfYearsEdit->setEnabled(false);
        extensionUnavailableReason =
            tr("This Spark Name could not be found and cannot be extended.");
    }

    if (okButton)
        okButton->setEnabled(extensionUnavailableReason.isEmpty());
    if (!extensionUnavailableReason.isEmpty()) {
        ui->balanceWarningLabel->clear();
        ui->balanceWarningLabel->setVisible(false);
    } else {
        checkSparkBalance();
    }
    updateFee();
}

void CreateSparkNamePage::on_generateButton_clicked()
{
    if (!model)
        return;

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
    if (!model) {
        QMessageBox::critical(this, tr("Error"), tr("The wallet is not available."));
        return;
    }

    if (extendMode && !extensionUnavailableReason.isEmpty()) {
        QMessageBox::warning(this, tr("Extension unavailable"), extensionUnavailableReason);
        return;
    }

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
        QPointer<CreateSparkNamePage> page(this);
        const bool extending = extendMode;
        if (CreateSparkNameTransaction(sparkName.toStdString(), sparkAddress.toStdString(), numberOfYears, additionalInfo.toStdString())) {
            if (!page)
                return;
            QMessageBox::information(
                page.data(),
                tr("Transaction submitted"),
                extending
                    ? tr("The updated expiry will appear after the extension transaction is confirmed.")
                    : tr("The Spark Name will appear after the registration transaction is confirmed."));
            if (!page)
                return;
            QDialog::accept();
        }
    }
}

void CreateSparkNamePage::updateFee() {
    if (extendMode && !extensionUnavailableReason.isEmpty()) {
        ui->feeTextLabel->setText(extensionUnavailableReason);
        return;
    }

    QString sparkName = ui->sparkNameEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();

    if (sparkName.isEmpty() || cmp::greater(sparkName.length(), CSparkNameManager::maximumSparkNameLength) ||
        numberOfYears == 0 || numberOfYears > ui->numberOfYearsEdit->maximum()) {
        ui->feeTextLabel->setText(feeText.arg("?"));
        return;
    }

    int fee = Params().GetConsensus().nSparkNamesFee[sparkName.length()] * numberOfYears;
    QString label;

    if (extendMode) {
        try {
            constexpr int nBlocksPerHour = 24;
            const int64_t newValidityBlocks = numberOfYears * SPARK_NAME_BLOCKS_PER_YEAR;

            int nextBlockHeight;
            {
                LOCK(cs_main);
                nextBlockHeight = chainActive.Height() + 1;
            }
            const int64_t currentExpirationHeight = static_cast<int64_t>(
                CSparkNameManager::GetInstance()->GetSparkNameBlockHeight(
                    CSparkNameManager::ToUpper(sparkName.toStdString())));

            int64_t blocksFromNow = newValidityBlocks;
            if (nextBlockHeight >= Params().GetConsensus().nSparkNamesV21StartBlock) {
                blocksFromNow += std::max<int64_t>(
                    0, currentExpirationHeight - nextBlockHeight);
            }

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
    QPointer<CreateSparkNamePage> page(this);
    WalletModel* const walletModel = model;
    const bool extending = extendMode;
    if (!walletModel)
        return false;

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
        sparkNameData.sparkNameValidityBlocks = static_cast<uint32_t>(
            numberOfYears * SPARK_NAME_BLOCKS_PER_YEAR);

        std::string strError;

        if (!sparkNameManager->ValidateSparkNameData(sparkNameData, strError)) {
            QMessageBox::critical(page.data(), tr("Error validating Spark Name parameter"), strError.c_str());
            return false;
        }

        assert(!name.empty() && name.length() <= CSparkNameManager::maximumSparkNameLength);

        CAmount sparkNameFee = consensusParams.nSparkNamesFee[name.length()]*COIN*numberOfYears;
        FIRO_UNUSED CAmount txFee;

        WalletModelTransaction tx = walletModel->initSparkNameTransaction(sparkNameFee);

        using UnlockContext = WalletModel::UnlockContext;
        std::unique_ptr<UnlockContext> ctx = std::unique_ptr<UnlockContext>(new UnlockContext(walletModel->requestUnlock()));
        if (!page || !ctx->isValid())
            return false;

        WalletModel::SendCoinsReturn prepareStatus;
        GUIUtil::runWalletOperation([walletModel, &prepareStatus, &tx, &sparkNameData, sparkNameFee, nextBlockHeight] {
            prepareStatus = walletModel->prepareSparkNameTransaction(
                tx, sparkNameData, sparkNameFee, nullptr, nextBlockHeight);
        });
        if (!page)
            return false;
        if (prepareStatus.status != WalletModel::StatusCode::OK) {
            QString errorText = extending
                ? tr("Failed to prepare the Spark Name extension transaction.")
                : tr("Failed to prepare the Spark Name registration transaction.");
            if (!prepareStatus.reasonCommitFailed.isEmpty())
                errorText.append(QStringLiteral("\n\n") + prepareStatus.reasonCommitFailed);
            QMessageBox::critical(
                page.data(),
                tr("Error"),
                errorText);
            return false;
        }

        QString questionString = extending
            ? tr("Are you sure you want to extend this Spark Name?")
            : tr("Are you sure you want to register this Spark Name?");
        questionString.append(tr(" You are sending FIRO from a Spark address to the Spark Name fee address."));

        // Keep this stack dialog independent: the modeless page may be deleted while
        // a nested event loop is running.
        SendConfirmationDialog confirmationDialog(
            extending ? tr("Confirm Spark Name extension") : tr("Confirm Spark Name registration"),
            questionString, SEND_CONFIRM_DELAY, nullptr);
        confirmationDialog.exec();

        if (!page)
            return false;

        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

        if (retval != QMessageBox::Yes) {
            return false;
        }

        WalletModel::SendCoinsReturn sendStatus;
        GUIUtil::runWalletOperation([walletModel, &sendStatus, &tx] {
            sendStatus = walletModel->spendSparkCoins(tx);
        });
        if (!page)
            return false;
        if (sendStatus.status != WalletModel::StatusCode::OK) {
            QString errorText = extending
                ? tr("Failed to submit the Spark Name extension transaction.")
                : tr("Failed to submit the Spark Name registration transaction.");
            if (!sendStatus.reasonCommitFailed.isEmpty())
                errorText.append(QStringLiteral("\n\n") + sendStatus.reasonCommitFailed);
            QMessageBox::critical(
                page.data(),
                tr("Error"),
                errorText);
            return false;
        }

    }
    catch (const std::exception &) {
        if (page) {
            QMessageBox::critical(
                page.data(),
                tr("Error"),
                extending
                    ? tr("Failed to extend the Spark Name.")
                    : tr("Failed to register the Spark Name."));
        }
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
