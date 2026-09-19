#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"
#include "sendcoinsdialog.h"
#include "addressbookpage.h"

#include "guitheme.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "validation.h"
#include "sparkname.h"

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QEvent>
#include <QMenu>
#include <QPushButton>
#include <QStyle>
#include <QMessageBox>
#include <QPointer>
#include <QDateTime>
#include <QLocale>
#include <QSignalBlocker>
#include <QToolButton>
#include <QToolTip>

#include <algorithm>
#include <cstdint>

#define SEND_CONFIRM_DELAY   3

namespace {

constexpr int64_t SPARK_NAME_BLOCKS_PER_YEAR = 365LL * 24 * 24;
constexpr int64_t MAXIMUM_SPARK_NAME_VALIDITY = 15 * SPARK_NAME_BLOCKS_PER_YEAR;

}

CreateSparkNamePage::CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateSparkNamePage),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    const QSize available = GUIUtil::availableScreenSize(this);
    resize(qMin(width(), qMax(1, available.width() - 40)),
           qMin(height(), qMax(1, available.height() - 40)));

    ui->detailsWidget->hide();
    ui->expiryLabel->hide();
    ui->balanceWarningLabel->hide();
    connect(ui->detailsButton, &QToolButton::toggled, this, [this](bool expanded) {
        ui->detailsWidget->setVisible(expanded);
        ui->detailsButton->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    });

    const QString nameHelp = tr("A memorable name, such as @sparky, that people can use to send FIRO to your Spark address while preserving your transaction privacy.");
    ui->nameHelpButton->setToolTip(nameHelp);
    ui->nameHelpButton->setAccessibleDescription(nameHelp);
    ui->nameLabel->setToolTip(nameHelp);
    ui->sparkNameEdit->setToolTip(tr("Use 1–20 letters (A–Z), numbers, hyphens or periods. Names are not case-sensitive."));

    // Derive the displayed tiers from the same schedule used to calculate the fee.
    const auto& fees = Params().GetConsensus().nSparkNamesFee;
    QString feeRows;
    for (size_t first = 1; first < fees.size();) {
        size_t last = first;
        while (last + 1 < fees.size() && fees[last + 1] == fees[first])
            ++last;
        const QString length = first == last
            ? (first == 1 ? tr("1 character") : tr("%1 characters").arg(first))
            : tr("%1–%2 characters").arg(first).arg(last);
        feeRows += QStringLiteral("<tr><td>%1</td><td align=\"right\">%2</td></tr>")
            .arg(length.toHtmlEscaped(), QLocale().toString(fees[first]));
        first = last + 1;
    }
    ui->feeHelpButton->setToolTip(QStringLiteral("<p>%1</p><table cellspacing=\"6\"><tr><th>%2</th><th>%3</th></tr>%4</table><p>%5</p>")
        .arg(tr("Shorter names cost more. The registration fee depends on your name’s length and the number of years selected.").toHtmlEscaped(),
             tr("Name length").toHtmlEscaped(), tr("FIRO per year").toHtmlEscaped(), feeRows,
             tr("The network fee is additional.").toHtmlEscaped()));
    ui->feeHelpButton->setAccessibleDescription(tr("Fees are charged per year based on the length of the name. The network fee is additional."));
    ui->feeLabel->setToolTip(ui->feeHelpButton->toolTip());
    for (QToolButton* button : {ui->nameHelpButton, ui->feeHelpButton}) {
        button->installEventFilter(this);
        connect(button, &QToolButton::clicked, this, [button] {
            QToolTip::showText(button->mapToGlobal(QPoint(0, button->height())), button->toolTip(), button);
        });
    }

    auto* addressMenu = new QMenu(ui->addressOptionsButton);
    addressMenu->addAction(tr("Choose existing address…"), this, &CreateSparkNamePage::chooseExistingAddress);
    addressMenu->addAction(tr("Generate new address"), this, &CreateSparkNamePage::generateSparkAddress);
    addressMenu->addAction(tr("Paste address"), this, [this] {
        if (!extendMode) {
            ui->sparkAddressEdit->setText(QApplication::clipboard()->text().trimmed());
            ui->sparkAddressEdit->setFocus();
        }
    });
    ui->addressOptionsButton->setMenu(addressMenu);
    int nextBlockHeight;
    {
        LOCK(cs_main);
        nextBlockHeight = chainActive.Height() + 1;
    }
    const int maximumYears = nextBlockHeight >= Params().GetConsensus().nSparkNamesV21StartBlock
        ? 15
        : 10;
    ui->numberOfYearsEdit->setValue(1);
    ui->numberOfYearsEdit->setRange(1, maximumYears);
    updateFee();

    ui->numberOfYearsEdit->setMinimumWidth(120);
    ui->numberOfYearsEdit->setAlignment(Qt::AlignLeft);
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
        "QDialog#CreateSparkNamePage, QScrollArea, QScrollArea > QWidget > QWidget { background: $PANEL; border: none; }"
        "QLabel { background: transparent; color: $INK; font-size: 14px; }"
        "QLabel#titleLabel { font-size: 22px; font-weight: 700; }"
        "QLabel#nameLabel, QLabel#addressLabel, QLabel#periodLabel, QLabel#feeLabel { font-weight: 600; }"
        "QLabel#feeTextLabel { font-size: 18px; font-weight: 600; }"
        "QLabel#feeHintLabel, QLabel#detailsHintLabel, QLabel#expiryLabel { color: $INK_SOFT; font-size: 12px; }"
        "QLabel#balanceWarningLabel { color: $ERROR; font-size: 13px; font-weight: 600; }"
        "QLabel#namePrefix { color: $WINE; font-size: 18px; }"
        "QFrame#nameField, QFrame#addressField { background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 10px; }"
        "QLineEdit { background: transparent; color: $INK; border: 1px solid transparent; border-radius: 4px; padding: 4px 0; min-height: 28px; font-size: 16px; }"
        "QLineEdit:focus { border-bottom-color: $WINE; }"
        "QLineEdit:disabled { color: $INK_SOFT; }"
        "QTextEdit { background: $PANEL_SOFT; color: $INK; border: 1px solid $BORDER; border-radius: 10px; padding: 6px 10px; font-size: 14px; }"
        "QTextEdit:focus { border-color: $WINE; }"
        "QToolButton { color: $INK_SOFT; background: transparent; border: 1px solid transparent; padding: 0; font-size: 13px; }"
        "QToolButton:hover, QToolButton:focus { color: $INK; border-color: $WINE; }"
        "QToolButton#nameHelpButton, QToolButton#feeHelpButton { border-color: $BORDER; border-radius: 10px; min-width: 18px; max-width: 18px; min-height: 18px; max-height: 18px; font-weight: 600; }"
        "QToolButton#nameHelpButton:hover, QToolButton#feeHelpButton:hover, QToolButton#nameHelpButton:focus, QToolButton#feeHelpButton:focus { border-color: $WINE; }"
        "QToolButton#addressOptionsButton { min-width: 28px; min-height: 28px; border-radius: 6px; }"
        "QToolButton#addressOptionsButton::menu-indicator { image: none; }"
        "QFrame#divider { background: $BORDER; border: none; max-height: 1px; }")));

    ui->numberOfYearsEdit->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QSpinBox {"
        " background: $PANEL_SOFT; color: $INK;"
        " border: 1px solid $BORDER; border-radius: 10px;"
        " min-height: 36px; font-size: 16px;"
        "}"
        "QSpinBox:focus { border: 1px solid $WINE; }"
        "QSpinBox QLineEdit { %1 }"))
        .arg(GUIUtil::spinBoxInnerLineEditReset()));

    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle(QStringLiteral("5px 14px"));
    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle(QStringLiteral("5px 14px"));
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok))
        okButton->setStyleSheet(primaryButtonStyle);
    if (QPushButton* cancelButton = ui->buttonBox->button(QDialogButtonBox::Cancel))
        cancelButton->setStyleSheet(secondaryButtonStyle);
}

bool CreateSparkNamePage::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::FocusIn &&
        (watched == ui->nameHelpButton || watched == ui->feeHelpButton)) {
        auto* button = qobject_cast<QToolButton*>(watched);
        QToolTip::showText(button->mapToGlobal(QPoint(0, button->height())), button->toolTip(), button);
    }
    return QDialog::eventFilter(watched, event);
}

CreateSparkNamePage::~CreateSparkNamePage()
{
    delete ui;
}

void CreateSparkNamePage::setModel(WalletModel *model)
{
    if (this->model) {
        disconnect(this->model.data(), &WalletModel::balanceChanged,
                   this, &CreateSparkNamePage::checkSparkBalance);
    }
    this->model = model;

    connect(ui->sparkAddressEdit, &QLineEdit::textChanged,
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    connect(ui->sparkNameEdit,    &QLineEdit::textChanged,
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    connect(ui->numberOfYearsEdit, qOverload<int>(&QSpinBox::valueChanged),
            this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    if (model) {
        connect(model, &WalletModel::balanceChanged,
                this, &CreateSparkNamePage::checkSparkBalance, Qt::UniqueConnection);
    }
    checkSparkBalance();
}

void CreateSparkNamePage::setExtendMode(const QString &name, const QString &address)
{
    extendMode = true;
    ui->sparkNameEdit->setText(name);
    ui->sparkNameEdit->setEnabled(false);
    ui->sparkAddressEdit->setText(address);
    ui->sparkAddressEdit->setEnabled(false);
    ui->addressOptionsButton->setEnabled(false);
    ui->titleLabel->setText(tr("Extend Spark Name"));
    ui->periodLabel->setText(tr("Extend by"));
    ui->feeLabel->setText(tr("Extension fee"));
    QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok);
    if (okButton)
        okButton->setText(tr("Extend"));
    this->setWindowTitle(tr("Extend Spark Name"));

    try {
        CSparkNameManager* sparkNameManager = CSparkNameManager::GetInstance();
        ui->additionalInfoEdit->setPlainText(QString::fromStdString(
            sparkNameManager->GetSparkNameAdditionalData(name.toStdString())));
        ui->detailsButton->setChecked(!ui->additionalInfoEdit->toPlainText().isEmpty());

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

void CreateSparkNamePage::chooseExistingAddress()
{
    if (!model || extendMode)
        return;

    QPointer<CreateSparkNamePage> page(this);
    const QPointer<WalletModel> walletModel(model);
    // The page can close during the picker's nested event loop.
    AddressBookPage picker(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, nullptr);
    picker.setInitialAddressType(AddressBookPage::Spark);
    picker.setModel(walletModel->getAddressTableModel());
    connect(this, &QObject::destroyed, &picker, &QDialog::reject);
    connect(walletModel.data(), &QObject::destroyed, &picker, &QDialog::reject);
    if (picker.exec() != QDialog::Accepted || !page || !walletModel || model != walletModel || extendMode)
        return;

    const QString address = picker.getReturnValue();
    if (!model->validateSparkAddress(address) || !model->isSparkAddressMine(address)) {
        QMessageBox::warning(this, tr("Invalid address"), tr("Choose a Spark address that belongs to this wallet."));
        return;
    }
    QString existingName;
    if (model->GetSparkNameByAddress(address, existingName)) {
        QMessageBox::warning(this, tr("Address already registered"),
            tr("This address is already registered as @%1. Extend that name from the Spark Names page, or choose another address.").arg(existingName));
        return;
    }
    ui->sparkAddressEdit->setText(address);
}

void CreateSparkNamePage::generateSparkAddress()
{
    if (!model || extendMode)
        return;
    QString newSparkAddress = model->generateSparkAddress();
    if (!newSparkAddress.isEmpty())
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
    QString sparkAddress = ui->sparkAddressEdit->text().trimmed();
    int numberOfYears = ui->numberOfYearsEdit->value();
    QString additionalInfo = ui->additionalInfoEdit->toPlainText();
    QString strError;

    if (!model->validateSparkAddress(sparkAddress))
        QMessageBox::critical(this, tr("Error"), tr("Invalid spark address"));
    else if (!model->isSparkAddressMine(sparkAddress))
        QMessageBox::critical(this, tr("Error"), tr("The Spark address does not belong to this wallet."));
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
    const int numberOfYears = ui->numberOfYearsEdit->value();
    ui->numberOfYearsEdit->setSuffix(numberOfYears == 1 ? tr(" year") : tr(" years"));
    ui->expiryLabel->clear();
    ui->expiryLabel->setVisible(extendMode);
    if (extendMode && !extensionUnavailableReason.isEmpty()) {
        ui->feeTextLabel->setText(tr("Unavailable"));
        ui->expiryLabel->setText(extensionUnavailableReason);
        return;
    }

    QString sparkName = ui->sparkNameEdit->text();

    if (!CSparkNameManager::IsSparkNameValid(sparkName.toStdString()) ||
        numberOfYears == 0 || numberOfYears > ui->numberOfYearsEdit->maximum()) {
        ui->feeTextLabel->setText(sparkName.isEmpty() ? tr("Enter a name") : tr("Enter a valid name"));
        return;
    }

    int fee = Params().GetConsensus().nSparkNamesFee[sparkName.length()] * numberOfYears;
    ui->feeTextLabel->setText(tr("%1 FIRO").arg(QLocale().toString(fee)));

    if (extendMode) {
        try {
            constexpr int nBlocksPerHour = 24;
            const int64_t newValidityBlocks = numberOfYears * SPARK_NAME_BLOCKS_PER_YEAR;

            int currentBlockHeight;
            {
                LOCK(cs_main);
                currentBlockHeight = chainActive.Height();
            }
            const int nextBlockHeight = currentBlockHeight + 1;
            const int64_t currentExpirationHeight = static_cast<int64_t>(
                CSparkNameManager::GetInstance()->GetSparkNameBlockHeight(
                    CSparkNameManager::ToUpper(sparkName.toStdString())));

            int64_t estimatedExpirationHeight = nextBlockHeight + newValidityBlocks;
            if (nextBlockHeight >= Params().GetConsensus().nSparkNamesV21StartBlock) {
                estimatedExpirationHeight += std::max<int64_t>(
                    0, currentExpirationHeight - nextBlockHeight);
            }
            const int64_t blocksFromNow = std::max<int64_t>(
                0, estimatedExpirationHeight - currentBlockHeight);

            QDateTime expirationDate = QDateTime::currentDateTime().addSecs(
                (qint64)blocksFromNow * 3600 / nBlocksPerHour);

            ui->expiryLabel->setText(tr("New estimated expiration: %1")
                .arg(QLocale::system().toString(expirationDate.date(), QLocale::LongFormat)));
        } catch (const std::runtime_error&) {
            ui->expiryLabel->setText(tr("The updated expiration estimate is unavailable."));
        }
    }
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

        WalletModelTransaction tx = walletModel->initSparkNameTransaction(sparkNameFee);

        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!page || !ctx.isValid())
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
    CAmount available = model->getCachedPrivateBalance();

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
