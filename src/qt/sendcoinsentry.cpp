// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendcoinsentry.h"
#include "ui_sendcoinsentry.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "rosenbridge.h"
#include "walletmodel.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"

#include <QApplication>
#include <QClipboard>

#include <QRegularExpression>

#include<QResizeEvent>

SendCoinsEntry::SendCoinsEntry(const PlatformStyle *_platformStyle, QWidget *parent) :
    QStackedWidget(parent),
    ui(new Ui::SendCoinsEntry),
    model(0),
    platformStyle(_platformStyle),
    isPcodeEntry(false)
{
    ui->setupUi(this);

    QIcon icon_;
    icon_.addFile(QString::fromUtf8(":/icons/ic_warning"), QSize(), QIcon::Normal, QIcon::On);
    ui->iconWarning->setPixmap(icon_.pixmap(18, 18));
    ui->iconMessageWarning->setPixmap(icon_.pixmap(18, 18));

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    setCurrentWidget(ui->SendCoins);

    updatePageSizePolicies();
    connect(this, &QStackedWidget::currentChanged,
            this, [this](int) { updatePageSizePolicies(); });

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);
#if QT_VERSION >= 0x040700
    ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
#endif

    // normal Firo address field
    GUIUtil::setupAddressWidget(ui->payTo, this, true);

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
    connect(ui->checkboxSubtractFeeFromAmount, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
    connect(ui->deleteButton, &QToolButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->messageTextLabel, &QLineEdit::textChanged, this, &SendCoinsEntry::on_MemoTextChanged);

    ui->messageLabel->setVisible(false);
    ui->messageTextLabel->setVisible(false);
    ui->iconMessageWarning->setVisible(false);
    ui->rosenBridgeLabel->setVisible(false);
    ui->rosenBridgeDetails->setVisible(false);

    ui->SendCoins->setAttribute(Qt::WA_StyledBackground, true);
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &SendCoinsEntry::applyTheme);
    applyTheme();
    ui->payAmount->setExpanding(true, 420);
}

void SendCoinsEntry::updatePageSizePolicies()
{
    for (int i = 0; i < count(); ++i) {
        QWidget* page = widget(i);
        if (!page)
            continue;
        page->setSizePolicy(QSizePolicy::Preferred,
                            i == currentIndex() ? QSizePolicy::Preferred
                                                : QSizePolicy::Ignored);
    }
    updateGeometry();
}

void SendCoinsEntry::applyTheme()
{
    ui->SendCoins->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QFrame#SendCoins {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 18px;
        }
        QFrame#SendCoins QLabel {
            background: transparent;
            border: none;
        }
        QFrame#SendCoins QLabel#payToLabel,
        QFrame#SendCoins QLabel#labellLabel,
        QFrame#SendCoins QLabel#amountLabel,
        QFrame#SendCoins QLabel#messageLabel {
            color: $INK_FAINT;
            font-size: 11px;
            font-weight: 700;
        }
        QFrame#SendCoins QLabel#sparkNameResolvedLabel {
            color: $INK_FAINT;
            font-size: 10px;
            font-weight: 700;
        }
        QFrame#SendCoins QLabel#sparkNameResolvedAddress {
            color: $TEAL;
            font-size: 11px;
            font-weight: 600;
            font-family: monospace;
        }
        QFrame#SendCoins QValidatedLineEdit,
        QFrame#SendCoins QLineEdit,
        QFrame#SendCoins AmountSpinBox {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
            selection-background-color: $WINE;
        }
        QFrame#SendCoins QValidatedLineEdit:focus,
        QFrame#SendCoins QLineEdit:focus,
        QFrame#SendCoins AmountSpinBox:focus {
            background: $PANEL_SOFT;
            border: 1px solid $WINE;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
        }
        QFrame#SendCoins AmountSpinBox[invalidInput="true"],
        QFrame#SendCoins QValidatedLineEdit[invalidInput="true"] {
            border-color: #E5484D;
        }
        QFrame#SendCoins AmountSpinBox QLineEdit { %1 }
        QFrame#SendCoins QValueComboBox {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 6px 10px;
            color: $INK;
        }
        QFrame#SendCoins QValueComboBox QAbstractItemView {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 4px;
            outline: none;
            color: $INK;
        }
        QFrame#SendCoins QValueComboBox::item {
            padding: 8px 10px;
            border-radius: 8px;
            color: $INK;
        }
        QFrame#SendCoins QValueComboBox::item:alternate {
            background: $PANEL;
            color: $INK;
        }
        QFrame#SendCoins QValueComboBox::item:selected {
            background: $WINE;
            color: #FFFFFF;
        }
        QFrame#SendCoins QToolButton {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 8px;
            padding: 4px;
            margin-left: 6px;
        }
        QFrame#SendCoins QToolButton:hover {
            background: $PANEL_SOFT;
        }
        QFrame#SendCoins QCheckBox {
            color: $INK_FAINT;
            font-size: 10px;
            font-weight: 700;
        }
        QFrame#SendCoins QCheckBox::indicator:unchecked {
            image: url(:/images/checkbox_normal_light);
        }
        QFrame#SendCoins QCheckBox::indicator:checked {
            image: url(:/images/checkbox_checked_light);
        }
    )")).arg(GUIUtil::spinBoxInnerLineEditReset()));
}

SendCoinsEntry::~SendCoinsEntry()
{
    delete ui;
}

void SendCoinsEntry::on_MemoTextChanged(const QString &text)
{
    const spark::Params* params = spark::Params::get_default();
    int maxLength = params->get_memo_bytes();
    bool isOverLimit = text.length() > maxLength;

    if (isOverLimit) {
        ui->messageWarning->setText(QString("Message exceeds %1 bytes limit").arg(maxLength));
        ui->messageWarning->setVisible(true);
        ui->messageTextLabel->setStyleSheet("border: 1px solid red;");
        ui->iconMessageWarning->setVisible(true);
        ui->messageWarningRow->setVisible(true);
    } else {
        QString sanitized = text;
        sanitized.remove(QRegularExpression("[\\x00-\\x1F\\x7F]"));
        if (sanitized != text) {
            ui->messageTextLabel->setText(sanitized);
            return;
        }
        ui->messageWarning->clear();
        ui->messageWarning->setVisible(false);
        ui->messageTextLabel->setStyleSheet("");
        ui->iconMessageWarning->setVisible(false);
        ui->messageWarningRow->setVisible(false);
    }
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    const QString text = QApplication::clipboard()->text().trimmed();
    if (!applyPaymentURI(text)) {
        clearRosenBridgeData();
        ui->payTo->setText(text);
    }
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        clearRosenBridgeData();
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
    if (!applyingRecipient && address.startsWith(QStringLiteral("firo:"), Qt::CaseInsensitive) &&
        applyPaymentURI(address)) {
        return;
    }
    if (!applyingRecipient && !recipient.opReturnData.empty()) {
        clearRosenBridgeData();
    }

    updateLabel(address);
    setWarning(fAnonymousMode);

    bool isSparkAddress = false;
    if (model) {
        const QString payToText = ui->payTo->text();
        isSparkAddress = model->validateSparkAddress(address) ||
                        (payToText.startsWith("@") && payToText.size() <= CSparkNameManager::maximumSparkNameLength + 1);
    }
    ui->messageLabel->setVisible(isSparkAddress);
    ui->messageTextLabel->setVisible(isSparkAddress);

    updateSparkNameResolution();
}

void SendCoinsEntry::updateSparkNameResolution()
{
    const QString payToText = ui->payTo->text();
    QString resolvedAddress;
    if (model && payToText.startsWith(QStringLiteral("@")) && payToText.size() > 1 &&
        cmp::less_equal(payToText.size(), CSparkNameManager::maximumSparkNameLength + 1)) {
        resolvedAddress = model->getSparkNameAddress(payToText.mid(1));
    }

    const bool resolved = !resolvedAddress.isEmpty();
    ui->sparkNameResolvedRow->setVisible(resolved);
    if (resolved) {
        const QString truncated = resolvedAddress.size() > 24
            ? resolvedAddress.left(14) + QStringLiteral("...") + resolvedAddress.right(8)
            : resolvedAddress;
        ui->sparkNameResolvedAddress->setText(truncated);
        ui->sparkNameResolvedAddress->setToolTip(resolvedAddress);
    } else {
        ui->sparkNameResolvedAddress->clear();
        ui->sparkNameResolvedAddress->setToolTip(QString());
    }
}

bool SendCoinsEntry::applyPaymentURI(const QString& uri)
{
    if (!uri.startsWith(QStringLiteral("firo:"), Qt::CaseInsensitive)) {
        return false;
    }

    SendCoinsRecipient parsed;
    if (!GUIUtil::parseBitcoinURI(uri, &parsed) || parsed.address.isEmpty()) {
        return false;
    }

    setValue(parsed);
    return true;
}

void SendCoinsEntry::clearRosenBridgeData()
{
    if (recipient.opReturnData.empty()) {
        return;
    }

    recipient.opReturnData.clear();
    updateRosenBridgeDisplay();
    Q_EMIT rosenBridgeChanged();
}

void SendCoinsEntry::updateRosenBridgeDisplay()
{
    RosenBridge::Metadata metadata;
    const bool valid = !recipient.opReturnData.empty() && RosenBridge::Parse(recipient.opReturnData, &metadata);

    const bool subtractFeeAllowed = !fAnonymousMode && !valid;

    ui->rosenBridgeLabel->setVisible(valid);
    ui->rosenBridgeDetails->setVisible(valid);
    ui->rosenBridgeRow->setVisible(valid);
    ui->payAmount->setReadOnly(valid);

    ui->checkboxSubtractFeeFromAmount->setEnabled(subtractFeeAllowed);
    if (!subtractFeeAllowed) {
        ui->checkboxSubtractFeeFromAmount->setChecked(false);
    }

    if (!valid) {
        ui->rosenBridgeDetails->clear();
        ui->rosenBridgeDetails->setToolTip(QString());
        ui->rosenBridgeDetails->setStyleSheet(QString());
        return;
    }

    QString details = tr("Metadata: %1 bytes\n").arg(static_cast<qulonglong>(recipient.opReturnData.size()));
    details += RosenBridge::FormatDetails(metadata);
    details += tr("\nRaw data: %1").arg(RosenBridge::HexStr(recipient.opReturnData));

    if (fAnonymousMode) {
        details.prepend(tr("Switch to Transparent Balance to send this Rosen Bridge transfer.\n"));
        ui->rosenBridgeDetails->setStyleSheet(QStringLiteral("color: #aa0000;"));
    } else {
        ui->rosenBridgeDetails->setStyleSheet(QString());
    }

    ui->rosenBridgeDetails->setText(details);
    ui->rosenBridgeDetails->setToolTip(tr("This transaction includes Rosen Bridge OP_RETURN metadata."));
}

void SendCoinsEntry::setModel(WalletModel *_model)
{
    this->model = _model;

    if (_model && _model->getOptionsModel())
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsEntry::updateDisplayUnit);

    clear();
}

void SendCoinsEntry::clear()
{
    applyingRecipient = true;
    recipient = SendCoinsRecipient();

    // clear UI elements for normal payment
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    ui->checkboxSubtractFeeFromAmount->setCheckState(Qt::Unchecked);
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();
    updateSparkNameResolution();

    applyingRecipient = false;
    updateRosenBridgeDisplay();
    Q_EMIT rosenBridgeChanged();

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendCoinsEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

void SendCoinsEntry::setWarning(bool fAnonymousMode) {
    if (!model) {
        ui->textWarning->clear();
        ui->textWarning->hide();
        ui->iconWarning->hide();
        ui->addressWarningRow->hide();
        return;
    }

    const QString address = ui->payTo->text();
    const QString warningText = generateWarningText(address, fAnonymousMode);
    const bool hasValidAddress = model &&
        (model->validateAddress(address) || model->validateSparkAddress(address));
    ui->textWarning->setText(warningText);
    ui->textWarning->setVisible(!warningText.isEmpty() && hasValidAddress);
    ui->iconWarning->setVisible(!warningText.isEmpty() && hasValidAddress);
    ui->addressWarningRow->setVisible(!warningText.isEmpty() && hasValidAddress);
}

QString SendCoinsEntry::generateWarningText(const QString& address, const bool fAnonymousMode)
{
    QString warningText;

    if (address.startsWith("EX")) {
        warningText = tr(" You are sending Firo to an Exchange Address. Exchange Addresses can only receive funds from a transparent address.");
    } else {
        if (!fAnonymousMode) {
            if (pwalletMain->validateAddress(address.toStdString())) {
                warningText = tr(" You are sending Firo from a transparent address to another transparent address. To protect your privacy, we recommend using Spark addresses instead.");
            } else if (pwalletMain->validateSparkAddress(address.toStdString())) {
                warningText = tr(" You are sending Firo from a transparent address to a Spark address.");
            }
        } else {
            if (pwalletMain->validateSparkAddress(address.toStdString())) {
                warningText = tr(" You are sending Firo from a Spark address to another Spark address. This transaction is fully private.");
            } else if (pwalletMain->validateAddress(address.toStdString())) {
                warningText = tr(" You are sending Firo from a private Spark pool to a transparent address. Please note that some exchanges do not accept direct Spark deposits.");
            }
        }
    }
    return warningText;
}

bool SendCoinsEntry::validate()
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

    if (!recipient.opReturnData.empty()) {
        if (fAnonymousMode || !model->validateAddress(ui->payTo->text()) ||
            !RosenBridge::Parse(recipient.opReturnData) ||
            ui->checkboxSubtractFeeFromAmount->isChecked()) {
            retval = false;
        }
    }

    isPcodeEntry = bip47::CPaymentCode::validate(ui->payTo->text().toStdString());

    if (ui->payTo->text().startsWith("@") && cmp::less_equal(ui->payTo->text().size(), CSparkNameManager::maximumSparkNameLength+1)) {
        const bool nameResolves = !model->getSparkNameAddress(ui->payTo->text().mid(1)).isEmpty();
        ui->payTo->setValid(nameResolves);
        if (!nameResolves)
            retval = false;
    }
    else if (!(model->validateAddress(ui->payTo->text()) || model->validateSparkAddress(ui->payTo->text()) || isPcodeEntry))
    {
        ui->payTo->setValid(false);
        retval = false;
    }

    if (!ui->payAmount->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(0) <= 0)
    {
        ui->payAmount->setValid(false);
        retval = false;
    }

    // Reject dust outputs:
    if (retval && GUIUtil::isDust(ui->payTo->text(), ui->payAmount->value())) {
        ui->payAmount->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient SendCoinsEntry::getValue()
{
    recipient.address = ui->payTo->text();
    recipient.label = ui->addAsLabel->text();
    recipient.amount = ui->payAmount->value();
    recipient.message = ui->messageTextLabel->text();
    recipient.fSubtractFeeFromAmount = recipient.opReturnData.empty() &&
        (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

    return recipient;
}

QWidget *SendCoinsEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addAsLabel);
    QWidget *w = ui->payAmount->setupTabChain(ui->addAsLabel);
    QWidget::setTabOrder(w, ui->checkboxSubtractFeeFromAmount);
    QWidget::setTabOrder(ui->checkboxSubtractFeeFromAmount, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void SendCoinsEntry::setValue(const SendCoinsRecipient &value)
{
    applyingRecipient = true;
    recipient = value;
    if (!recipient.opReturnData.empty() && !RosenBridge::Parse(recipient.opReturnData)) {
        recipient.opReturnData.clear();
    }
    if (!recipient.opReturnData.empty()) {
        recipient.fSubtractFeeFromAmount = false;
    }
    {
        // message
        ui->messageTextLabel->setText(recipient.message);
        ui->messageTextLabel->setVisible(!recipient.message.isEmpty());
        ui->messageLabel->setVisible(!recipient.message.isEmpty());

        ui->addAsLabel->clear();
        ui->payTo->setText(recipient.address); // this may set a label from addressbook
        if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            ui->addAsLabel->setText(recipient.label);
        ui->payAmount->setValue(recipient.amount);
        ui->checkboxSubtractFeeFromAmount->setChecked(recipient.fSubtractFeeFromAmount);
    }
    applyingRecipient = false;
    updateRosenBridgeDisplay();
    Q_EMIT rosenBridgeChanged();
}

void SendCoinsEntry::setAddress(const QString &address)
{
    clearRosenBridgeData();
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void SendCoinsEntry::setSubtractFeeFromAmount(bool enable)
{
    ui->checkboxSubtractFeeFromAmount->setCheckState(enable && recipient.opReturnData.empty() ? Qt::Checked : Qt::Unchecked);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

bool SendCoinsEntry::hasRosenBridgeData() const
{
    return !recipient.opReturnData.empty();
}

bool SendCoinsEntry::isPayToPcode() const
{
    return isPcodeEntry;
}

void SendCoinsEntry::setfAnonymousMode(bool fAnonymousMode)
{
    this->fAnonymousMode = fAnonymousMode;

    // A Spark spend may need more than one transaction, and the fee cannot then be
    // taken out of a single recipient's amount. prepareSpendSparkTransactionsSingleInput
    // rejects the flag, so take the checkbox away rather than failing at send time.
    if (fAnonymousMode) {
        ui->checkboxSubtractFeeFromAmount->setCheckState(Qt::Unchecked);
    }
    ui->checkboxSubtractFeeFromAmount->setEnabled(!fAnonymousMode);

    updateRosenBridgeDisplay();
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

bool SendCoinsEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel;
    if(bip47::CPaymentCode::validate(address.toStdString()))
    {
        associatedLabel = QString::fromStdString(model->getWallet()->GetSendingPcodeLabel(address.toStdString()));
    }
    else
    {
        associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    }

    ui->addAsLabel->setText(associatedLabel);
    return true;
}
void SendCoinsEntry::resizeEvent(QResizeEvent* event) {
    QStackedWidget::resizeEvent(event);

    const int newWidth = event->size().width();
    const int newHeight = event->size().height();

    adjustTextSize(newWidth, newHeight);
}


void SendCoinsEntry::adjustTextSize(int width, int height) {
   const double fontSizeScalingFactor = 130.0;
    int baseFontSize = width / fontSizeScalingFactor;
    int fontSize = std::max(12,baseFontSize);
    QFont font = this->font();
    font.setPointSize(fontSize);

    ui->payToLabel->setFont(font);
    ui->labellLabel->setFont(font);
    ui->addAsLabel->setFont(font);
    ui->amountLabel->setFont(font);
    ui->messageLabel->setFont(font);
    ui->messageTextLabel->setFont(font);
    ui->rosenBridgeLabel->setFont(font);
    ui->rosenBridgeDetails->setFont(font);
    ui->payTo->setFont(font);
    ui->checkboxSubtractFeeFromAmount->setFont(font);
    ui->deleteButton->setFont(font);
    ui->pasteButton->setFont(font);
    ui->addressBookButton->setFont(font);
}
