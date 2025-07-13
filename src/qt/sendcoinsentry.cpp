// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendcoinsentry.h"
#include "ui_sendcoinsentry.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"

#include <QApplication>
#include <QClipboard>
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
    ui->deleteButton_is->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->deleteButton_s->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    setCurrentWidget(ui->SendCoins);

    if (platformStyle->getUseExtraSpacing())
        ui->payToLayout->setSpacing(4);
#if QT_VERSION >= 0x040700
    ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
#endif

    // normal Firo address field
    GUIUtil::setupAddressWidget(ui->payTo, this);
    // just a label for displaying Firo address(es)
    ui->payTo_is->setFont(GUIUtil::fixedPitchFont());

    // Connect signals
    connect(ui->payAmount, &BitcoinAmountField::valueChanged, this, &SendCoinsEntry::payAmountChanged);
    connect(ui->checkboxSubtractFeeFromAmount, &QCheckBox::toggled, this, &SendCoinsEntry::subtractFeeFromAmountChanged);
    connect(ui->deleteButton, &QToolButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->deleteButton_is, &QToolButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->deleteButton_s, &QToolButton::clicked, this, &SendCoinsEntry::deleteClicked);
    connect(ui->messageTextLabel, &QLineEdit::textChanged, this, &SendCoinsEntry::on_MemoTextChanged);

    ui->messageLabel->setVisible(false);
    ui->messageTextLabel->setVisible(false);
    ui->iconMessageWarning->setVisible(false);
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
    } else {
        QString sanitized = text;
        sanitized.remove(QRegExp("[\\x00-\\x1F\\x7F]"));
        if (sanitized != text) {
            ui->messageTextLabel->setText(sanitized);
            return;
        }
        ui->messageWarning->clear();
        ui->messageWarning->setVisible(false);
        ui->messageTextLabel->setStyleSheet("");
        ui->iconMessageWarning->setVisible(false);
    }
}

void SendCoinsEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SendCoinsEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payTo->setText(dlg.getReturnValue());
        ui->payAmount->setFocus();
    }
}

void SendCoinsEntry::on_payTo_textChanged(const QString &address)
{
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
    // clear UI elements for normal payment
    ui->payTo->clear();
    ui->addAsLabel->clear();
    ui->payAmount->clear();
    ui->checkboxSubtractFeeFromAmount->setCheckState(Qt::Unchecked);
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();
    // clear UI elements for unauthenticated payment request
    ui->payTo_is->clear();
    ui->memoTextLabel_is->clear();
    ui->payAmount_is->clear();
    // clear UI elements for authenticated payment request
    ui->payTo_s->clear();
    ui->memoTextLabel_s->clear();
    ui->payAmount_s->clear();

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendCoinsEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

void SendCoinsEntry::setWarning(bool fAnonymousMode) {
    const QString address = ui->payTo->text();
    const QString warningText = generateWarningText(address, fAnonymousMode);
    const bool hasValidAddress = model->validateAddress(address) || model->validateSparkAddress(address);
    ui->textWarning->setText(warningText);
    ui->textWarning->setVisible(!warningText.isEmpty() && hasValidAddress);
    ui->iconWarning->setVisible(!warningText.isEmpty() && hasValidAddress);
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

    isPcodeEntry = bip47::CPaymentCode::validate(ui->payTo->text().toStdString());

    if (ui->payTo->text().startsWith("@") && ui->payTo->text().size() <= CSparkNameManager::maximumSparkNameLength+1) {
        ui->payTo->setValid(true);
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
    recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

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
    recipient = value;
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
    }
}

void SendCoinsEntry::setAddress(const QString &address)
{
    ui->payTo->setText(address);
    ui->payAmount->setFocus();
}

void SendCoinsEntry::setSubtractFeeFromAmount(bool enable)
{
    ui->checkboxSubtractFeeFromAmount->setCheckState(enable ? Qt::Checked : Qt::Unchecked);
}

bool SendCoinsEntry::isClear()
{
    return ui->payTo->text().isEmpty() && ui->payTo_is->text().isEmpty() && ui->payTo_s->text().isEmpty();
}

bool SendCoinsEntry::isPayToPcode() const
{
    return isPcodeEntry;
}

void SendCoinsEntry::setfAnonymousMode(bool fAnonymousMode)
{
    this->fAnonymousMode = fAnonymousMode;
}

void SendCoinsEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendCoinsEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmount with the current unit
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmount_is->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmount_s->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
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
    ui->payTo->setFont(font);
    ui->payTo_is->setFont(font);
    ui->memoLabel_is->setFont(font);
    ui->memoTextLabel_is->setFont(font);
    ui->amountLabel_is->setFont(font);
    ui->payToLabel_s->setFont(font);
    ui->payTo_s->setFont(font);
    ui->memoLabel_s->setFont(font);
    ui->memoTextLabel_s->setFont(font);
    ui->amountLabel_s->setFont(font);
    ui->checkboxSubtractFeeFromAmount->setFont(font);
    ui->deleteButton->setFont(font);
    ui->pasteButton->setFont(font);
    ui->addressBookButton->setFont(font);
}