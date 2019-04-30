#include "sigmapage.h"
#include "ui_sigmapage.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "manualmintdialog.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "sendcoinsdialog.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"

#include "../zerocoin_v3.h"
#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../sigma/coin.h"

#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QTimer>

#include <unordered_map>

#define SEND_CONFIRM_DELAY   3

SigmaPage::SigmaPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SigmaPage),
    clientModel(0),
    walletModel(0),
    isNewRecipientAllowed(true),
    platformStyle(platformStyle)
{
    ui->setupUi(this);
    setWindowTitle(tr("Sigma"));

    ui->scrollArea->setBackgroundRole(QPalette::Base);

    if (platformStyle->getImagesOnButtons()) {
        ui->sendButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
        ui->clearButton->setIcon(platformStyle->SingleColorIcon(":/icons/quit"));
        ui->addButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));

        ui->mintButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->selectDenomsButton->setIcon(platformStyle->SingleColorIcon(":/icons/edit"));
    } else {
        ui->sendButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->addButton->setIcon(QIcon());

        ui->mintButton->setIcon(QIcon());
        ui->selectDenomsButton->setIcon(QIcon());
    }

    addEntry();

    // spend
    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
}

void SigmaPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;

    if (model) {
        bool sigmaAllowed = IsSigmaAllowed(model->getNumBlocks());

        connect(model, SIGNAL(numBlocksChanged(int, const QDateTime&, double, bool)), this, SLOT(numBlocksChanged(int, const QDateTime&, double, bool)));

        ui->mintButton->setEnabled(sigmaAllowed);
        ui->sendButton->setEnabled(sigmaAllowed);
    }
}

void SigmaPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;

    if (model && model->getOptionsModel()) {
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)),
            this, SLOT(updateAvailableToMintBalance(CAmount)));
        updateAvailableToMintBalance(model->getBalance());
        connect(model, SIGNAL(notifySigmaChanged(const std::vector<CZerocoinEntryV3>, const std::vector<CZerocoinEntryV3>)),
            this, SLOT(updateCoins(const std::vector<CZerocoinEntryV3>, const std::vector<CZerocoinEntryV3>)));
        model->checkSigmaAmount(true);
        for (int i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if (entry) {
                entry->setModel(model);
            }
        }
    }
}

SigmaPage::~SigmaPage()
{
    delete ui;
}

void SigmaPage::numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if (!header) {
        bool sigmaAllowed = IsSigmaAllowed(count);

        ui->mintButton->setEnabled(sigmaAllowed);
        ui->sendButton->setEnabled(sigmaAllowed);
    }
}

void SigmaPage::on_mintButton_clicked()
{
    auto rawAmount = ui->amountToMint->value();
    CAmount amount(rawAmount * COIN);

    // round any thing smaller than 0.1
    // if more than or equal 0.05 round to 0.1 otherwise round to 0.0
    amount = amount / CENT * CENT + ((amount % CENT >= CENT / 2) ? CENT : 0);

    try {
        walletModel->sigmaMint(amount);
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("You cannot mint Sigma because %1").arg(tr(e.what())),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }

    QMessageBox::information(this, tr("Success"),
        tr("Sigma successfully minted"),
        QMessageBox::Ok, QMessageBox::Ok);

    ui->amountToMint->setValue(0);
}

void SigmaPage::on_sendButton_clicked()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;

    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (entry) {
            if (entry->validate()) {
                recipients.append(entry->getValue());
            } else {
                valid = false;
            }
        }
    }

    if (!valid || recipients.isEmpty()) {
        return;
    }

    isNewRecipientAllowed = false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        isNewRecipientAllowed = true;
        return;
    }

    // prepare transaction for getting txFee earlier
    std::vector<CHDMint> selectedCoins;
    std::vector<CHDMint> changes;
    WalletModelTransaction currentTransaction(recipients);
    auto prepareStatus = walletModel->prepareSigmaSpendTransaction(currentTransaction, selectedCoins, changes);

    // process prepareStatus and on error generate message shown to user
    processSpendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    if (prepareStatus.status != WalletModel::OK) {
        isNewRecipientAllowed = true;
        return;
    }

    CAmount txFee = currentTransaction.getTransactionFee();

    // Format confirmation message
    QStringList formatted;
    for (const auto& rcp : currentTransaction.getRecipients()) {
        // generate bold amount string
        QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), rcp.amount);
        amount.append("</b>");

        // generate monospace address string
        QString address = "<span style='font-family: monospace;'>" + rcp.address;
        address.append("</span>");

        QString recipientElement;

        if (!rcp.paymentRequest.IsInitialized()) {
            if (rcp.label.length() > 0) { // label with address
                recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                recipientElement.append(QString(" (%1)").arg(address));
            } else { // just address
                recipientElement = tr("%1 to %2").arg(amount, address);
            }
        } else if (!rcp.authenticatedMerchant.isEmpty()) { // authenticated payment request
            recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.authenticatedMerchant));
        } else { // unauthenticated payment request
            recipientElement = tr("%1 to %2").arg(amount, address);
        }

        formatted.append(recipientElement);
    }

    QString questionString = tr("Are you sure you want to spend?");
    questionString.append("<br /><br />%1");

    if (txFee > 0) {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)currentTransaction.getTransactionSize() / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
    QStringList alternativeUnits;
    Q_FOREACH(BitcoinUnits::Unit u, BitcoinUnits::availableUnits()) {
        if (u != walletModel->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    questionString.append(QString("<span style='font-size:8pt;font-weight:normal;float:right;'> <br/> <br/> %1</span>")
        .arg("Change will be reminted and amounts smaller than 0.1 will be paid as fees to miners."));

    SendConfirmationDialog confirmationDialog(tr("Confirm spend coins"),
        questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);

    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if (retval != QMessageBox::Yes) {
        isNewRecipientAllowed = true;
        return;
    }

    // now send the prepared transaction
    WalletModel::SendCoinsReturn sendStatus = walletModel->sendSigma(currentTransaction, selectedCoins, changes);
    // process sendStatus and on error generate message shown to user
    processSpendCoinsReturn(sendStatus);

    isNewRecipientAllowed = true;
}

void SigmaPage::clear()
{
    // Remove entries until only one left
    while (ui->entries->count()) {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

SendCoinsEntry *SigmaPage::addEntry() {
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(walletModel);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(SendCoinsEntry*)), this, SLOT(removeEntry(SendCoinsEntry*)));

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if (bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void SigmaPage::updateTabsAndLabels()
{
    setupTabChain(0);
}

void SigmaPage::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

void SigmaPage::updateAvailableToMintBalance(const CAmount& balance)
{
    QString formattedBalance = BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), balance);
    ui->availableAmount->setText(formattedBalance);
}

QWidget *SigmaPage::setupTabChain(QWidget *prev)
{
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (entry) {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SigmaPage::processSpendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // WalletModel::TransactionCommitFailed is used only in WalletModel::sendCoins()
    // all others are used only in WalletModel::prepareTransaction()
    switch (sendCoinsReturn.status) {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::TransactionCommitFailed:
        msgParams.first = tr("The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // case WalletModel::AbsurdFee:
    //     msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), maxTxFee));
    //     break;
    case WalletModel::PaymentRequestExpired:
        msgParams.first = tr("Payment request expired.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

static QString formatAmount(CAmount n)
{
    qint64 coin = BitcoinUnits::factor(BitcoinUnits::Unit::BTC);

    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    qint64 remainder = (n_abs % coin) * 10 / coin;

    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(1, '0');

    if (n < 0)
        quotient_str.insert(0, '-');
    return quotient_str + QString(".") + remainder_str;
}

void SigmaPage::updateCoins(const std::vector<CZerocoinEntryV3>& spendable, const std::vector<CZerocoinEntryV3>& pending)
{
    std::unordered_map<sigma::CoinDenominationV3, int> spendableDenominationCoins;

    CAmount sum(0);
    for (const auto& c : spendable) {
        spendableDenominationCoins[c.get_denomination()]++;
        sum += c.get_denomination_value();
    }

    // update coins amount
    int denom100Amount = spendableDenominationCoins[sigma::CoinDenominationV3::SIGMA_DENOM_100];
    int denom10Amount = spendableDenominationCoins[sigma::CoinDenominationV3::SIGMA_DENOM_10];
    int denom1Amount = spendableDenominationCoins[sigma::CoinDenominationV3::SIGMA_DENOM_1];
    int denom05Amount = spendableDenominationCoins[sigma::CoinDenominationV3::SIGMA_DENOM_0_5];
    int denom01Amount = spendableDenominationCoins[sigma::CoinDenominationV3::SIGMA_DENOM_0_1];

    ui->amountDenom100->setText(QString::fromStdString(std::to_string(denom100Amount)));
    ui->amountDenom10->setText(QString::fromStdString(std::to_string(denom10Amount)));
    ui->amountDenom1->setText(QString::fromStdString(std::to_string(denom1Amount)));
    ui->amountDenom05->setText(QString::fromStdString(std::to_string(denom05Amount)));
    ui->amountDenom01->setText(QString::fromStdString(std::to_string(denom01Amount)));

    CAmount pendingSum(0);
    for (const auto& c : pending) {
        pendingSum += c.get_denomination_value();
    }

    QString pendingAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(pendingSum));
    QString spendableAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(sum));
    QString totalAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(sum + pendingSum));

    ui->pending->setText(pendingAmount);
    ui->spendable->setText(spendableAmount);
    ui->total->setText(totalAmount);
}
