#include "sigmadialog.h"
#include "ui_sigmadialog.h"
#include "ui_blanksigmadialog.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "manualmintdialog.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "sendcoinsdialog.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"

#include "../sigma.h"
#include "../wallet/wallet.h"
#include "../wallet/walletdb.h"
#include "../sigma/coin.h"

#include <qt/sigmacoincontroldialog.h>
#include <wallet/coincontrol.h>

#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QTimer>

#include <unordered_map>

#define SEND_CONFIRM_DELAY   3

BlankSigmaDialog::BlankSigmaDialog() :
    ui(new Ui::BlankSigmaDialog)
{
    ui->setupUi(this);
    setWindowTitle(tr("sigma"));
}

BlankSigmaDialog::~BlankSigmaDialog()
{
    delete ui;
}

SigmaDialog::SigmaDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SigmaDialog),
    clientModel(0),
    walletModel(0),
    isNewRecipientAllowed(true),
    platformStyle(platformStyle)
{
    ui->setupUi(this);
    setWindowTitle(tr("Sigma"));

    ui->scrollArea->setBackgroundRole(QPalette::Base);
    ui->selectDenomsButton->hide();

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

    // init coin control section
    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
    // Coin Control
    connect(ui->pushButtonCoinControl, SIGNAL(clicked()), this, SLOT(coinControlButtonClicked()));
    connect(ui->checkBoxCoinControlChange, SIGNAL(stateChanged(int)), this, SLOT(coinControlChangeChecked(int)));
    connect(ui->lineEditCoinControlChange, SIGNAL(textEdited(const QString &)), this, SLOT(coinControlChangeEdited(const QString &)));
    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardPriorityAction = new QAction(tr("Copy priority"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardFee()));
    connect(clipboardAfterFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAfterFee()));
    connect(clipboardBytesAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardBytes()));
    connect(clipboardPriorityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardPriority()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardChange()));
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlPriority->addAction(clipboardPriorityAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    ui->amountToMint->setLocale(QLocale::c());

    //check if user clicked at a tab
    connect(ui->tabWidget, SIGNAL(currentChanged(int)), this, SLOT(tabSelected()));
}

void SigmaDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;

    if (model) {
        bool sigmaAllowed = sigma::IsSigmaAllowed(model->getNumBlocks());

        connect(model, SIGNAL(numBlocksChanged(int, const QDateTime&, double, bool)), this, SLOT(numBlocksChanged(int, const QDateTime&, double, bool)));

        ui->mintButton->setEnabled(sigmaAllowed);
        ui->sendButton->setEnabled(sigmaAllowed);
    }
}

void SigmaDialog::setWalletModel(WalletModel *model)
{
    this->walletModel = model;

    if (model && model->getOptionsModel()) {
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)),
            this, SLOT(updateAvailableToMintBalance(CAmount)));
        updateAvailableToMintBalance(model->getBalance());
        connect(model, SIGNAL(notifySigmaChanged(const std::vector<CMintMeta>, const std::vector<CMintMeta>)),
            this, SLOT(updateCoins(const std::vector<CMintMeta>, const std::vector<CMintMeta>)));
        model->checkSigmaAmount(true);
        for (int i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if (entry) {
                entry->setModel(model);
                entry->setSubtractFeeFromAmount(true);
            }
        }
    }

    // Coin Control
    connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(coinControlUpdateLabels()));
    connect(model->getOptionsModel(), SIGNAL(coinControlFeaturesChanged(bool)), this, SLOT(coinControlFeatureChanged(bool)));
    ui->frameCoinControl->setVisible(model->getOptionsModel()->getCoinControlFeatures());
    coinControlUpdateLabels();
}

void SigmaDialog::tabSelected(){
    bool coinControlSelected = walletModel->getOptionsModel()->getCoinControlFeatures();
    if(ui->tabWidget->currentIndex()==0){
        SigmaCoinControlDialog::fMintTabSelected = true;
        if(coinControlSelected)
            ui->coinControlChange->show();
    }
    if(ui->tabWidget->currentIndex()==1){
        SigmaCoinControlDialog::fMintTabSelected = false;
        if(coinControlSelected)
            ui->coinControlChange->hide();
    }
}

SigmaDialog::~SigmaDialog()
{
    delete ui;
}

void SigmaDialog::numBlocksChanged(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if (!header) {
        bool sigmaAllowed = sigma::IsSigmaAllowed(count);

        ui->mintButton->setEnabled(sigmaAllowed);
        ui->sendButton->setEnabled(sigmaAllowed);
    }
}

static QString formatAmount(CAmount n);

void SigmaDialog::on_mintButton_clicked()
{
    auto rawAmount = ui->amountToMint->value();
    CAmount amount(rawAmount * COIN);

    // round any thing smaller than 0.01
    // if more than or equal 0.005 round to 0.01 otherwise round to 0.00
    amount = amount / CENT * CENT + ((amount % CENT >= CENT / 2) ? CENT : 0);

    // check if amount to mint is impossible to process.
    std::vector<sigma::CoinDenomination> denoms;
    sigma::GetAllDenoms(denoms);

    auto smallestDenomination = denoms.back();
    CAmount smallestDenominationValue;
    sigma::DenominationToInteger(smallestDenomination, smallestDenominationValue);

    if (amount < smallestDenominationValue) {
        QMessageBox::critical(this, tr("Amount too small to mint"),
            tr("Amount to mint must not be lower than %1 XZC.").arg(formatAmount(smallestDenominationValue)),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }

    if (amount % smallestDenominationValue != 0) {
        amount -= amount % smallestDenominationValue;
        auto reply = QMessageBox::question(
            this, tr("Unable to mint."),
            tr("Amount to mint must be a multiple of 0.05 XZC. Do you want to spend %1 XZC?"
            ).arg(formatAmount(amount)));

        if (reply == QMessageBox::No) {
            return;
        }
    }

    try {
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid()) {
            return;
        }
        if (walletModel->getOptionsModel()->getCoinControlFeatures()){
            walletModel->sigmaMint(amount, SigmaCoinControlDialog::coinControl);
        }else{
            walletModel->sigmaMint(amount);
        }
    } catch (const std::runtime_error& e) {
        QMessageBox::critical(this, tr("Error"),
            tr("You cannot mint Sigma because %1").arg(tr(e.what())),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }



    QMessageBox::information(this, tr("Success"),
        tr("Sigma successfully minted"),
        QMessageBox::Ok, QMessageBox::Ok);

    SigmaCoinControlDialog::coinControl->UnSelectAll();
    coinControlUpdateLabels();

    ui->amountToMint->setValue(0);
}

void SigmaDialog::on_sendButton_clicked()
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
    std::vector<CSigmaEntry> selectedCoins;
    std::vector<CHDMint> changes;
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;
    bool fChangeAddedToFee = false;
    if (walletModel->getOptionsModel()->getCoinControlFeatures()){
        prepareStatus = walletModel->prepareSigmaSpendTransaction(currentTransaction, selectedCoins, changes, fChangeAddedToFee, SigmaCoinControlDialog::coinControl);
    }else{
        prepareStatus = walletModel->prepareSigmaSpendTransaction(currentTransaction, selectedCoins, changes, fChangeAddedToFee);
    }

    // process prepareStatus and on error generate message shown to user
    processSpendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    // Check unsafe coins
    if (prepareStatus.status == WalletModel::AmountExceedsBalance) {
        auto unsafeCoins = walletModel->GetUnsafeCoins();
        std::vector<CAmount> unsafeDenomVals;
        for (const auto coin : unsafeCoins) {
            unsafeDenomVals.push_back(coin.get_denomination_value());
        }
        std::sort(unsafeDenomVals.begin(), unsafeDenomVals.end());

        QString unsafeDenomsStr = tr("");
        for (const auto denomVal : unsafeDenomVals) {
            sigma::CoinDenomination denom;
            sigma::IntegerToDenomination(denomVal, denom);
            auto denomStr = sigma::DenominationToString(denom).c_str();
            unsafeDenomsStr.append(tr("%1, ").arg(denomStr));
        }

        if (!unsafeCoins.empty()) {
            unsafeDenomsStr.resize(unsafeDenomsStr.size() - 2);
            unsafeDenomsStr.append(tr(" denomination"));
            if (unsafeCoins.size() > 1) {
                unsafeDenomsStr.append(tr("s"));
            }

            QMessageBox::information(this, tr("Have unspendable coins."),
                tr("To protect your privacy, we require you to wait until more people mint %1, Once this is done, your minted coin will be spendable.").arg(unsafeDenomsStr),
                QMessageBox::Ok);
        }
    }

    if (prepareStatus.status != WalletModel::OK) {
        isNewRecipientAllowed = true;
        return;
    }

    CAmount txFee = currentTransaction.getTransactionFee();
    CAmount totalAmount(0);

    auto walletTx = currentTransaction.getTransaction();

    // Format confirmation message
    QStringList formatted;
    for (auto const &rcp : currentTransaction.getRecipients()) {

        CAmount realAmount = rcp.amount;
        CScript recipientScriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());

        for (auto const &out : walletTx->tx->vout) {
            if (out.scriptPubKey == recipientScriptPubKey) {
                realAmount = out.nValue;
            }
        }

        totalAmount += realAmount;

        // generate bold amount string
        QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), realAmount);
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
    totalAmount += txFee;
    QStringList alternativeUnits;
    Q_FOREACH(BitcoinUnits::Unit u, BitcoinUnits::availableUnits()) {
        if (u != walletModel->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    std::string info = "";

    if(walletTx->tx->vout.size() > recipients.size())
        info += "Change will be reminted";

    if(fChangeAddedToFee) {
        if(info == "")
            info = "Amounts smaller than 0.05 are added to fee.";
        else
            info += " and amounts smaller than 0.05 are added to fee.";
    }

    questionString.append(QString("<span style='font-size:8pt;font-weight:normal;float:right;'> <br/> <br/> %1</span>")
        .arg(tr(info.c_str())));

    SendConfirmationDialog confirmationDialog(tr("Confirm spend coins"),
        questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);

    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if (retval != QMessageBox::Yes) {
        isNewRecipientAllowed = true;
        return;
    }

    //reset cc
    if(walletModel->getOptionsModel()->getCoinControlFeatures())
        SigmaCoinControlDialog::coinControl->SetNull();

    // now send the prepared transaction
    WalletModel::SendCoinsReturn sendStatus = walletModel->sendSigma(currentTransaction, selectedCoins, changes);
    // process sendStatus and on error generate message shown to user
    processSpendCoinsReturn(sendStatus);

    if (sendStatus.status == WalletModel::OK) {
        accept();
        SigmaCoinControlDialog::coinControl->UnSelectAll();
        coinControlUpdateLabels();
    }

    isNewRecipientAllowed = true;
}

void SigmaDialog::clear()
{
    // Remove entries until only one left
    while (ui->entries->count()) {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

void SigmaDialog::accept()
{
    clear();
}

SendCoinsEntry *SigmaDialog::addEntry() {
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(walletModel);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(SendCoinsEntry*)), this, SLOT(removeEntry(SendCoinsEntry*)));

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setSubtractFeeFromAmount(true);
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if (bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void SigmaDialog::updateTabsAndLabels()
{
    setupTabChain(0);
}

void SigmaDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

void SigmaDialog::updateAvailableToMintBalance(const CAmount& balance)
{
    QString formattedBalance = BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), balance);
    ui->availableAmount->setText(formattedBalance);
}

// Coin Control: copy label "Quantity" to clipboard
void SigmaDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SigmaDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SigmaDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SigmaDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SigmaDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Priority" to clipboard
void SigmaDialog::coinControlClipboardPriority()
{
    GUIUtil::setClipboard(ui->labelCoinControlPriority->text());
}

// Coin Control: copy label "Dust" to clipboard
void SigmaDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SigmaDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: update labels
void SigmaDialog::coinControlUpdateLabels()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;

    // set pay amounts
    SigmaCoinControlDialog::payAmounts.clear();
    SigmaCoinControlDialog::fSubtractFeeFromAmount = false;
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            SigmaCoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                SigmaCoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (SigmaCoinControlDialog::coinControl->HasSelected())
    {

        // actual coin control calculation
        SigmaCoinControlDialog::updateLabels(walletModel, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

// Coin Control: button inputs -> show actual coin control dialog
void SigmaDialog::coinControlButtonClicked()
{
    SigmaCoinControlDialog dlg(platformStyle);
    dlg.setModel(walletModel);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SigmaDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked)
    {
        SigmaCoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SigmaDialog::coinControlChangeEdited(const QString& text)
{
    if (walletModel && walletModel->getAddressTableModel())
    {
        // Default to no change address until verified
        SigmaCoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        CBitcoinAddress addr = CBitcoinAddress(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!addr.IsValid()) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Zcoin address"));
        }
        else // Valid address
        {
            CKeyID keyid;
            addr.GetKeyID(keyid);
            if (!walletModel->havePrivKey(keyid)) // Unknown change address
            {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = walletModel->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                SigmaCoinControlDialog::coinControl->destChange = addr.Get();
            }
        }
    }
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SigmaDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && walletModel) // coin control features disabled
        SigmaCoinControlDialog::coinControl->SetNull();

    coinControlUpdateLabels();
}

QWidget *SigmaDialog::setupTabChain(QWidget *prev)
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

void SigmaDialog::processSpendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
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
    case WalletModel::ExceedLimit:
        msgParams.first = tr("Transaction exceeds max number of spends (35) or value (500 XZC per transaction), please reduce the amount you wish to spend.");
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
    qint64 remainder = (n_abs % coin) * 100 / coin;

    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(2, '0');

    if (n < 0)
        quotient_str.insert(0, '-');
    return quotient_str + QString(".") + remainder_str;
}

void SigmaDialog::updateCoins(const std::vector<CMintMeta>& spendable, const std::vector<CMintMeta>& pending)
{
    std::unordered_map<sigma::CoinDenomination, int> spendableDenominationCoins;

    CAmount sum(0);
    int64_t denom;
    for (const auto& c : spendable) {
        spendableDenominationCoins[c.denom]++;
        DenominationToInteger(c.denom, denom);
        sum += denom;
    }

    // update coins amount
    int denom100Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_100];
    int denom25Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_25];
    int denom10Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_10];
    int denom1Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_1];
    int denom05Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_0_5];
    int denom01Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_0_1];
    int denom005Amount = spendableDenominationCoins[sigma::CoinDenomination::SIGMA_DENOM_0_05];

    ui->amountDenom100->setText(QString::fromStdString(std::to_string(denom100Amount)));
    ui->amountDenom25->setText(QString::fromStdString(std::to_string(denom25Amount)));
    ui->amountDenom10->setText(QString::fromStdString(std::to_string(denom10Amount)));
    ui->amountDenom1->setText(QString::fromStdString(std::to_string(denom1Amount)));
    ui->amountDenom05->setText(QString::fromStdString(std::to_string(denom05Amount)));
    ui->amountDenom01->setText(QString::fromStdString(std::to_string(denom01Amount)));
    ui->amountDenom005->setText(QString::fromStdString(std::to_string(denom005Amount)));

    CAmount pendingSum(0);
    for (const auto& c : pending) {
        DenominationToInteger(c.denom, denom);
        pendingSum += denom;
    }

    QString pendingAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(pendingSum));
    QString spendableAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(sum));
    QString totalAmount = QString("<span style='white-space: nowrap;'>%1</span>").arg(formatAmount(sum + pendingSum));

    ui->pending->setText(pendingAmount);
    ui->spendable->setText(spendableAmount);
    ui->total->setText(totalAmount);
}
