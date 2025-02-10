// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendcoinsdialog.h"
#include "ui_sendcoinsdialog.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "clientmodel.h"
#include "coincontroldialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "sendcoinsentry.h"
#include "walletmodel.h"

#include "base58.h"
#include "chainparams.h"
#include "lelantus.h"
#include "wallet/coincontrol.h"
#include "validation.h" // mempool and minRelayTxFee
#include "ui_interface.h"
#include "txmempool.h"
#include "wallet/wallet.h"
#include "overviewpage.h"

#include <QFontMetrics>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>

#define SEND_CONFIRM_DELAY   3

SendCoinsDialog::SendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendCoinsDialog),
    clientModel(0),
    model(0),
    fNewRecipientAllowed(true),
    fFeeMinimized(true),
    fAnonymousMode(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
    }

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);
    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &SendCoinsDialog::coinControlChangeEdited);
    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardLowOutputAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardLowOutput);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    ui->frameCoinControl->setAutoFillBackground(true);
    ui->scrollArea->setAutoFillBackground(true);
    ui->frameFee->setAutoFillBackground(true);

    {
        auto allowed = spark::IsSparkAllowed();
        setAnonymizeMode(allowed);

        if (!allowed) {
            ui->switchFundButton->setEnabled(false);
        }
    }

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nCustomFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nCustomFeeRadio", 1); // total at least
    if (!settings.contains("nCustomFeeRadio"))
        settings.setValue("nCustomFeeRadio", 0); // per kilobyte
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_TRANSACTION_FEE);
    if (!settings.contains("fPayOnlyMinFee"))
        settings.setValue("fPayOnlyMinFee", false);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->groupCustomFee->setId(ui->radioCustomPerKilobyte, 0);
    ui->groupCustomFee->setId(ui->radioCustomAtLeast, 1);
    ui->groupCustomFee->button((int)std::max(0, std::min(1, settings.value("nCustomFeeRadio").toInt())))->setChecked(true);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    ui->checkBoxMinimumFee->setChecked(settings.value("fPayOnlyMinFee").toBool());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel)
    {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateBlocks);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        auto privateBalance = _model->getSparkBalance();

        if (model->getWallet()) {
            auto allowed = (spark::IsSparkAllowed() && model->getWallet()->sparkWallet);
            setAnonymizeMode(allowed);

            if (!allowed) {
                ui->switchFundButton->setEnabled(false);
            }
        }

        setBalance(
            _model->getBalance(), _model->getUnconfirmedBalance(), _model->getImmatureBalance(),
            _model->getWatchBalance(), _model->getWatchUnconfirmedBalance(), _model->getWatchImmatureBalance(),
            privateBalance.first, privateBalance.second, _model->getAnonymizableBalance());

        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        // fee section
        connect(ui->sliderSmartFee, &QSlider::valueChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->sliderSmartFee, &QSlider::valueChanged, this, &SendCoinsDialog::updateGlobalFeeVariables);
        connect(ui->sliderSmartFee, &QSlider::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->groupFee, qOverload<int>(&QButtonGroup::idClicked), this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, qOverload<int>(&QButtonGroup::idClicked), this, &SendCoinsDialog::updateGlobalFeeVariables);
        connect(ui->groupFee, qOverload<int>(&QButtonGroup::idClicked), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->groupCustomFee, qOverload<int>(&QButtonGroup::idClicked), this, &SendCoinsDialog::updateGlobalFeeVariables);
        connect(ui->groupCustomFee, qOverload<int>(&QButtonGroup::idClicked), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::updateGlobalFeeVariables);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->checkBoxMinimumFee, &QCheckBox::stateChanged, this, &SendCoinsDialog::setMinimumFee);
        connect(ui->checkBoxMinimumFee, &QCheckBox::stateChanged, this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->checkBoxMinimumFee, &QCheckBox::stateChanged, this, &SendCoinsDialog::updateGlobalFeeVariables);
        connect(ui->checkBoxMinimumFee, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        ui->customFee->setSingleStep(CWallet::GetRequiredFee(1000));
        updateFeeSectionControls();
        updateMinFeeLabel();
        updateSmartFeeLabel();
        updateGlobalFeeVariables();

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("nSmartFeeSliderPosition").toInt() == 0)
            ui->sliderSmartFee->setValue(ui->sliderSmartFee->maximum() - model->getDefaultConfirmTarget() + 2);
        else
            ui->sliderSmartFee->setValue(settings.value("nSmartFeeSliderPosition").toInt());
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", true);
    settings.setValue("nCustomFeeRadio", ui->groupCustomFee->checkedId());
    settings.setValue("nSmartFeeSliderPosition", ui->sliderSmartFee->value());
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());
    settings.setValue("fPayOnlyMinFee", ui->checkBoxMinimumFee->isChecked());

    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked()
{
    updateGlobalFeeVariables();

    if(!model || !model->getOptionsModel())
        return;

    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    using UnlockContext = WalletModel::UnlockContext;
    std::unique_ptr<UnlockContext> ctx;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            if(entry->validate())
            {
                SendCoinsRecipient recipient = entry->getValue();
                recipients.append(recipient);
            }
            else
            {
                valid = false;
            }
        }
    }

    if(!valid || recipients.isEmpty())
    {
        return;
    }

    fNewRecipientAllowed = false;
    if(!ctx)
    {
        ctx = std::unique_ptr<UnlockContext>(new UnlockContext(model->requestUnlock()));
    }
    if(!ctx->isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    // prepare transaction for getting txFee earlier
    std::vector<WalletModelTransaction> transactions;
    WalletModel::SendCoinsReturn prepareStatus;
    std::vector<std::pair<CWalletTx, CAmount>> wtxAndFees;
    std::list<CReserveKey> reservekeys;

    // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
    CCoinControl ctrl;
    if (model->getOptionsModel()->getCoinControlFeatures()) {
        ctrl = *CoinControlDialog::coinControl;
        removeUnmatchedOutput(ctrl);
    }
    if (ui->radioSmartFee->isChecked())
        ctrl.nConfirmTarget = ui->sliderSmartFee->maximum() - ui->sliderSmartFee->value() + 2;
    else
        ctrl.nConfirmTarget = 0;

    int sparkAddressCount = 0;
    int exchangeAddressCount = 0;
    for(int i = 0; i < recipients.size(); ++i){
        if (model->validateSparkAddress(recipients[i].address))
            sparkAddressCount++;
        if (model->validateExchangeAddress(recipients[i].address))
            exchangeAddressCount++;
    }

    bool fGoThroughTransparentAddress = false;
    __decltype(recipients) exchangeRecipients;
    CScript intermediateAddressScript;
    CAmount extraFee = 0;

    if (fAnonymousMode && exchangeAddressCount > 0) {
        CAmount exchangeAddressAmount = 0;
        // if the transaction is performed in two stages through the intermediate address we need to calculate the size of the second transaction
        uint32_t secondTxSize = 8 /*CTransaction: nVersion, nLockTime*/ + 1 /*vinSize*/ + 148 /*vin[0]*/ + 20 /*safety*/ + 1 /*voutSize*/;

        fGoThroughTransparentAddress = true;

        // remove exchange addresses from recipients array and add them to exchangeRecipients array
        for(int i = 0; i < recipients.size(); ){
            if (model->validateExchangeAddress(recipients[i].address)) {
                exchangeAddressAmount += recipients[i].amount;
                // we use different fee calculation system and therefore can't reliably do the calculation
                // of fee for the second transaction if some of recipients have this flag set
                recipients[i].fSubtractFeeFromAmount = false;
                exchangeRecipients.push_back(recipients[i]);

                secondTxSize += 8 /*amount*/ + 1 /*scriptSize*/ + 26 /*scriptPubKey*/;

                recipients.erase(recipients.begin() + i);
            }
            else {
                ++i;
            }
        }

        LOCK2(cs_main, pwalletMain->cs_wallet);
        // create a new transparent address and add it to the recipients array
        if (!pwalletMain->IsLocked()) {
            pwalletMain->TopUpKeyPool();
        }
        CPubKey newKey;
        if (!pwalletMain->GetKeyFromPool(newKey)) {
            fNewRecipientAllowed = true;
            return;
        }
        pwalletMain->SetAddressBook(newKey.GetID(), "", "receive");
        intermediateAddressScript = GetScriptForDestination(newKey.GetID());

        extraFee = CWallet::GetMinimumFee(secondTxSize, nTxConfirmTarget, mempool);

        SendCoinsRecipient newRecipient;        
        newRecipient.address = CBitcoinAddress(newKey.GetID()).ToString().c_str();
        newRecipient.amount = exchangeAddressAmount + extraFee;
        newRecipient.fSubtractFeeFromAmount = false;
        recipients.push_back(newRecipient);
    }

    WalletModelTransaction currentTransaction(recipients);

    CAmount mintSparkAmount = 0;
    CAmount txFee = 0;
    CAmount totalAmount = 0;
    size_t confirmed, unconfirmed;
    if (model->getWallet() &&
        model->getWallet()->GetPrivateBalance(confirmed, unconfirmed).first > 0 &&
        spark::IsSparkAllowed() &&
        chainActive.Height() < ::Params().GetConsensus().nLelantusGracefulPeriod) {
        MigrateLelantusToSparkDialog migrateLelantusToSpark(model);
        bool clickedButton = migrateLelantusToSpark.getClickedButton();
        if(!clickedButton) {
            fNewRecipientAllowed = true;
            return;
        }
    }
    if ((fAnonymousMode == true) && spark::IsSparkAllowed()) {
        prepareStatus = model->prepareSpendSparkTransaction(currentTransaction, &ctrl);
    } else if ((fAnonymousMode == false) && (recipients.size() == sparkAddressCount)) {
        if (spark::IsSparkAllowed())
            prepareStatus = model->prepareMintSparkTransaction(transactions, recipients, wtxAndFees, reservekeys, &ctrl);
        else {
            processSendCoinsReturn(WalletModel::InvalidAddress);
            return;
        }
    } else if ((fAnonymousMode == false) && (sparkAddressCount == 0)) {
        prepareStatus = model->prepareTransaction(currentTransaction, &ctrl);
    } else {
        fNewRecipientAllowed = true;
        return;
    }

    // process prepareStatus and on error generate message shown to user
    processSendCoinsReturn(prepareStatus,
        BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

    if(prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        return;
    }

    // If the transaction is performed in two stages through the intermediate address we need to show the real
    // recipients (for informational purposes), replacing the intermediate transparent address with the exchange address(es)
    __decltype(recipients) realRecipients = recipients;
    if (fGoThroughTransparentAddress) {
        realRecipients.erase(realRecipients.end() - 1);
        realRecipients.append(exchangeRecipients);
    }

    // Format confirmation message
    QStringList formatted;
    QString warningMessage;

    for(int i = 0; i < recipients.size(); ++i) {
        warningMessage = entry->generateWarningText(recipients[i].address, fAnonymousMode);
        if ((model->validateSparkAddress(recipients[i].address)) || (recipients[i].address.startsWith("EX"))) {
            break;
        }
    }

    if ((fAnonymousMode == false) && (recipients.size() == sparkAddressCount) && spark::IsSparkAllowed()) 
    {
        for(int i = 0; i < recipients.size(); i++) {
            recipients[i].amount = 0;
        }

        for (auto &transaction : transactions)
        {
            for (auto &rcp : transaction.getRecipients()) 
            {
                for(int i = 0; i < recipients.size(); i++) {
                    if( recipients[i].address == rcp.address) {
                        recipients[i].amount += rcp.amount;
                    }
                }
            }
        }    

        for (auto &rcp : recipients) 
        {
            // generate bold amount string
            QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
            amount.append("</b>");
            // generate monospace address string
            QString address = "<span style='font-family: monospace;'>" + rcp.address;
            address.append("</span>");
            QString recipientElement;
            {
                if(rcp.label.length() > 0) // label with address
                {
                    recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                    recipientElement.append(QString(" (%1)").arg(address));
                }
                else // just address
                {
                    recipientElement = tr("%1 to %2").arg(amount, address);
                }
            }
            formatted.append(recipientElement);
        }
    } else if ((fAnonymousMode == true) && (recipients.size() == 1) && spark::IsSparkAllowed()) {
        for (auto &rcp : realRecipients)
        {
            // generate bold amount string
            CAmount namount = rcp.amount;
            if(rcp.fSubtractFeeFromAmount) {
                namount = rcp.amount - currentTransaction.getTransactionFee();
            }
            QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), namount);
            amount.append("</b>");
            // generate monospace address string
            QString address = "<span style='font-family: monospace;'>" + rcp.address;
            address.append("</span>");
            QString recipientElement;
            {
                if(rcp.label.length() > 0) // label with address
                {
                    recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                    recipientElement.append(QString(" (%1)").arg(address));
                }
                else // just address
                {
                    recipientElement = tr("%1 to %2").arg(amount, address);
                }
            }
            formatted.append(recipientElement);
        }
    } else {
        for (auto &rcp : realRecipients)
        {
            // generate bold amount string
            QString amount = "<b>" + BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
            amount.append("</b>");
            // generate monospace address string
            QString address = "<span style='font-family: monospace;'>" + rcp.address;
            address.append("</span>");

            QString recipientElement;

            {
                if(rcp.label.length() > 0) // label with address
                {
                    recipientElement = tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label));
                    recipientElement.append(QString(" (%1)").arg(address));
                }
                else // just address
                {
                    recipientElement = tr("%1 to %2").arg(amount, address);
                }
            }
            formatted.append(recipientElement);
        }
    }

    if (fGoThroughTransparentAddress) {
        QString transparentAddress = "<span style='font-family: monospace;'>" + recipients[recipients.size()-1].address + "</span>";
        formatted.append("<br />");
        formatted.append(tr("EX-addresses can only receive FIRO from transparent addresses.<br /><br />"
            "Your FIRO will go from Spark to a newly generated transparent address %1 and then immediately be sent to the EX-address.").arg(transparentAddress));
    }

    QString questionString = tr("Are you sure you want to send?");
    questionString.append(warningMessage);
    questionString.append("<br /><br />%1");
    bool firstMessage = true;
    for (const auto& rec : recipients) {
        if (!rec.message.isEmpty()) {
            if (firstMessage) {
                questionString.append("<hr><b>" + tr("Messages") + ":</b><br>");
                firstMessage = false;
            }
            QString sanitizedMsg = GUIUtil::HtmlEscape(rec.message, true);
            questionString.append("• " + sanitizedMsg + "<br>");
        }
    }

    double txSize;
    if ((fAnonymousMode == false) && (recipients.size() == sparkAddressCount) && spark::IsSparkAllowed()) 
    {
        for (auto &transaction : transactions) {
            txFee += transaction.getTransactionFee();
            mintSparkAmount += transaction.getTotalTransactionAmount();
            txSize +=  (double)transaction.getTransactionSize();
        }
    } else {
        txFee = currentTransaction.getTransactionFee();
        txSize = (double)currentTransaction.getTransactionSize();
    }

    if(txFee > 0)
    {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number(txSize / 1000) + " kB)");

        if (fGoThroughTransparentAddress) {
            QString feeString;
            feeString.append("<span style='color:#aa0000;'>");
            feeString.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), extraFee));
            feeString.append("</span>");
            
            questionString.append(tr(". An additional transaction fee of %1 will apply to complete the send from the transparent address to the EX-address.").arg(feeString));
        }
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    if ((fAnonymousMode == false) && (recipients.size() == sparkAddressCount) && spark::IsSparkAllowed()) 
    {
        totalAmount = mintSparkAmount + txFee;
    } else if ((fAnonymousMode == true) && (recipients.size() == 1) && spark::IsSparkAllowed()) {
        if(recipients[0].fSubtractFeeFromAmount) {
            totalAmount = recipients[0].amount;
        } else {
            totalAmount = recipients[0].amount + currentTransaction.getTransactionFee();
        }
    } else {
        totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
    }

    QStringList alternativeUnits;
    for (BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
    {
        if(u != model->getOptionsModel()->getDisplayUnit())
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
    }
    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    SendConfirmationDialog confirmationDialog(tr("Confirm send coins"),
        questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    // now send the prepared transaction
    WalletModel::SendCoinsReturn sendStatus;

    if ((fAnonymousMode == true) && spark::IsSparkAllowed()) {
        sendStatus = model->spendSparkCoins(currentTransaction);
    } else if ((fAnonymousMode == false) && (sparkAddressCount == recipients.size()) && spark::IsSparkAllowed()) {
        sendStatus = model->mintSparkCoins(transactions, wtxAndFees, reservekeys);
    } else if ((fAnonymousMode == false) && (sparkAddressCount == 0)) {
        sendStatus = model->sendCoins(currentTransaction);
    } else {
        return;
    }

    // process sendStatus and on error generate message shown to user
    processSendCoinsReturn(sendStatus);

    if (sendStatus.status == WalletModel::OK)
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        }
        accept();
        CoinControlDialog::coinControl->UnSelectAll();
        coinControlUpdateLabels();
    }

    // Launch the second stage of the transaction if needed
    if (fGoThroughTransparentAddress) {
        // prepare the coin control so the transaction will use (by default) only the transparent address
        // created in the first stage
        COutPoint outpoint;
        outpoint.hash = currentTransaction.getTransaction()->GetHash();
        outpoint.n = UINT_MAX;

        const auto &vout = currentTransaction.getTransaction()->tx->vout;
        for (size_t i = 0; i < vout.size(); i++) {
            if (vout[i].scriptPubKey == intermediateAddressScript) {
                outpoint.n = i;
                break;
            }
        }

        if (outpoint.n == UINT_MAX) {
            sendStatus.status = WalletModel::InvalidAddress;
            sendStatus.reasonCommitFailed = "Intermediate address was not found in the transaction";
            fNewRecipientAllowed = true;
            return;
        }

        CCoinControl ctrl;
        ctrl.fAllowOtherInputs = false;
        ctrl.fNoChange = true;
        ctrl.Select(outpoint);

        WalletModelTransaction  secondTransaction(exchangeRecipients);

        prepareStatus = model->prepareTransaction(secondTransaction, &ctrl);

        // process prepareStatus and on error generate message shown to user
        processSendCoinsReturn(prepareStatus,
            BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), currentTransaction.getTransactionFee()));

        if(prepareStatus.status != WalletModel::OK) {
            fNewRecipientAllowed = true;
            return;
        }

        sendStatus = model->sendCoins(secondTransaction);
        // process sendStatus and on error generate message shown to user
        processSendCoinsReturn(sendStatus);
    }

    fNewRecipientAllowed = true;
}

void SendCoinsDialog::on_switchFundButton_clicked()
{
    setAnonymizeMode(!fAnonymousMode);
    entry->setfAnonymousMode(fAnonymousMode);
    entry->setWarning(fAnonymousMode);
    coinControlUpdateLabels();
}

void SendCoinsDialog::clear()
{
    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    entry->setfAnonymousMode(fAnonymousMode);
    entry->setWarning(fAnonymousMode);

    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if (header)
    {
        return;
    }

    auto allowed = (spark::IsSparkAllowed() && model->getWallet() && model->getWallet()->sparkWallet);


    if (allowed && !ui->switchFundButton->isEnabled())
    {
        setAnonymizeMode(true);
        ui->switchFundButton->setEnabled(true);
    }
    else if (!allowed && ui->switchFundButton->isEnabled())
    {
        setAnonymizeMode(false);
        ui->switchFundButton->setEnabled(false);
    }
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(0);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }
    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(
    const CAmount& balance,
    const CAmount& unconfirmedBalance,
    const CAmount& immatureBalance,
    const CAmount& watchBalance,
    const CAmount& watchUnconfirmedBalance,
    const CAmount& watchImmatureBalance,
    const CAmount& privateBalance,
    const CAmount& unconfirmedPrivateBalance,
    const CAmount& anonymizableBalance)
{
    Q_UNUSED(unconfirmedBalance);
    Q_UNUSED(immatureBalance);
    Q_UNUSED(watchBalance);
    Q_UNUSED(watchUnconfirmedBalance);
    Q_UNUSED(watchImmatureBalance);
    Q_UNUSED(unconfirmedPrivateBalance);
    Q_UNUSED(anonymizableBalance);

    if(model && model->getOptionsModel())
    {
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(),
            fAnonymousMode ? privateBalance : balance));
    }
}

void SendCoinsDialog::updateDisplayUnit()
{
    auto privateBalance = model->getSparkBalance();
    setBalance(model->getBalance(), 0, 0, 0, 0, 0, privateBalance.first, 0, 0);
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateMinFeeLabel();
    updateSmartFeeLabel();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // WalletModel::TransactionCommitFailed is used only in WalletModel::sendCoins()
    // all others are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
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
        msgParams.first = tr("The transaction was rejected with the following reason: %1").arg(sendCoinsReturn.reasonCommitFailed);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), maxTxFee));
        break;
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

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::setMinimumFee()
{
    ui->radioCustomPerKilobyte->setChecked(true);
    ui->customFee->setValue(CWallet::GetRequiredFee(1000));
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->sliderSmartFee          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFeeNormal     ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFeeFast       ->setEnabled(ui->radioSmartFee->isChecked());

    ui->confirmationTargetLabel ->setEnabled(ui->radioSmartFee->isChecked());
    ui->checkBoxMinimumFee      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelMinFeeWarning      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->radioCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
    ui->radioCustomAtLeast      ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked() && CoinControlDialog::coinControl->HasSelected());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
}

void SendCoinsDialog::updateGlobalFeeVariables()
{
    if (ui->radioSmartFee->isChecked())
    {
        int nConfirmTarget = ui->sliderSmartFee->maximum() - ui->sliderSmartFee->value() + 2;
        payTxFee = CFeeRate(0);

        // set nMinimumTotalFee to 0 to not accidentally pay a custom fee
        CoinControlDialog::coinControl->nMinimumTotalFee = 0;

        // show the estimated required time for confirmation
        ui->confirmationTargetLabel->setText(GUIUtil::formatDurationStr(nConfirmTarget * Params().GetConsensus().nPowTargetSpacing) + " / " + tr("%n block(s)", "", nConfirmTarget));
    }
    else
    {
        payTxFee = CFeeRate(ui->customFee->value());

        // if user has selected to set a minimum absolute fee, pass the value to coincontrol
        // set nMinimumTotalFee to 0 in case of user has selected that the fee is per KB
        CoinControlDialog::coinControl->nMinimumTotalFee = ui->radioCustomAtLeast->isChecked() ? ui->customFee->value() : 0;
    }
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) +
            ((ui->radioCustomPerKilobyte->isChecked()) ? "/kB" : ""));
    }
}

void SendCoinsDialog::setAnonymizeMode(bool enableAnonymizeMode)
{
    fAnonymousMode = enableAnonymizeMode;

    if (fAnonymousMode) {
        ui->switchFundButton->setText(QString(tr("Use Transparent Balance")));
        ui->labelBalanceText->setText(QString(tr("Private Balance")));

        ui->checkBoxCoinControlChange->setEnabled(false);
        ui->lineEditCoinControlChange->setEnabled(false);

    } else {
        ui->switchFundButton->setText(QString(tr("Use Private Balance")));
        ui->labelBalanceText->setText(QString(tr("Transparent Balance")));

        ui->checkBoxCoinControlChange->setEnabled(true);
        if (ui->checkBoxCoinControlChange->isChecked()) {
            ui->lineEditCoinControlChange->setEnabled(true);
        }

    }

    if (model) {
        auto privateBalance = model->getSparkBalance();
        setBalance(model->getBalance(), 0, 0, 0, 0, 0, privateBalance.first, 0, 0);
    }
}

void SendCoinsDialog::removeUnmatchedOutput(CCoinControl &coinControl)
{
    std::vector<COutPoint> outpoints;
    coinControl.ListSelected(outpoints);

    for (auto const &out : outpoints) {
        auto it = pwalletMain->mapWallet.find(out.hash);
        if (it == pwalletMain->mapWallet.end()) {
            coinControl.UnSelect(out);
            continue;
        }

        auto isMint = it->second.tx->vout[out.n].scriptPubKey.IsMint();

        if (isMint != fAnonymousMode) {
            coinControl.UnSelect(out);
        }
    }
}

void SendCoinsDialog::updateMinFeeLabel()
{
    if (model && model->getOptionsModel())
        ui->checkBoxMinimumFee->setText(tr("Pay only the required fee of %1").arg(
            BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), CWallet::GetRequiredFee(1000)) + "/kB")
        );
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    int nBlocksToConfirm = ui->sliderSmartFee->maximum() - ui->sliderSmartFee->value() + 2;
    int estimateFoundAtBlocks = nBlocksToConfirm;
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocksToConfirm, &estimateFoundAtBlocks);
    if (feeRate <= CFeeRate(0)) // not enough data => minfee
    {
        ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(
            model->getOptionsModel()->getDisplayUnit(),
            std::max(CWallet::fallbackFee.GetFeePerK(), CWallet::GetRequiredFee(1000))) + "/kB");
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(GUIUtil::TextWidth(QFontMetrics(ui->fallbackFeeWarningLabel->font()), "x"));
    }
    else
    {
        ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(),
                                                                std::max(feeRate.GetFeePerK(), CWallet::GetRequiredFee(1000))) + "/kB");
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", estimateFoundAtBlocks));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void SendCoinsDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) // coin control features disabled
        CoinControlDialog::coinControl->SetNull();

    // make sure we set back the confirmation target
    updateGlobalFeeVariables();
    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    CoinControlDialog dlg(fAnonymousMode, platformStyle);
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked)
    {
        CoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel())
    {
        // Default to no change address until verified
        CoinControlDialog::coinControl->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        CBitcoinAddress addr = CBitcoinAddress(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!addr.IsValid()) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Firo address"));
        }
        else // Valid address
        {
            CKeyID keyid;
            addr.GetKeyID(keyid);
            if (!model->havePrivKey(keyid)) // Unknown change address
            {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    CoinControlDialog::coinControl->destChange = addr.Get();
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                CoinControlDialog::coinControl->destChange = addr.Get();
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    if (model->getOptionsModel()->getCoinControlFeatures())
    {
        // enable minimum absolute fee UI controls
        ui->radioCustomAtLeast->setVisible(true);

        // only enable the feature if inputs are selected
        ui->radioCustomAtLeast->setEnabled(ui->radioCustomFee->isChecked()
            && !ui->checkBoxMinimumFee->isChecked()
            && CoinControlDialog::coinControl->HasSelected());
    }
    else
    {
        // in case coin control is disabled (=default), hide minimum absolute fee UI controls
        ui->radioCustomAtLeast->setVisible(false);
        return;
    }

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (CoinControlDialog::coinControl->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(model, this, fAnonymousMode);

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

SendConfirmationDialog::SendConfirmationDialog(const QString &title, const QString &text, int _secDelay,
    QWidget *parent) :
    QMessageBox(QMessageBox::Question, title, text, QMessageBox::Yes | QMessageBox::Cancel, parent), secDelay(_secDelay)
{
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    updateYesButton();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(tr("Yes") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(tr("Yes"));
    }
}

void SendCoinsDialog::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);

    // Retrieve new dimensions from the resize event
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();

    const int labelMinWidth = static_cast<int>(newWidth * 0.15);

    // Resize and adjust components
    ui->sendButton->setMinimumWidth(labelMinWidth);
    ui->clearButton->setMinimumWidth(labelMinWidth);
    ui->addButton->setMinimumWidth(labelMinWidth);
    ui->buttonChooseFee->setMinimumWidth(labelMinWidth);
    ui->buttonMinimizeFee->setMinimumWidth(labelMinWidth);
    ui->switchFundButton->setMinimumWidth(labelMinWidth);
    ui->pushButtonCoinControl->setMinimumWidth(labelMinWidth);


    // Dynamically adjust text sizes based on the new dimensions
    adjustTextSize(newWidth, newHeight);
}

void SendCoinsDialog::adjustTextSize(int width, int height) {
    const double fontSizeScalingFactor = 131.3;
    int baseFontSize = width / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));

    QFont font =  ui->labelBalance->font();
    font.setPointSize(fontSize);

    QFont textFont = font;
    textFont.setBold(true);

    // Set font size for all labels
    ui->labelBalance->setFont(font);
    ui->lineEditCoinControlChange->setFont(font);
    ui->labelFeeEstimation->setFont(font);
    ui->labelFeeHeadline->setFont(font);
    ui->labelCoinControlFeatures->setFont(textFont);
    ui->labelCoinControlAutomaticallySelected->setFont(font);
    ui->labelCoinControlInsuffFunds->setFont(font);
    ui->labelCoinControlQuantity->setFont(font);
    ui->labelCoinControlBytes->setFont(font);
    ui->labelCoinControlAmount->setFont(font);
    ui->labelCoinControlLowOutput->setFont(font);
    ui->labelCoinControlFee->setFont(font);
    ui->labelCoinControlAfterFee->setFont(font);
    ui->labelCoinControlChange->setFont(font);
    ui->labelFeeMinimized->setFont(font);
    ui->labelBalance->setFont(font);
    ui->radioSmartFee->setFont(font);
    ui->radioCustomPerKilobyte->setFont(font);
    ui->radioCustomFee->setFont(font);
    ui->radioCustomAtLeast->setFont(font);
    ui->labelBalanceText->setFont(font);
    ui->labelFeeEstimation->setFont(font);
    ui->labelSmartFee->setFont(font);
    ui->labelSmartFee2->setFont(font);
    ui->labelSmartFee3->setFont(font);
    ui->labelSmartFeeNormal->setFont(font);
    ui->labelSmartFeeFast->setFont(font);
    ui->labelCoinControlQuantityText->setFont(font);
    ui->labelCoinControlBytesText->setFont(font);
    ui->labelCoinControlAmountText->setFont(font);
    ui->labelCoinControlLowOutputText->setFont(font);
    ui->labelCoinControlFeeText->setFont(font);
    ui->labelCoinControlAfterFeeText->setFont(font);
    ui->labelCoinControlChangeText->setFont(font);
    ui->labelCoinControlChangeLabel->setFont(font);
    ui->labelMinFeeWarning->setFont(font);
    ui->fallbackFeeWarningLabel->setFont(font);
    ui->checkBoxMinimumFee->setFont(font);
    ui->checkBoxCoinControlChange->setFont(font);
    ui->confirmationTargetLabel->setFont(font);


    // Adjust font for all buttons 
    ui->sendButton->setFont(font);
    ui->clearButton->setFont(font);
    ui->addButton->setFont(font);
    ui->pushButtonCoinControl->setFont(font);
    ui->customFee->setFont(font);
}
