/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#include "createtokendialog.h"
#include "ui_createtokendialog.h"

#include "elysium/createpayload.h"
#include "elysium/elysium.h"
#include "elysium/errors.h"
#include "elysium/parse_string.h"
#include "elysium/property.h"
#include "elysium/rules.h"
#include "elysium/utilsbitcoin.h"

#include "clientmodel.h"
#include "coincontroldialog.h"
#include "guiutil.h"
#include "lelantusmodel.h"
#include "walletmodel.h"

#include "chainparams.h"
#include "elysium_qtutils.h"
#include "lelantus.h"
#include "ui_interface.h"
#include "wallet/wallet.h"

CreateTokenDialog::CreateTokenDialog(QWidget* parent) : QWidget(parent),
                                                        ui(new Ui::CreateTokenDialog),
                                                        clientModel(0),
                                                        model(0)
{
    ui->setupUi(this);

    this->tempQuantity = "";

    this->divisibleQuantityValidator = new QRegExpValidator(QRegExp("([0-9]+\\.?[0-9]{0,8}|\\.[0-9]{1,8})"), this);
    this->indivisibleQuantityValidator = new QRegExpValidator(QRegExp("[1-9][0-9]*"), this);

    GUIUtil::setupAddressWidget(ui->addressLineEdit, this);

    setWindowTitle("Create Tokens");

    connect(ui->managedCheckBox, SIGNAL(toggled(bool)), this, SLOT(onManagedCheckBoxChanged(bool)));
    connect(ui->divisibleCheckBox, SIGNAL(toggled(bool)), this, SLOT(onDivisibleCheckBoxChanged(bool)));

    connect(ui->createButton, SIGNAL(clicked()), this, SLOT(onCreateButtonClicked()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(onClearButtonClicked()));

    // Use Hard Enabled by default
    // // setup lelantus status combobox
    // QStringList statusList;
    // statusList.append(tr("Soft Disabled"));
    // statusList.append(tr("Soft Enabled"));
    // statusList.append(tr("Hard Disabled"));
    // statusList.append(tr("Hard Enabled"));
    // ui->lelantusStatusComboBox->addItems(statusList);

    // setup ecosystem combobox
    QStringList ecosystemList;
    ecosystemList.append(tr("Main Ecosystem"));
    ecosystemList.append(tr("Test Ecosystem"));
    ui->ecosystemComboBox->addItems(ecosystemList);

    ui->divisibleCheckBox->setChecked(false);
    ui->quantityLineEdit->setValidator(indivisibleQuantityValidator);

    // ui->previousIDLineEdit->setValidator(new QRegExpValidator(QRegExp("[0-9]*"), this));
}

CreateTokenDialog::~CreateTokenDialog()
{
    delete ui;
}

void CreateTokenDialog::setClientModel(ClientModel* _clientModel)
{
    this->clientModel = _clientModel;
}

void CreateTokenDialog::setModel(WalletModel* _model)
{
    this->model = _model;
}

void CreateTokenDialog::onClearButtonClicked()
{
    clear();
}

void CreateTokenDialog::clear()
{
    ui->nameLineEdit->clear();
    ui->addressLineEdit->clear();
    // ui->previousIDLineEdit->clear(); // not enabled/implemented yet
    ui->categoryLineEdit->clear();
    ui->subcategoryLineEdit->clear();
    ui->urlLineEdit->clear();
    ui->dataLineEdit->clear();

    ui->divisibleCheckBox->setChecked(false);
    ui->managedCheckBox->setChecked(false);

    ui->quantityLineEdit->clear();
    ui->quantityLineEdit->setEnabled(true);

    // ui->lelantusStatusComboBox->setCurrentIndex(0);
    ui->ecosystemComboBox->setCurrentIndex(0);

    this->tempQuantity = "";
}

void CreateTokenDialog::onCreateButtonClicked()
{
    if (!model) {
        return;
    }

    std::string name = ui->nameLineEdit->text().toStdString();
    if (name.size() == 0) {
        Q_EMIT message(tr("Missing Token Name"), tr("The token name must not be empty."), CClientUIInterface::MSG_ERROR);
        return;
    }

    std::string fromAddress = ui->addressLineEdit->text().toStdString();
    if (fromAddress.size() == 0 || !model->validateAddress(ui->addressLineEdit->text())) {
        ui->addressLineEdit->setValid(false);
        Q_EMIT message(tr("Invalid address"), tr("Invalid FIRO address entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    // bool success;
    // uint64_t previousIdValue = ui->previousIDLineEdit->text().toULongLong(&success, 10);
    // if (!success) {
    //     Q_EMIT message(tr("Invalid Property ID"), tr("Invalid previous property ID entered."), CClientUIInterface::MSG_ERROR);
    //     return;
    // }

    // default to zero
    uint32_t previousId = 0; // static_cast<uint32_t>(previousIdValue);
    // if (previousId != 0) {
    //     Q_EMIT message(tr("Invalid Property ID"), tr("Previous property ID not supported yet\nSet to 0."), CClientUIInterface::MSG_ERROR);
    //     return;
    // }

    // default to Hard Enabled which is 3
    int lelantusIndex = 3; //ui->lelantusStatusComboBox->currentIndex();
    elysium::LelantusStatus lelantus = static_cast<elysium::LelantusStatus>(lelantusIndex);
    // if (!elysium::IsFeatureActivated(elysium::FEATURE_LELANTUS, elysium::GetHeight())) {
    //     Q_EMIT message(tr("Lelantus Error"), tr("Lelantus feature is not activated yet."), CClientUIInterface::MSG_ERROR);
    //     return;
    // }
    // if (!elysium::IsLelantusStatusValid(lelantus)) {
    //     Q_EMIT message(tr("Lelantus Error"), tr("Property has not enabled Lelantus."), CClientUIInterface::MSG_ERROR);
    //     return;
    // }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid()) {
        Q_EMIT message(tr("Wallet Error"), tr("The token creation transaction has been cancelled.\n\nThe wallet unlock process must be completed to send a transaction."), CClientUIInterface::MSG_ERROR);
        return;
    }

    bool divisible = ui->divisibleCheckBox->isChecked();
    uint16_t type = divisible ? 2 : 1; // (1 for indivisible tokens, 2 for divisible tokens)

    std::string category = ui->categoryLineEdit->text().toStdString();
    std::string subcategory = ui->subcategoryLineEdit->text().toStdString();
    std::string url = ui->urlLineEdit->text().toStdString();
    std::string data = ui->dataLineEdit->text().toStdString();

    // ecosystem (1 = main, 2 = test only)
    int ecosystemIndex = ui->ecosystemComboBox->currentIndex();
    uint8_t ecosystem = static_cast<uint8_t>(ecosystemIndex + 1); // add one as combobox index starts at zero

    std::vector<unsigned char> payload;

    if (ui->managedCheckBox->isChecked()) // elysium_sendissuancemanaged
    {
        // create a payload for the transaction
        payload = CreatePayload_IssuanceManaged(
            ecosystem,
            type,
            previousId,
            category,
            subcategory,
            name,
            url,
            data,
            lelantus);
    } else // elysium_sendissuancefixed
    {
        std::string amountString = ui->quantityLineEdit->text().toStdString();
        int64_t amount = elysium::StrToInt64(amountString, divisible);

        if (amount == 0) {
            Q_EMIT message(tr("Invalid amount"), tr("Invalid amount entered."), CClientUIInterface::MSG_ERROR);
            return;
        }

        // create a payload for the transaction
        payload = CreatePayload_IssuanceFixed(
            ecosystem,
            type,
            previousId,
            category,
            subcategory,
            name,
            url,
            data,
            amount,
            lelantus);
    }

    // request the wallet build the transaction (and if needed commit it)
    auto& consensus = elysium::ConsensusParams();
    uint256 txid;
    std::string rawHex;
    std::string receiver;
    CAmount fee = 0;

    if (elysium::IsRequireCreationFee(ecosystem)) {
        receiver = consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString();
        fee = consensus.PROPERTY_CREATION_FEE;
    }

    int result = elysium::WalletTxBuilder(fromAddress, receiver, "", fee, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        std::string errorMessage = strprintf("The create token transaction has failed.\n\nThe error code was: %d\nThe error message was:\n%s", result, error_str(result).c_str());
        Q_EMIT message(tr("Transaction Failed"), tr(errorMessage.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    } else {
        if (!autoCommit) {
            elysium::PopulateSimpleDialog(rawHex, "Raw Hex (auto commit is disabled)", "Raw transaction hex");
        } else {
            elysium::PopulateTXSentDialog(txid.GetHex());
        }
    }
    clear();
}

void CreateTokenDialog::onDivisibleCheckBoxChanged(bool divisible)
{
    elysium::FormatElysiumAmount(ui->quantityLineEdit, divisible);
    if (divisible) {
        ui->quantityLineEdit->setValidator(divisibleQuantityValidator);
    } else {
        ui->quantityLineEdit->setValidator(indivisibleQuantityValidator);
    }
}

void CreateTokenDialog::onManagedCheckBoxChanged(bool managed)
{
    ui->quantityLineEdit->setEnabled(!managed);
    ui->quantityLabel->setEnabled(!managed);
    if (managed) {
        this->tempQuantity = ui->quantityLineEdit->text();
        ui->quantityLineEdit->clear();
    } else {
        ui->quantityLineEdit->setText(this->tempQuantity);
        this->tempQuantity = "";
    }
    elysium::FormatElysiumAmount(ui->quantityLineEdit, ui->divisibleCheckBox->isChecked());
}
