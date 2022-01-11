/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#include "minttokendialog.h"
#include "ui_minttokendialog.h"

#include "elysium/createpayload.h"
#include "elysium/elysium.h"
#include "elysium/errors.h"
#include "elysium/parse_string.h"
#include "elysium/pending.h"
#include "elysium/rules.h"
#include "elysium/sp.h"
#include "elysium/tx.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/wallet.h"
#include "elysium/wallettxs.h"

#include "clientmodel.h"
#include "elysium_qtutils.h"
#include "guiutil.h"
#include "validation.h"

#include <QClipboard>
#include <QMessageBox>

using namespace elysium;

MintTokenDialog::MintTokenDialog(QWidget* parent) : QWidget(parent),
                                                    ui(new Ui::MintTokenDialog),
                                                    clientModel(0),
                                                    walletModel(0)
{
    ui->setupUi(this);

    this->divisibleQuantityValidator = new QRegExpValidator(QRegExp("([0-9]+\\.?[0-9]{0,8}|\\.[0-9]{1,8})"), this);
    this->indivisibleQuantityValidator = new QRegExpValidator(QRegExp("[1-9][0-9]*"), this);

    setWindowTitle("Mint Tokens");

    connect(ui->mintButton, SIGNAL(clicked()), this, SLOT(onMintButtonClicked()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(onClearButtonClicked()));
    connect(ui->tokenComboBox, SIGNAL(activated(int)), this, SLOT(onTokenComboBoxChanged(int)));
    connect(ui->addressComboBox, SIGNAL(activated(int)), this, SLOT(onAddressComboBoxChanged(int)));

    balancesUpdated();
}

MintTokenDialog::~MintTokenDialog()
{
    delete ui;
}

void MintTokenDialog::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        connect(model, SIGNAL(refreshElysiumBalance()), this, SLOT(balancesUpdated()));
        connect(model, SIGNAL(reinitElysiumState()), this, SLOT(balancesUpdated()));
    }
}

void MintTokenDialog::setModel(WalletModel* model)
{
    this->walletModel = model;
}

void MintTokenDialog::onTokenComboBoxChanged(int index)
{
    updateAddressComboBox();
    updateBalanceLabel();
    updateAmountValidator();
}

void MintTokenDialog::onAddressComboBoxChanged(int index)
{
    updateBalanceLabel();
}

void MintTokenDialog::onClearButtonClicked()
{
    clear();
}

void MintTokenDialog::clear()
{
    ui->quantityLineEdit->clear();
}

void MintTokenDialog::onMintButtonClicked()
{
    if (!walletModel) {
        return;
    }
    std::string fromAddress = ui->addressComboBox->currentText().toStdString();
    uint32_t propertyId = (ui->tokenComboBox->itemData(ui->tokenComboBox->currentIndex()).toString()).toUInt();

    if (!IsFeatureActivated(FEATURE_LELANTUS, GetHeight())) {
        Q_EMIT message(tr("Lelantus Error"), tr("Lelantus feature is not activated yet."), CClientUIInterface::MSG_ERROR);
        return;
    }

    if (!IsLelantusEnabled(propertyId)) {
        Q_EMIT message(tr("Lelantus Error"), tr("Property has not enabled Lelantus."), CClientUIInterface::MSG_ERROR);
        return;
    }

    std::string amountString = ui->quantityLineEdit->text().toStdString();
    int64_t amount = StrToInt64(amountString, isPropertyDivisible(propertyId));

    if (amount == 0) {
        Q_EMIT message(tr("Invalid Amount"), tr("Invalid amount entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    int64_t balance = getMPbalance(fromAddress, propertyId, BALANCE);
    if (balance < amount) {
        Q_EMIT message(tr("Insufficient Balance"), tr("Sender has insufficient balance."), CClientUIInterface::MSG_ERROR);
        return;
    }
    int64_t balanceUnconfirmed = getUserAvailableMPbalance(fromAddress, propertyId);
    if (balanceUnconfirmed < amount) {
        Q_EMIT message(tr("Insufficient Balance"), tr("Sender has insufficient balance (due to pending transactions)."), CClientUIInterface::MSG_ERROR);
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        return; // Unlock wallet was cancelled
    }

    auto mint = wallet->CreateLelantusMint(propertyId, amount);
    auto coin = mint.coin;

    CDataStream serializedSchnorrProof(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(coin, serializedSchnorrProof);

    uint256 txid;
    std::string rawHex;

    auto payload = CreatePayload_CreateLelantusMint(propertyId, coin.getPublicCoin(), mint.id, amount, {serializedSchnorrProof.begin(), serializedSchnorrProof.end()});
    auto result = WalletTxBuilder(fromAddress, "", "", payload, txid, rawHex, autoCommit);

    QMessageBox messageBox;
    if (result != 0) {
        std::string errorMessage = strprintf("The mint transaction has failed.\n\nThe error code was: %d\nThe error message was:\n%s", result, error_str(result).c_str());
        Q_EMIT message(tr("Transaction Failed"), tr(errorMessage.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    }

    // success then commit
    mint.Commit();

    if (!autoCommit) {
        elysium::PopulateSimpleDialog(rawHex, "Raw Hex (auto commit is disabled)", "Raw transaction hex");
    } else {
        PendingAdd(txid, fromAddress, ELYSIUM_TYPE_LELANTUS_MINT, propertyId, amount);
        elysium::PopulateTXSentDialog(txid.GetHex());
    }
    clear();
}

void MintTokenDialog::updateAddressComboBox()
{
    // cache currently selected from address & clear address selector
    std::string currentFromAddress = ui->addressComboBox->currentText().toStdString();
    ui->addressComboBox->clear();

    uint32_t propertyId = (ui->tokenComboBox->itemData(ui->tokenComboBox->currentIndex()).toString()).toUInt();

    LOCK(cs_main);
    for (std::unordered_map<string, CMPTally>::iterator my_it = mp_tally_map.begin(); my_it != mp_tally_map.end(); ++my_it) {
        string address = (my_it->first).c_str();
        uint32_t id = 0;
        bool includeAddress = false;
        (my_it->second).init();
        while (0 != (id = (my_it->second).next())) {
            if (id == propertyId) {
                includeAddress = true;
                break;
            }
        }
        if (!includeAddress) {
            //ignore this address, has never transacted in this propertyId
            continue;
        }
        if (IsMyAddress(address) != ISMINE_SPENDABLE) continue;        // ignore this address, it's not spendable
        if (!getUserAvailableMPbalance(address, propertyId)) continue; // ignore this address, has no available balance to spend
        ui->addressComboBox->addItem(QString::fromStdString(address));
    }

    // attempt to set from address back to cached value
    int fromIdx = ui->addressComboBox->findText(QString::fromStdString(currentFromAddress), Qt::MatchContains);
    if (fromIdx != -1) {
        ui->addressComboBox->setCurrentIndex(fromIdx);
    } // -1 means the cached from address doesn't have a balance in the newly selected property
}

void MintTokenDialog::updateBalanceLabel()
{
    uint32_t propertyId = (ui->tokenComboBox->itemData(ui->tokenComboBox->currentIndex()).toString()).toUInt();
    std::string currentFromAddress = ui->addressComboBox->currentText().toStdString();
    ui->balanceLabel->setText(QString::fromStdString("Available Balance (current address): " + FormatMP(propertyId, getUserAvailableMPbalance(currentFromAddress, propertyId))));
}

// update combobox with available private token balances
void MintTokenDialog::updateTokenComboBox()
{
    LOCK(cs_main);

    uint32_t nextPropIdMainEco = GetNextPropertyId(true);  // these allow us to end the for loop at the highest existing
    uint32_t nextPropIdTestEco = GetNextPropertyId(false); // property ID rather than a fixed value like 100000 (optimization)

    QString currentPropertyId = ui->tokenComboBox->itemData(ui->tokenComboBox->currentIndex()).toString();
    ui->tokenComboBox->clear();

    int concatLength = 24;

    for (unsigned int propertyId = 1; propertyId < nextPropIdMainEco; propertyId++) {
        if ((global_balance_money[propertyId] > 0) || (global_balance_reserved[propertyId] > 0)) {
            std::string name = getPropertyName(propertyId);
            std::string propertyIdString = strprintf("%d", propertyId);

            if (name.size() > concatLength) {
                name = name.substr(0, concatLength) + "...";
            }
            // pad name if shorter than concat + length of "..."
            if (name.size() < (concatLength + 3)) {
                int padLength = concatLength + 3 - name.size();
                while (padLength > 0) {
                    name += " ";
                    padLength--;
                }
            }
            name += "\t(ID: " + propertyIdString + ")";

            ui->tokenComboBox->addItem(name.c_str(), propertyIdString.c_str());
        }
    }
    for (unsigned int propertyId = 2147483647; propertyId < nextPropIdTestEco; propertyId++) {
        if ((global_balance_money[propertyId] > 0) || (global_balance_reserved[propertyId] > 0)) {
            std::string name = getPropertyName(propertyId);
            std::string propertyIdString = strprintf("%d", propertyId);

            if (name.size() > concatLength) {
                name = name.substr(0, concatLength) + "...";
            }
            // pad name if shorter than concat + length of "..."
            if (name.size() < (concatLength + 3)) {
                int padLength = concatLength + 3 - name.size();
                while (padLength > 0) {
                    name += " ";
                    padLength--;
                }
            }
            name += "\t(ID: " + propertyIdString + ")";

            ui->tokenComboBox->addItem(name.c_str(), propertyIdString.c_str());
        }
    }
    int propIdx = ui->tokenComboBox->findData(currentPropertyId);
    if (propIdx != -1) {
        ui->tokenComboBox->setCurrentIndex(propIdx);
    }
}

void MintTokenDialog::balancesUpdated()
{
    updateTokenComboBox();
    updateAddressComboBox();
    updateBalanceLabel();
    updateAmountValidator();
}

void MintTokenDialog::updateAmountValidator()
{
    uint32_t propertyId = ui->tokenComboBox->currentData().toString().toUInt();
    bool divisible = isPropertyDivisible(propertyId);

    if (divisible) {
        ui->quantityLineEdit->setValidator(divisibleQuantityValidator);
    } else {
        ui->quantityLineEdit->setValidator(indivisibleQuantityValidator);
    }

    FormatElysiumAmount(ui->quantityLineEdit, divisible);
}