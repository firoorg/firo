/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#include "elysiumprivatesenddialog.h"
#include "ui_elysiumprivatesenddialog.h"

#include "elysium/createpayload.h"
#include "elysium/elysium.h"
#include "elysium/errors.h"
#include "elysium/lelantusutils.h"
#include "elysium/parse_string.h"
#include "elysium/pending.h"
#include "elysium/rules.h"
#include "elysium/tx.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/wallet.h"

#include "addressbookpage.h"
#include "clientmodel.h"
#include "elysium_qtutils.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "validation.h"

#include <QClipboard>
#include <QMessageBox>

using namespace elysium;

ElysiumPrivateSendDialog::ElysiumPrivateSendDialog(const PlatformStyle* platformStyle, QWidget* parent) : QWidget(parent),
                                                                                                          ui(new Ui::ElysiumPrivateSendDialog),
                                                                                                          platformstyle(platformStyle),
                                                                                                          clientModel(0),
                                                                                                          walletModel(0)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformstyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformstyle->SingleColorIcon(":/icons/editpaste"));

    GUIUtil::setupAddressWidget(ui->sendToLineEdit, this);

    this->divisibleQuantityValidator = new QRegExpValidator(QRegExp("([0-9]+\\.?[0-9]{0,8}|\\.[0-9]{1,8})"), this);
    this->indivisibleQuantityValidator = new QRegExpValidator(QRegExp("[1-9][0-9]*"), this);

    setWindowTitle("Elysium Private Send");

    connect(ui->sendButton, SIGNAL(clicked()), this, SLOT(onSendButtonClicked()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(onClearButtonClicked()));
    connect(ui->pasteButton, SIGNAL(clicked()), this, SLOT(onPasteButtonClicked()));
    connect(ui->addressBookButton, SIGNAL(clicked()), this, SLOT(onAddressBookButtonClicked()));
    connect(ui->tokenComboBox, SIGNAL(activated(int)), this, SLOT(onTokenComboBoxChanged(int)));

    balancesUpdated();
}

ElysiumPrivateSendDialog::~ElysiumPrivateSendDialog()
{
    delete ui;
}
void ElysiumPrivateSendDialog::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model != NULL) {
        connect(model, SIGNAL(refreshElysiumBalance()), this, SLOT(balancesUpdated()));
        connect(model, SIGNAL(reinitElysiumState()), this, SLOT(balancesUpdated()));
    }
}

void ElysiumPrivateSendDialog::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

// update combobox with available private token balances
void ElysiumPrivateSendDialog::updateTokenComboBox()
{
    LOCK2(cs_main, pwalletMain->cs_wallet); 

    QString currentPropertyId = ui->tokenComboBox->itemData(ui->tokenComboBox->currentIndex()).toString();
    ui->tokenComboBox->clear();

    std::vector<LelantusMint> mints;

    wallet->ListLelantusMints(boost::make_function_output_iterator([&](const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsSpent() || !m.second.IsOnChain()) {
            return;
        }
        mints.push_back(m.second);
    }));

    balances.clear();
    for (const auto& mint : mints) {
        balances[mint.property] += mint.amount;
    }

    int concatLength = 24;
    for (const auto& balance : balances) {
        std::string name = getPropertyName(balance.first);
        std::string propertyIdString = strprintf("%d", balance.first);

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

    int propIdx = ui->tokenComboBox->findData(currentPropertyId);
    if (propIdx != -1) {
        ui->tokenComboBox->setCurrentIndex(propIdx);
    }
}

void ElysiumPrivateSendDialog::updateBalanceLabel()
{
    uint32_t propertyId = ui->tokenComboBox->currentData().toString().toUInt();
    std::string balance = "Wallet Balance (Available): " + FormatMP(propertyId, balances[propertyId]);
    ui->balanceLabel->setText(QString::fromStdString(balance));
}

void ElysiumPrivateSendDialog::updateAmountFieldValidators()
{
    uint32_t propertyId = ui->tokenComboBox->currentData().toString().toUInt();
    bool divisible = isPropertyDivisible(propertyId);
    if (divisible) {
        ui->amountLineEdit->setValidator(divisibleQuantityValidator);
        // ui->referenceAmountLineEdit->setValidator(divisibleQuantityValidator);
    } else {
        ui->amountLineEdit->setValidator(indivisibleQuantityValidator);
        // ui->referenceAmountLineEdit->setValidator(indivisibleQuantityValidator);
    }

    FormatElysiumAmount(ui->amountLineEdit, divisible);
    // FormatElysiumAmount(ui->referenceAmountLineEdit, divisible);
}

void ElysiumPrivateSendDialog::onClearButtonClicked()
{
    clear();
}

void ElysiumPrivateSendDialog::clear()
{
    ui->sendToLineEdit->clear();
    ui->amountLineEdit->clear();
    // ui->referenceAmountLineEdit->clear();
}

void ElysiumPrivateSendDialog::onSendButtonClicked()
{
    if (!walletModel) {
        return;
    }

    uint32_t propertyId = ui->tokenComboBox->currentData().toString().toUInt();
    bool divisible = isPropertyDivisible(propertyId);

    std::string toAddress = ui->sendToLineEdit->text().toStdString();

    CBitcoinAddress address(toAddress);
    if (toAddress.size() == 0 || !address.IsValid()) {
        ui->sendToLineEdit->setValid(false);
        Q_EMIT message(tr("Invalid address"), tr("Invalid FIRO address entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    std::string amountString = ui->amountLineEdit->text().toStdString();
    if (amountString.size() == 0 || amountString == ".") {
        Q_EMIT message(tr("Invalid amount"), tr("Invalid amount entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    int64_t amount = elysium::StrToInt64(amountString, divisible);
    if (amount == 0) {
        Q_EMIT message(tr("Invalid amount"), tr("Invalid amount entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    // amountString = ui->referenceAmountLineEdit->text().toStdString();
    int64_t referenceAmount = 0; //amountString.size() == 0 ? 0 : elysium::StrToInt64(amountString, divisible);
    // if ((0.01 * COIN) < referenceAmount) {
    //     Q_EMIT message(tr("Invalid reference amount"), tr("Reference amount higher is than 0.01 FIRO."), CClientUIInterface::MSG_ERROR);
    //     return;
    // }

    if (!IsFeatureActivated(FEATURE_LELANTUS, GetHeight())) {
        Q_EMIT message(tr("Lelantus Error"), tr("Lelantus feature is not activated yet."), CClientUIInterface::MSG_ERROR);
        return;
    }

    if (!IsLelantusEnabled(propertyId)) {
        Q_EMIT message(tr("Lelantus Error"), tr("Property has not enabled Lelantus."), CClientUIInterface::MSG_ERROR);
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        Q_EMIT message(tr("Wallet Error"), tr("The send transaction has been cancelled.\n\nThe wallet unlock process must be completed to send a transaction."), CClientUIInterface::MSG_ERROR);
        return;
    }

    if (referenceAmount <= 0) {
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(address).Get());
        referenceAmount = GetDustThreshold(scriptPubKey);
    }

    auto metaData = PrepareSpendMetadata(address, referenceAmount);

    std::vector<SpendableCoin> spendables;
    boost::optional<LelantusWallet::MintReservation> reservation;
    LelantusAmount changeValue = 0;

    std::vector<unsigned char> payload;

    try {
        auto joinSplit = wallet->CreateLelantusJoinSplit(propertyId, amount, metaData, spendables, reservation, changeValue);

        boost::optional<JoinSplitMint> joinSplitMint;
        if (reservation.get_ptr() != nullptr) {
            auto pub = reservation->coin.getPublicCoin();
            EncryptedValue enc;
            EncryptMintAmount(changeValue, pub.getValue(), enc);

            joinSplitMint = JoinSplitMint(
                reservation->id,
                pub,
                enc);
        }

        payload = CreatePayload_CreateLelantusJoinSplit(propertyId, amount, joinSplit, joinSplitMint);

    } catch (InsufficientFunds& e) {
        Q_EMIT message(tr("Insufficient Funds"), tr("The selected sending address does not have a sufficient balance to cover the amount entered.\n\nPlease double-check the transction details thoroughly before retrying your send transaction."), CClientUIInterface::MSG_ERROR);
        return;
    } catch (WalletError& e) {
        Q_EMIT message(tr("Wallet Error"), tr(e.what()), CClientUIInterface::MSG_ERROR);
        return;
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder("", toAddress, "", referenceAmount, payload, txid, rawHex, autoCommit, InputMode::LELANTUS);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        std::string errorMessage = strprintf("The send transaction has failed.\n\nThe error code was: %d\nThe error message was:\n%s", result, error_str(result).c_str());
        Q_EMIT message(tr("Transaction Failed"), tr(errorMessage.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    } else {
        // mark the coin as used
        for (auto const& s : spendables) {
            wallet->SetLelantusMintUsedTransaction(s.id, txid);
        }

        if (reservation.get_ptr() != nullptr) {
            reservation->Commit();
        }

        if (!autoCommit) {
            PopulateSimpleDialog(rawHex, "Raw Hex (auto commit is disabled)", "Raw transaction hex");
        } else {
            PendingAdd(txid, "Lelantus Joinsplit", ELYSIUM_TYPE_LELANTUS_JOINSPLIT, propertyId, amount, false, toAddress);
            PopulateTXSentDialog(txid.GetHex());
        }
    }
    clear();
}

void ElysiumPrivateSendDialog::onTokenComboBoxChanged(int index)
{
    updateBalanceLabel();
    updateAmountFieldValidators();
}

void ElysiumPrivateSendDialog::balancesUpdated()
{
    updateTokenComboBox();
    updateBalanceLabel();
    updateAmountFieldValidators();
}

void ElysiumPrivateSendDialog::onPasteButtonClicked()
{
    ui->sendToLineEdit->setText(QApplication::clipboard()->text());
}

void ElysiumPrivateSendDialog::onAddressBookButtonClicked()
{
    if (!walletModel) return;

    AddressBookPage addressBook(platformstyle, AddressBookPage::ForSelection, AddressBookPage::SendingTab, this);
    addressBook.setModel(walletModel->getAddressTableModel());
    if (addressBook.exec()) {
        ui->sendToLineEdit->setText(addressBook.getReturnValue());
        ui->amountLineEdit->setFocus();
    }
}
