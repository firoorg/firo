/**********************************************************************
 * Copyright (c) 2021-2021 The Firo Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 **********************************************************************/

#include "managetokendialog.h"
#include "ui_managetokendialog.h"

#include "elysium_qtutils.h"

#include "clientmodel.h"
#include "walletmodel.h"

#include "elysium/createpayload.h"
#include "elysium/errors.h"
#include "elysium/parse_string.h"
#include "elysium/pending.h"
#include "elysium/sp.h"
#include "elysium/tally.h"
#include "elysium/tx.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/wallettxs.h"

#include "amount.h"
#include "base58.h"
#include "elysium_qtutils.h"
#include "guiutil.h"
#include "sync.h"
#include "uint256.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <QClipboard>
#include <QFontDatabase>
#include <QMessageBox>

#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace elysium;

ManageTokenDialog::ManageTokenDialog(QWidget* parent) : QWidget(parent),
                                                        ui(new Ui::ManageTokenDialog),
                                                        clientModel(0),
                                                        walletModel(0)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->issueToLineEdit, this);

    this->divisibleQuantityValidator = new QRegExpValidator(QRegExp("([0-9]+\\.?[0-9]{0,8}|\\.[0-9]{1,8})"), this);
    this->indivisibleQuantityValidator = new QRegExpValidator(QRegExp("[1-9][0-9]*"), this);

    setWindowTitle("Manage Tokens");

    connect(ui->issueButton, SIGNAL(clicked()), this, SLOT(onIssueButtonClicked()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(onClearButtonClicked()));

    connect(ui->issuerComboBox, SIGNAL(activated(int)), this, SLOT(issuerComboBoxChanged(int)));

    updateOwnedTokens();


    QFontDatabase db;
    QStringList list = db.families();

    for (QStringList::iterator it = list.begin(); it != list.end(); ++it) {
        QString current = *it;
        printf("%s\n", current.toStdString().c_str());
    }
}

ManageTokenDialog::~ManageTokenDialog()
{
    delete ui;
}

void ManageTokenDialog::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        connect(model, SIGNAL(refreshElysiumBalance()), this, SLOT(updateOwnedTokens()));
        connect(model, SIGNAL(reinitElysiumState()), this, SLOT(updateOwnedTokens()));
    }
}

void ManageTokenDialog::setModel(WalletModel* model)
{
    this->walletModel = model;
}

void ManageTokenDialog::updateOwnedTokens()
{
    LOCK(cs_main);

    uint32_t nextPropIdMainEco = GetNextPropertyId(true);  // these allow us to end the for loop at the highest existing
    uint32_t nextPropIdTestEco = GetNextPropertyId(false); // property ID rather than a fixed value like 100000 (optimization)
    QString currentPropertyId = ui->issuerComboBox->itemData(ui->issuerComboBox->currentIndex()).toString();
    ui->issuerComboBox->clear();
    ownIdAddressMap.clear();

    int concatLength = 24;

    for (unsigned int propertyId = 1; propertyId < nextPropIdMainEco; propertyId++) {
        CMPSPInfo::Entry sp;
        if (_my_sps->getSP(propertyId, sp)) {
            if (!sp.fixed && sp.manual) {
                if (IsMyAddress(sp.issuer)) {
                    ownIdAddressMap[propertyId] = sp.issuer;
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
                    name += " \t(Issuing Address: " + sp.issuer + ")";
                    name += "   (ID: " + propertyIdString + ")";
                    // name += isPropertyDivisible(propertyId) ? " [D]" : " [I]";

                    ui->issuerComboBox->addItem(tr(name.c_str()), propertyIdString.c_str());
                }
            }
        }
    }
    for (unsigned int propertyId = 2147483647; propertyId < nextPropIdTestEco; propertyId++) {
        CMPSPInfo::Entry sp;
        if (_my_sps->getSP(propertyId, sp)) {
            if (!sp.fixed && sp.manual) {
                if (IsMyAddress(sp.issuer)) {
                    ownIdAddressMap[propertyId] = sp.issuer;
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
                    name += " \t(Issuing Address: " + sp.issuer + ")";
                    name += "   (ID: " + propertyIdString + ")";
                    // name += isPropertyDivisible(propertyId) ? " [D]" : " [I]";

                    ui->issuerComboBox->addItem(tr(name.c_str()), propertyIdString.c_str());
                }
            }
        }
    }
    int propIdx = ui->issuerComboBox->findData(currentPropertyId);
    if (propIdx != -1) {
        ui->issuerComboBox->setCurrentIndex(propIdx);
    }

    updateAmountValidator();
}

void ManageTokenDialog::onClearButtonClicked()
{
    clear();
}

void ManageTokenDialog::onIssueButtonClicked()
{
    if (!walletModel) {
        return;
    }

    std::string toAddress = ui->issueToLineEdit->text().toStdString();
    if (toAddress.size() == 0 || !walletModel->validateAddress(ui->issueToLineEdit->text())) {
        ui->issueToLineEdit->setValid(false);
        Q_EMIT message(tr("Invalid address"), tr("Invalid FIRO address entered."), CClientUIInterface::MSG_ERROR);
        return;
    }


    uint32_t propertyId = ui->issuerComboBox->currentData().toString().toUInt();
    std::string amountString = ui->amountLineEdit->text().toStdString();
    int64_t amount = StrToInt64(amountString, isPropertyDivisible(propertyId));
    if (amount == 0) {
        Q_EMIT message(tr("Invalid Amount"), tr("Invalid amount entered."), CClientUIInterface::MSG_ERROR);
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid()) {
        Q_EMIT message(tr("Wallet Error"), tr("The token issue transaction has been cancelled.\n\nThe wallet unlock process must be completed to issue a token."), CClientUIInterface::MSG_ERROR);
        return;
    }

    std::string fromAddress = ownIdAddressMap[propertyId];
    std::string memo = ui->memoLineEdit->text().toStdString();

    std::vector<unsigned char> payload = CreatePayload_Grant(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;

    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);
    if (result != 0) {
        std::string errorMessage = strprintf("The token issuance transaction has failed.\n\nThe error code was: %d\nThe error message was:\n%s", result, error_str(result).c_str());
        Q_EMIT message(tr("Transaction Failed"), tr(errorMessage.c_str()), CClientUIInterface::MSG_ERROR);
        return;
    } else {
        if (!autoCommit) {
            PopulateSimpleDialog(rawHex, "Raw Hex (auto commit is disabled)", "Raw transaction hex");
        } else {
            PopulateTXSentDialog(txid.GetHex());
        }
    }
    clear();
}

void ManageTokenDialog::issuerComboBoxChanged(int index)
{
    updateAmountValidator();
}

void ManageTokenDialog::updateAmountValidator()
{
    uint32_t propertyId = ui->issuerComboBox->currentData().toString().toUInt();
    bool divisible = isPropertyDivisible(propertyId);

    if (divisible) {
        ui->amountLineEdit->setValidator(divisibleQuantityValidator);
    } else {
        ui->amountLineEdit->setValidator(indivisibleQuantityValidator);
    }

    FormatElysiumAmount(ui->amountLineEdit, divisible);
}

void ManageTokenDialog::clear()
{
    ui->issueToLineEdit->clear();
    ui->amountLineEdit->clear();
    ui->memoLineEdit->clear();
}
