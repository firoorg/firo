// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "metadexcanceldialog.h"
#include "ui_metadexcanceldialog.h"

#include "exodus_qtutils.h"

#include "clientmodel.h"
#include "ui_interface.h"
#include "walletmodel.h"

#include "elysium/createpayload.h"
#include "elysium/errors.h"
#include "elysium/mdex.h"
#include "elysium/exodus.h"
#include "elysium/sp.h"
#include "elysium/pending.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/wallettxs.h"

#include <stdint.h>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <QDateTime>
#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QWidget>

using std::ostringstream;
using std::string;
using namespace exodus;

MetaDExCancelDialog::MetaDExCancelDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MetaDExCancelDialog),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    connect(ui->radioCancelPair, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));
    connect(ui->radioCancelPrice, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));
    connect(ui->radioCancelEverything, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));
    connect(ui->cancelButton, SIGNAL(clicked()),this, SLOT(SendCancelTransaction()));
    connect(ui->fromCombo, SIGNAL(activated(int)), this, SLOT(fromAddressComboBoxChanged(int)));

    // perform initial from address population
    UpdateAddressSelector();
}

MetaDExCancelDialog::~MetaDExCancelDialog()
{
    delete ui;
}

/**
 * Sets the client model.
 */
void MetaDExCancelDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model != NULL) {
        connect(model, SIGNAL(refreshOmniBalance()), this, SLOT(RefreshUI()));
        connect(model, SIGNAL(reinitOmniState()), this, SLOT(ReinitUI()));
    }
}

/**
 * Sets the wallet model.
 */
void MetaDExCancelDialog::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void MetaDExCancelDialog::ReinitUI()
{
    UpdateAddressSelector();
}

/**
 * Refreshes the cancellation address selector
 *
 * Note: only addresses that have a currently open MetaDEx trade (determined by
 * the metadex map) will be shown in the address selector (cancellations sent from
 * addresses without an open MetaDEx trade are invalid).
 */
void MetaDExCancelDialog::UpdateAddressSelector()
{
    LOCK(cs_main);

    QString selectedItem = ui->fromCombo->currentText();
    ui->fromCombo->clear();

    for (md_PropertiesMap::iterator my_it = metadex.begin(); my_it != metadex.end(); ++my_it) {
        md_PricesMap & prices = my_it->second;
        for (md_PricesMap::iterator it = prices.begin(); it != prices.end(); ++it) {
            md_Set & indexes = (it->second);
            for (md_Set::iterator it = indexes.begin(); it != indexes.end(); ++it) {
                CMPMetaDEx obj = *it;
                if(IsMyAddress(obj.getAddr())) { // this address is ours and has an active MetaDEx trade
                    int idx = ui->fromCombo->findText(QString::fromStdString(obj.getAddr())); // avoid adding duplicates
                    if (idx == -1) ui->fromCombo->addItem(QString::fromStdString(obj.getAddr()));
                }
            }
        }
    }

    // restore initial selection
    int idx = ui->fromCombo->findText(selectedItem);
    if (idx != -1) {
        ui->fromCombo->setCurrentIndex(idx);
    }
}

/**
 * Refreshes the cancel combo when the address selector is changed
 */
void MetaDExCancelDialog::fromAddressComboBoxChanged(int)
{
    UpdateCancelCombo(); // all that's needed at this stage
}

/**
 * Refreshes the cancel combo with the latest data based on the currently selected
 * radio button.
 */
void MetaDExCancelDialog::UpdateCancelCombo()
{
    string senderAddress = ui->fromCombo->currentText().toStdString();
    QString existingSelection = ui->cancelCombo->currentText();

    if (senderAddress.empty()) {
        return; // no sender address selected, likely no wallet addresses have open MetaDEx trades
    }

    if ((!ui->radioCancelPair->isChecked()) && (!ui->radioCancelPrice->isChecked()) && (!ui->radioCancelEverything->isChecked())) {
        return; // no radio button is selected
    }

    ui->cancelCombo->clear();

    bool fMainEcosystem = false;
    bool fTestEcosystem = false;

    LOCK(cs_main);

    for (md_PropertiesMap::iterator my_it = metadex.begin(); my_it != metadex.end(); ++my_it) {
        md_PricesMap & prices = my_it->second;
        for (md_PricesMap::iterator it = prices.begin(); it != prices.end(); ++it) {
            md_Set & indexes = it->second;
            for (md_Set::iterator it = indexes.begin(); it != indexes.end(); ++it) {
                CMPMetaDEx obj = *it;
                if(senderAddress == obj.getAddr()) {
                    // for "cancel all":
                    if (isMainEcosystemProperty(obj.getProperty())) fMainEcosystem = true;
                    if (isTestEcosystemProperty(obj.getProperty())) fTestEcosystem = true;

                    bool isBuy = false; // sell or buy? (from UI perspective)
                    if ((obj.getProperty() == ELYSIUM_PROPERTY_ELYSIUM) || (obj.getProperty() == ELYSIUM_PROPERTY_TELYSIUM)) isBuy = true;
                    string sellToken = getPropertyName(obj.getProperty()).c_str();
                    string desiredToken = getPropertyName(obj.getDesProperty()).c_str();
                    string sellId = strprintf("%d", obj.getProperty());
                    string desiredId = strprintf("%d", obj.getDesProperty());
                    if(sellToken.size()>30) sellToken=sellToken.substr(0,30)+"...";
                    sellToken += " (#" + sellId + ")";
                    if(desiredToken.size()>30) desiredToken=desiredToken.substr(0,30)+"...";
                    desiredToken += " (#" + desiredId + ")";
                    string comboStr = "Cancel all orders ";
                    if (isBuy) { comboStr += "buying " + desiredToken; } else { comboStr += "selling " + sellToken; }
                    string dataStr = sellId + "/" + desiredId;
                    if (ui->radioCancelPrice->isChecked()) { // append price if needed
                        comboStr += " priced at " + StripTrailingZeros(obj.displayUnitPrice());
                        if ((obj.getProperty() == ELYSIUM_PROPERTY_ELYSIUM) || (obj.getDesProperty() == ELYSIUM_PROPERTY_ELYSIUM)) { comboStr += " ELYSIUM/SPT"; } else { comboStr += " TELYSIUM/SPT"; }
                        dataStr += ":" + obj.displayUnitPrice();
                    }
                    int index = ui->cancelCombo->findText(QString::fromStdString(comboStr));
                    if ( index == -1 ) { ui->cancelCombo->addItem(QString::fromStdString(comboStr),QString::fromStdString(dataStr)); }
                }
            }
        }
    }

    if (ui->radioCancelEverything->isChecked()) {
        ui->cancelCombo->clear();
        if (fMainEcosystem) ui->cancelCombo->addItem("All active orders in the main ecosystem", 1);
        if (fTestEcosystem) ui->cancelCombo->addItem("All active orders in the test ecosystem", 2);
    }

    int idx = ui->cancelCombo->findText(existingSelection, Qt::MatchExactly);
    if (idx != -1) ui->cancelCombo->setCurrentIndex(idx); // if value selected before update and it still exists, reselect it
}

/**
 * Refreshes the UI fields with the most current data - called when the
 * refreshOmniState() signal is received.
 */
void MetaDExCancelDialog::RefreshUI()
{
    UpdateAddressSelector();
    UpdateCancelCombo();
}


/**
 * Takes the data from the fields in the cancellation UI and asks the wallet to construct a
 * MetaDEx cancel transaction.  Then commits & broadcast the created transaction.
 */
void MetaDExCancelDialog::SendCancelTransaction()
{

    std::string fromAddress = ui->fromCombo->currentText().toStdString();
    if (fromAddress.empty()) {
        // no sender address selected
        QMessageBox::critical( this, "Unable to send transaction",
        "Please select the address you would like to send the cancellation transaction from." );
        return;
    }

    uint8_t action = 0;
    /*
     * 1 = NEW
     * 2 = CANCEL_AT_PRICE
     * 3 = CANCEL_ALL_FOR_PAIR
     * 4 = CANCEL_EVERYTHING
     */

    if (ui->radioCancelPrice->isChecked()) action = 2;
    if (ui->radioCancelPair->isChecked()) action = 3;
    if (ui->radioCancelEverything->isChecked()) action = 4;
    if (action == 0) {
        // no cancellation method selected
        QMessageBox::critical( this, "Unable to send transaction",
        "Please ensure you have selected a cancellation method and valid cancellation criteria." );
        return;
    }
}
