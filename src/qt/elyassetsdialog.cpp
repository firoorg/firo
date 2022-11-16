// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2021 The Firo developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "elyassetsdialog.h"
#include "forms/ui_elyassetsdialog.h"

#include "clientmodel.h"
#include "walletmodel.h"
#include "guiutil.h"

#include "elysium/elysium.h"
#include "elysium/sp.h"
#include "elysium/tally.h"
#include "elysium/wallet.h"
#include "elysium/wallettxs.h"

#include "amount.h"
#include "sync.h"
#include "ui_interface.h"
#include "wallet/wallet.h"

#include <stdint.h>
#include <map>
#include <regex>
#include <sstream>
#include <string>

#include <QAbstractItemView>
#include <QAction>
#include <QDialog>
#include <QHeaderView>
#include <QMenu>
#include <QModelIndex>
#include <QPoint>
#include <QResizeEvent>
#include <QString>
#include <QTableWidgetItem>
#include <QWidget>

using std::ostringstream;
using std::string;
using namespace elysium;

ElyAssetsDialog::ElyAssetsDialog(QWidget *parent) :
    QWidget(parent), ui(new Ui::ElyAssetsDialog()), clientModel(0), walletModel(0)
{
    // setup
    ui->setupUi(this);
    ui->balancesTable->setColumnCount(5);
    ui->balancesTable->setHorizontalHeaderItem(0, new QTableWidgetItem("ID"));
    ui->balancesTable->setHorizontalHeaderItem(1, new QTableWidgetItem("Ticker"));
    ui->balancesTable->setHorizontalHeaderItem(2, new QTableWidgetItem("Name"));
    ui->balancesTable->setHorizontalHeaderItem(3, new QTableWidgetItem("Pending"));
    ui->balancesTable->setHorizontalHeaderItem(4, new QTableWidgetItem("Available"));
    borrowedColumnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(ui->balancesTable, 100, 100, this);
    // note neither resizetocontents or stretch allow user to adjust - go interactive then manually set widths
    #if QT_VERSION < 0x050000
       ui->balancesTable->horizontalHeader()->setResizeMode(0, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setResizeMode(1, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setResizeMode(2, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setResizeMode(3, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setResizeMode(4, QHeaderView::Interactive);
    #else
       ui->balancesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
       ui->balancesTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Interactive);
    #endif
    ui->balancesTable->setAlternatingRowColors(true);
    ui->balancesTable->setSortingEnabled(true);

    // do an initial population
    populateBalances();

    // initial resizing
    ui->balancesTable->resizeColumnToContents(0);
    ui->balancesTable->resizeColumnToContents(1);
    ui->balancesTable->resizeColumnToContents(3);
    ui->balancesTable->resizeColumnToContents(4);
    borrowedColumnResizingFixer->stretchColumnWidth(2);
    ui->balancesTable->verticalHeader()->setVisible(false);
    ui->balancesTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui->balancesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->balancesTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->balancesTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    ui->balancesTable->setTabKeyNavigation(false);
    ui->balancesTable->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->balancesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // Actions
    QAction *balancesCopyIDAction = new QAction(tr("Copy property ID"), this);
    QAction *balancesCopyTickerAction = new QAction(tr("Copy ticker"), this);
    QAction *balancesCopyNameAction = new QAction(tr("Copy property name"), this);
    QAction *balancesCopyPendingAmountAction = new QAction(tr("Copy pending amount"), this);
    QAction *balancesCopyAvailableAmountAction = new QAction(tr("Copy available amount"), this);

    contextMenu = new QMenu();
    contextMenu->addAction(balancesCopyIDAction);
    contextMenu->addAction(balancesCopyTickerAction);
    contextMenu->addAction(balancesCopyNameAction);
    contextMenu->addAction(balancesCopyPendingAmountAction);
    contextMenu->addAction(balancesCopyAvailableAmountAction);

    // Connect actions
    connect(ui->balancesTable, &QWidget::customContextMenuRequested, this, &ElyAssetsDialog::contextualMenu);
    connect(balancesCopyIDAction, &QAction::triggered, this, &ElyAssetsDialog::balancesCopyCol0);
    connect(balancesCopyNameAction, &QAction::triggered, this, &ElyAssetsDialog::balancesCopyCol1);
    connect(balancesCopyAvailableAmountAction, &QAction::triggered, this, &ElyAssetsDialog::balancesCopyCol3);
}

ElyAssetsDialog::~ElyAssetsDialog()
{
    delete ui;
}

void ElyAssetsDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model != NULL) {
        connect(model, &ClientModel::refreshElysiumBalance, this, &ElyAssetsDialog::populateBalances);
        connect(model, &ClientModel::reinitElysiumState, this, &ElyAssetsDialog::populateBalances);
    }
}

void ElyAssetsDialog::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model != NULL) { } // do nothing, signals from walletModel no longer needed
}

void ElyAssetsDialog::addRow(const std::string& id, const std::string& ticker, const std::string& name, const std::string& pending, const std::string& available)
{
    int workingRow = ui->balancesTable->rowCount();
    ui->balancesTable->insertRow(workingRow);
    QTableWidgetItem *idCell = new QTableWidgetItem(QString::fromStdString(id));
    QTableWidgetItem *tickerCell = new QTableWidgetItem(QString::fromStdString(ticker));
    QTableWidgetItem *nameCell = new QTableWidgetItem(QString::fromStdString(name));
    QTableWidgetItem *pendingCell = new QTableWidgetItem(QString::fromStdString(pending));
    QTableWidgetItem *availableCell = new QTableWidgetItem(QString::fromStdString(available));
    idCell->setTextAlignment(Qt::AlignLeft + Qt::AlignVCenter);
    tickerCell->setTextAlignment(Qt::AlignLeft + Qt::AlignVCenter);
    nameCell->setTextAlignment(Qt::AlignLeft + Qt::AlignVCenter);
    pendingCell->setTextAlignment(Qt::AlignRight + Qt::AlignVCenter);
    availableCell->setTextAlignment(Qt::AlignRight + Qt::AlignVCenter);
    ui->balancesTable->setItem(workingRow, 0, idCell);
    ui->balancesTable->setItem(workingRow, 1, tickerCell);
    ui->balancesTable->setItem(workingRow, 2, nameCell);
    ui->balancesTable->setItem(workingRow, 3, pendingCell);
    ui->balancesTable->setItem(workingRow, 4, availableCell);
}

void ElyAssetsDialog::populateBalances()
{
    ui->balancesTable->setRowCount(0); // fresh slate (note this will automatically cleanup all existing QWidgetItems in the table)

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // get anonymous balances
    std::vector<LelantusMint> mints;
    wallet->ListLelantusMints(boost::make_function_output_iterator([&](const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsSpent() || !m.second.IsOnChain()) {
            return;
        }
        mints.push_back(m.second);
    }));

    //         ID                     pending           anon
    std::map<PropertyId, std::pair<LelantusAmount, LelantusAmount>> balances;
    for (const auto& mint : mints) {
        std::pair<LelantusAmount, LelantusAmount>& p = balances[mint.property];
        p.second = mint.amount;
    }

    // get "pending" (not anonymous) balances
    // loop over the wallet property list and add the wallet totals
    for (const auto propertyId : global_wallet_property_list) {
        std::pair<LelantusAmount, LelantusAmount>& p = balances[propertyId];
        p.first = global_balance_money[propertyId];
    }

    std::regex rgx("\\(([A-Z0-9]{3,4}\\))$"); // ticker regex

    for (const auto& balance : balances) {
        std::string id = strprintf("%d", balance.first);
        std::string name = getPropertyName(balance.first);
        std::string pending = FormatMP(balance.first, balance.second.first);
        std::string available = FormatMP(balance.first, balance.second.second);

        std::smatch matches;
        std::string ticker = "";
        std::regex_search(name, matches, rgx);
        if (matches.size() != 0 && matches[0] != "(FIRO)") { // ignore special exception "(FIRO)""
            ticker = matches[0];
            name = name.substr(0, name.length() - ticker.length()); // remove ticker from name to be displayed
            ticker = ticker.substr(1, ticker.length() - 2); // remove brackets
        }

        addRow(id, ticker, name, pending, available);
    }
}

void ElyAssetsDialog::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->balancesTable->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void ElyAssetsDialog::balancesCopyCol0()
{
    GUIUtil::setClipboard(ui->balancesTable->item(ui->balancesTable->currentRow(),0)->text());
}

void ElyAssetsDialog::balancesCopyCol1()
{
    GUIUtil::setClipboard(ui->balancesTable->item(ui->balancesTable->currentRow(),1)->text());
}

void ElyAssetsDialog::balancesCopyCol2()
{
    GUIUtil::setClipboard(ui->balancesTable->item(ui->balancesTable->currentRow(),2)->text());
}

void ElyAssetsDialog::balancesCopyCol3()
{
    GUIUtil::setClipboard(ui->balancesTable->item(ui->balancesTable->currentRow(),3)->text());
}

void ElyAssetsDialog::balancesCopyCol4()
{
    GUIUtil::setClipboard(ui->balancesTable->item(ui->balancesTable->currentRow(),4)->text());
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ElyAssetsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    borrowedColumnResizingFixer->stretchColumnWidth(2);
}
