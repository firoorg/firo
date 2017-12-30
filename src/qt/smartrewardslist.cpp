#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif
 
#include "smartrewardslist.h"
#include "ui_smartrewardslist.h"
 
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "txmempool.h"
#include "walletmodel.h"
 
#include "coincontrol.h"
#include "init.h"
#include "main.h" // For minRelayTxFee
#include "wallet/wallet.h"
 
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
 
#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QTableWidget>

SmartrewardsList::SmartrewardsList(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SmartrewardsList),
    model(0)
{
    ui->setupUi(this);
 
    int columnAliasWidth = 200;
    int columnAddressWidth = 250;
    int columnAmountWidth = 160;
    int columnSmartAmountWidth = 200;
 
    ui->tableWidget->setColumnWidth(0, columnAliasWidth);
    ui->tableWidget->setColumnWidth(1, columnAddressWidth);
    ui->tableWidget->setColumnWidth(2, columnAmountWidth);
    ui->tableWidget->setColumnWidth(3, columnSmartAmountWidth);
 
}
 
SmartrewardsList::~SmartrewardsList()
{
    delete ui;
}
 
 void SmartrewardsList::setModel(WalletModel *model)
{
    this->model = model;
    if(!model) {
       return;
    }
 
    ui->tableWidget->setAlternatingRowColors(true);
 
    int nDisplayUnit = model->getOptionsModel()->getDisplayUnit();
 
    std::map<QString, std::vector<COutput> > mapCoins;
    model->listCoins(mapCoins);
 
    //ui->tableWidget->setRowCount(10);
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->setShowGrid(false);
 
    int nNewRow = 0;
 
    BOOST_FOREACH(const PAIRTYPE(QString, std::vector<COutput>)& coins, mapCoins) {
        QString sWalletAddress = coins.first;
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");
 
        ui->tableWidget->insertRow(nNewRow);
 
        CAmount nSum = 0;
        //double dPrioritySum = 0;
        int nChildren = 0;
        //int nInputSum = 0;
        BOOST_FOREACH(const COutput& out, coins.second) {
            //int nInputSize = 0;
            nSum += out.tx->vout[out.i].nValue;
            nChildren++;
 
            // address
            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.tx->vout[out.i].scriptPubKey, outputAddress))
            {
                sAddress = QString::fromStdString(CBitcoinAddress(outputAddress).ToString());
            }
 
 
            ui->tableWidget->setItem(nNewRow, 0, new QTableWidgetItem(sWalletLabel));
            ui->tableWidget->setItem(nNewRow, 1, new QTableWidgetItem(sWalletAddress));
            ui->tableWidget->setItem(nNewRow, 2, new QTableWidgetItem(BitcoinUnits::format(nDisplayUnit, out.tx->vout[out.i].nValue)));
 
        }
        nNewRow++;
 
    }

}
 
