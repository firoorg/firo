
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

    std::map<QString, std::vector<COutput> > mapCoins;
    model->listCoins(mapCoins);

    //ui->tableWidget->setRowCount(10);
    //ui->tableWidget->setColumnCount(4);
    //ui->tableWidget->setShowGrid(false);

    BOOST_FOREACH(const PAIRTYPE(QString, std::vector<COutput>)& coins, mapCoins) {

        QString sWalletAddress = coins.first;
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");




        ui->tableWidget->setItem(0, 1, new QTableWidgetItem("Hello"));
    }


   //ui->tableWidget->setItem(0, 1, new QTableWidgetItem("Hello"));

//    proxyModel = new QSortFilterProxyModel(this);
//    proxyModel->setSourceModel(model);
//    proxyModel->setDynamicSortFilter(true);
//    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
//    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

//    // Receive filter
//    proxyModel->setFilterRole(AddressTableModel::TypeRole);
//    proxyModel->setFilterFixedString(AddressTableModel::Receive);

//    ui->tableWidget->setModel(proxyModel);
//    ui->tableWidget->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
//#if QT_VERSION < 0x050000
//    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
//    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
//#else
//    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
//    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
//#endif



}
