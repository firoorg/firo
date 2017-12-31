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
#include <QTime>

int GetTimeOffsetFromUtc()
{
#if QT_VERSION < 0x050200
    const QDateTime dateTime1 = QDateTime::currentDateTime();
    const QDateTime dateTime2 = QDateTime(dateTime1.date(), dateTime1.time(), Qt::UTC);
    return dateTime1.secsTo(dateTime2);
#else
    return QDateTime::currentDateTime().offsetFromUtc();
#endif
}

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
 
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->setShowGrid(false);
 
    int nNewRow = 0;

    //Smartrewards snapshot date
    QDateTime lastSmartrewardsSnapshotDateTimeUtc = QDateTime::currentDateTime();
    int currentDay = QDateTime::currentDateTimeUtc().toString("dd").toInt();
    if(currentDay < SMARTREWARDS_DAY){
       lastSmartrewardsSnapshotDateTimeUtc = lastSmartrewardsSnapshotDateTimeUtc.addMonths(-1);
    }
    int snapshotMonth = lastSmartrewardsSnapshotDateTimeUtc.toString("MM").toInt();
    int snapshotYear = lastSmartrewardsSnapshotDateTimeUtc.toString("yyyy").toInt();
    lastSmartrewardsSnapshotDateTimeUtc = QDateTime(QDate(snapshotYear, snapshotMonth, SMARTREWARDS_DAY), QTime(SMARTREWARDS_UTC_HOUR, 0), Qt::UTC);


    BOOST_FOREACH(const PAIRTYPE(QString, std::vector<COutput>)& coins, mapCoins) {
        QString sWalletAddress = coins.first;
        QString sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");
 
        ui->tableWidget->insertRow(nNewRow);
 
        CAmount amountSum = 0;
        CAmount smartRewardsSum = 0;
        CAmount txAmount = 0;
        int nChildren = 0;
        BOOST_FOREACH(const COutput& out, coins.second) {

            amountSum += out.tx->vout[out.i].nValue;
            txAmount = out.tx->vout[out.i].nValue;
            nChildren++;
 
            //address
            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.tx->vout[out.i].scriptPubKey, outputAddress))
            {
                sAddress = QString::fromStdString(CBitcoinAddress(outputAddress).ToString());
            }

            //tx date
            int64_t nTimeTx = out.tx->GetTxTime();
            QDateTime txDateTime = QDateTime::fromTime_t((qint32)nTimeTx);
            QDateTime txDateTimeUtc = txDateTime.toUTC();

            //check if the tx is after the snapshot date
            if(txDateTimeUtc < lastSmartrewardsSnapshotDateTimeUtc){
                smartRewardsSum += txAmount;
            }

            ui->tableWidget->setItem(nNewRow, 0, new QTableWidgetItem(sWalletLabel));
            ui->tableWidget->setItem(nNewRow, 1, new QTableWidgetItem(sWalletAddress));
            ui->tableWidget->setItem(nNewRow, 2, new QTableWidgetItem(BitcoinUnits::format(nDisplayUnit, amountSum)));

            //check min eligible amount to rewards
            if(amountSum >= SMARTREWARDS_MINIMUM_AMOUNT){
                 ui->tableWidget->setItem(nNewRow, 3, new QTableWidgetItem(BitcoinUnits::format(nDisplayUnit, smartRewardsSum)));
            }else{
                 ui->tableWidget->setItem(nNewRow, 3, new QTableWidgetItem(BitcoinUnits::format(nDisplayUnit, 0)));
            }

        }
        nNewRow++;
 
    }

}
 
