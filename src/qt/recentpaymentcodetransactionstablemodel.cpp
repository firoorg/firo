// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "recentpaymentcodetransactionstablemodel.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"

#include "clientversion.h"
#include "streams.h"

#include <boost/foreach.hpp>
#include <QMessageBox>
#include <QString>

RecentPCodeTransactionsTableModel::RecentPCodeTransactionsTableModel(CWallet *wallet, WalletModel *parent) :
    QAbstractTableModel(parent), walletModel(parent)
{
    Q_UNUSED(wallet);
    nRecentPCodeNotificationMaxId = 0;

    // Load entries from wallet
    std::vector<std::string> vPCodeNotificationTransactions;
    parent->loadPCodeNotificationTransactions(vPCodeNotificationTransactions);
    BOOST_FOREACH(const std::string& request, vPCodeNotificationTransactions)
        addNewRequest(request);

    /* These columns must match the indices in the ColumnIndex enumeration */
    columns << "Receiver's Masked Payment Code" << "Fee" << "Timestamp";

    connect(walletModel->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
}

RecentPCodeTransactionsTableModel::~RecentPCodeTransactionsTableModel()
{
    /* Intentionally left empty */
}

int RecentPCodeTransactionsTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return list.length();
}

int RecentPCodeTransactionsTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return columns.length();
}

QVariant RecentPCodeTransactionsTableModel::data(const QModelIndex &index, int role) const
{
    
    if(!index.isValid() || index.row() >= list.length())
        return QVariant();

    const RecentPCodeTransactionEntry *rec = &list[index.row()];

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case RPCode:
            return rec->rpcode;
        case Fee:
            return QString("%1 XZC").arg(BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), rec->fee, false, BitcoinUnits::separatorNever));
        case Timestamp:
            return GUIUtil::dateTimeStr(rec->date);
        }
    }
    return QVariant();
}

bool RecentPCodeTransactionsTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    return true;
}

QVariant RecentPCodeTransactionsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}


QModelIndex RecentPCodeTransactionsTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return createIndex(row, column);
}

bool RecentPCodeTransactionsTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);

    return false;
}

Qt::ItemFlags RecentPCodeTransactionsTableModel::flags(const QModelIndex &index) const
{
    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

// called when adding a request from the GUI
void RecentPCodeTransactionsTableModel::addNewRequest(const QString &rpcode, CAmount fee)
{
    RecentPCodeTransactionEntry newEntry;
    newEntry.id = ++nRecentPCodeNotificationMaxId;
    newEntry.date = QDateTime::currentDateTime();
    newEntry.rpcode = rpcode;
    newEntry.fee = fee;

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << newEntry;

    if (!walletModel->savePCodeNotificationTransaction(rpcode.toStdString(), newEntry.id, ss.str()))
        return;

    addNewRequest(newEntry);
}

// called from ctor when loading from wallet
void RecentPCodeTransactionsTableModel::addNewRequest(const std::string &recipient)
{
    std::vector<char> data(recipient.begin(), recipient.end());
    CDataStream ss(data, SER_DISK, CLIENT_VERSION);

    RecentPCodeTransactionEntry entry;
    ss >> entry;

    if (entry.id == 0) // should not happen
        return;

    if (entry.id > nRecentPCodeNotificationMaxId)
        nRecentPCodeNotificationMaxId = entry.id;

    addNewRequest(entry);
}

// actually add to table in GUI
void RecentPCodeTransactionsTableModel::addNewRequest(RecentPCodeTransactionEntry &recipient)
{
    beginInsertRows(QModelIndex(), 0, 0);
    list.prepend(recipient);
    endInsertRows();
}

void RecentPCodeTransactionsTableModel::sort(int column, Qt::SortOrder order)
{
    qSort(list.begin(), list.end(), RecentPCodeTransactionEntryLessThan(column, order));
    Q_EMIT dataChanged(index(0, 0, QModelIndex()), index(list.size() - 1, NUMBER_OF_COLUMNS - 1, QModelIndex()));
}

void RecentPCodeTransactionsTableModel::updateDisplayUnit()
{
    // updateAmountColumnTitle();
}

bool RecentPCodeTransactionEntryLessThan::operator()(RecentPCodeTransactionEntry &left, RecentPCodeTransactionEntry &right) const
{
    RecentPCodeTransactionEntry *pLeft = &left;
    RecentPCodeTransactionEntry *pRight = &right;
    if (order == Qt::DescendingOrder)
        std::swap(pLeft, pRight);

    switch(column)
    {
    case RecentPCodeTransactionsTableModel::RPCode:
        return pLeft->rpcode.compare(pRight->rpcode);
    case RecentPCodeTransactionsTableModel::Fee:
        return pLeft->fee < pRight->fee;
    case RecentPCodeTransactionsTableModel::Timestamp:
        return pLeft->date.toTime_t() < pRight->date.toTime_t();
    default:
        return pLeft->id < pRight->id;
    }
}


