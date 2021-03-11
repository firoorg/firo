// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pcodemodel.h"
#include "../bip47/paymentcode.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"

#include "clientversion.h"
#include "streams.h"
#include "bip47/account.h"

#include <boost/foreach.hpp>

namespace {
static void OnPcodeCreated_(PcodeModel *pcodeModel, bip47::CPaymentCodeDescription const & pcodeDescr)
{
    pcodeModel->OnPcodeCreated(pcodeDescr);
}
}

PcodeModel::PcodeModel(CWallet *wallet, WalletModel *parent) :
    QAbstractTableModel(parent),
    walletMain(*wallet),
    walletModel(parent)
{
    /* These columns must match the indices in the ColumnIndex enumeration */
    columns << tr("#") << tr("Payment code") << tr("Label");

    wallet->NotifyPcodeCreated.connect(boost::bind(OnPcodeCreated_, this, _1));
    items = wallet->ListPcodes();
}

PcodeModel::~PcodeModel()
{
    walletMain.NotifyPcodeCreated.disconnect(boost::bind(OnPcodeCreated_, this, _1));
}

std::vector<bip47::CPaymentCodeDescription> const & PcodeModel::getItems() const
{
    return items;
}

int PcodeModel::rowCount(const QModelIndex &) const
{
    return items.size();
}

int PcodeModel::columnCount(const QModelIndex &) const
{
    return columns.length();
}

QVariant PcodeModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid() || index.row() >= int(items.size()))
        return QVariant();

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        bip47::CPaymentCodeDescription const & desc = items[index.row()];
        switch(ColumnIndex(index.column()))
        {
            case ColumnIndex::Number:
                return int(std::get<0>(desc));
            case ColumnIndex::Pcode:
                return std::get<1>(desc).toString().c_str();
            case ColumnIndex::Label:
                return std::get<2>(desc).c_str();
        }
    }
    else if (role == Qt::TextAlignmentRole)
    {
        if (ColumnIndex(index.column()) == ColumnIndex::Number)
            return int((Qt::AlignCenter|Qt::AlignVCenter));
    }
    return QVariant();
}

bool PcodeModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    return true;
}

QVariant PcodeModel::headerData(int section, Qt::Orientation orientation, int role) const
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

QModelIndex PcodeModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return createIndex(row, column);
}

Qt::ItemFlags PcodeModel::flags(const QModelIndex &) const
{
    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

bool PcodeModel::getNotificationTxid(bip47::CPaymentCode const & paymentCode, uint256 & txid)
{
    bool result = false;
    LOCK(walletMain.cs_wallet);
    walletMain.GetBip47Wallet()->enumerateSenders(
        [&paymentCode, &result, &txid](bip47::CAccountSender const & sender)
        {
            if (sender.getTheirPcode() == paymentCode && !sender.getNotificationTxId().IsNull()) {
                txid = sender.getNotificationTxId();
                return false;
            }
            return true;
        }
    );
    return result;
}

void PcodeModel::OnPcodeCreated(bip47::CPaymentCodeDescription const & pcodeDescr)
{
    beginInsertRows(QModelIndex(), 0, 0);
    items.push_back(pcodeDescr);
    endInsertRows();
}

void PcodeModel::sort(int column, Qt::SortOrder order)
{
    std::function<bool(bip47::CPaymentCodeDescription const &, bip47::CPaymentCodeDescription const &)> 
    sortPred = [&column, &order](bip47::CPaymentCodeDescription const & lhs, bip47::CPaymentCodeDescription const & rhs)
    {
        bip47::CPaymentCodeDescription const & cmp1 = (order == Qt::SortOrder::DescendingOrder ? lhs : rhs);
        bip47::CPaymentCodeDescription const & cmp2 = (order == Qt::SortOrder::DescendingOrder ? rhs : lhs);

        switch(ColumnIndex(column)) {
            case ColumnIndex::Number:
            default:
                return std::get<0>(cmp1) < std::get<0>(cmp2);
            case ColumnIndex::Pcode:
                return std::get<1>(cmp1).toString() < std::get<1>(cmp2).toString();
            case ColumnIndex::Label:
                return std::get<2>(cmp1) < std::get<2>(cmp2);
        }
    };
    qSort(items.begin(), items.end(), sortPred);
    Q_EMIT dataChanged(index(0, 0, QModelIndex()), index(items.size() - 1, int(ColumnIndex::NumberOfColumns) - 1, QModelIndex()));
}
