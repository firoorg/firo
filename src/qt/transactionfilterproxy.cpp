// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionfilterproxy.h"

#include "transactiontablemodel.h"
#include "transactionrecord.h"

#include <cstdlib>

#include <QDateTime>

// Earliest date that can be represented (far in the past)
const QDateTime TransactionFilterProxy::MIN_DATE = QDateTime::fromSecsSinceEpoch(0);
// Last date that can be represented (far in the future)
const QDateTime TransactionFilterProxy::MAX_DATE = QDateTime::fromSecsSinceEpoch(0xFFFFFFFF);

TransactionFilterProxy::TransactionFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent),
    dateFrom(MIN_DATE),
    dateTo(MAX_DATE),
    addrPrefix(),
    typeFilter(ALL_TYPES),
    watchOnlyFilter(WatchOnlyFilter_All),
    instantsendFilter(InstantSendFilter_All),
    minAmount(0),
    limitRows(-1),
    showInactive(true)
{
}

bool TransactionFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (showInactive && typeFilter == ALL_TYPES &&
        watchOnlyFilter == WatchOnlyFilter_All && instantsendFilter == InstantSendFilter_All &&
        dateFrom == MIN_DATE && dateTo == MAX_DATE && addrPrefix.isEmpty() && minAmount <= 0)
        return true;

    QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);

    if (!showInactive && index.data(TransactionTableModel::StatusRole).toInt() == TransactionStatus::Conflicted)
        return false;
    if (typeFilter != ALL_TYPES && !(TYPE(index.data(TransactionTableModel::TypeRole).toInt()) & typeFilter))
        return false;
    if (watchOnlyFilter != WatchOnlyFilter_All) {
        const bool involvesWatchAddress = index.data(TransactionTableModel::WatchonlyRole).toBool();
        if ((involvesWatchAddress && watchOnlyFilter == WatchOnlyFilter_No) ||
            (!involvesWatchAddress && watchOnlyFilter == WatchOnlyFilter_Yes))
            return false;
    }
    if (instantsendFilter != InstantSendFilter_All) {
        const bool lockedByInstantSend = index.data(TransactionTableModel::InstantSendRole).toBool();
        if ((lockedByInstantSend && instantsendFilter == InstantSendFilter_No) ||
            (!lockedByInstantSend && instantsendFilter == InstantSendFilter_Yes))
            return false;
    }
    if (dateFrom != MIN_DATE || dateTo != MAX_DATE) {
        const QDateTime datetime = index.data(TransactionTableModel::DateRole).toDateTime();
        if (datetime < dateFrom || datetime > dateTo)
            return false;
    }
    if (!addrPrefix.isEmpty()) {
        const QString address = index.data(TransactionTableModel::AddressRole).toString();
        const QString label = index.data(TransactionTableModel::LabelRole).toString();
        if (!address.contains(addrPrefix, Qt::CaseInsensitive) && !label.contains(addrPrefix, Qt::CaseInsensitive))
            return false;
    }
    if (minAmount > 0 && llabs(index.data(TransactionTableModel::AmountRole).toLongLong()) < minAmount)
        return false;

    return true;
}

void TransactionFilterProxy::setDateRange(const QDateTime &from, const QDateTime &to)
{
    this->dateFrom = from;
    this->dateTo = to;
    invalidateFilter();
}

void TransactionFilterProxy::setAddressPrefix(const QString &_addrPrefix)
{
    this->addrPrefix = _addrPrefix;
    invalidateFilter();
}

void TransactionFilterProxy::setTypeFilter(quint32 modes)
{
    this->typeFilter = modes;
    invalidateFilter();
}

void TransactionFilterProxy::setMinAmount(const CAmount& minimum)
{
    this->minAmount = minimum;
    invalidateFilter();
}

void TransactionFilterProxy::setWatchOnlyFilter(WatchOnlyFilter filter)
{
    this->watchOnlyFilter = filter;
    invalidateFilter();
}

void TransactionFilterProxy::setInstantSendFilter(InstantSendFilter filter)
{
    this->instantsendFilter = filter;
    invalidateFilter();
}

void TransactionFilterProxy::setLimit(int limit)
{
    this->limitRows = limit;
}

void TransactionFilterProxy::setShowInactive(bool _showInactive)
{
    this->showInactive = _showInactive;
    invalidateFilter();
}

int TransactionFilterProxy::rowCount(const QModelIndex &parent) const
{
    if(limitRows != -1)
    {
        return std::min(QSortFilterProxyModel::rowCount(parent), limitRows);
    }
    else
    {
        return QSortFilterProxyModel::rowCount(parent);
    }
}
