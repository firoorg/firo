// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PCODEMODEL_H
#define PCODEMODEL_H

#include "walletmodel.h"

#include <QAbstractTableModel>
#include <QStringList>
#include <QDateTime>


class CWallet;

class PcodeModel: public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit PcodeModel(CWallet *wallet, WalletModel *parent);
    ~PcodeModel();

    enum struct ColumnIndex : int {
        Number = 0,
        Pcode,
        Label,
        NumberOfColumns
    };

    std::vector<bip47::CPaymentCodeDescription> const & getItems() const;

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    void OnPcodeCreated(bip47::CPaymentCodeDescription const & pcodeDescr);

public Q_SLOTS:
    void sort(int column, Qt::SortOrder order);

private:
    CWallet & walletMain;
    WalletModel *walletModel;
    QStringList columns;
    std::vector<bip47::CPaymentCodeDescription> items;
};

#endif /* PCODEMODEL_H */

