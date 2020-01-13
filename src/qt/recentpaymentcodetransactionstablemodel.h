// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// @author top1st

#ifndef BITCOIN_QT_RECENTRPAYMENTCODETRNASACTIONSTABLEMODEL_H
#define BITCOIN_QT_RECENTRPAYMENTCODETRNASACTIONSTABLEMODEL_H



#include "walletmodel.h"

#include <QAbstractTableModel>
#include <QStringList>
#include <QDateTime>
#include <QString>

class CWallet;
class WalletModel;

class RecentPCodeTransactionEntry
{
public:
    RecentPCodeTransactionEntry() : nVersion(RecentPCodeTransactionEntry::CURRENT_VERSION), id(0) { }

    RecentPCodeTransactionEntry(int64_t pid, double_t pfee, QString prpccode): nVersion(RecentPCodeTransactionEntry::CURRENT_VERSION), id(pid), fee(pfee), date(QDateTime::currentDateTime()), rpcode(prpccode) {}       
    
    static const int CURRENT_VERSION = 1;
    int nVersion;
    int64_t id;
    QDateTime date;
    CAmount fee;
    QString rpcode;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        unsigned int nDate = date.toTime_t();
        std::string srpcode = rpcode.toStdString();


        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(id);
        READWRITE(nDate);
        READWRITE(fee);
        READWRITE(srpcode);

        if (ser_action.ForRead()) 
        {
            date = QDateTime::fromTime_t(nDate);
            rpcode = QString::fromStdString(srpcode);
        }
            
    }
};

class RecentPCodeTransactionEntryLessThan
{
public:
    RecentPCodeTransactionEntryLessThan(int nColumn, Qt::SortOrder fOrder):
        column(nColumn), order(fOrder) {}
    bool operator()(RecentPCodeTransactionEntry &left, RecentPCodeTransactionEntry &right) const;

private:
    int column;
    Qt::SortOrder order;
};

/** Model for list of recently generated payment requests / bitcoin: URIs.
 * Part of wallet model.
 */
class RecentPCodeTransactionsTableModel: public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit RecentPCodeTransactionsTableModel(CWallet *wallet, WalletModel *parent);
    ~RecentPCodeTransactionsTableModel();

    enum ColumnIndex {
        RPCode = 0,
        Fee = 1,
        Timestamp = 2,
        NUMBER_OF_COLUMNS
    };

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    void addNewRequest(const QString &rpcode, CAmount fee);
    void addNewRequest(const std::string &recipient);
    void addNewRequest(RecentPCodeTransactionEntry &recipient);

public Q_SLOTS:
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder);
    void updateDisplayUnit();

private:
    WalletModel *walletModel;
    QStringList columns;
    QList<RecentPCodeTransactionEntry> list;
    int64_t nRecentPCodeNotificationMaxId;

};

#endif // BITCOIN_QT_RECENTRPAYMENTCODETRNASACTIONSTABLEMODEL_H
