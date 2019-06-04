#ifndef ZC2SIGMAMODEL_H
#define ZC2SIGMAMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AddressTablePriv;
class WalletModel;
class CWallet;

class Zc2SigmaModel: public QAbstractTableModel
{
    Q_OBJECT

public:
    Zc2SigmaModel();
    ~Zc2SigmaModel();

    enum ColumnIndex {
        MintCount = 0,
        Denomination = 1,
        Version = 2
    };


    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

private:
    QStringList columns;
    class ContImpl;
    ContImpl * pContImpl;

};

#endif /* ZEROCOINREMINTMODEL_H */

