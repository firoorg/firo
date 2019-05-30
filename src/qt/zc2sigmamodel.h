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
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    /* Add an address to the model.
       Returns the added address on success, and an empty string otherwise.
     */
    QString addRow(const QString &mintCount, const QString &denomination, const QString &version);

private:
    QStringList columns;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    void updateEntry(const QString &pubCoin, const QString &isUsed, int status);

    friend class AddressTablePriv;
};

#endif /* ZEROCOINREMINTMODEL_H */

