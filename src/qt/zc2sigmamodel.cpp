#include "zc2sigmamodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "base58.h"
#include "wallet/wallet.h"
#include "main.h"

#include <boost/foreach.hpp>

#include <QFont>
#include <QDebug>


Zc2SigmaModel::Zc2SigmaModel()
: QAbstractTableModel(nullptr)
{
    columns << tr("Mint count") << tr("Denomination") << tr("Version");
}

Zc2SigmaModel::~Zc2SigmaModel()
{
}

int Zc2SigmaModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 0;
}

int Zc2SigmaModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant Zc2SigmaModel::data(const QModelIndex &index, int role) const
{
    return QVariant();

    if(!index.isValid())
        return QVariant();
}

bool Zc2SigmaModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    return false;
    if(!index.isValid())
        return false;
}

QVariant Zc2SigmaModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags Zc2SigmaModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    return 0;
}

QModelIndex Zc2SigmaModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return QModelIndex();
}

void Zc2SigmaModel::updateEntry(const QString &address,
        const QString &label, bool isMine, const QString &purpose, int status)
{
}

//[zcoin] Zc2SigmaModel.updateEntry()
void Zc2SigmaModel::updateEntry(const QString &pubCoin, const QString &isUsed, int status)
{
}

QString Zc2SigmaModel::addRow(const QString &mintCount, const QString &denomination, const QString &version)
{
    return mintCount;
}

bool Zc2SigmaModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    return true;
}

void Zc2SigmaModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
