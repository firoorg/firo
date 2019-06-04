#include "zc2sigmamodel.h"

#include "guiutil.h"

#include <boost/foreach.hpp>

#include <QFont>
#include <QDebug>


namespace {
    struct MintInfo {
        uint mintCount;
        uint denomination;
        uint version;
        uint get(size_t mem) {
            if(mem == 0)
                return mintCount;
            if(mem == 1)
                return denomination;
            if(mem == 2)
                return version;
            throw std::runtime_error("Wrong index requested");
        }
    };
}

class Zc2SigmaModel::ContImpl : public std::vector<MintInfo>
{
};

Zc2SigmaModel::Zc2SigmaModel()
: QAbstractTableModel(nullptr)
, pContImpl (new ContImpl)
{
    columns << tr("Mint count") << tr("Denomination") << tr("Version");

    std::vector<uint> const versions{2};
    std::vector<uint> const denominations{1, 10, 25, 50, 100};

    BOOST_FOREACH(uint ver, versions) {
        BOOST_FOREACH(uint den, denominations) {
            // GetNumberOfUnspentMintsForDenomination(int version, libzerocoin::CoinDenomination d)
            pContImpl->push_back({den, den, ver});
        }
    }
}

Zc2SigmaModel::~Zc2SigmaModel()
{
    delete pContImpl;
}

int Zc2SigmaModel::rowCount(const QModelIndex &) const
{
    return pContImpl->size();
}

int Zc2SigmaModel::columnCount(const QModelIndex &) const
{
    return columns.length();
}

QVariant Zc2SigmaModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid() || size_t(index.row()) >= pContImpl->size() || index.column() >= 3)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        return pContImpl->at(index.row()).get(index.column());
    }
    return QVariant();
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

    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}
