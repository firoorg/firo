#include "zc2sigmamodel.h"

#include "guiutil.h"

#include <boost/foreach.hpp>

#include <QFont>
#include <QDebug>

#include "../wallet/wallet.h"

namespace {
    struct MintInfo {
        int mintCount;
        int denomination;
        int version;
        int get(size_t mem) {
            if(mem == 0)
                return mintCount;
            if(mem == 1)
                return denomination;
            if(mem == 2)
                return version;
            throw std::runtime_error("Wrong index requested");
        }
        bool operator==(MintInfo const & other) const {
            return mintCount == other.mintCount
                    && denomination == other.denomination
                    && version == other.version;
        }
        bool operator!=(MintInfo const & other) const {
            return !operator==(other);
        }
    };
}

class Zc2SigmaModel::ContImpl : public std::vector<MintInfo>
{
public:
    bool operator==(Zc2SigmaModel::ContImpl const & other) const {
        if(size() != other.size())
            return false;
        for(size_t i = 0; i < size(); ++i)
            if(operator[](i) != other[i])
                return false;
        return true;
    }
};

std::shared_ptr<Zc2SigmaModel::ContImpl> Zc2SigmaModel::GetAvailMints() {
    using libzerocoin::CoinDenomination;
    std::shared_ptr<ContImpl> container = std::shared_ptr<ContImpl>(new ContImpl);

    std::vector<int> const versions{2};
    std::vector<CoinDenomination> const denominations{CoinDenomination::ZQ_LOVELACE, CoinDenomination::ZQ_GOLDWASSER, CoinDenomination::ZQ_RACKOFF, CoinDenomination::ZQ_PEDERSEN, CoinDenomination::ZQ_WILLIAMSON};

    BOOST_FOREACH(int ver, versions) {
        BOOST_FOREACH(CoinDenomination den, denominations) {
            int nMints;
            {
                LOCK(pwalletMain->cs_wallet);
                nMints = pwalletMain->GetNumberOfUnspentMintsForDenomination(ver, den);
            }
            if(nMints > 0)
                container->push_back({nMints, int(den), ver});
        }
    }
    return container;
}

size_t Zc2SigmaModel::GetAvailMintsNumber() {
    return GetAvailMints()->size();
}

Zc2SigmaModel::Zc2SigmaModel()
: QAbstractTableModel(nullptr)
, pContImpl (new ContImpl)
{
    columns << tr("Mint count") << tr("Denomination") << tr("Version");
    updateRows();
}

bool Zc2SigmaModel::updateRows() {
    std::shared_ptr<ContImpl> container = GetAvailMints();
    if(*container != *pContImpl) {
        beginResetModel();
        *pContImpl = *container;
        endResetModel();
        return true;
    }
    return false;
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
