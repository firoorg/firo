// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addresstablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "base58.h"
#include "wallet/wallet.h"
#include "validation.h"

#include <boost/foreach.hpp>

#include <QFont>
#include <QDebug>

const QString AddressTableModel::Send = "S";
const QString AddressTableModel::Receive = "R";
const QString AddressTableModel::Zerocoin = "X";

struct AddressTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Zerocoin,
        Hidden /* QSortFilterProxyModel will filter these out */
    };

    Type type;
    QString label;
    QString address;
    QString pubcoin;

    AddressTableEntry() {}
    AddressTableEntry(Type _type, const QString &_label, const QString &_address):
        type(_type), label(_label), address(_address) {}
    AddressTableEntry(Type _type, const QString &_pubcoin):
        type(_type), pubcoin(_pubcoin) {}
};

struct AddressTableEntryLessThan
{
    bool operator()(const AddressTableEntry &a, const AddressTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const AddressTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const AddressTableEntry &b) const
    {
        return a < b.address;
    }
};

/* Determine address type from address purpose */
static AddressTableEntry::Type translateTransactionType(const QString &strPurpose, bool isMine)
{
    AddressTableEntry::Type addressType = AddressTableEntry::Hidden;
    // "refund" addresses aren't shown, and change addresses aren't in mapAddressBook at all.
    if (strPurpose == "send")
        addressType = AddressTableEntry::Sending;
    else if (strPurpose == "receive")
        addressType = AddressTableEntry::Receiving;
    else if (strPurpose == "unknown" || strPurpose == "") // if purpose not set, guess
        addressType = (isMine ? AddressTableEntry::Receiving : AddressTableEntry::Sending);
    return addressType;
}

// Private implementation
class AddressTablePriv
{
public:
    CWallet *wallet;
    QList<AddressTableEntry> cachedAddressTable;
    AddressTableModel *parent;

    AddressTablePriv(CWallet *_wallet, AddressTableModel *_parent):
        wallet(_wallet), parent(_parent) {}

    void refreshAddressTable()
    {
        cachedAddressTable.clear();
        {
            LOCK(wallet->cs_wallet);
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, wallet->mapAddressBook)
            {
                const CBitcoinAddress& address = item.first;
                bool fMine = IsMine(*wallet, address.Get());
                AddressTableEntry::Type addressType = translateTransactionType(
                        QString::fromStdString(item.second.purpose), fMine);
                const std::string& strName = item.second.name;
                cachedAddressTable.append(AddressTableEntry(addressType,
                                  QString::fromStdString(strName),
                                  QString::fromStdString(address.ToString())));
            }
            //[zcoin] add load pubcoin
            std::list<CZerocoinEntry> listPubcoin;
            CWalletDB(wallet->strWalletFile).ListPubCoin(listPubcoin);
            BOOST_FOREACH(const CZerocoinEntry& item, listPubcoin)
            {
                if(item.randomness != 0 && item.serialNumber != 0){
                    const std::string& pubCoin = item.value.GetHex();
                    const std::string& isUsedDenomStr = item.IsUsed
                            ? "Used (" + std::to_string(item.denomination) + " mint)"
                            : "New (" + std::to_string(item.denomination) + " mint)";
                    cachedAddressTable.append(AddressTableEntry(AddressTableEntry::Zerocoin,
                                                                QString::fromStdString(isUsedDenomStr),
                                                                QString::fromStdString(pubCoin)));
                }
            }
        }
        // qLowerBound() and qUpperBound() require our cachedAddressTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        qSort(cachedAddressTable.begin(), cachedAddressTable.end(), AddressTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = qLowerBound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = qUpperBound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        int upperIndex = (upper - cachedAddressTable.begin());
        bool inModel = (lower != upper);
        AddressTableEntry::Type newEntryType = translateTransactionType(purpose, isMine);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_UPDATED, but entry is not in model";
                break;
            }
            lower->type = newEntryType;
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_DELETED, but entry is not in model";
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedAddressTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }
    //[zcoin] updateEntry
    void updateEntry(const QString &pubCoin, const QString &isUsed, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = qLowerBound(
                cachedAddressTable.begin(), cachedAddressTable.end(), pubCoin, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = qUpperBound(
                cachedAddressTable.begin(), cachedAddressTable.end(), pubCoin, AddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        bool inModel = (lower != upper);
        AddressTableEntry::Type newEntryType = AddressTableEntry::Zerocoin;

        switch(status)
        {
            case CT_NEW:
                if(inModel)
                {
                    qWarning() << "Warning: AddressTablePriv::updateEntry: Got CT_NOW, but entry is already in model";
                }
                parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, isUsed, pubCoin));
                parent->endInsertRows();
                break;
            case CT_UPDATED:
                if(!inModel)
                {
                    qWarning() << "Warning: AddressTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model";
                    break;
                }
                lower->type = newEntryType;
                lower->label = isUsed;
                parent->emitDataChanged(lowerIndex);
                break;
        }

    }

    int size()
    {
        return cachedAddressTable.size();
    }

    AddressTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedAddressTable.size())
        {
            return &cachedAddressTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

ZCoinTableModel::ZCoinTableModel(CWallet *wallet, WalletModel *parent): QAbstractTableModel(parent), walletModel(parent), wallet(wallet) {}

AddressTableModel::AddressTableModel(CWallet *wallet, WalletModel *parent) :
    ZCoinTableModel(wallet, parent),priv(0)
{
    columns << tr("Label") << tr("Address");
    priv = new AddressTablePriv(wallet, this);
    priv->refreshAddressTable();
}

AddressTableModel::~AddressTableModel()
{
    delete priv;
}

int AddressTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int AddressTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant AddressTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case AddressTableEntry::Sending:
            return Send;
        case AddressTableEntry::Receiving:
            return Receive;
        case AddressTableEntry::Zerocoin:
            return Zerocoin;
        default: break;
        }
    }
    return QVariant();
}

bool AddressTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());
    std::string strPurpose = (rec->type == AddressTableEntry::Sending ? "send" : "receive");
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        LOCK(wallet->cs_wallet); /* For SetAddressBook / DelAddressBook */
        CTxDestination curAddress = CBitcoinAddress(rec->address.toStdString()).Get();
        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            wallet->SetAddressBook(curAddress, value.toString().toStdString(), strPurpose);
        } else if(index.column() == Address) {
            CTxDestination newAddress = CBitcoinAddress(value.toString().toStdString()).Get();
            // Refuse to set invalid address, set error status and return false
            if(boost::get<CNoDestination>(&newAddress))
            {
                editStatus = INVALID_ADDRESS;
                return false;
            }
            // Do nothing, if old address == new address
            else if(newAddress == curAddress)
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
            // to paste an existing address over another address (with a different label)
            else if(wallet->mapAddressBook.count(newAddress))
            {
                editStatus = DUPLICATE_ADDRESS;
                return false;
            }
            // Double-check that we're not overwriting a receiving address
            else if(rec->type == AddressTableEntry::Sending)
            {
                // Remove old entry
                wallet->DelAddressBook(curAddress);
                // Add new entry with new address
                wallet->SetAddressBook(newAddress, rec->label.toStdString(), strPurpose);
            }
        }
        return true;
    }
    return false;
}

QVariant AddressTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags AddressTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(rec->type == AddressTableEntry::Sending ||
      (rec->type == AddressTableEntry::Receiving && index.column()==Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex AddressTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    AddressTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void AddressTableModel::updateEntry(const QString &address,
        const QString &label, bool isMine, const QString &purpose, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, isMine, purpose, status);
}

//[zcoin] AddressTableModel.updateEntry()
void AddressTableModel::updateEntry(const QString &pubCoin, const QString &isUsed, int status)
{
    // Update stealth address book model from Bitcoin core
    priv->updateEntry(pubCoin, isUsed, status);
}

QString AddressTableModel::addRow(const QString &type, const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(!walletModel->validateAddress(address))
        {
            editStatus = INVALID_ADDRESS;
            return QString();
        }
        // Check for duplicate addresses
        {
            LOCK(wallet->cs_wallet);
            if(wallet->mapAddressBook.count(CBitcoinAddress(strAddress).Get()))
            {
                editStatus = DUPLICATE_ADDRESS;
                return QString();
            }
        }
    }
    else if(type == Receive)
    {
        // Generate a new address to associate with given label
        CPubKey newKey;
        if(!wallet->GetKeyFromPool(newKey))
        {
            WalletModel::UnlockContext ctx(walletModel->requestUnlock());
            if(!ctx.isValid())
            {
                // Unlock wallet failed or was cancelled
                editStatus = WALLET_UNLOCK_FAILURE;
                return QString();
            }
            if(!wallet->GetKeyFromPool(newKey))
            {
                editStatus = KEY_GENERATION_FAILURE;
                return QString();
            }
        }
        strAddress = CBitcoinAddress(newKey.GetID()).ToString();
    }
    else
    {
        return QString();
    }

    // Add entry
    {
        LOCK(wallet->cs_wallet);
        wallet->SetAddressBook(CBitcoinAddress(strAddress).Get(), strLabel,
                               (type == Send ? "send" : "receive"));
    }
    return QString::fromStdString(strAddress);
}

bool AddressTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    AddressTableEntry *rec = priv->index(row);
    if(count != 1 || !rec || rec->type == AddressTableEntry::Receiving)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->DelAddressBook(CBitcoinAddress(rec->address.toStdString()).Get());
    }
    return true;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString AddressTableModel::labelForAddress(const QString &address) const
{
    {
        LOCK(wallet->cs_wallet);
        CBitcoinAddress address_parsed(address.toStdString());
        std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(address_parsed.Get());
        if (mi != wallet->mapAddressBook.end())
        {
            return QString::fromStdString(mi->second.name);
        }
    }
    return QString();
}

int AddressTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void AddressTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

bool AddressTableModel::zerocoinMint(string &stringError, string denomAmount)
{
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet failed or was cancelled
        return false;
    }

    return wallet->CreateZerocoinMintModel(stringError, denomAmount, ZEROCOIN);
}

bool AddressTableModel::zerocoinSpend(string &stringError, string thirdPartyAddress, string denomAmount)
{
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet failed or was cancelled
        return false;
    }

    return wallet->CreateZerocoinSpendModel(stringError, thirdPartyAddress, denomAmount);
}


/*
 * @bip47 
 * PaymentCodeTable
 * 
 * */

const QString PaymentCodeTableModel::Send = "S";
const QString PaymentCodeTableModel::Receive = "R";

struct PaymentCodeTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Hidden /* QSortFilterProxyModel will filter these out */
    };

    Type type;
    QString label;
    QString address;

    PaymentCodeTableEntry() {}
    PaymentCodeTableEntry(Type type, const QString &label, const QString &address):
        type(type), label(label), address(address) {}
};

struct MyRAPEntry
{
    QString label;
    QString address;

    MyRAPEntry() {}
    MyRAPEntry(const QString &label, const QString &address):label(label), address(address) {}
};

struct PaymentCodeTableEntryLessThan
{
    bool operator()(const PaymentCodeTableEntry &a, const PaymentCodeTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const PaymentCodeTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const PaymentCodeTableEntry &b) const
    {
        return a < b.address;
    }
};

struct MyRAPTableEntryLessThan
{
    bool operator()(const MyRAPEntry &a, const MyRAPEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const MyRAPEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const MyRAPEntry &b) const
    {
        return a < b.address;
    }
};

/* Determine address type from address purpose */
static PaymentCodeTableEntry::Type translatePCodeTransactionType(const QString &strPurpose, bool isMine) // lgtm [cpp/unused-static-function]
{
    PaymentCodeTableEntry::Type addressType = PaymentCodeTableEntry::Hidden;
    // "refund" addresses aren't shown, and change addresses aren't in mapAddressBook at all.
    if (strPurpose == "send")
        addressType = PaymentCodeTableEntry::Sending;
    else if (strPurpose == "receive")
        addressType = PaymentCodeTableEntry::Receiving;
    else if (strPurpose == "unknown" || strPurpose == "") // if purpose not set, guess
        addressType = (isMine ? PaymentCodeTableEntry::Receiving : PaymentCodeTableEntry::Sending);
    return addressType;
}

// Private implementation
class PaymentCodeTablePriv
{
public:
    CWallet *wallet;
    QList<PaymentCodeTableEntry> cachedPaymentCodeTable;
    PaymentCodeTableModel *parent;

    PaymentCodeTablePriv(CWallet *wallet, PaymentCodeTableModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshPaymentCodeTable()
    {
        cachedPaymentCodeTable.clear();
        {
            LOCK(wallet->cs_wallet);
            BOOST_FOREACH(const PAIRTYPE(string, std::vector<CBIP47PaymentChannel>)& item, wallet->m_Bip47channels)
            {
                const string& address = item.first;
                PaymentCodeTableEntry::Type addressType = PaymentCodeTableEntry::Sending;
                std::string strName = item.second[0].getLabel();
                cachedPaymentCodeTable.append(PaymentCodeTableEntry(addressType,
                                  QString::fromStdString(strName),
                                  QString::fromStdString(address)));
            }
            
        }
        // qLowerBound() and qUpperBound() require our cachedPaymentCodeTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        qSort(cachedPaymentCodeTable.begin(), cachedPaymentCodeTable.end(), PaymentCodeTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status)
    {
        // Find address / label in model
        QList<PaymentCodeTableEntry>::iterator lower = qLowerBound(
            cachedPaymentCodeTable.begin(), cachedPaymentCodeTable.end(), address, PaymentCodeTableEntryLessThan());
        QList<PaymentCodeTableEntry>::iterator upper = qUpperBound(
            cachedPaymentCodeTable.begin(), cachedPaymentCodeTable.end(), address, PaymentCodeTableEntryLessThan());
        int lowerIndex = (lower - cachedPaymentCodeTable.begin());
        int upperIndex = (upper - cachedPaymentCodeTable.begin());
        bool inModel = (lower != upper);
        PaymentCodeTableEntry::Type newEntryType = PaymentCodeTableEntry::Sending;

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "PaymentCodeTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedPaymentCodeTable.insert(lowerIndex, PaymentCodeTableEntry(newEntryType, label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                qWarning() << "PaymentCodeTablePriv::updateEntry: Warning: Got CT_UPDATED, but entry is not in model";
                break;
            }
            lower->type = newEntryType;
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "PaymentCodeTablePriv::updateEntry: Warning: Got CT_DELETED, but entry is not in model";
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedPaymentCodeTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedPaymentCodeTable.size();
    }

    PaymentCodeTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedPaymentCodeTable.size())
        {
            return &cachedPaymentCodeTable[idx];
        }
        else
        {
            return 0;
        }
    }
};


// Private implementation
class MyRAPTablePriv
{
public:
    CWallet *wallet;
    QList<MyRAPEntry> cachedRAPTable;
    MyRAPTableModel *parent;

    MyRAPTablePriv(CWallet *wallet, MyRAPTableModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshMyRAPTable()
    {
        cachedRAPTable.clear();
        {
            LOCK(wallet->cs_wallet);
            BOOST_FOREACH(const CBIP47Account& item, wallet->m_CBIP47Accounts)
            {
                const string& pcode = item.getStringPaymentCode();
                std::string label = wallet->GetPaymentCodeLabel(pcode);
                cachedRAPTable.append(MyRAPEntry(QString::fromStdString(label),
                                  QString::fromStdString(pcode)));
            }
            
        }
        // qLowerBound() and qUpperBound() require our cachedPaymentCodeTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        qSort(cachedRAPTable.begin(), cachedRAPTable.end(), MyRAPTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, int status)
    {
        // Find address / label in model
        QList<MyRAPEntry>::iterator lower = qLowerBound(
            cachedRAPTable.begin(), cachedRAPTable.end(), address, MyRAPTableEntryLessThan());
        QList<MyRAPEntry>::iterator upper = qUpperBound(
            cachedRAPTable.begin(), cachedRAPTable.end(), address, MyRAPTableEntryLessThan());
        int lowerIndex = (lower - cachedRAPTable.begin());
        int upperIndex = (upper - cachedRAPTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "MyRAPTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedRAPTable.insert(lowerIndex, MyRAPEntry(label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                qWarning() << "MyRAPTablePriv::updateEntry: Warning: Got CT_UPDATED, but entry is not in model";
                break;
            }
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        }
    }

    int size()
    {
        return cachedRAPTable.size();
    }

    MyRAPEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedRAPTable.size())
        {
            return &cachedRAPTable[idx];
        }
        else
        {
            return 0;
        }
    }
};


// PaymentCodeTableModel implementation

PaymentCodeTableModel::PaymentCodeTableModel(CWallet *wallet, WalletModel *parent) :
    ZCoinTableModel(wallet, parent),priv(0)
{
    columns << tr("Label") << tr("Payment Code");
    priv = new PaymentCodeTablePriv(wallet, this);
    priv->refreshPaymentCodeTable();
}

PaymentCodeTableModel::~PaymentCodeTableModel()
{
    delete priv;
}

int PaymentCodeTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int PaymentCodeTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant PaymentCodeTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    PaymentCodeTableEntry *rec = static_cast<PaymentCodeTableEntry*>(index.internalPointer());
    
    qWarning() << "address of rec" << rec->address;

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case PaymentCodeTableEntry::Sending:
            return Send;
        case PaymentCodeTableEntry::Receiving:
            return Receive;
        default: break;
        }
    }
    return QVariant();
}

bool PaymentCodeTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    PaymentCodeTableEntry *rec = static_cast<PaymentCodeTableEntry*>(index.internalPointer());
    std::string strPurpose = (rec->type == PaymentCodeTableEntry::Sending ? "send" : "receive");
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        LOCK(wallet->cs_wallet); /* For SetAddressBook / DelAddressBook */
        std::string curAddress = rec->address.toStdString();
        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            wallet->setBip47ChannelLabel(curAddress, value.toString().toStdString());
        } else if(index.column() == Address) {
            std::string newAddress = value.toString().toStdString();
            // Refuse to set invalid address, set error status and return false
            if(!CPaymentCode(newAddress).isValid())
            {
                editStatus = INVALID_PAYMENTCODE;
                return false;
            }
            // Do nothing, if old address == new address
            else if(newAddress == curAddress)
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
            // to paste an existing address over another address (with a different label)
            else if(wallet->m_Bip47channels.count(newAddress))
            {
                editStatus = DUPLICATE_PAYMENTCODE;
                return false;
            }
            // Double-check that we're not overwriting a receiving address
            else if(rec->type == PaymentCodeTableEntry::Sending)
            {
                wallet->setBip47ChannelLabel(curAddress, value.toString().toStdString());
            }
        }
        return true;
    }
    return false;
}

QVariant PaymentCodeTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags PaymentCodeTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    PaymentCodeTableEntry *rec = static_cast<PaymentCodeTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(rec->type == PaymentCodeTableEntry::Sending ||
      (rec->type == PaymentCodeTableEntry::Receiving && index.column()==Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex PaymentCodeTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    PaymentCodeTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void PaymentCodeTableModel::updateEntry(const QString &address,
        const QString &label, bool isMine, const QString &purpose, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, isMine, purpose, status);
}

QString PaymentCodeTableModel::addRow(const QString &type, const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(!walletModel->validatePaymentCode(address))
        {
            editStatus = INVALID_PAYMENTCODE;
            return QString();
        }
        // Check for duplicate addresses
        {
            LOCK(wallet->cs_wallet);
            if(wallet->m_Bip47channels.count(strAddress))
            {
                editStatus = DUPLICATE_PAYMENTCODE;
                return QString();
            }
        }
    }
    else
    {
        return QString();
    }

    // Add entry
    {
        LOCK(wallet->cs_wallet);
        wallet->setBip47ChannelLabel(strAddress, strLabel);
    }
    return QString::fromStdString(strAddress);
}

bool PaymentCodeTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    return false;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString PaymentCodeTableModel::labelForAddress(const QString &address) const
{
    {
        LOCK(wallet->cs_wallet);
        std::map<string, std::vector<CBIP47PaymentChannel>>::iterator mi = wallet->m_Bip47channels.find(address.toStdString());
        if (mi != wallet->m_Bip47channels.end())
        {
            return QString::fromStdString(mi->second[0].getLabel());
        }
    }
    return QString();
}

int PaymentCodeTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void PaymentCodeTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

void PaymentCodeTableModel::refreshModel()
{
    priv->refreshPaymentCodeTable();
}


// MyRAPTableModel implementation

MyRAPTableModel::MyRAPTableModel(CWallet *wallet, WalletModel *parent) :
    ZCoinTableModel(wallet, parent),priv(0)
{
    columns << tr("Label") << tr("Address");
    priv = new MyRAPTablePriv(wallet, this);
    priv->refreshMyRAPTable();
}

MyRAPTableModel::~MyRAPTableModel()
{
    delete priv;
}

int MyRAPTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int MyRAPTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant MyRAPTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    MyRAPEntry *rec = static_cast<MyRAPEntry*>(index.internalPointer());
    
    qWarning() << "address of rec" << rec->address;

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    return QVariant();
}

bool MyRAPTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    MyRAPEntry *rec = static_cast<MyRAPEntry*>(index.internalPointer());
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        LOCK(wallet->cs_wallet); /* For SetAddressBook / DelAddressBook */
        std::string curAddress = rec->address.toStdString();
        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            wallet->SetPaymentCodeBookLabel(curAddress, value.toString().toStdString());
        } else if(index.column() == Address) {
            std::string newAddress = value.toString().toStdString();
            // Refuse to set invalid address, set error status and return false
            if(!CPaymentCode(newAddress).isValid())
            {
                editStatus = INVALID_PAYMENTCODE;
                return false;
            }
            // Do nothing, if old address == new address
            else if(newAddress == curAddress)
            {
                editStatus = NO_CHANGES;
                return false;
            }
        }
        return true;
    }
    return false;
}

QVariant MyRAPTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags MyRAPTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    MyRAPEntry *rec = static_cast<MyRAPEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(index.column()==Label)
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex MyRAPTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    MyRAPEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void MyRAPTableModel::updateEntry(const QString &address,
        const QString &label, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, status);
}

QString MyRAPTableModel::addRow(const QString &type, const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    
    return QString();
}

bool MyRAPTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    return false;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString MyRAPTableModel::labelForAddress(const QString &address) const
{
    {
        LOCK(wallet->cs_wallet);
        return QString::fromStdString(wallet->GetPaymentCodeLabel(address.toStdString()));
    }
    return QString();
}

int MyRAPTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()), Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void MyRAPTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

void MyRAPTableModel::refreshModel()
{
    priv->refreshMyRAPTable();
}
