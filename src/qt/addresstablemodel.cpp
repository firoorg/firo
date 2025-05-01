// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addresstablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "base58.h"
#include "wallet/wallet.h"
#include "validation.h"
#include "bip47/defs.h"
#include "bip47/paymentchannel.h"
#include "../sparkname.h"

#include <boost/foreach.hpp>

#include <QFont>
#include <QDebug>

const QString AddressTableModel::Send = "S";
const QString AddressTableModel::Receive = "R";
const QString AddressTableModel::Zerocoin = "X";
const QString AddressTableModel::Transparent = "Transparent";
const QString AddressTableModel::Spark = "Spark";
const QString AddressTableModel::RAP = "RAP";
const QString AddressTableModel::SparkName = "Spark names";

struct AddressTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Zerocoin,
        Hidden /* QSortFilterProxyModel will filter these out */
    };

/*    enum AddressType {
        Spark,
        Transparent,
        RAP,
        SparkName
    };*/

    Type type;
    QString label;
    QString address;
    QString addressType;
    QString pubcoin;
    bool isMine{false};

    AddressTableEntry() {}
    AddressTableEntry(Type _type, const QString &_label, const QString &_address, const QString &_addressType, bool _isMine):
        type(_type), label(_label), address(_address), addressType(_addressType), isMine(_isMine) {}
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

    struct PendingSparkNameChange {
        int changeType;
        CSparkNameBlockIndexData sparkNameData;
    };
    QList<PendingSparkNameChange> pendingSparkNameChanges;

    CCriticalSection cs_pendingSparkNameChanges;

private:
    void sparkNameAdded(const CSparkNameBlockIndexData &sparkNameData) {
        LOCK(cs_pendingSparkNameChanges);
        pendingSparkNameChanges.append(PendingSparkNameChange{CT_NEW, sparkNameData});
    }

    void sparkNameRemoved(const CSparkNameBlockIndexData &sparkNameData) {
        LOCK(cs_pendingSparkNameChanges);
        pendingSparkNameChanges.append(PendingSparkNameChange{CT_DELETED, sparkNameData});
    }

public:
    AddressTablePriv(CWallet *_wallet, AddressTableModel *_parent):
        wallet(_wallet), parent(_parent) {

        uiInterface.NotifySparkNameAdded.connect(boost::bind(&AddressTablePriv::sparkNameAdded, this, _1));
        uiInterface.NotifySparkNameRemoved.connect(boost::bind(&AddressTablePriv::sparkNameRemoved, this, _1));
    }

    ~AddressTablePriv() {
        uiInterface.NotifySparkNameAdded.disconnect(boost::bind(&AddressTablePriv::sparkNameAdded, this, _1));
        uiInterface.NotifySparkNameRemoved.disconnect(boost::bind(&AddressTablePriv::sparkNameRemoved, this, _1));
    }

    void refreshSparkNames()
    {
        CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
        std::vector<CSparkNameBlockIndexData> sparkNames = sparkNameManager->DumpSparkNameData();

        for (const auto &entry : sparkNames) {
            const std::string &sparkAddress = entry.sparkAddress;
            const std::string &strName = std::string("@") + entry.name;
            bool fMine = wallet->IsSparkAddressMine(sparkAddress);
            AddressTableEntry::Type addressType = translateTransactionType("send", fMine);
            cachedAddressTable.append(AddressTableEntry(addressType,
                        QString::fromStdString(strName),
                        QString::fromStdString(sparkAddress),
                        AddressTableModel::SparkName,
                        fMine));
        }
    }

    void refreshAddressTable()
    {
        cachedAddressTable.clear();
        {
            LOCK(cs_main);      // for CSparkNameManager
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
                                QString::fromStdString(address.ToString()),
                                AddressTableModel::Transparent,
                                fMine));
            }

            BOOST_FOREACH(const PAIRTYPE(std::string, CAddressBookData)& item, wallet->mapSparkAddressBook)
            {
                const std::string& address = item.first;
                bool fMine = wallet->IsSparkAddressMine(address);
                AddressTableEntry::Type addressType = translateTransactionType(
                        QString::fromStdString(item.second.purpose), fMine);
                const std::string& strName = item.second.name;
                cachedAddressTable.append(AddressTableEntry(addressType,
                                QString::fromStdString(strName),
                                QString::fromStdString(address),
                                AddressTableModel::Spark,
                                fMine));
            }

            BOOST_FOREACH(const PAIRTYPE(std::string, CAddressBookData)& item, wallet->mapRAPAddressBook)
            {
                const std::string& address = item.first;
                bip47::CPaymentCode pcode(address);
                boost::optional<bip47::CPaymentCodeDescription> pcodeDesc;
                pcodeDesc = wallet->FindPcode(pcode);
                if(pcodeDesc) {
                    const std::string& strName = item.second.name;
                    if(QString::fromStdString(item.second.purpose) == "send"){
                        cachedAddressTable.append(AddressTableEntry(AddressTableEntry::Sending,
                                        QString::fromStdString(strName),
                                        QString::fromStdString(address),
                                        AddressTableModel::RAP,
                                        false));
                    }
                }
            }

            refreshSparkNames();
        }
        // qLowerBound() and qUpperBound() require our cachedAddressTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        std::sort(cachedAddressTable.begin(), cachedAddressTable.end(), AddressTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = std::lower_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = std::upper_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        int upperIndex = (upper - cachedAddressTable.begin());
        bool inModel = (lower != upper);
        AddressTableEntry::Type newEntryType = translateTransactionType(purpose, isMine);
        CBitcoinAddress addressParsed(address.toStdString());

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            if(addressParsed.IsValid()){
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address, AddressTableModel::Transparent, isMine));
            } else if (bip47::CPaymentCode::validate(address.toStdString())){
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address, AddressTableModel::RAP, isMine));
            } else {
                QString addressType = label.startsWith("@") ? AddressTableModel::SparkName : AddressTableModel::Spark;
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address, addressType, isMine));
            }
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
            if (label.startsWith("@"))
                lower->addressType = AddressTableModel::SparkName;
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
    //[firo] updateEntry
    void updateEntry(const QString &pubCoin, const QString &isUsed, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = std::lower_bound(
                cachedAddressTable.begin(), cachedAddressTable.end(), pubCoin, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = std::upper_bound(
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
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, isUsed, pubCoin, "", false));
                parent->endInsertRows();
                break;
            case CT_UPDATED:
                if(!inModel)
                {
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

    void processPendingSparkNameChanges() {
        QList<PendingSparkNameChange> pendingChanges;
        {
            LOCK(cs_pendingSparkNameChanges);
            pendingChanges = pendingSparkNameChanges;
            pendingSparkNameChanges.clear();
        }

        LOCK(wallet->cs_wallet);
        for (const PendingSparkNameChange &change : pendingChanges) {
            int changeType = change.changeType;
            if (changeType == CT_NEW) {
                QString address = QString::fromStdString(change.sparkNameData.sparkAddress);
                // Check if the address is already in the model
                if (std::lower_bound(cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan()) !=
                        std::upper_bound(cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan()))
                    changeType = CT_UPDATED;
            }

            updateEntry(QString::fromStdString(change.sparkNameData.sparkAddress),
                    QString("@") + QString::fromStdString(change.sparkNameData.name),
                    wallet->IsSparkAddressMine(change.sparkNameData.sparkAddress),
                    "send",
                    changeType);
        }
    }
};

AddressTableModel::AddressTableModel(CWallet *_wallet, WalletModel *parent) :
    QAbstractTableModel(parent),walletModel(parent),wallet(_wallet),priv(0)
{
    columns << tr("Label") << tr("Address") << tr("Address Type");
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
        case AddressType:
            if(rec->addressType == AddressTableModel::Transparent)
            {
                return "transparent";
            }
            else if(rec->addressType == AddressTableModel::Spark)
            {
                return "spark";
            }
            else if (rec->addressType == AddressTableModel::SparkName)
            {
                return rec->isMine ? "own spark name" : "spark name";
            }
            else if(rec->addressType == AddressTableModel::RAP)
            {
                return "RAP";
            }
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
        std::string curSAddress = rec->address.toStdString();
        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            if(rec->addressType == AddressTableModel::Spark){
                wallet->SetSparkAddressBook(curSAddress, value.toString().toStdString(), strPurpose);
            } else if(rec->addressType == AddressTableModel::Transparent) {
                wallet->SetAddressBook(curAddress, value.toString().toStdString(), strPurpose);
            } else if(rec->addressType == AddressTableModel::RAP){
                wallet->SetRAPAddressBook(curSAddress, value.toString().toStdString(), strPurpose);
            } else {
                return false;
            }
        } else if(index.column() == Address) {
            if(rec->addressType == AddressTableModel::Spark){
                std::string newSparkAddress = value.toString().toStdString();
                if(!walletModel->validateSparkAddress(value.toString())) {
                    editStatus = INVALID_ADDRESS;
                    return false;
                } else if(newSparkAddress == curSAddress)
                {
                    editStatus = NO_CHANGES;
                    return false;
                } else if(wallet->mapSparkAddressBook.count(newSparkAddress))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return false;
                }else if(rec->type == AddressTableEntry::Sending)
                {
                    // Remove old entry
                    wallet->DelAddressBook(curSAddress);
                    // Add new entry with new address
                    wallet->SetSparkAddressBook(newSparkAddress, rec->label.toStdString(), strPurpose);
                }
            } else if(rec->addressType == AddressTableModel::Transparent){
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
            } else if(rec->addressType == AddressTableModel::RAP){
                std::string newPcode = value.toString().toStdString();
                if(!bip47::CPaymentCode::validate(newPcode)) {
                    editStatus = AddressTableModel::PCODE_VALIDATION_FAILURE;
                    return false;
                } else if(newPcode == curSAddress)
                {
                    editStatus = NO_CHANGES;
                    return false;
                } else if(wallet->mapRAPAddressBook.count(newPcode))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return false;
                }else if(rec->type == AddressTableEntry::Sending)
                {
                    // Remove old entry
                    wallet->DelAddressBook(curSAddress);
                    // Add new entry with new address
                    wallet->SetRAPAddressBook(newPcode, rec->label.toStdString(), strPurpose);
                }
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
        return Qt::ItemFlags();
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

//[firo] AddressTableModel.updateEntry()
void AddressTableModel::updateEntry(const QString &pubCoin, const QString &isUsed, int status)
{
    // Update stealth address book model from Bitcoin core
    priv->updateEntry(pubCoin, isUsed, status);
}

QString AddressTableModel::addRow(const QString &type, const QString &label, const QString &address, const QString &addressType)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(addressType == AddressTableModel::Spark) {
            if(!(walletModel->validateSparkAddress(address)))
            {
                editStatus = INVALID_SPARK_ADDRESS;
                return QString();
            }
            // Check for duplicate addresses
            {
                LOCK(wallet->cs_wallet);
                if(wallet->mapSparkAddressBook.count(strAddress))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return QString();
                }
            }
        } else if(addressType == AddressTableModel::Transparent){
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
        } else if(addressType == AddressTableModel::RAP){
            if(!bip47::CPaymentCode::validate(strAddress))
            {
                editStatus = AddressTableModel::PCODE_VALIDATION_FAILURE;
                return QString();
            }

            // Check for duplicate addresses
            {
                LOCK(wallet->cs_wallet);
                if(wallet->mapRAPAddressBook.count(strAddress))
                {
                    editStatus = DUPLICATE_ADDRESS;
                    return QString();
                }
            }
        }
    }
    else if(type == Receive)
    {
        if(addressType == AddressTableModel::Spark) {
            spark::Address addr = wallet->sparkWallet->generateNewAddress();
            unsigned char network = spark::GetNetworkType();
            strAddress = addr.encode(network);
        } else {
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
    }
    else
    {
        return QString();
    }

    // Add entry
    {
        LOCK(wallet->cs_wallet);
        if(addressType == AddressTableModel::Spark) {
            wallet->SetSparkAddressBook(strAddress, strLabel,
                                (type == Send ? "send" : "receive"));
        } else if(addressType == AddressTableModel::Transparent){
            wallet->SetAddressBook(CBitcoinAddress(strAddress).Get(), strLabel,
                                (type == Send ? "send" : "receive"));
        } else if(addressType == AddressTableModel::RAP) {
            wallet->SetRAPAddressBook(strAddress, strLabel,
                                (type == Send ? "send" : "receive"));
        }
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
        wallet->DelAddressBook(rec->address.toStdString());
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
        if(address_parsed.IsValid()) {
            std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(address_parsed.Get());
            if (mi != wallet->mapAddressBook.end())
            {
                return QString::fromStdString(mi->second.name);
            }
        } else if(walletModel->validateSparkAddress(address)) {
            std::map<std::string, CAddressBookData>::iterator mi = wallet->mapSparkAddressBook.find(address.toStdString());
            if(mi != wallet->mapSparkAddressBook.end())
            {
                return QString::fromStdString(mi->second.name);
            }
        } else if(bip47::CPaymentCode::validate(address.toStdString())) {
            std::map<std::string, CAddressBookData>::iterator mi = wallet->mapRAPAddressBook.find(address.toStdString());
            if(mi != wallet->mapRAPAddressBook.end())
            {
                return QString::fromStdString(mi->second.name);
            }
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

PcodeAddressTableModel * AddressTableModel::getPcodeAddressTableModel()
{
    if(!walletModel)
        return nullptr;
    return walletModel->getPcodeAddressTableModel();
}

bool AddressTableModel::IsSparkAllowed(){
    return spark::IsSparkAllowed();
}

void AddressTableModel::ProcessPendingSparkNameChanges()
{
    priv->processPendingSparkNameChanges();
}


// RAP pcodes

static void NotifyPcodeLabeled(PcodeAddressTableModel *walletmodel, std::string pcode, std::string label, bool removed)
{
    QMetaObject::invokeMethod(walletmodel, "onPcodeLabeled", Qt::QueuedConnection,
                            Q_ARG(QString, QString::fromStdString(pcode)),
                            Q_ARG(QString, QString::fromStdString(label)),
                            Q_ARG(bool, removed)
        );
}

PcodeAddressTableModel::PcodeAddressTableModel(CWallet *wallet_, WalletModel *parent)
:AddressTableModel(wallet_, parent)
{
    // columns[AddressTableModel::Address] = tr("RAP payment code");
    updatePcodeData();
    wallet->NotifyPcodeLabeled.connect(boost::bind(NotifyPcodeLabeled, this, _1, _2, _3));
}

PcodeAddressTableModel::~PcodeAddressTableModel()
{
    wallet->NotifyPcodeLabeled.disconnect(boost::bind(NotifyPcodeLabeled, this, _1, _2, _3));
}

int PcodeAddressTableModel::rowCount(const QModelIndex &) const
{
    return pcodeData.size();
}

int PcodeAddressTableModel::columnCount(const QModelIndex &) const
{
    return columns.size();
}

QVariant PcodeAddressTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    int const row = index.row();
    if(row >= pcodeData.size())
        return QVariant();

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(ColumnIndex(index.column()))
        {
            case ColumnIndex::Label:
                return QString::fromStdString(pcodeData[row].second);
            case ColumnIndex::Pcode:
                return QString::fromStdString(pcodeData[row].first);
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(ColumnIndex(index.column()) == ColumnIndex::Pcode)
        {
            font = GUIUtil::fixedPitchFont();
        }
        return font;
    }
    return QVariant();
}

bool PcodeAddressTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    int const row = index.row();
    if(row >= pcodeData.size())
        return false;

    if(role == Qt::EditRole)
    {
        if(ColumnIndex(index.column()) == ColumnIndex::Label)
        {
            std::string const newLab = value.toString().toStdString();
            if(pcodeData[row].second == newLab)
            {
                editStatus = AddressTableModel::NO_CHANGES;
                return false;
            }

            wallet->LabelSendingPcode(pcodeData[row].first, newLab, false);
            updatePcodeData();
            editStatus = AddressTableModel::OK;
            Q_EMIT dataChanged(createIndex(row, 0), createIndex(row, columns.length() - 1));
        }
        else if(ColumnIndex(index.column()) == ColumnIndex::Pcode)
        {
            std::string const newPcode = value.toString().toStdString();
            if(!bip47::CPaymentCode::validate(newPcode))
            {
                editStatus = AddressTableModel::PCODE_VALIDATION_FAILURE;
                return false;
            }

            wallet->LabelSendingPcode(pcodeData[row].first, "", true);
            wallet->LabelSendingPcode(newPcode, pcodeData[row].second, false);
            updatePcodeData();
            Q_EMIT dataChanged(createIndex(row, 0), createIndex(row, columns.length() - 1));

        }
        return true;
    }
    return false;
}

QVariant PcodeAddressTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section >= 0 && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}

bool PcodeAddressTableModel::removeRows(int row, int count, const QModelIndex &)
{
    if(count != 1 || row >= pcodeData.size())
        return false;

    wallet->LabelSendingPcode(pcodeData[row].first, "", true);
    return true;
}

Qt::ItemFlags PcodeAddressTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return Qt::ItemFlags();
    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    if(index.column() == int(ColumnIndex::Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QString PcodeAddressTableModel::addRow(const QString &type, const QString &label, const QString &address, const QString &addressType)
{
    std::string const strLabel = label.toStdString();
    std::string const strPcode = address.toStdString();

    editStatus = AddressTableModel::OK;

    if(!bip47::CPaymentCode::validate(strPcode))
    {
        editStatus = AddressTableModel::PCODE_VALIDATION_FAILURE;
        return QString();
    }

    if(isReceivingPcode(bip47::CPaymentCode(address.toStdString())))
    {
        editStatus = AddressTableModel::PCODE_CANNOT_BE_LABELED;
        return QString();
    }

    wallet->LabelSendingPcode(strPcode, strLabel);

    return QString::fromStdString(strPcode);
}

void PcodeAddressTableModel::updatePcodeData()
{
    LOCK(wallet->cs_wallet);
    pcodeData.clear();
    std::multimap<std::string, std::string>::const_iterator iter = wallet->mapCustomKeyValues.lower_bound(bip47::PcodeLabel());
    for(; iter != wallet->mapCustomKeyValues.end() && iter->first.compare(0, bip47::PcodeLabel().size(), bip47::PcodeLabel()) <= 0; ++iter) {
        pcodeData.push_back(std::make_pair(iter->first.substr(bip47::PcodeLabel().size(), iter->first.size() - bip47::PcodeLabel().size()), iter->second));
    }
}

std::string PcodeAddressTableModel::findLabel(QString const & pcode)
{
    return wallet->GetSendingPcodeLabel(pcode.toStdString());
}

bool PcodeAddressTableModel::isReceivingPcode(bip47::CPaymentCode const & pcode)
{
    boost::optional<bip47::CPaymentCodeDescription> descr = wallet->FindPcode(pcode);
    if(!descr)
        return false;
    return std::get<4>(*descr) == bip47::CPaymentCodeSide::Receiver;
}

void PcodeAddressTableModel::onPcodeLabeled(QString pcode_, QString label_, bool removed)
{
    std::string const & pcode = pcode_.toStdString();
    std::string const & label = label_.toStdString();
    if(removed)
    {
        std::vector<std::pair<std::string, std::string>>::iterator iter = std::find_if(
                pcodeData.begin(),
                pcodeData.end(),
                [&pcode](std::pair<std::string, std::string> const & item) -> bool {
                    return item.first == pcode;
                });
        if (iter == pcodeData.end())
            return;
        int const row = std::distance(pcodeData.begin(), iter);
        beginRemoveRows(QModelIndex(), row, row);
        updatePcodeData();
        endRemoveRows();
    }
    else
    {
        std::vector<std::pair<std::string, std::string>>::const_iterator iter =
            std::lower_bound(pcodeData.begin(), pcodeData.end(), pcode,
                [](std::pair<std::string, std::string> const & item, std::string const & val) { return item.first < val; }
            );
        int const pos = std::distance(pcodeData.cbegin(), iter);

        if(iter != pcodeData.end() && iter->first == pcode)
        {
            updatePcodeData();
            Q_EMIT dataChanged(createIndex(pos, 0), createIndex(pos, columns.length() - 1));
        }
        else
        {
            beginInsertRows(QModelIndex(), pos, pos);
            updatePcodeData();
            endInsertRows();
        }
    }


}
