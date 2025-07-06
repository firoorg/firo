// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ADDRESSTABLEMODEL_H
#define BITCOIN_QT_ADDRESSTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AddressTablePriv;
class WalletModel;
class PcodeAddressTableModel;

class CWallet;

namespace bip47{
class CPaymentCode;
}

/**
   Qt model of the address book in the core. This allows views to access and modify the address book.
 */
class AddressTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit AddressTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~AddressTableModel();

    enum ColumnIndex {
        Label = 0,   /**< User specified label */
        Address = 1,  /**< Bitcoin address */
        AddressType = 2
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_ADDRESS,        /**< Unparseable address */
        DUPLICATE_ADDRESS,      /**< Address already in address book */
        WALLET_UNLOCK_FAILURE,  /**< Wallet could not be unlocked to create new receiving address */
        KEY_GENERATION_FAILURE,  /**< Generating a new public key for a receiving address failed */
        PCODE_VALIDATION_FAILURE,/**< Failed to validate the payment code */
        PCODE_CANNOT_BE_LABELED,  /**< Receiving pcodes cannot be relabeled*/
        INVALID_SPARK_ADDRESS
    };

    static const QString Send;      /**< Specifies send address */
    static const QString Receive;   /**< Specifies receive address */
    static const QString Zerocoin;   /**< Specifies stealth address */
    static const QString Transparent;
    static const QString Spark;
    static const QString SparkName;
    static const QString RAP;

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
    virtual QString addRow(const QString &type, const QString &label, const QString &address, const QString &addressType);

    /* Look up label for address in address book, if not found return empty string.
     */
    QString labelForAddress(const QString &address) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString &address) const;

    EditStatus getEditStatus() const { return editStatus; }

    PcodeAddressTableModel * getPcodeAddressTableModel();

    bool IsSparkAllowed();
    void ProcessPendingSparkNameChanges();

    WalletModel *getWalletModel() const { return walletModel; }
protected:
    WalletModel *walletModel;
    CWallet *wallet;
    EditStatus editStatus;
    QStringList columns;

private:
    AddressTablePriv *priv;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    void updateEntry(const QString &pubCoin, const QString &isUsed, int status);

    friend class AddressTablePriv;
};


class PcodeAddressTableModel : public AddressTableModel
{
    Q_OBJECT
public:
    explicit PcodeAddressTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~PcodeAddressTableModel();

    enum struct ColumnIndex : int {
        Label = 0,
        Pcode
    };

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    QString addRow(const QString &type, const QString &label, const QString &address, const QString &addressType) override;

    AddressTableModel::EditStatus getEditStatus() const { return editStatus; }

    std::string findLabel(QString const & pcode);
    bool isReceivingPcode(bip47::CPaymentCode const & pcode);
    Q_INVOKABLE void onPcodeLabeled(QString pcode, QString label, bool removed);

private:
    std::vector<std::pair<std::string, std::string>> pcodeData;

    void updatePcodeData();
};

#endif // BITCOIN_QT_ADDRESSTABLEMODEL_H
