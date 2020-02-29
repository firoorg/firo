// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ADDRESSTABLEMODEL_H
#define BITCOIN_QT_ADDRESSTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class AddressTablePriv;
class WalletModel;

class CWallet;

/**
   Qt model of the address book in the core. This allows views to access and modify the address book.
 */

 /** Return status of edit/insert operation */
enum EditStatus {
    OK,                     /**< Everything ok */
    NO_CHANGES,             /**< No changes were made during edit operation */
    INVALID_ADDRESS,
    DUPLICATE_ADDRESS,
    INVALID_PAYMENTCODE,        /**< Unparseable address */
    DUPLICATE_PAYMENTCODE,      /**< Address already in address book */
    WALLET_UNLOCK_FAILURE,  /**< Wallet could not be unlocked to create new receiving address */
    KEY_GENERATION_FAILURE  /**< Generating a new public key for a receiving address failed */
};

class ZCoinTableModel : public QAbstractTableModel {
public: 
    explicit ZCoinTableModel(CWallet *wallet, WalletModel *parent = 0);
    enum ColumnIndex {
        Label = 0,   /**< User specified label */
        Address = 1  /**< Bitcoin address */
    };
     /* Add an address to the model.
       Returns the added address on success, and an empty string otherwise.
     */
    virtual QString addRow(const QString &type, const QString &label, const QString &address) = 0;

    /* Look up label for address in address book, if not found return empty string.
     */
    virtual QString labelForAddress(const QString &address) const = 0;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    virtual int lookupAddress(const QString &address) const = 0;

    EditStatus getEditStatus() const { return editStatus; }
protected: 
    WalletModel *walletModel;
    CWallet *wallet;
    QStringList columns;
    EditStatus editStatus;
public:
    /** Notify listeners that data changed. */
    virtual void emitDataChanged(int index) = 0;
};

class AddressTableModel : public ZCoinTableModel
{
    Q_OBJECT

public:
    explicit AddressTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~AddressTableModel();

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    static const QString Send;      /**< Specifies send address */
    static const QString Receive;   /**< Specifies receive address */
    static const QString Zerocoin;   /**< Specifies stealth address */

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
    QString addRow(const QString &type, const QString &label, const QString &address);

    /* Look up label for address in address book, if not found return empty string.
     */
    QString labelForAddress(const QString &address) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString &address) const;
    void emitDataChanged(int idx);
    bool zerocoinMint(std::string &stringError, std::string denomAmount);
    bool zerocoinSpend(std::string &stringError, std::string thirdPartyAddress, std::string denomAmount);

private:
    AddressTablePriv *priv;

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    void updateEntry(const QString &pubCoin, const QString &isUsed, int status);

    friend class AddressTablePriv;
};

class PaymentCodeTablePriv;

class PaymentCodeTableModel : public ZCoinTableModel
{
    Q_OBJECT

public:
    explicit PaymentCodeTableModel(CWallet *wallet, WalletModel *parent = 0);
    ~PaymentCodeTableModel();

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    static const QString Send;      /**< Specifies send address */
    static const QString Receive;   /**< Specifies receive address */

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
    QString addRow(const QString &type, const QString &label, const QString &address);

    /* Look up label for address in address book, if not found return empty string.
     */
    QString labelForAddress(const QString &address) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString &address) const;
    void emitDataChanged(int idx);
private:
    PaymentCodeTablePriv *priv;

public Q_SLOTS:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    
    void refreshModel();
    

    friend class PaymentCodeTablePriv;
};

#endif // BITCOIN_QT_ADDRESSTABLEMODEL_H
