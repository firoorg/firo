// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODEL_H
#define BITCOIN_QT_WALLETMODEL_H

#include "walletmodeltransaction.h"

#include "support/allocators/secure.h"
#ifdef ENABLE_WALLET
#include "wallet/walletdb.h"
#include "wallet/wallet.h"
#endif // ENABLE_WALLET
#include "wallet/coincontrol.h"

#include <map>
#include <vector>

#include <QObject>

class AddressTableModel;
class PcodeAddressTableModel;
class LelantusModel;
class SparkModel;
class OptionsModel;
class PlatformStyle;
class RecentRequestsTableModel;
class TransactionTableModel;
class WalletModelTransaction;
class PcodeModel;

class CCoinControl;
class CKeyID;
class COutPoint;
class COutput;
class CPubKey;
class CWallet;
class uint256;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendCoinsRecipient
{
public:
    explicit SendCoinsRecipient() : amount(0), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) { }
    explicit SendCoinsRecipient(const QString &addr, const QString &addrType, const QString &_label, const CAmount& _amount, const QString &_message):
        address(addr), label(_label), amount(_amount), message(_message), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) {}

    // If from an unauthenticated payment request, this is used for storing
    // the addresses, e.g. address-A<br />address-B<br />address-C.
    // Info: As we don't need to process addresses in here when using
    // payment requests, we can abuse it for displaying an address list.
    // Todo: This is a hack, should be replaced with a cleaner solution!
    QString address;
    QString label;
    CAmount amount;
    // If from a payment request, this is used for storing the memo
    QString message;
    // If building with BIP70 is disabled, keep the payment request around as
    // serialized string to ensure load/store is lossless
    std::string sPaymentRequest;
    // Empty if no authentication or invalid signature/cert/etc.
    QString authenticatedMerchant;

    bool fSubtractFeeFromAmount; // memory only

    static const int CURRENT_VERSION = 1;
    int nVersion;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::string sAddress = address.toStdString();
        std::string sLabel = label.toStdString();
        std::string sMessage = message.toStdString();
        std::string sAuthenticatedMerchant = authenticatedMerchant.toStdString();

        READWRITE(this->nVersion);
        READWRITE(sAddress);
        READWRITE(sLabel);
        READWRITE(amount);
        READWRITE(sMessage);
        READWRITE(sPaymentRequest);
        READWRITE(sAuthenticatedMerchant);

        if (ser_action.ForRead())
        {
            address = QString::fromStdString(sAddress);
            label = QString::fromStdString(sLabel);
            message = QString::fromStdString(sMessage);
            authenticatedMerchant = QString::fromStdString(sAuthenticatedMerchant);
        }
    }
};

/** Interface to Bitcoin wallet from Qt view code. */
class WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit WalletModel(const PlatformStyle *platformStyle, CWallet *wallet, OptionsModel *optionsModel, QObject *parent = 0);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        TransactionCommitFailed,
        AbsurdFee,
        PaymentRequestExpired,
        ExceedLimit
    };

    enum EncryptionStatus
    {
        Unencrypted,  // !wallet->IsCrypted()
        Locked,       // wallet->IsCrypted() && wallet->IsLocked()
        UnlockedForMixingOnly,  // wallet->IsCrypted() && !wallet->IsLocked(true) && wallet->IsLocked()
        Unlocked      // wallet->IsCrypted() && !wallet->IsLocked()
    };

    OptionsModel *getOptionsModel();
    AddressTableModel *getAddressTableModel();
    PcodeAddressTableModel *getPcodeAddressTableModel();
    LelantusModel *getLelantusModel();
    SparkModel *getSparkModel();
    TransactionTableModel *getTransactionTableModel();
    RecentRequestsTableModel *getRecentRequestsTableModel();
    PcodeModel *getPcodeModel();

    CWallet *getWallet() const { return wallet; }

    CAmount getBalance(const CCoinControl *coinControl = NULL, bool fExcludeLocked = false) const;
    CAmount getUnconfirmedBalance() const;
    CAmount getImmatureBalance() const;
    bool haveWatchOnly() const;
    CAmount getWatchBalance() const;
    CAmount getWatchUnconfirmedBalance() const;
    CAmount getWatchImmatureBalance() const;
    CAmount getAnonymizableBalance() const;

    EncryptionStatus getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString &address);
    bool validateExchangeAddress(const QString &address);
    bool validateSparkAddress(const QString &address);
    std::pair<CAmount, CAmount> getSparkBalance();

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode _status = OK, QString _reasonCommitFailed = "")
            : status(_status),
              reasonCommitFailed(_reasonCommitFailed)
        {
        }
        StatusCode status;
        QString reasonCommitFailed;
    };

    // prepare transaction for getting txfee before sending coins
    SendCoinsReturn prepareTransaction(WalletModelTransaction &transaction, const CCoinControl *coinControl = NULL);

    // prepare transaction for getting txfee before sending coins in anonymous mode
    SendCoinsReturn prepareJoinSplitTransaction(WalletModelTransaction &transaction, const CCoinControl *coinControl = NULL);

    // prepare transaction for getting txfee before anonymizing coins
    SendCoinsReturn prepareMintTransactions(
        CAmount amount,
        std::vector<WalletModelTransaction> &transactions,
        std::list<CReserveKey> &reserveKeys,
        std::vector<CHDMint> &mints,
        const CCoinControl *coinControl);

    SendCoinsReturn prepareMintSparkTransaction(
        std::vector<WalletModelTransaction> &transactions,
        QList<SendCoinsRecipient> recipients,
        std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFees,
        std::list<CReserveKey> &reserveKeys,
        const CCoinControl *coinControl);

    SendCoinsReturn prepareSpendSparkTransaction(
        WalletModelTransaction &transaction,
        const CCoinControl *coinControl);

    SendCoinsReturn spendSparkCoins(
        WalletModelTransaction &transaction);

    SendCoinsReturn prepareSparkNameTransaction(
        WalletModelTransaction &transaction,
        CSparkNameTxData &sparkNameData,
        CAmount sparkNameFee,
        const CCoinControl *coinControl);
        
    SendCoinsReturn mintSparkCoins(
        std::vector<WalletModelTransaction> &transactions,
        std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee,
        std::list<CReserveKey> &reserveKeys
        );
    
    bool migrateLelantusToSpark();
    
    bool getAvailableLelantusCoins();

    // Send coins to a list of recipients
    SendCoinsReturn sendCoins(WalletModelTransaction &transaction);

    // Send private coins to a list of recipients
    SendCoinsReturn sendPrivateCoins(WalletModelTransaction &transaction);

    // Anonymize coins.
    SendCoinsReturn sendAnonymizingCoins(
        std::vector<WalletModelTransaction> &transactions,
        std::list<CReserveKey> &reservekeys,
        std::vector<CHDMint> &mints);

    // Wallet encryption
    bool setWalletEncrypted(bool encrypted, const SecureString &passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString &passPhrase=SecureString());
    void lockWalletDelayed(int seconds);
    bool changePassphrase(const SecureString &oldPass, const SecureString &newPass);
    // Wallet backup
    bool backupWallet(const QString &filename);

    // RAI object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel *wallet, bool valid, bool relock);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Copy operator and constructor transfer the context
        UnlockContext(const UnlockContext& obj) { CopyFrom(obj); }
        UnlockContext& operator=(const UnlockContext& rhs) { CopyFrom(rhs); return *this; }

        void delayRelock(int seconds);
    private:
        WalletModel *wallet;
        bool valid;
        mutable bool relock; // mutable, as it can be set to false by copying
        int delay;

        void CopyFrom(const UnlockContext& rhs);
    };

    UnlockContext requestUnlock(const QString & info = "");

    bool IsSpendable(const CTxDestination& dest) const;
    bool IsSpendable(const CScript& script) const;
    bool getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    bool havePrivKey(const CKeyID &address) const;
    bool getPrivKey(const CKeyID &address, CKey& vchPrivKeyOut) const;
    void getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs, boost::optional<bool> fMintTabSelected = boost::none);
    bool isSpent(const COutPoint& outpoint) const;
    void listCoins(std::map<QString, std::vector<COutput> >& mapCoins, CoinType nCoinType=CoinType::ALL_COINS) const;

    bool isLockedCoin(uint256 hash, unsigned int n) const;
    void lockCoin(COutPoint& output);
    void unlockCoin(COutPoint& output);
    void listLockedCoins(std::vector<COutPoint>& vOutpts);

    void listProTxCoins(std::vector<COutPoint>& vOutpts);

    bool hasMasternode();

    void loadReceiveRequests(std::vector<std::string>& vReceiveRequests);
    bool saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest);

    bool transactionCanBeAbandoned(uint256 hash) const;
    bool abandonTransaction(uint256 hash) const;

    static bool isWalletEnabled();

    bool hdEnabled() const;

    int getDefaultConfirmTarget() const;

    bool transactionCanBeRebroadcast(uint256 hash) const;
    bool rebroadcastTransaction(uint256 hash, CValidationState &state);

    CAmount GetJMintCredit(const CTxOut& txout) const;

private:
    CWallet *wallet;

    bool fHaveWatchOnly;
    bool fForceCheckBalanceChanged;

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel *optionsModel;

    AddressTableModel *addressTableModel;
    PcodeAddressTableModel *pcodeAddressTableModel;
    LelantusModel *lelantusModel;
    SparkModel *sparkModel;
    TransactionTableModel *transactionTableModel;
    RecentRequestsTableModel *recentRequestsTableModel;
    PcodeModel *pcodeModel;

    // Cache some values to be able to detect changes
    CAmount cachedBalance;
    CAmount cachedUnconfirmedBalance;
    CAmount cachedImmatureBalance;
    CAmount cachedWatchOnlyBalance;
    CAmount cachedWatchUnconfBalance;
    CAmount cachedWatchImmatureBalance;
    CAmount cachedAnonymizableBalance;
    CAmount cachedPrivateBalance;
    CAmount cachedUnconfirmedPrivateBalance;
    EncryptionStatus cachedEncryptionStatus;
    int cachedNumBlocks;

    QTimer *pollTimer;

    int cachedNumISLocks;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
    void checkBalanceChanged();



Q_SIGNALS:
    // Signal that balance in wallet changed
    void balanceChanged(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                        const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance,
                        const CAmount& privateBalance, const CAmount& unconfirmedPrivateBalance,
                        const CAmount& anonymizableBalance);

    void updateMintable();

    // Encryption status of wallet changed
    void encryptionStatusChanged(int status);

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock(const QString &info);

    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

    // Coins sent: from wallet, to recipient, in (serialized) transaction:
    void coinsSent(CWallet* wallet, SendCoinsRecipient recipient, QByteArray transaction);

    // Show progress dialog e.g. for rescan
    void showProgress(const QString &title, int nProgress);

    // Watch-only address added
    void notifyWatchonlyChanged(bool fHaveWatchonly);

public Q_SLOTS:
    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction();
    /* IS-Lock received */
    void updateNumISLocks();
    /* ChainLock received */
    void updateChainLockHeight(int chainLockHeight);
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    /* New zerocoin book entry */
    void updateAddressBook(const QString &pubCoin, const QString &isUsed, int status);
    /* Watch-only added */
    void updateWatchOnlyFlag(bool fHaveWatchonly);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();
    // Handle the changed BIP47 privkeys
    void handleBip47Keys(int receiverAccountNum, void * pBlockIndex);
    // Locks wallet from timer calls
    bool lockWallet();
};

#endif // BITCOIN_QT_WALLETMODEL_H
