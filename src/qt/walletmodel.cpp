// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletmodel.h"
#include "clientmodel.h"
#include "addresstablemodel.h"
#include "consensus/validation.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "sparkmodel.h"
#include "paymentserver.h"
#include "policy/policy.h"
#include "recentrequeststablemodel.h"
#include "spark/state.h"
#include "transactiontablemodel.h"

#include "base58.h"
#include "keystore.h"
#include "validation.h"
#include "net.h" // for g_connman
#include "sync.h"
#include "util.h" // for GetBoolArg
#include "wallet/sparkbatchplanner.h"
#include "wallet/sparkspendbatch.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h" // for BackupWallet
#include "wallet/walletexcept.h"
#include "txmempool.h"
#include "consensus/validation.h"
#include "bip47/account.h"
#include "bip47/bip47utils.h"
#include "cancelpassworddialog.h"

#include <algorithm>
#include <stdint.h>

#include <QDebug>
#include <QSet>
#include <QStringList>
#include <QTimer>

#include <boost/foreach.hpp>

namespace {
constexpr size_t MAX_SINGLE_INPUT_SPARK_TRANSACTIONS = 50;

bool CompareSparkCoins(const CSparkMintMeta& a, const CSparkMintMeta& b)
{
    if (a.v != b.v) return a.v > b.v;
    if (a.nHeight != b.nHeight) return a.nHeight < b.nHeight;
    if (a.txid != b.txid) return a.txid < b.txid;
    return a.GetNonceHash() < b.GetNonceHash();
}

bool HasMultipleSelectedCoins(const CCoinControl* coinControl)
{
    if (!coinControl || !coinControl->HasSelected()) return false;

    std::vector<COutPoint> selected;
    coinControl->ListSelected(selected);
    return selected.size() > 1;
}

// With one input the transaction size does not depend on the fee, so the
// planner can use the same per-send fee policy as construction.
CAmount EstimateSingleInputSparkFee(
    size_t privateOutputs,
    size_t transparentOutputs,
    const CCoinControl* coinControl)
{
    const unsigned int estimatedSize =
        spark::EstimateSingleInputSparkSize(privateOutputs, transparentOutputs);

    return CWallet::GetMinimumFee(estimatedSize, coinControl, mempool);
}
}

WalletModel::WalletModel(const PlatformStyle *platformStyle, CWallet *_wallet, OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent), wallet(_wallet), optionsModel(_optionsModel), _client_model(0),
    addressTableModel(0), pcodeAddressTableModel(0), sparkModel(0),
    transactionTableModel(0),
    recentRequestsTableModel(0),
    cachedBalance(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0),
    cachedNumISLocks(0)
{
    fHaveWatchOnly = wallet->HaveWatchOnly();
    fForceCheckBalanceChanged = false;

    addressTableModel = new AddressTableModel(wallet, this);
    pcodeAddressTableModel = new PcodeAddressTableModel(wallet, this);
    sparkModel = new SparkModel(platformStyle, wallet, _optionsModel, this);
    transactionTableModel = new TransactionTableModel(platformStyle, wallet, this);
    recentRequestsTableModel = new RecentRequestsTableModel(wallet, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout, this, &WalletModel::pollBalanceChanged);
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getBalance(const CCoinControl *coinControl, bool fExcludeLocked) const
{
    if (coinControl)
    {
        CAmount nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput& out, vCoins)
            if(out.fSpendable)
                nBalance += out.tx->tx->vout[out.i].nValue;

        return nBalance;
    }

    return wallet->GetBalance(fExcludeLocked);
}

CAmount WalletModel::getAnonymizableBalance() const
{
    CAmount amount = 0;
    if (sparkModel && spark::IsSparkAllowed()){
        amount = sparkModel->getMintableSparkAmount();
    }
    return amount;
}

CAmount WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

CAmount WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

CAmount WalletModel::getWatchBalance() const
{
    return wallet->GetWatchOnlyBalance();
}

CAmount WalletModel::getWatchUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedWatchOnlyBalance();
}

CAmount WalletModel::getWatchImmatureBalance() const
{
    return wallet->GetImmatureWatchOnlyBalance();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        Q_EMIT encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    if (!_client_model) {
        // ClientModel not yet set; defer to avoid cs_main locking and races
       return;
    }
    int currentNumBlocks = _client_model->cachedNumBlocks;

    if(fForceCheckBalanceChanged || currentNumBlocks != cachedNumBlocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = currentNumBlocks;

        QMetaObject::invokeMethod(this, "checkBalanceChanged", Qt::QueuedConnection);
        if(transactionTableModel)
            QMetaObject::invokeMethod(transactionTableModel, "updateConfirmations", Qt::QueuedConnection);
    }
}


void WalletModel::setClientModel(ClientModel* client_model)
{
    _client_model = client_model;
}


void WalletModel::checkBalanceChanged()
{
    // Get the required locks upfront with try-semantics. Balance computation
    // (including the Spark balance) needs cs_main/cs_wallet/cs_spark_wallet,
    // which are held for long stretches while a block or transaction is being
    // processed (Spark proof verification, trial decryption of incoming
    // coins). Blocking here would freeze the GUI for that whole time, so give
    // up and retry on the next poll instead.
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain) {
        fForceCheckBalanceChanged = true; // retry on next pollBalanceChanged
        return;
    }
    TRY_LOCK(wallet->cs_wallet, lockWallet);
    if (!lockWallet) {
        fForceCheckBalanceChanged = true;
        return;
    }

    CAmount newBalance = cachedBalance;
    CAmount newUnconfirmedBalance = cachedUnconfirmedBalance;
    CAmount newImmatureBalance = cachedImmatureBalance;
    CAmount newWatchOnlyBalance = 0;
    CAmount newWatchUnconfBalance = 0;
    CAmount newWatchImmatureBalance = 0;
    CAmount newAnonymizableBalance = cachedAnonymizableBalance;

    if (!wallet->TryGetBalances(newBalance, newUnconfirmedBalance, newImmatureBalance, newAnonymizableBalance)) {
        fForceCheckBalanceChanged = true;
        return;
    }

    // getSparkBalance() takes cs_spark_wallet, which can also be held by
    // Spark wallet background tasks that do not hold cs_main, so it has to be
    // try-locked as well.
    CAmount newPrivateBalance = 0, newUnconfirmedPrivateBalance = 0;
    if (wallet->sparkWallet) {
        TRY_LOCK(wallet->sparkWallet->cs_spark_wallet, lockSpark);
        if (!lockSpark) {
            fForceCheckBalanceChanged = true;
            return;
        }
        std::tie(newPrivateBalance, newUnconfirmedPrivateBalance) =
                getSparkBalance();
    }

    if (haveWatchOnly())
    {
        newWatchOnlyBalance = getWatchBalance();
        newWatchUnconfBalance = getWatchUnconfirmedBalance();
        newWatchImmatureBalance = getWatchImmatureBalance();
    }

    if(cachedBalance != newBalance
        || cachedUnconfirmedBalance != newUnconfirmedBalance
        || cachedImmatureBalance != newImmatureBalance
        || cachedWatchOnlyBalance != newWatchOnlyBalance
        || cachedWatchUnconfBalance != newWatchUnconfBalance
        || cachedWatchImmatureBalance != newWatchImmatureBalance
        || cachedPrivateBalance != newPrivateBalance
        || cachedUnconfirmedPrivateBalance != newUnconfirmedPrivateBalance
        || cachedAnonymizableBalance != newAnonymizableBalance)
    {
        cachedBalance = newBalance;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        cachedWatchOnlyBalance = newWatchOnlyBalance;
        cachedWatchUnconfBalance = newWatchUnconfBalance;
        cachedWatchImmatureBalance = newWatchImmatureBalance;
        cachedPrivateBalance = newPrivateBalance;
        cachedUnconfirmedPrivateBalance = newUnconfirmedPrivateBalance;
        cachedAnonymizableBalance = newAnonymizableBalance;
        Q_EMIT balanceChanged(
            newBalance,
            newUnconfirmedBalance,
            newImmatureBalance,
            newWatchOnlyBalance,
            newWatchUnconfBalance,
            newWatchImmatureBalance,
            newPrivateBalance,
            newUnconfirmedPrivateBalance,
            newAnonymizableBalance);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateNumISLocks()
{
    fForceCheckBalanceChanged = true;
    cachedNumISLocks++;
    if (transactionTableModel)
        transactionTableModel->updateNumISLocks(cachedNumISLocks);
}

void WalletModel::updateChainLockHeight(int chainLockHeight)
{
    if (transactionTableModel)
        transactionTableModel->updateChainLockHeight(chainLockHeight);
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

void WalletModel::updateAddressBook(const QString &pubCoin, const QString &isUsed, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(pubCoin, isUsed, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

bool WalletModel::validateExchangeAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid() && addressParsed.Get().type() == typeid(CExchangeKeyID);
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl *coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;
            
        {   // User-entered bitcoin address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        transaction.newPossibleKeyChange(wallet);

        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        std::string strFailReason;

        CWalletTx *newTx = transaction.getTransaction();
        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        bool fCreated = wallet->CreateTransaction(vecSend, *newTx, *keyChange, nFeeRequired, nChangePosRet, strFailReason, coinControl);
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && fCreated)
            transaction.reassignAmounts(nChangePosRet);

        if(!fCreated)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (nFeeRequired > maxTxFee)
            return AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        for (const SendCoinsRecipient &rcp : transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal firo:URI (firo:123...?message=example)
                newTx->vOrderForm.push_back(make_pair("Message", rcp.message.toStdString()));
        }

        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        CValidationState state;
        if(!wallet->CommitTransaction(*newTx, *keyChange, g_connman.get(), state))
            return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(state.GetRejectReason()));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx->tx;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = CBitcoinAddress(strAddress).Get();
            std::string strLabel = rcp.label.toStdString();
            {
                LOCK(wallet->cs_wallet);

                std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(dest);

                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end())
                {
                    wallet->SetAddressBook(dest, strLabel, "send");
                }
                else if (mi->second.name != strLabel)
                {
                    wallet->SetAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(wallet, rcp, transaction_array);
    }
    // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits.
    // Queued so that it runs on the GUI thread even when sendCoins is called from a worker thread.
    QMetaObject::invokeMethod(this, "checkBalanceChanged", Qt::QueuedConnection);

    return SendCoinsReturn(OK);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

PcodeAddressTableModel *WalletModel::getPcodeAddressTableModel()
{
    return pcodeAddressTableModel;
}

SparkModel *WalletModel::getSparkModel()
{
    return sparkModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::lockWallet()
{
    return wallet->Lock();
}

void WalletModel::lockWalletDelayed(int seconds)
{
    QTimer::singleShot(seconds * 1000, this, &WalletModel::lockWallet);
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return wallet->BackupWallet(filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(CBitcoinAddress(address).ToString());
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
}

static void NotifySparkAddressBookChanged(WalletModel* walletmodel, CWallet* wallet, const std::string& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(address);
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifySparkAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
        Q_ARG(QString, strAddress),
        Q_ARG(QString, strLabel),
        Q_ARG(bool, isMine),
        Q_ARG(QString, strPurpose),
        Q_ARG(int, status));
}

static void NotifyRAPAddressBookChanged(WalletModel* walletmodel, CWallet* wallet, const std::string& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(address);
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyRAPAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
        Q_ARG(QString, strAddress),
        Q_ARG(QString, strLabel),
        Q_ARG(bool, isMine),
        Q_ARG(QString, strPurpose),
        Q_ARG(int, status));
}

static void NotifyZerocoinChanged(WalletModel *walletmodel, CWallet *wallet, const std::string &pubCoin, const std::string &isUsed, ChangeType status)
{
    qDebug() << "NotifyZerocoinChanged:" + QString::fromStdString(pubCoin) + " " + QString::fromStdString(isUsed) + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(pubCoin)),
                              Q_ARG(QString, QString::fromStdString(isUsed)),
                              Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
}

static void NotifyISLockReceived(WalletModel *walletmodel)
{
    QMetaObject::invokeMethod(walletmodel, "updateNumISLocks", Qt::QueuedConnection);
}

static void NotifyChainLockReceived(WalletModel *walletmodel, int chainLockHeight)
{
    QMetaObject::invokeMethod(walletmodel, "updateChainLockHeight", Qt::QueuedConnection,
                              Q_ARG(int, chainLockHeight));
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
}

static void NotifyBip47KeysChanged(WalletModel *walletmodel, int receiverAccountNum, CBlockIndex * pBlockIndex)
{
    QMetaObject::invokeMethod(walletmodel, "handleBip47Keys", Qt::QueuedConnection,
                            Q_ARG(int, receiverAccountNum),
                            Q_ARG(void *, pBlockIndex)
                        );
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifySparkAddressBookChanged.connect(boost::bind(NotifySparkAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyRAPAddressBookChanged.connect(boost::bind(NotifyRAPAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->NotifyISLockReceived.connect(boost::bind(NotifyISLockReceived, this));
    wallet->NotifyChainLockReceived.connect(boost::bind(NotifyChainLockReceived, this, _1));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.connect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyZerocoinChanged.connect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));
    wallet->NotifyBip47KeysChanged.connect(boost::bind(NotifyBip47KeysChanged, this, _1, _2));

}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifySparkAddressBookChanged.disconnect(boost::bind(NotifySparkAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyRAPAddressBookChanged.disconnect(boost::bind(NotifyRAPAddressBookChanged, this, _1, _2, _3, _4, _5, _6));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->NotifyISLockReceived.disconnect(boost::bind(NotifyISLockReceived, this));
    wallet->NotifyChainLockReceived.disconnect(boost::bind(NotifyChainLockReceived, this, _1));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    wallet->NotifyWatchonlyChanged.disconnect(boost::bind(NotifyWatchonlyChanged, this, _1));
    wallet->NotifyZerocoinChanged.disconnect(boost::bind(NotifyZerocoinChanged, this, _1, _2, _3, _4));
    wallet->NotifyBip47KeysChanged.disconnect(boost::bind(NotifyBip47KeysChanged, this, _1, _2));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock(const QString & info)
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock(info);
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock),
        delay(0)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        if(delay == 0)
        {
            wallet->setWalletLocked(true);
        }
        else
        {
            wallet->lockWalletDelayed(delay);
        }
    }
}

void WalletModel::UnlockContext::delayRelock(int seconds)
{
    delay = seconds;
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    wallet = rhs.wallet;
    valid = rhs.valid;
    relock = rhs.relock;
    delay = rhs.delay;
    rhs.relock = false;
}

bool WalletModel::IsSpendable(const CTxDestination& dest) const
{
    return IsMine(*wallet, dest) & ISMINE_SPENDABLE;
}

bool WalletModel::IsSpendable(const CScript& script) const
{
    return IsMine(*wallet, script) & ISMINE_SPENDABLE;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);
}

bool WalletModel::havePrivKey(const CKeyID &address) const
{
    return wallet->HaveKey(address);
}

bool WalletModel::getPrivKey(const CKeyID &address, CKey& vchPrivKeyOut) const
{
    return wallet->GetKey(address, vchPrivKeyOut);
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs, boost::optional<bool> fMintTabSelected)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;

    BOOST_FOREACH(const COutPoint& outpoint, vOutpoints)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        if (fMintTabSelected != boost::none) {
            if(wallet->mapWallet[outpoint.hash].tx->vout[outpoint.n].scriptPubKey.IsSigmaMint()) {
                if (fMintTabSelected.get()) // only allow mint outputs on the "Spend" tab
                    continue;
            }
            else {
                if (!fMintTabSelected.get())
                    continue; // only allow normal outputs on the "Mint" tab
            }
        }
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);
        vOutputs.push_back(out);
    }
}

bool WalletModel::isSpent(const COutPoint& outpoint) const
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return false;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return false;
    return wallet->IsSpent(outpoint.hash, outpoint.n);
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address)
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins, CoinType nCoinType) const
{
    std::vector<COutput> vCoins;
    CCoinControl coinControl;
    coinControl.nCoinType = nCoinType;
    wallet->AvailableCoins(vCoins, true, &coinControl, false);

    TRY_LOCK(cs_main,lock_main); // ListLockedCoins, mapWallet
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;

    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);

    // add locked coins
    BOOST_FOREACH(const COutPoint& outpoint, vLockedCoins)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);

        auto const &vout = out.tx->tx->vout[out.i];
        bool isMint = vout.scriptPubKey.IsMint();

        if(nCoinType == CoinType::ALL_COINS){
            // We are now taking ALL_COINS to mean everything sans mints
            if (isMint) continue;
        } else if(nCoinType == CoinType::ONLY_MINTS){
            // Do not consider anything other than mints
            if (!isMint) continue;
        }

        if (outpoint.n < out.tx->tx->vout.size() && wallet->IsMine(out.tx->tx->vout[outpoint.n], *out.tx->tx) == ISMINE_SPENDABLE)
            vCoins.push_back(out);
    }

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->GetHash(), cout.tx->tx->vout[cout.i]) && cout.tx->tx->vin.size() > 0 && wallet->IsMine(cout.tx->tx->vin[0], *cout.tx->tx))
        {
            if (!wallet->mapWallet.count(cout.tx->tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->tx->vin[0].prevout.hash], cout.tx->tx->vin[0].prevout.n, 0, true, true);
        }

        CTxDestination address;
        auto const &vout = cout.tx->tx->vout[cout.i];
        if (vout.scriptPubKey.IsMint()) {
            mapCoins[QString::fromStdString("(mint)")].push_back(out);
            continue;
        }
        else if(!out.fSpendable || !ExtractDestination(cout.tx->tx->vout[cout.i].scriptPubKey, address)){
            continue;
        }

        mapCoins[QString::fromStdString(CBitcoinAddress(address).ToString())].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return false;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return false;
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;
    wallet->LockCoin(output);
    Q_EMIT updateMintable();
}

void WalletModel::unlockCoin(COutPoint& output)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;
    wallet->UnlockCoin(output);
    Q_EMIT updateMintable();
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;
    wallet->ListLockedCoins(vOutpts);
}

void WalletModel::listProTxCoins(std::vector<COutPoint>& vOutpts)
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return;
    wallet->ListProTxCoins(vOutpts);
}

bool WalletModel::hasMasternode()
{
    TRY_LOCK(cs_main,lock_main);
    if (!lock_main)
        return false;
    TRY_LOCK(wallet->cs_wallet,lock_wallet);
    if (!lock_wallet)
        return false;
    return wallet->HasMasternode();
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    LOCK(wallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, wallet->mapAddressBook)
        BOOST_FOREACH(const PAIRTYPE(std::string, std::string)& item2, item.second.destdata)
            if (item2.first.size() > 2 && item2.first.substr(0,2) == "rr") // receive request
                vReceiveRequests.push_back(item2.second);

    BOOST_FOREACH (const PAIRTYPE(std::string, CAddressBookData) & item, wallet->mapSparkAddressBook)
        BOOST_FOREACH (const PAIRTYPE(std::string, std::string) & item2, item.second.destdata)
            if (item2.first.size() > 2 && item2.first.substr(0, 2) == "rr") // receive request
                vReceiveRequests.push_back(item2.second);
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    LOCK(wallet->cs_wallet);
    if (sRequest.empty())
        return wallet->EraseDestData(sAddress, key);
    else
        return wallet->AddDestData(sAddress, key, sRequest);
}

bool WalletModel::transactionCanBeAbandoned(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx *wtx = wallet->GetWalletTx(hash);
    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0 || wtx->InMempool() || wtx->InStempool())
        return false;
    return true;
}

bool WalletModel::abandonTransaction(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->AbandonTransaction(hash);
}

bool WalletModel::transactionCanBeRebroadcast(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx *wtx = wallet->GetWalletTx(hash);
    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0)
        return false;
    return wtx->GetRequestCount() <= 0;
}

bool WalletModel::rebroadcastTransaction(uint256 hash, CValidationState &state)
{
    LOCK2(cs_main, wallet->cs_wallet);
    CWalletTx *wtx = const_cast<CWalletTx*>(wallet->GetWalletTx(hash));

    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0)
        return false;
    if (wtx->GetRequestCount() > 0)
        return false;

    CCoinsViewCache &view = *pcoinsTip;
    bool fHaveChain = false;
    for (size_t i=0; i<wtx->tx->vout.size() && !fHaveChain; i++) {
        if (view.HaveCoin(COutPoint(hash, i)))
            fHaveChain = true;
    }

    bool fHaveMempool = mempool.exists(hash);

    if (!fHaveMempool && !fHaveChain) {
        // push to local node and sync with wallets
        bool fMissingInputs;
        if (!AcceptToMemoryPool(mempool, state, wtx->tx, false, &fMissingInputs, NULL, true, false, maxTxFee))
            return false;
    } else if (fHaveChain) {
        return false;
    }

    g_connman->RelayTransaction(*wtx->tx);
    return true;
}

CAmount WalletModel::GetJMintCredit(const CTxOut& txout, const CTransaction& tx) const
{
    return wallet->GetCredit(txout, tx, ISMINE_SPENDABLE);
}

bool WalletModel::isWalletEnabled()
{
   return !GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

bool WalletModel::hdEnabled() const
{
    return wallet->IsHDEnabled();
}

int WalletModel::getDefaultConfirmTarget() const
{
    return nTxConfirmTarget;
}

void WalletModel::handleBip47Keys(int receiverAccountNum, void * pBlockIndex_)
{
    //These statics are to display only one password prompt at a time and block consequent prompts
    static std::mutex singlePasswordPromptMutex, queueMutex;
    static std::deque<bip47::CAccountReceiver const *> receiverAccountNumQueue;

    if(!pBlockIndex_)
        return;
    CBlockIndex * pBlockIndex = reinterpret_cast<CBlockIndex *>(pBlockIndex_);

    if (wallet->GetBip47Wallet()) {
        bip47::CAccountReceiver const * acc = wallet->GetBip47Wallet()->getReceivingAccount(uint32_t(receiverAccountNum));
        if (!acc)
            return;

        std::unique_lock<std::mutex> _(singlePasswordPromptMutex, std::try_to_lock);
        if (!_.owns_lock()) {
            std::lock_guard<std::mutex> _(queueMutex);
            receiverAccountNumQueue.push_back(acc);
            return;
        }

        static QString const unlockText = tr("You have received a payment to a RAP address, please unlock your wallet to receive.");
        UnlockContext ctx(requestUnlock(unlockText));
        while(!ctx.isValid()) {
            CancelPasswordDialog msgDialog(
                    tr("RAP address payment"),
                    tr("RAP addresses require you to unlock your wallet every time a payment to it is received."),
                    3
            );
            msgDialog.setInformativeText(tr("If you do not enter your password now, you will need to rescan your wallet to receive your FIRO.<br/><br/>Re-enter your password?"));
            if(msgDialog.exec() == QMessageBox::Cancel)
                return;
            ctx = requestUnlock(unlockText);
        }
        ctx.delayRelock(60);
        bip47::utils::AddReceiverSecretAddresses(*acc, *wallet);
        {
            std::lock_guard<std::mutex> _(queueMutex);
            for(std::deque<bip47::CAccountReceiver const *>::iterator iter = receiverAccountNumQueue.begin(); iter != receiverAccountNumQueue.end(); ++iter)
                bip47::utils::AddReceiverSecretAddresses(**iter, *wallet);
            receiverAccountNumQueue.clear();
        }
        LOCK(cs_main);
        if (!chainActive.Contains(pBlockIndex)) {
            pBlockIndex = const_cast<CBlockIndex*>(chainActive.FindFork(pBlockIndex));
            if (!pBlockIndex) return;
        }
        if (pBlockIndex != chainActive.Tip()) {
            wallet->ScanForWalletTransactions(pBlockIndex, false, false);
        }
    }
}

bool WalletModel::validateSparkAddress(const QString& address)
{
    const spark::Params* params = spark::Params::get_default();
    unsigned char network = spark::GetNetworkType();
    unsigned char coinNetwork;
    spark::Address addr(params);
    try {
        coinNetwork = addr.decode(address.toStdString());
    } catch (...) {
        return false;
    }
    return network == coinNetwork;
}

bool WalletModel::isSparkAddressMine(const QString& address)
{
    return wallet->IsSparkAddressMine(address.toStdString());
}

QString WalletModel::signSparkMessage(const QString& sparkAddress, const QString& message, QString& error)
{
    // Signing touches no chain state, so cs_wallet alone is enough; taking cs_main here
    // would block the GUI thread whenever a block is being connected.
    LOCK(wallet->cs_wallet);

    if (!wallet->sparkWallet) {
        error = tr("Spark wallet is not available.");
        return QString();
    }

    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);
    unsigned char coinNetwork;
    try {
        coinNetwork = address.decode(sparkAddress.toStdString());
    } catch (const std::exception&) {
        error = tr("The entered address is invalid.");
        return QString();
    }

    // Match the RPC signing path and spark::VerifyMessage, which both reject
    // addresses encoded for a different network.
    if (coinNetwork != spark::GetNetworkType()) {
        error = tr("The entered address is for a different network.");
        return QString();
    }

    if (!wallet->sparkWallet->isAddressMine(address)) {
        error = tr("The entered address does not belong to this wallet.");
        return QString();
    }

    try {
        return QString::fromStdString(wallet->sparkWallet->SignMessage(address, message.toStdString()));
    } catch (const std::exception& e) {
        // Remaining failures are internal (spend key generation), so surface them verbatim
        // rather than guessing at a friendlier wording.
        error = QString::fromStdString(e.what());
        return QString();
    }
}

QString WalletModel::generateSparkAddress()
{
    const spark::Params* params = spark::Params::get_default();
    spark::Address address(params);

    {
        LOCK(wallet->cs_wallet);
        address = wallet->sparkWallet->generateNewAddress();
        unsigned char network = spark::GetNetworkType();

        wallet->SetSparkAddressBook(address.encode(network), "", "receive");
        return QString::fromStdString(address.encode(network));
    }
}

std::pair<CAmount, CAmount> WalletModel::getSparkBalance()
{
    LOCK(wallet->cs_wallet);
    return wallet->GetSparkBalance();
}

WalletModel::SendCoinsReturn WalletModel::prepareMintSparkTransaction(std::vector<WalletModelTransaction> &transactions, QList<SendCoinsRecipient> recipients, std::vector<std::pair<CWalletTx, CAmount> >& wtxAndFees, std::list<CReserveKey>& reservekeys, const CCoinControl* coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;

    if (recipients.empty()) {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;
    std::vector<spark::MintedCoinData> outputs;
    const spark::Params* params = spark::Params::get_default();
    // Pre-check input data for validity
    Q_FOREACH (const SendCoinsRecipient& rcp, recipients) {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

        { // User-entered Firo address / amount:
            if (!validateSparkAddress(rcp.address)) {
                return InvalidAddress;
            }
            if (rcp.amount <= 0) {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            spark::Address address(params);
            address.decode(rcp.address.toStdString());
            spark::MintedCoinData data;
            data.address = address;
            data.memo = rcp.message.toStdString();
            data.v = rcp.amount;
            outputs.push_back(data);
            total += rcp.amount;
        }
    }
    if (setAddress.size() != nAddresses) {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if (total > nBalance) {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;

        std::string strFailReason;
        bool fCreated = wallet->CreateSparkMintTransactions(outputs, wtxAndFees, nFeeRequired, reservekeys, nChangePosRet, fSubtractFeeFromAmount, strFailReason, optionsModel->getfSplit(), coinControl, false);
        transactions.clear();
        transactions.reserve(wtxAndFees.size());
        for (auto &wtxAndFee : wtxAndFees) {
            auto &wtx = wtxAndFee.first;
            auto fee = wtxAndFee.second;

            int changePos = -1;
            for (size_t i = 0; i != wtx.tx->vout.size(); i++) {
                if (!wtx.tx->vout[i].scriptPubKey.IsMint()) changePos = i;
            }

            transactions.emplace_back(recipients);
            auto &tx = transactions.back();

            *tx.getTransaction() = wtx;
            tx.setTransactionFee(fee);
            tx.reassignAmounts(changePos);
        }
        
        if (!fCreated) {
            return SendCoinsReturn(TransactionCreationFailed, QString::fromStdString(strFailReason));
        }

        if (!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance) {
            return SendCoinsReturn(AmountWithFeeExceedsBalance);
        }
        
        if (nFeeRequired > maxTxFee) {
            return AbsurdFee;
        }
    }
    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::prepareSpendSparkTransactionsSingleInput(
    std::vector<WalletModelTransaction>& transactions,
    const QList<SendCoinsRecipient>& recipients,
    const CCoinControl* coinControl)
{
    transactions.clear();
    if (recipients.empty()) {
        return OK;
    }

    // A selected set is a single coin-control instruction. Splitting it into
    // separate transactions would silently change its "use all inputs"
    // semantics, so this path accepts at most one selected Spark coin.
    if (HasMultipleSelectedCoins(coinControl)) {
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("Spark Coin Control temporarily supports selecting at most one coin. Clear the selection to let the wallet split the payment automatically."));
    }

    struct RecipientPlan {
        SendCoinsRecipient recipient;
        CScript scriptPubKey;
        spark::OutputCoinData privateOutput;
        bool isPrivate;
    };

    struct AvailableCoin {
        CAmount value;
        COutPoint outpoint;
    };

    CAmount total = 0;
    QSet<QString> addresses;
    std::vector<RecipientPlan> recipientPlans;
    std::vector<spark::BatchRecipient> plannerRecipients;
    recipientPlans.reserve(recipients.size());
    plannerRecipients.reserve(recipients.size());
    const spark::Params* params = spark::Params::get_default();

    for (const SendCoinsRecipient& recipient : recipients) {
        if (recipient.amount <= 0 || !MoneyRange(recipient.amount)) {
            return InvalidAmount;
        }
        if (recipient.fSubtractFeeFromAmount) {
            return SendCoinsReturn(
                TransactionCreationFailed,
                tr("Subtracting the fee from the amount is temporarily unavailable for Spark spends."));
        }
        if (addresses.contains(recipient.address)) {
            return DuplicateAddress;
        }
        addresses.insert(recipient.address);

        if (total > MAX_MONEY - recipient.amount) {
            return InvalidAmount;
        }
        total += recipient.amount;

        RecipientPlan plan;
        plan.recipient = recipient;
        plan.isPrivate = false;

        if (validateAddress(recipient.address)) {
            plan.scriptPubKey = GetScriptForDestination(CBitcoinAddress(recipient.address.toStdString()).Get());
        } else if (validateSparkAddress(recipient.address)) {
            try {
                plan.privateOutput.address = spark::Address(params);
                plan.privateOutput.address.decode(recipient.address.toStdString());
            } catch (const std::exception&) {
                return InvalidAddress;
            }
            plan.privateOutput.memo = recipient.message.toStdString();
            plan.isPrivate = true;
        } else {
            return InvalidAddress;
        }

        const CAmount minimumOutputAmount = plan.isPrivate
            ? 1
            : sparkspendbatch::TransparentMinimumOutputAmount(plan.scriptPubKey);
        plannerRecipients.push_back({recipient.amount, plan.isPrivate, minimumOutputAmount});
        recipientPlans.push_back(std::move(plan));
    }

    CAmount balance;
    std::tie(balance, std::ignore) = getSparkBalance();
    if (total > balance) {
        return AmountExceedsBalance;
    }

    std::vector<AvailableCoin> availableCoins;
    spark::BatchPlanLimits limits;
    int expectedNextBlockHeight;
    {
        // Snapshot the chain-dependent selection data. Proof generation below
        // performs its own per-transaction locking and revalidates each selected
        // outpoint, so block processing is not stalled for the entire batch.
        LOCK2(cs_main, wallet->cs_wallet);

        std::list<CSparkMintMeta> coinMetadata = wallet->GetAvailableSparkCoins(coinControl);
        coinMetadata.sort(CompareSparkCoins);
        availableCoins.reserve(coinMetadata.size());
        for (const CSparkMintMeta& coin : coinMetadata) {
            if (coin.v > static_cast<uint64_t>(MAX_MONEY)) {
                continue;
            }

            COutPoint outpoint;
            if (spark::GetOutPoint(outpoint, coin.coin)) {
                availableCoins.push_back({static_cast<CAmount>(coin.v), outpoint});
            }
        }

        const auto& consensus = Params().GetConsensus();
        expectedNextBlockHeight = chainActive.Height() + 1;
        limits.maxTransactions = MAX_SINGLE_INPUT_SPARK_TRANSACTIONS;
        limits.maxPrivateOutputs = consensus.nMaxSparkOutLimitPerTx > 1
            ? consensus.nMaxSparkOutLimitPerTx - 2
            : 0;
        limits.maxTransparentAmount =
            consensus.GetMaxValueSparkSpendPerTransaction(
                expectedNextBlockHeight);
        limits.maxFee = maxTxFee;
        limits.maxMoney = MAX_MONEY;
        limits.maxWeight = MAX_NEW_TX_WEIGHT;
        limits.weightScaleFactor = WITNESS_SCALE_FACTOR;
    }

    std::vector<CAmount> coinValues;
    coinValues.reserve(availableCoins.size());
    for (const AvailableCoin& coin : availableCoins) {
        coinValues.push_back(coin.value);
    }

    spark::BatchPlanResult plan;

    try {
        plan = spark::PlanSingleInputSpend(
            coinValues,
            plannerRecipients,
            limits,
            [coinControl](size_t privateOutputs, size_t transparentOutputs) {
                return EstimateSingleInputSparkFee(
                    privateOutputs, transparentOutputs, coinControl);
            },
            spark::EstimateSingleInputSparkSize);
    } catch (const std::exception& e) {
        return SendCoinsReturn(TransactionCreationFailed, QString::fromStdString(e.what()));
    }

    switch (plan.status) {
    case spark::BatchPlanStatus::OK:
        break;
    case spark::BatchPlanStatus::INVALID_AMOUNT:
        return InvalidAmount;
    case spark::BatchPlanStatus::TRANSPARENT_LIMIT:
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("Spend to transparent address limit exceeded."));
    case spark::BatchPlanStatus::FEE_TOO_HIGH:
        return AbsurdFee;
    case spark::BatchPlanStatus::TOO_MANY_TRANSACTIONS:
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("A Spark payment may use at most %1 transactions.")
                .arg(MAX_SINGLE_INPUT_SPARK_TRANSACTIONS));
    case spark::BatchPlanStatus::INSUFFICIENT_FUNDS:
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("The available Spark coins cannot cover the amount and the required transaction fees."));
    }

    transactions.reserve(plan.batches.size());
    for (const spark::SingleInputBatch& batch : plan.batches) {
        QList<SendCoinsRecipient> guiRecipients;
        std::vector<CRecipient> transparentRecipients;
        std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients;
        guiRecipients.reserve(batch.fragments.size());
        transparentRecipients.reserve(batch.transparentOutputs);
        privateRecipients.reserve(batch.privateOutputs);

        for (const spark::BatchFragment& fragment : batch.fragments) {
            const RecipientPlan& recipient = recipientPlans.at(fragment.recipientIndex);
            SendCoinsRecipient guiRecipient = recipient.recipient;
            guiRecipient.amount = fragment.amount;
            guiRecipient.fSubtractFeeFromAmount = false;
            guiRecipients.append(std::move(guiRecipient));

            if (recipient.isPrivate) {
                spark::OutputCoinData output = recipient.privateOutput;
                output.v = fragment.amount;
                privateRecipients.emplace_back(std::move(output), false);
            } else {
                transparentRecipients.push_back({recipient.scriptPubKey, fragment.amount, false});
            }
        }

        CCoinControl singleCoinControl = coinControl ? *coinControl : CCoinControl();
        singleCoinControl.UnSelectAll();
        singleCoinControl.fAllowOtherInputs = false;
        singleCoinControl.fRequireAllInputs = true;
        singleCoinControl.Select(availableCoins.at(batch.coinIndex).outpoint);

        CAmount fee = 0;
        CWalletTx walletTransaction;
        try {
            walletTransaction = wallet->CreateSparkSpendTransaction(
                transparentRecipients,
                privateRecipients,
                fee,
                &singleCoinControl,
                expectedNextBlockHeight);
        } catch (const std::exception& e) {
            transactions.clear();
            return SendCoinsReturn(TransactionCreationFailed, QString::fromStdString(e.what()));
        }

        if (!walletTransaction.tx || spark::GetSpendInputs(*walletTransaction.tx) != 1) {
            transactions.clear();
            return SendCoinsReturn(
                TransactionCreationFailed,
                tr("Unable to create a single-input Spark transaction."));
        }

        // The plan was costed with EstimateSingleInputSparkFee; if the wallet
        // disagrees, the two size models have drifted and the split is no longer
        // guaranteed to be funded. Refuse rather than send something unplanned.
        if (fee != batch.fee) {
            transactions.clear();
            return SendCoinsReturn(
                TransactionCreationFailed,
                tr("Spark fee estimate did not match the wallet (planned %1, wallet %2).")
                    .arg(batch.fee)
                    .arg(fee));
        }

        transactions.emplace_back(guiRecipients);
        WalletModelTransaction& transaction = transactions.back();
        *transaction.getTransaction() = std::move(walletTransaction);
        transaction.setTransactionFee(fee);
    }

    return OK;
}

WalletModel::SendCoinsReturn WalletModel::prepareSpendSparkTransactions(
    std::vector<WalletModelTransaction>& transactions,
    const QList<SendCoinsRecipient>& recipients,
    const CCoinControl* coinControl)
{
    int expectedNextBlockHeight;
    {
        LOCK(cs_main);
        expectedNextBlockHeight = chainActive.Height() + 1;
    }

    if (expectedNextBlockHeight <
        Params().GetConsensus().nSparkChaumV2StartBlock) {
        return prepareSpendSparkTransactionsSingleInput(
            transactions, recipients, coinControl);
    }

    transactions.clear();
    if (recipients.empty()) {
        return OK;
    }

    CAmount total = 0;
    bool subtractFeeFromAmount = false;
    QSet<QString> addresses;
    std::vector<CRecipient> transparentRecipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients;
    QList<SendCoinsRecipient> transparentGuiRecipients;
    QList<SendCoinsRecipient> privateGuiRecipients;
    const spark::Params* params = spark::Params::get_default();

    for (const SendCoinsRecipient& recipient : recipients) {
        if (recipient.amount <= 0 || !MoneyRange(recipient.amount)) {
            return InvalidAmount;
        }
        if (addresses.contains(recipient.address)) {
            return DuplicateAddress;
        }
        addresses.insert(recipient.address);
        if (total > MAX_MONEY - recipient.amount) {
            return InvalidAmount;
        }
        total += recipient.amount;
        subtractFeeFromAmount |= recipient.fSubtractFeeFromAmount;

        if (validateAddress(recipient.address)) {
            transparentRecipients.push_back({
                GetScriptForDestination(
                    CBitcoinAddress(recipient.address.toStdString()).Get()),
                recipient.amount,
                recipient.fSubtractFeeFromAmount});
            transparentGuiRecipients.push_back(recipient);
        } else if (validateSparkAddress(recipient.address)) {
            try {
                spark::OutputCoinData output;
                output.address = spark::Address(params);
                output.address.decode(recipient.address.toStdString());
                output.memo = recipient.message.toStdString();
                output.v = recipient.amount;
                privateRecipients.emplace_back(
                    std::move(output), recipient.fSubtractFeeFromAmount);
                privateGuiRecipients.push_back(recipient);
            } catch (const std::exception&) {
                return InvalidAddress;
            }
        } else {
            return InvalidAddress;
        }
    }

    CAmount balance;
    std::tie(balance, std::ignore) = getSparkBalance();
    if (total > balance) {
        return AmountExceedsBalance;
    }

    // Construction serializes transparent outputs before private outputs.
    // Keep the GUI's recipient list in the same order so fee-subtracted
    // amounts are reassigned from the corresponding transaction outputs.
    transparentGuiRecipients.append(privateGuiRecipients);
    CAmount fee = 0;
    CWalletTx walletTransaction;
    std::vector<CAmount> recipientAmounts;
    try {
        walletTransaction = wallet->CreateSparkSpendTransaction(
            transparentRecipients,
            privateRecipients,
            fee,
            coinControl,
            expectedNextBlockHeight,
            &recipientAmounts);
    } catch (const InsufficientFunds&) {
        transactions.clear();
        if (!subtractFeeFromAmount && total <= MAX_MONEY - fee &&
            total + fee > balance) {
            return AmountWithFeeExceedsBalance;
        }
        return AmountExceedsBalance;
    } catch (const std::exception& e) {
        transactions.clear();
        return SendCoinsReturn(
            TransactionCreationFailed,
            QString::fromStdString(e.what()));
    }

    if (fee > maxTxFee) {
        transactions.clear();
        return AbsurdFee;
    }
    if (!walletTransaction.tx || !walletTransaction.tx->IsSparkSpendV2() ||
        recipientAmounts.size() !=
            static_cast<std::size_t>(transparentGuiRecipients.size())) {
        transactions.clear();
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("Unable to create a versioned Spark transaction."));
    }

    for (int i = 0; i < transparentGuiRecipients.size(); ++i) {
        transparentGuiRecipients[i].amount = recipientAmounts[i];
    }
    transactions.emplace_back(transparentGuiRecipients);
    WalletModelTransaction& transaction = transactions.back();
    *transaction.getTransaction() = std::move(walletTransaction);
    transaction.setTransactionFee(fee);
    return OK;
}

bool WalletModel::sparkNamesAllowed() const
{
    int chainHeight;
    {
        LOCK(cs_main);
        chainHeight = chainActive.Height();
    }
    return chainHeight + 1 >= Params().GetConsensus().nSparkNamesStartBlock;
}

bool WalletModel::versionedSparkSpendsAllowed() const
{
    LOCK(cs_main);
    return chainActive.Height() + 1 >=
        Params().GetConsensus().nSparkChaumV2StartBlock;
}

bool WalletModel::GetSparkNameByAddress(const QString& sparkAddress, QString& name)
{
    std::string name_ = name.toStdString();
    bool result = CSparkNameManager::GetInstance()->GetSparkNameByAddress(sparkAddress.toStdString(), name_);
    if (result)
        name = QString::fromStdString(name_);
    return result;
}

bool WalletModel::validateSparkNameData(const QString &name, const QString &sparkAddress, const QString &additionalData, QString &strError) {
    CSparkNameTxData sparkNameData;

    sparkNameData.name = name.toStdString();
    sparkNameData.sparkAddress = sparkAddress.toStdString();
    sparkNameData.additionalInfo = additionalData.toStdString();
    sparkNameData.sparkNameValidityBlocks = 1000;   // doesn't matter
    std::string _strError;
    bool result = CSparkNameManager::GetInstance()->ValidateSparkNameData(sparkNameData, _strError);
    strError = QString::fromStdString(_strError);
    return result;
}

WalletModelTransaction WalletModel::initSparkNameTransaction(CAmount sparkNameFee) {
    const auto &consensusParams = Params().GetConsensus();
    SendCoinsRecipient recipient;

    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height() + 1;
    }

    std::string destAddress = nHeight >= consensusParams.stage41StartBlockDevFundAddressChange
        ? consensusParams.stage3CommunityFundAddress
        : consensusParams.stage3DevelopmentFundAddress;
        
    recipient.address = QString::fromStdString(destAddress);
    recipient.amount = sparkNameFee;
    recipient.fSubtractFeeFromAmount = false;

    return WalletModelTransaction({recipient});
}

QString WalletModel::getSparkNameAddress(const QString &sparkName) {
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    std::string sparkAddress;
    if (sparkNameManager->GetSparkAddress(sparkName.toStdString(), sparkAddress)) {
        return QString::fromStdString(sparkAddress);
    }
    else {
        return "";
    }
}

WalletModel::SendCoinsReturn WalletModel::prepareSparkNameTransaction(WalletModelTransaction &transaction, CSparkNameTxData &sparkNameData, CAmount sparkNameFee, const CCoinControl* coinControl)
{
    CAmount nBalance;
    std::tie(nBalance, std::ignore) = getSparkBalance();

    if (sparkNameFee > nBalance) {
        return AmountExceedsBalance;
    }

    int expectedNextBlockHeight;
    {
        LOCK(cs_main);
        expectedNextBlockHeight = chainActive.Height() + 1;
    }
    const bool versionedSpend = expectedNextBlockHeight >=
        Params().GetConsensus().nSparkChaumV2StartBlock;

    CCoinControl singleCoinControl;
    const CCoinControl* constructionControl = coinControl;
    if (!versionedSpend) {
        if (HasMultipleSelectedCoins(coinControl)) {
            return SendCoinsReturn(
                TransactionCreationFailed,
                tr("Spark name registration temporarily uses a single Spark coin. Please select at most one."));
        }

        LOCK2(cs_main, wallet->cs_wallet);

        std::list<CSparkMintMeta> availableCoins = wallet->GetAvailableSparkCoins(coinControl);
        availableCoins.sort(CompareSparkCoins);
        if (availableCoins.empty()) {
            return AmountExceedsBalance;
        }

        COutPoint outpoint;
        if (!spark::GetOutPoint(outpoint, availableCoins.front().coin)) {
            return SendCoinsReturn(TransactionCreationFailed, tr("Unable to select a Spark coin."));
        }

        singleCoinControl = coinControl ? *coinControl : CCoinControl();
        singleCoinControl.UnSelectAll();
        singleCoinControl.fAllowOtherInputs = false;
        singleCoinControl.fRequireAllInputs = true;
        singleCoinControl.Select(outpoint);
        constructionControl = &singleCoinControl;
    }

    CAmount nFeeRequired = 0;
    CWalletTx *newTx = transaction.getTransaction();
    try {
        *newTx = wallet->CreateSparkNameTransaction(
            sparkNameData,
            sparkNameFee,
            nFeeRequired,
            constructionControl,
            expectedNextBlockHeight);
    }
    catch (InsufficientFunds const&) {
        transaction.setTransactionFee(nFeeRequired);
        if (!versionedSpend) {
            return SendCoinsReturn(
                TransactionCreationFailed,
                tr("Spark name registration temporarily requires one Spark coin large enough to cover the registration and transaction fees."));
        }
        return AmountExceedsBalance;
    }
    catch (const std::exception& e) {
        return SendCoinsReturn(
            TransactionCreationFailed,
            QString::fromStdString(e.what()));
    }
    if (nFeeRequired > maxTxFee) {
        return AbsurdFee;
    }
    if (!newTx->tx ||
        (!versionedSpend && spark::GetSpendInputs(*newTx->tx) != 1) ||
        (versionedSpend && !newTx->tx->IsSparkSpendV2())) {
        return SendCoinsReturn(
            TransactionCreationFailed,
            tr("Unable to create the expected Spark transaction format."));
    }

    int changePos = -1;
    for (size_t i = 0; i != newTx->tx->vout.size(); i++) {
        if (!newTx->tx->vout[i].scriptPubKey.IsSparkSMint()) {
            changePos = i;
        }
    }
    transaction.setTransactionFee(nFeeRequired);
    transaction.reassignAmounts(changePos);

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::mintSparkCoins(std::vector<WalletModelTransaction> &transactions, std::vector<std::pair<CWalletTx, CAmount> >& wtxAndFee, std::list<CReserveKey>& reserveKeys)
{
    QByteArray transaction_array; /* store serialized transaction */
    {
        LOCK2(cs_main, wallet->cs_wallet);
        CValidationState state;
        auto reservekey = reserveKeys.begin();

        for (size_t i = 0; i != wtxAndFee.size(); i++) {
            if (!wallet->CommitTransaction(wtxAndFee[i].first, *reservekey++, g_connman.get(), state))
                return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(state.GetRejectReason()));

            Q_FOREACH(const SendCoinsRecipient &rcp, transactions[i].getRecipients())
            {
                // CWalletTx* newTx = transactions[i].getTransaction();
                if (!rcp.message.isEmpty()) // Message from normal firo:URI (firo:123...?message=example)
                    wtxAndFee[i].first.vOrderForm.push_back(make_pair("Message", rcp.message.toStdString()));

                CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
                ssTx << *wtxAndFee[i].first.tx;
                transaction_array.append(&(ssTx[0]), ssTx.size());

                {
                    std::string strAddress = rcp.address.toStdString();
                    std::string strLabel = rcp.label.toStdString();
                    {
                        std::map<std::string, CAddressBookData>::iterator mi = wallet->mapSparkAddressBook.find(strAddress);

                        // Check if we have a new address or an updated label
                        if (mi == wallet->mapSparkAddressBook.end()) {
                            wallet->SetSparkAddressBook(strAddress, strLabel, "send");
                        } else if (mi->second.name != strLabel) {
                            wallet->SetSparkAddressBook(strAddress, strLabel, ""); // "" means don't change purpose
                        }
                    }
                }
                Q_EMIT coinsSent(wallet, rcp, transaction_array);
            }

        }
    }

    // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits.
    // Queued so that it runs on the GUI thread even when mintSparkCoins is called from a worker thread.
    QMetaObject::invokeMethod(this, "checkBalanceChanged", Qt::QueuedConnection);

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::spendSparkCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */
    const QList<SendCoinsRecipient> recipients = transaction.getRecipients();

    for (const SendCoinsRecipient& recipient : recipients) {
        if (!validateAddress(recipient.address) &&
            !validateSparkAddress(recipient.address)) {
            return InvalidAddress;
        }
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CValidationState state;
        CReserveKey reserveKey(wallet);
        CWalletTx* newTx = transaction.getTransaction();
        if (!newTx->tx || !spark::IsSparkSpendFormatAllowed(
                *newTx->tx, chainActive.Height() + 1)) {
            return SendCoinsReturn(
                TransactionCommitFailed,
                tr("Refusing to commit an incompatible Spark transaction format."));
        }
        for (const SendCoinsRecipient& recipient : recipients) {
            if (!recipient.message.isEmpty()) {
                newTx->vOrderForm.emplace_back(
                    "Message", recipient.message.toStdString());
            }
        }

        if (!wallet->CommitTransaction(
                *newTx,
                reserveKey,
                g_connman.get(),
                state,
                wallet->GetBroadcastTransactions())) {
            return SendCoinsReturn(
                TransactionCommitFailed,
                QString::fromStdString(state.GetRejectReason()));
        }
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx->tx;
        transaction_array.append(&ssTx[0], ssTx.size());

        for (const SendCoinsRecipient& rcp : recipients) {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = CBitcoinAddress(strAddress).Get();
            std::string strLabel = rcp.label.toStdString();
            if (validateAddress(rcp.address)) {
                std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(dest);
                // Check if we have a new address or an updated label
                if (mi == wallet->mapAddressBook.end()) {
                    wallet->SetAddressBook(dest, strLabel, "send");
                } else if (mi->second.name != strLabel) {
                    wallet->SetAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            } else {
                std::map<std::string, CAddressBookData>::iterator mi = wallet->mapSparkAddressBook.find(strAddress);

                // Check if we have a new address or an updated label
                if (mi == wallet->mapSparkAddressBook.end()) {
                    wallet->SetSparkAddressBook(strAddress, strLabel, "send");
                } else if (mi->second.name != strLabel) {
                    wallet->SetSparkAddressBook(strAddress, strLabel, ""); // "" means don't change purpose
                }
            }
            Q_EMIT coinsSent(wallet, rcp, transaction_array);
        }
    }

    // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits.
    // Queued so that it runs on the GUI thread even when spendSparkCoins is called from a worker thread.
    QMetaObject::invokeMethod(this, "checkBalanceChanged", Qt::QueuedConnection);

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::spendSparkCoins(std::vector<WalletModelTransaction>& transactions)
{
    for (WalletModelTransaction& transaction : transactions) {
        const CWalletTx* walletTransaction = transaction.getTransaction();
        if (!walletTransaction->tx) {
            return SendCoinsReturn(
                TransactionCommitFailed,
                tr("Refusing to commit an incomplete Spark transaction."));
        }

        for (const SendCoinsRecipient& recipient : transaction.getRecipients()) {
            if (!validateAddress(recipient.address) && !validateSparkAddress(recipient.address)) {
                return InvalidAddress;
            }
        }
    }

    SendCoinsReturn result = OK;
    bool committedAny = false;
    // Every transaction that made it out, so a partial failure can tell the user
    // exactly what was sent instead of leaving them to reconstruct it.
    QStringList committed;
    {
        LOCK2(cs_main, wallet->cs_wallet);

        for (WalletModelTransaction& transaction : transactions) {
            CWalletTx* walletTransaction = transaction.getTransaction();
            if (!spark::IsSparkSpendFormatAllowed(
                    *walletTransaction->tx, chainActive.Height() + 1)) {
                return SendCoinsReturn(
                    TransactionCommitFailed,
                    tr("Refusing to commit an incompatible Spark transaction format."));
            }
            for (const SendCoinsRecipient& recipient : transaction.getRecipients()) {
                if (!recipient.message.isEmpty()) {
                    walletTransaction->vOrderForm.emplace_back("Message", recipient.message.toStdString());
                }
            }

            CValidationState state;
            CReserveKey reserveKey(wallet);
            // The last argument is CommitTransaction's fCheckTransaction: it makes the
            // transaction go through the mempool before it is added to the wallet, so a
            // rejection stops the batch instead of being discovered afterwards. It is
            // passed as GetBroadcastTransactions() rather than true because with
            // -walletbroadcast=0 CommitTransaction relays unconditionally when
            // fCheckTransaction is set, which would override the user's setting. Under
            // -walletbroadcast=0 nothing is validated or sent, so no batch can fail
            // part-way in the first place.
            if (!wallet->CommitTransaction(
                    *walletTransaction,
                    reserveKey,
                    g_connman.get(),
                    state,
                    wallet->GetBroadcastTransactions())) {
                QString reason = QString::fromStdString(state.GetRejectReason());
                if (committedAny) {
                    reason.append(tr(" This payment was split across %1 transactions and %2 of them "
                                     "were already sent, so the recipients have been paid only in "
                                     "part. Do not retry the whole payment. Already sent: %3")
                                      .arg(transactions.size())
                                      .arg(committed.size())
                                      .arg(committed.join(", ")));
                }
                result = SendCoinsReturn(TransactionCommitFailed, reason, committedAny);
                break;
            }
            committedAny = true;
            committed.append(QString::fromStdString(walletTransaction->GetHash().ToString()));

            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << *walletTransaction->tx;
            QByteArray transactionArray;
            transactionArray.append(&stream[0], stream.size());

            for (const SendCoinsRecipient& recipient : transaction.getRecipients()) {
                const std::string address = recipient.address.toStdString();
                const std::string label = recipient.label.toStdString();

                if (validateAddress(recipient.address)) {
                    const CTxDestination destination = CBitcoinAddress(address).Get();
                    const auto item = wallet->mapAddressBook.find(destination);
                    if (item == wallet->mapAddressBook.end()) {
                        wallet->SetAddressBook(destination, label, "send");
                    } else if (item->second.name != label) {
                        wallet->SetAddressBook(destination, label, "");
                    }
                } else {
                    const auto item = wallet->mapSparkAddressBook.find(address);
                    if (item == wallet->mapSparkAddressBook.end()) {
                        wallet->SetSparkAddressBook(address, label, "send");
                    } else if (item->second.name != label) {
                        wallet->SetSparkAddressBook(address, label, "");
                    }
                }

                Q_EMIT coinsSent(wallet, recipient, transactionArray);
            }
        }
    }

    if (committedAny) {
        QMetaObject::invokeMethod(this, "checkBalanceChanged", Qt::QueuedConnection);
    }

    return result;
}
