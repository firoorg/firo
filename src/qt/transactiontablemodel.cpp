// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiontablemodel.h"

#include "addresstablemodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactiondesc.h"
#include "transactionrecord.h"
#include "walletmodel.h"

#include "core_io.h"
#include "validation.h"
#include "sync.h"
#include "util.h"
#include "wallet/wallet.h"

#include <QColor>
#include <QDateTime>
#include <QDebug>
#include <QIcon>
#include <QList>
#include <QScopedValueRollback>
#include <QTimer>

#include <algorithm>
#include <deque>

#include <boost/foreach.hpp>

// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
        Qt::AlignLeft|Qt::AlignVCenter, /* status */
        Qt::AlignLeft|Qt::AlignVCenter, /* watchonly */
        Qt::AlignLeft|Qt::AlignVCenter, /* instantsend */
        Qt::AlignLeft|Qt::AlignVCenter, /* date */
        Qt::AlignLeft|Qt::AlignVCenter, /* type */
        Qt::AlignLeft|Qt::AlignVCenter, /* address */
        Qt::AlignRight|Qt::AlignVCenter /* amount */
    };

// Comparison operator for sort/binary search of model tx list
struct TxLessThan
{
    bool operator()(const TransactionRecord &a, const TransactionRecord &b) const
    {
        return a.hash < b.hash;
    }
    bool operator()(const TransactionRecord &a, const uint256 &b) const
    {
        return a.hash < b;
    }
    bool operator()(const uint256 &a, const TransactionRecord &b) const
    {
        return a < b.hash;
    }
};

// Wallet notifications shared by rescan batching and GUI retries.
struct TransactionNotification
{
    TransactionNotification(uint256 _hash, int _status, bool _showTransaction):
        hash(_hash), status(_status), showTransaction(_showTransaction) {}

    void invoke(QObject *ttm) const
    {
        QString strHash = QString::fromStdString(hash.GetHex());
        qDebug() << "NotifyTransactionChanged: " + strHash + " status= " + QString::number(status);
        QMetaObject::invokeMethod(ttm, "updateTransaction", Qt::QueuedConnection,
                                  Q_ARG(QString, strHash),
                                  Q_ARG(int, status),
                                  Q_ARG(bool, showTransaction));
    }
    uint256 hash;
    int status;
    bool showTransaction;
};

// Private implementation
class TransactionTablePriv
{
public:
    TransactionTablePriv(CWallet *_wallet, TransactionTableModel *_parent) :
        wallet(_wallet),
        parent(_parent)
    {
    }

    CWallet *wallet;
    TransactionTableModel *parent;

    /* Local cache of wallet.
     * As it is in the same order as the CWallet, by definition
     * this is sorted by sha256.
     */
    QList<TransactionRecord> cachedWallet;
    std::deque<TransactionNotification> cachedUpdatedTx;
    bool processingUpdates = false;
    const CBlockIndex* cachedTip = nullptr;

    /* Query entire wallet anew from core.
     */
    void refreshWallet()
    {
        qDebug() << "TransactionTablePriv::refreshWallet";
        cachedWallet.clear();
        {
            LOCK2(cs_main, wallet->cs_wallet);
            cachedTip = chainActive.Tip();
            for(std::map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
            {
                if(TransactionRecord::showTransaction(it->second))
                    cachedWallet.append(TransactionRecord::decomposeTransaction(wallet, it->second));
            }
        }
    }

    // Return false only when lock contention requires retrying this notification.
    bool updateWallet(const uint256& hash, int status, bool showTransaction)
    {
        qDebug() << "TransactionTablePriv::updateWallet:" << QString::fromStdString(hash.ToString()) << status;

        const auto [lower, upper] = std::equal_range(cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
        const int lowerIndex = lower - cachedWallet.begin();
        const int upperIndex = upper - cachedWallet.begin();
        const bool inModel = lower != upper;

        if (status == CT_UPDATED) {
            if (showTransaction && !inModel)
                status = CT_NEW;
            else if (!showTransaction && inModel)
                status = CT_DELETED;
        }

        if (status == CT_DELETED) {
            if (!inModel) {
                qWarning() << "TransactionTablePriv::updateWallet: Got CT_DELETED, but transaction is not in model";
                return true;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex - 1);
            cachedWallet.erase(lower, upper);
            parent->endRemoveRows();
            return true;
        }
        if (status == CT_NEW && inModel) {
            qWarning() << "TransactionTablePriv::updateWallet: Got CT_NEW, but transaction is already in model";
            return true;
        }
        if (!showTransaction || (status != CT_NEW && status != CT_UPDATED))
            return true;

        // Insertions and status updates use the same non-blocking lock order.
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain)
            return false;
        TRY_LOCK(wallet->cs_wallet, lockWallet);
        if (!lockWallet)
            return false;
        const auto mi = wallet->mapWallet.find(hash);
        if (mi == wallet->mapWallet.end()) {
            qWarning() << "TransactionTablePriv::updateWallet: Transaction is not in wallet";
            return true;
        }

        if (status == CT_NEW) {
            const auto toInsert = TransactionRecord::decomposeTransaction(wallet, mi->second);
            if (!toInsert.isEmpty()) {
                parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex + toInsert.size() - 1);
                int insertIndex = lowerIndex;
                for (const auto& rec : toInsert) {
                    cachedWallet.insert(insertIndex, rec);
                    ++insertIndex;
                }
                parent->endInsertRows();
            }
        } else {
            // Changes such as abandonment can occur without a new block.
            for (auto it = lower; it != upper; ++it)
                it->updateStatus(mi->second, parent->getNumISLocks(), parent->getChainLockHeight());
            Q_EMIT parent->dataChanged(parent->index(lowerIndex, TransactionTableModel::Status),
                                       parent->index(upperIndex - 1, TransactionTableModel::Amount));
        }
        return true;
    }

    int size()
    {
        return cachedWallet.size();
    }

    TransactionRecord *index(int idx)
    {
        if(idx >= 0 && idx < cachedWallet.size())
        {
            TransactionRecord *rec = &cachedWallet[idx];

            // Get required locks upfront. This avoids the GUI from getting
            // stuck if the core is holding the locks for a longer time - for
            // example, during a wallet rescan.
            //
            // If a status update is needed (blocks came in since last check),
            //  update the status of this transaction from the wallet. Otherwise,
            // simply re-use the cached status.
            TRY_LOCK(cs_main, lockMain);
            if(lockMain)
            {
                TRY_LOCK(wallet->cs_wallet, lockWallet);
                if(lockWallet && (rec->statusUpdateNeeded(parent->getNumISLocks(), parent->getChainLockHeight())))
                {
                    std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);

                    if(mi != wallet->mapWallet.end())
                    {
                        rec->updateStatus(mi->second, parent->getNumISLocks(), parent->getChainLockHeight());
                    }
                }
            }
            return rec;
        }
        return 0;
    }

    QString describe(TransactionRecord *rec, int unit)
    {
        {
            LOCK2(cs_main, wallet->cs_wallet);
            std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);
            if (mi != wallet->mapWallet.end())
            {
                return TransactionDesc::toHTML(wallet, mi->second, rec, unit);
            }
        }
        return QString();
    }

    QString getTxHex(TransactionRecord *rec)
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);
        if (mi != wallet->mapWallet.end())
        {
            std::string strHex = EncodeHexTx(static_cast<CTransaction>(mi->second));
            return QString::fromStdString(strHex);
        }
        return QString();
    }
};

TransactionTableModel::TransactionTableModel(const PlatformStyle *_platformStyle, CWallet* _wallet, WalletModel *parent):
        QAbstractTableModel(parent),
        wallet(_wallet),
        walletModel(parent),
        priv(new TransactionTablePriv(_wallet, this)),
        fProcessingQueuedTransactions(false),
        platformStyle(_platformStyle),
        confirmationTimer(new QTimer(this))
{
    columns << QString() << QString() << QString() << tr("Date") << tr("Type") << tr("Address / Label") << BitcoinUnits::getAmountColumnTitle(walletModel->getOptionsModel()->getDisplayUnit());
    priv->refreshWallet();

    connect(walletModel->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &TransactionTableModel::updateDisplayUnit);
    confirmationTimer->setSingleShot(true);
    confirmationTimer->setInterval(MODEL_UPDATE_DELAY);
    connect(confirmationTimer, &QTimer::timeout, this, &TransactionTableModel::updateConfirmations);
    
    subscribeToCoreSignals();
}

TransactionTableModel::~TransactionTableModel()
{
    unsubscribeFromCoreSignals();
    delete priv;
}

/** Updates the column title to "Amount (DisplayUnit)" and emits headerDataChanged() signal for table headers to react. */
void TransactionTableModel::updateAmountColumnTitle()
{
    columns[Amount] = BitcoinUnits::getAmountColumnTitle(walletModel->getOptionsModel()->getDisplayUnit());
    Q_EMIT headerDataChanged(Qt::Horizontal,Amount,Amount);
}

void TransactionTableModel::processCachedTransactions()
{
    if (priv->processingUpdates)
        return;
    // Model signals may synchronously enqueue more notifications.
    const QScopedValueRollback<bool> processing(priv->processingUpdates, true);
    while (!priv->cachedUpdatedTx.empty()) {
        const auto& update = priv->cachedUpdatedTx.front();
        // Keep arrival order: a later deletion must not overtake a deferred insertion.
        if (!priv->updateWallet(update.hash, update.status, update.showTransaction)) {
            confirmationTimer->start();
            return;
        }
        priv->cachedUpdatedTx.pop_front();
    }
}

void TransactionTableModel::updateTransaction(const QString &hash, int status, bool showTransaction)
{
    uint256 updated;
    updated.SetHex(hash.toStdString());
    priv->cachedUpdatedTx.emplace_back(updated, status, showTransaction);
    processCachedTransactions();
}

void TransactionTableModel::updateConfirmations()
{
    confirmationTimer->stop();
    {
        TRY_LOCK(cs_main, lockMain);
        TRY_LOCK(wallet->cs_wallet, lockWallet);
        if (!lockMain || !lockWallet) {
            confirmationTimer->start();
            return;
        }
        // A reorg can undo conflicts on transactions outside the disconnected block.
        // Invalidate cached statuses even when the replacement tip has the same height.
        if (priv->cachedTip && !chainActive.Contains(priv->cachedTip)) {
            for (auto& rec : priv->cachedWallet)
                rec.status.cur_num_blocks = -1;
            if (priv->size() > 0)
                Q_EMIT dataChanged(index(0, Status), index(priv->size() - 1, InstantSend));
        }
        priv->cachedTip = chainActive.Tip();
    }

    Q_EMIT confirmationsChanged();

    // Process any cached transactions that couldn't be processed due to lock contention
    // This ensures transactions are eventually added even if wallet updates are infrequent
    processCachedTransactions();
}

void TransactionTableModel::updateNumISLocks(int numISLocks)
{
    if (cachedNumISLocks == numISLocks)
        return;

    cachedNumISLocks = numISLocks;
}

void TransactionTableModel::updateChainLockHeight(int chainLockHeight)
{
    cachedChainLockHeight = chainLockHeight;
    updateConfirmations();
}

int TransactionTableModel::getNumISLocks() const
{
    return cachedNumISLocks;
}

int TransactionTableModel::getChainLockHeight() const
{
    return cachedChainLockHeight;
}

int TransactionTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int TransactionTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QString TransactionTableModel::formatTxStatus(const TransactionRecord *wtx) const
{
    QString status;

    switch(wtx->status.status)
    {
    case TransactionStatus::OpenUntilBlock:
        status = tr("Open for %n more block(s)","",wtx->status.open_for);
        break;
    case TransactionStatus::OpenUntilDate:
        status = tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx->status.open_for));
        break;
    case TransactionStatus::Offline:
        status = tr("Offline");
        break;
    case TransactionStatus::Unconfirmed:
        status = tr("Unconfirmed");
        break;
    case TransactionStatus::Abandoned:
        status = tr("Abandoned");
        break;
    case TransactionStatus::Confirming:
        status = tr("Confirming (%1 of %2 recommended confirmations)").arg(wtx->status.depth).arg(TransactionRecord::RecommendedNumConfirmations);
        break;
    case TransactionStatus::Confirmed:
        status = tr("Confirmed (%1 confirmations)").arg(wtx->status.depth);
        break;
    case TransactionStatus::Conflicted:
        status = tr("Conflicted");
        break;
    case TransactionStatus::Immature:
        status = tr("Immature (%1 confirmations, will be available after %2)").arg(wtx->status.depth).arg(wtx->status.depth + wtx->status.matures_in);
        break;
    case TransactionStatus::MaturesWarning:
        status = tr("This block was not received by any other nodes and will probably not be accepted!");
        break;
    case TransactionStatus::NotAccepted:
        status = tr("Generated but not accepted");
        break;
    }

    return status;
}

QString TransactionTableModel::formatTxDate(const TransactionRecord *wtx) const
{
    if(wtx->time)
    {
        return GUIUtil::dateTimeStr(wtx->time);
    }
    return QString();
}

namespace {
    QString getPcodeLabel(CWallet * wallet, std::string const & pcode)
    {
        QString result;
        boost::optional<bip47::CPaymentCodeDescription> pcodeDesc;
        try {
            pcodeDesc = wallet->FindPcode(bip47::CPaymentCode(pcode));
        } catch (std::runtime_error const &)
        {}
        result = QString::fromStdString(std::get<2>(*pcodeDesc));
        if(result.isEmpty())
            result = QString::fromStdString(pcode);
        return result;
    }
}

/* Look up address in address book, if found return label (address)
   otherwise just return (address)
 */
QString TransactionTableModel::lookupAddress(const TransactionRecord *wtx, bool tooltip) const
{
    QString label;
    if(!wtx->pcode.empty())
    {
        label = getPcodeLabel(wallet, wtx->pcode);
    }
    else
        label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(wtx->address));

    QString description;
    if(!label.isEmpty())
    {
        description += label;
    }
    if(label.isEmpty() || tooltip)
    {
        QString name = "";
        if (walletModel->GetSparkNameByAddress(QString::fromStdString(wtx->address), name))
        {
            description += QString(" @") + name;
        } else {
            description += QString(" (") + QString::fromStdString(wtx->address) + QString(")");
        }
    }
    return description;
}

QString TransactionTableModel::formatTxType(const TransactionRecord *wtx) const
{
    switch(wtx->type)
    {
    case TransactionRecord::RecvWithAddress:
        return tr("Received with");
    case TransactionRecord::RecvFromOther:
        return tr("Received from");
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SendToOther:
        return tr("Sent to");
    case TransactionRecord::SendToSelf:
        return tr("Payment to yourself");
    case TransactionRecord::Generated:
        return tr("Mined");
    case TransactionRecord::SpendToAddress:
            return tr("Spend to");
    case TransactionRecord::SpendToSelf:
           return tr("Spend to yourself");
    case TransactionRecord::Anonymize:
           return tr("Anonymize");
    case TransactionRecord::SendToPcode:
            return tr("Sent to RAP address");
    case TransactionRecord::RecvWithPcode:
            return tr("Received with RAP address");
    case TransactionRecord::MintSparkToSelf:
            return tr("Mint spark to yourself");
    case TransactionRecord::SpendSparkToSelf:
            return tr("Spend spark to yourself");
    case TransactionRecord::MintSparkTo:
            return tr("Mint spark to");
    case TransactionRecord::SpendSparkTo:
            return tr("Spend spark to");
    case TransactionRecord::RecvSpark:
        return tr("Received Spark");
    default:
        return QString();
    }
}

QVariant TransactionTableModel::txAddressDecoration(const TransactionRecord *wtx) const
{
    switch(wtx->type)
    {
    case TransactionRecord::Generated:
        return QIcon(":/icons/tx_mined");
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::RecvFromOther:
        return QIcon(":/icons/tx_input");
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SendToOther:
    case TransactionRecord::SpendToAddress:
    case TransactionRecord::Anonymize:
        return QIcon(":/icons/tx_output");
    case TransactionRecord::SendToPcode:
    case TransactionRecord::RecvWithPcode:
        return QIcon(":/icons/paymentcode");
    case TransactionRecord::MintSparkToSelf:
    case TransactionRecord::SpendSparkToSelf:
    case TransactionRecord::MintSparkTo:
    case TransactionRecord::SpendSparkTo:
    case TransactionRecord::RecvSpark:
        return QIcon(":/icons/spark");
    default:
        return QIcon(":/icons/tx_inout");
    }
}

QString TransactionTableModel::formatTxToAddress(const TransactionRecord *wtx, bool tooltip) const
{
    QString watchAddress;
    if (tooltip) {
        // Mark transactions involving watch-only addresses by adding " (watch-only)"
        watchAddress = wtx->involvesWatchAddress ? QString(" (") + tr("watch-only") + QString(")") : QString("");
    }

    switch(wtx->type)
    {
    case TransactionRecord::RecvFromOther:
        return QString::fromStdString(wtx->address) + watchAddress;
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::RecvWithPcode:
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SpendToAddress:
    case TransactionRecord::SendToPcode:
    case TransactionRecord::Generated:
    case TransactionRecord::RecvSpark:
    case TransactionRecord::MintSparkTo:
    case TransactionRecord::SpendSparkTo:
        return lookupAddress(wtx, tooltip) + watchAddress;
    case TransactionRecord::SendToOther:
        return QString::fromStdString(wtx->address) + watchAddress;
    case TransactionRecord::Anonymize:
    case TransactionRecord::MintSparkToSelf:
        return tr("Anonymized");
    case TransactionRecord::SendToSelf:
    case TransactionRecord::SpendToSelf:
    case TransactionRecord::SpendSparkToSelf:
    default:
        return tr("(n/a)") + watchAddress;
    }
}

QVariant TransactionTableModel::addressColor(const TransactionRecord *wtx) const
{
    // Show addresses without label in a less visible color
    switch(wtx->type)
    {
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SpendToAddress:
    case TransactionRecord::Generated:
        {
        QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(wtx->address));
        if(label.isEmpty())
            return COLOR_BAREADDRESS;
        } break;
    case TransactionRecord::SendToSelf:
    case TransactionRecord::SpendToSelf:
    case TransactionRecord::Anonymize:
        return COLOR_BAREADDRESS;
    default:
        break;
    }
    return QVariant();
}

QString TransactionTableModel::formatTxAmount(const TransactionRecord *wtx, bool showUnconfirmed, BitcoinUnits::SeparatorStyle separators) const
{
    QString str = BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), wtx->credit + wtx->debit, false, separators);
    if(showUnconfirmed)
    {
        if(!wtx->status.countsForBalance)
        {
            str = QString("[") + str + QString("]");
        }
    }
    return QString(str);
}

QVariant TransactionTableModel::txStatusDecoration(const TransactionRecord *wtx) const
{
    switch(wtx->status.status)
    {
    case TransactionStatus::OpenUntilBlock:
    case TransactionStatus::OpenUntilDate:
        return COLOR_TX_STATUS_OPENUNTILDATE;
    case TransactionStatus::Offline:
        return COLOR_TX_STATUS_OFFLINE;
    case TransactionStatus::Unconfirmed:
        return QIcon(":/icons/transaction_0");
    case TransactionStatus::Abandoned:
        return QIcon(":/icons/transaction_abandoned");
    case TransactionStatus::Confirming:
        switch(wtx->status.depth)
        {
        case 1: return QIcon(":/icons/transaction_1");
        case 2: return QIcon(":/icons/transaction_2");
        case 3: return QIcon(":/icons/transaction_3");
        case 4: return QIcon(":/icons/transaction_4");
        default: return QIcon(":/icons/transaction_5");
        };
    case TransactionStatus::Confirmed:
        return QIcon(":/icons/transaction_confirmed");
    case TransactionStatus::Conflicted:
        return QIcon(":/icons/transaction_conflicted");
    case TransactionStatus::Immature: {
        int total = wtx->status.depth + wtx->status.matures_in;
        int part = (wtx->status.depth * 4 / total) + 1;
        return QIcon(QString(":/icons/transaction_%1").arg(part));
        }
    case TransactionStatus::MaturesWarning:
    case TransactionStatus::NotAccepted:
        return QIcon(":/icons/transaction_0");
    default:
        return COLOR_BLACK;
    }
}

QVariant TransactionTableModel::txWatchonlyDecoration(const TransactionRecord *wtx) const
{
    if (wtx->involvesWatchAddress)
        return QIcon(":/icons/eye");
    else
        return QVariant();
}

QVariant TransactionTableModel::txInstantSendDecoration(const TransactionRecord *wtx) const
{
    if (wtx->status.lockedByInstantSend) {
        return QIcon(":/icons/verify");
    }
    return QVariant();
}

QString TransactionTableModel::formatTooltip(const TransactionRecord *rec) const
{
    QString tooltip = formatTxStatus(rec) + QString("\n") + formatTxType(rec);
    if(rec->type==TransactionRecord::RecvFromOther || rec->type==TransactionRecord::RecvWithAddress ||
       rec->type==TransactionRecord::SendToAddress || rec->type==TransactionRecord::SpendToSelf ||
        rec->type==TransactionRecord::SpendToAddress || rec->type==TransactionRecord::SendToOther)
    {
        tooltip += QString(" ") + formatTxToAddress(rec, true);
    }
    if (rec->involvesWatchAddress)
        tooltip += QString("\n") + tr("Involves a watch-only address.");
    if (rec->status.lockedByInstantSend)
        tooltip += QString("\n") + tr("Locked by InstantSend.");
    return tooltip;
}

QVariant TransactionTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();
    TransactionRecord *rec = static_cast<TransactionRecord*>(index.internalPointer());

    switch(role)
    {
    case RawDecorationRole:
        switch(index.column())
        {
        case Status:
            return txStatusDecoration(rec);
        case Watchonly:
            return txWatchonlyDecoration(rec);
        case InstantSend:
            return txInstantSendDecoration(rec);
        case ToAddress:
            return txAddressDecoration(rec);
        }
        break;
    case Qt::DecorationRole:
    {
        QIcon icon = qvariant_cast<QIcon>(index.data(RawDecorationRole));
        return platformStyle->TextColorIcon(icon);
    }
    case Qt::DisplayRole:
        switch(index.column())
        {
        case Date:
            return formatTxDate(rec);
        case Type:
            return formatTxType(rec);
        case ToAddress:
            return formatTxToAddress(rec, false);
        case Amount:
            return formatTxAmount(rec, true, BitcoinUnits::separatorAlways);
        }
        break;
    case Qt::EditRole:
        // Edit role is used for sorting, so return the unformatted values
        switch(index.column())
        {
        case Status:
            return QString::fromStdString(rec->status.sortKey);
        case Date:
            return rec->time;
        case Type:
            return formatTxType(rec);
        case Watchonly:
            return (rec->involvesWatchAddress ? 1 : 0);
        case InstantSend:
            return (rec->status.lockedByInstantSend ? 1 : 0);
        case ToAddress:
            return formatTxToAddress(rec, true);
        case Amount:
            return qint64(rec->credit + rec->debit);
        }
        break;
    case Qt::ToolTipRole:
        return formatTooltip(rec);
    case Qt::TextAlignmentRole:
        return column_alignments[index.column()];
    case Qt::ForegroundRole:
        // Use the "danger" color for abandoned transactions
        if(rec->status.status == TransactionStatus::Abandoned)
        {
            return COLOR_TX_STATUS_DANGER;
        }
        if(rec->status.lockedByInstantSend)
        {
            return COLOR_TX_STATUS_LOCKED;
        }
        // Non-confirmed (but not immature) as transactions are grey
        if(!rec->status.countsForBalance && rec->status.status != TransactionStatus::Immature)
        {
            return COLOR_UNCONFIRMED;
        }
        if(index.column() == Amount && (rec->credit+rec->debit) < 0)
        {
            return COLOR_NEGATIVE;
        }
        if(index.column() == ToAddress)
        {
            return addressColor(rec);
        }
        break;
    case TypeRole:
        return rec->type;
    case DateRole:
        return QDateTime::fromSecsSinceEpoch(static_cast<uint>(rec->time));
    case WatchonlyRole:
        return rec->involvesWatchAddress;
    case WatchonlyDecorationRole:
        return txWatchonlyDecoration(rec);
    case InstantSendRole:
        return rec->status.lockedByInstantSend;
    case InstantSendDecorationRole:
        return txInstantSendDecoration(rec);
    case LongDescriptionRole:
        return priv->describe(rec, walletModel->getOptionsModel()->getDisplayUnit());
    case AddressRole:
        return QString::fromStdString(rec->address);
    case LabelRole:
        if(rec->pcode.empty())
            return walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->address));
        else
            return getPcodeLabel(wallet, rec->pcode);
    case AmountRole:
        return qint64(rec->credit + rec->debit);
    case TxIDRole:
        return rec->getTxID();
    case TxHashRole:
        return QString::fromStdString(rec->hash.ToString());
    case TxHexRole:
        return priv->getTxHex(rec);
    case TxPlainTextRole:
        {
            QString details;
            QDateTime date = QDateTime::fromSecsSinceEpoch(static_cast<uint>(rec->time));
            QString txLabel = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->address));

            details.append(date.toString("M/d/yy HH:mm"));
            details.append(" ");
            details.append(formatTxStatus(rec));
            details.append(". ");
            if(!formatTxType(rec).isEmpty()) {
                details.append(formatTxType(rec));
                details.append(" ");
            }
            if(!rec->address.empty()) {
                if(txLabel.isEmpty())
                    details.append(tr("(no label)") + " ");
                else {
                    details.append("(");
                    details.append(txLabel);
                    details.append(") ");
                }
                details.append(QString::fromStdString(rec->address));
                details.append(" ");
            }
            details.append(formatTxAmount(rec, false, BitcoinUnits::separatorNever));
            return details;
        }
    case ConfirmedRole:
        return rec->status.countsForBalance;
    case FormattedAmountRole:
        // Used for copy/export, so don't include separators
        return formatTxAmount(rec, false, BitcoinUnits::separatorNever);
    case StatusRole:
        return rec->status.status;
    case PcodeRole:
        return rec->pcode.c_str();
    }
    return QVariant();
}

QVariant TransactionTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return column_alignments[section];
        } else if (role == Qt::ToolTipRole)
        {
            switch(section)
            {
            case Status:
                return tr("Transaction status. Hover over this field to show number of confirmations.");
            case Date:
                return tr("Date and time that the transaction was received.");
            case Type:
                return tr("Type of transaction.");
            case Watchonly:
                return tr("Whether or not a watch-only address is involved in this transaction.");
            case InstantSend:
                return tr("Whether or not this transaction was locked by InstantSend.");
            case ToAddress:
                return tr("User-defined intent/purpose of the transaction.");
            case Amount:
                return tr("Amount removed from or added to balance.");
            }
        }
    }
    return QVariant();
}

QModelIndex TransactionTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    TransactionRecord *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, data);
    }
    return QModelIndex();
}

void TransactionTableModel::updateDisplayUnit()
{
    // emit dataChanged to update Amount column with the current unit
    updateAmountColumnTitle();
    Q_EMIT dataChanged(index(0, Amount), index(priv->size()-1, Amount));
}

static bool fQueueNotifications = false;
static std::vector< TransactionNotification > vQueueNotifications;

static void NotifyTransactionChanged(TransactionTableModel *ttm, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    // Find transaction in wallet
    std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(hash);
    // Determine whether to show transaction or not (determine this here so that no relocking is needed in GUI thread)
    bool inWallet = mi != wallet->mapWallet.end();
    bool showTransaction = (inWallet && TransactionRecord::showTransaction(mi->second));

    TransactionNotification notification(hash, status, showTransaction);

    if (fQueueNotifications)
    {
        vQueueNotifications.push_back(notification);
        return;
    }
    notification.invoke(ttm);
}

static void ShowProgress(TransactionTableModel *ttm, const std::string &title, int nProgress)
{
    if (nProgress == 0)
        fQueueNotifications = true;

    if (nProgress == 100)
    {
        fQueueNotifications = false;
        if (vQueueNotifications.size() > 10) // prevent balloon spam, show maximum 10 balloons
            QMetaObject::invokeMethod(ttm, "setProcessingQueuedTransactions", Qt::QueuedConnection, Q_ARG(bool, true));
        for (unsigned int i = 0; i < vQueueNotifications.size(); ++i)
        {
            if (vQueueNotifications.size() - i <= 10)
                QMetaObject::invokeMethod(ttm, "setProcessingQueuedTransactions", Qt::QueuedConnection, Q_ARG(bool, false));

            vQueueNotifications[i].invoke(ttm);
        }
        std::vector<TransactionNotification >().swap(vQueueNotifications); // clear
    }
}

void TransactionTableModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
}

void TransactionTableModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
}
