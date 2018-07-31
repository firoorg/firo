// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"

#include "omnicore/activation.h"
#include "omnicore/notifications.h"
#include "omnicore/omnicore.h"
#include "omnicore/rules.h"
#include "omnicore/sp.h"
#include "omnicore/tx.h"
#include "omnicore/pending.h"
#include "omnicore/utilsbitcoin.h"
#include "omnicore/wallettxs.h"

#include "main.h"
#include "sync.h"

#include <sstream>
#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#ifdef WIN32
#include <string.h>
#endif

#include "util.h"
#include "compat.h"

#include <QAbstractItemDelegate>
#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QListWidgetItem>
#include <QPainter>
#include <QRect>
#include <QString>
#include <QStyleOptionViewItem>
#include <QVariant>
#include <QVBoxLayout>
#include <QWidget>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5


using std::ostringstream;
using std::string;

using namespace exodus;

#define DECORATION_SIZE 64
#define NUM_ITEMS 6

struct OverviewCacheEntry
{
    OverviewCacheEntry()
      : address("unknown"), amount("0.0000000"), valid(false), sendToSelf(false), outbound(false)
    {}

    OverviewCacheEntry(const QString& addressIn, const QString& amountIn, bool validIn, bool sendToSelfIn, bool outboundIn)
      : address(addressIn), amount(amountIn), valid(validIn), sendToSelf(sendToSelfIn), outbound(outboundIn)
    {}

    QString address;
    QString amount;
    bool valid;
    bool sendToSelf;
    bool outbound;
};

std::map<uint256, OverviewCacheEntry> recentCache;

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(const PlatformStyle *platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcoinUnits::BTC),
        platformStyle(platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);

        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);

        // Rather ugly way to provide recent transaction display support - each time we paint a transaction we will check if
		// it's Exodus and override the values if so.  This will not scale at all, but since we're only ever doing 6 txns via the occasional
		// repaint performance should be a non-issue and it'll provide the functionality short term while a better approach is devised.
		uint256 hash;
		hash.SetHex(index.data(TransactionTableModel::TxIDRole).toString().toStdString());
		bool exodusOverride = false, exodusSendToSelf = false, valid = false, exodusOutbound = true;
		QString exodusAmountStr;

		// check pending
		{
			LOCK(cs_pending);

			PendingMap::iterator it = my_pending.find(hash);
			if (it != my_pending.end()) {
				exodusOverride = true;
				valid = true; // assume all outbound pending are valid prior to confirmation
				CMPPending *p_pending = &(it->second);
				address = QString::fromStdString(p_pending->src);
				if (isPropertyDivisible(p_pending->prop)) {
					exodusAmountStr = QString::fromStdString(FormatDivisibleShortMP(p_pending->amount) + getTokenLabel(p_pending->prop));
				} else {
					exodusAmountStr = QString::fromStdString(FormatIndivisibleMP(p_pending->amount) + getTokenLabel(p_pending->prop));
				}
				// override amount for cancels
				if (p_pending->type == EXODUS_TYPE_METADEX_CANCEL_PRICE || p_pending->type == EXODUS_TYPE_METADEX_CANCEL_PAIR ||
					p_pending->type == EXODUS_TYPE_METADEX_CANCEL_ECOSYSTEM || p_pending->type == EXODUS_TYPE_SEND_ALL) {
					exodusAmountStr = QString::fromStdString("N/A");
				}
			}
		}

		// check cache (avoid reparsing the same transactions repeatedly over and over on repaint)
		std::map<uint256, OverviewCacheEntry>::iterator cacheIt = recentCache.find(hash);
		if (cacheIt != recentCache.end()) {
			OverviewCacheEntry txEntry = cacheIt->second;
			address = txEntry.address;
			valid = txEntry.valid;
			exodusSendToSelf = txEntry.sendToSelf;
			exodusOutbound = txEntry.outbound;
			exodusAmountStr = txEntry.amount;
			exodusOverride = true;
			amount = 0;
		} else { // cache miss, check database
			if (p_txlistdb->exists(hash)) {
				exodusOverride = true;
				amount = 0;
				CTransaction wtx;
				uint256 blockHash;
				if (GetTransaction(hash, wtx, Params().GetConsensus(), blockHash, true)) {
					if (!blockHash.IsNull() || NULL == GetBlockIndex(blockHash)) {
						CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
						if (NULL != pBlockIndex) {
							int blockHeight = pBlockIndex->nHeight;
							CMPTransaction mp_obj;
							int parseRC = ParseTransaction(wtx, blockHeight, 0, mp_obj);
							if (0 < parseRC) { //positive RC means DEx payment
								std::string tmpBuyer, tmpSeller;
								uint64_t total = 0, tmpVout = 0, tmpNValue = 0, tmpPropertyId = 0;
								{
									LOCK(cs_tally);
									p_txlistdb->getPurchaseDetails(hash,1,&tmpBuyer,&tmpSeller,&tmpVout,&tmpPropertyId,&tmpNValue);
								}
								bool bIsBuy = IsMyAddress(tmpBuyer);
								LOCK(cs_tally);
								int numberOfPurchases=p_txlistdb->getNumberOfSubRecords(hash);
								if (0<numberOfPurchases) { // calculate total bought/sold
									for(int purchaseNumber = 1; purchaseNumber <= numberOfPurchases; purchaseNumber++) {
										p_txlistdb->getPurchaseDetails(hash,purchaseNumber,&tmpBuyer,&tmpSeller,&tmpVout,&tmpPropertyId,&tmpNValue);
										total += tmpNValue;
									}
									if (!bIsBuy) {
										  address = QString::fromStdString(tmpSeller);
									} else {
										  address = QString::fromStdString(tmpBuyer);
										  exodusOutbound = false;
									}
									exodusAmountStr = QString::fromStdString(FormatDivisibleMP(total));
								}
							} else if (0 == parseRC) {
								if (mp_obj.interpret_Transaction()) {
									valid = getValidMPTX(hash);
									uint32_t exodusPropertyId = mp_obj.getProperty();
									int64_t exodusAmount = mp_obj.getAmount();
									if (isPropertyDivisible(omniPropertyId)) {
										exodusAmountStr = QString::fromStdString(FormatDivisibleShortMP(exodusAmount) + getTokenLabel(exodusPropertyId));
									} else {
										exodusAmountStr = QString::fromStdString(FormatIndivisibleMP(exodusAmount) + getTokenLabel(exodusPropertyId));
									}
									if (!mp_obj.getReceiver().empty()) {
										if (IsMyAddress(mp_obj.getReceiver())) {
											exodusOutbound = false;
											if (IsMyAddress(mp_obj.getSender())) exodusSendToSelf = true;
										}
										address = QString::fromStdString(mp_obj.getReceiver());
									} else {
										address = QString::fromStdString(mp_obj.getSender());
									}
								}
							}

							// override amount for cancels
							if (mp_obj.getType() == EXODUS_TYPE_METADEX_CANCEL_PRICE || mp_obj.getType() == EXODUS_TYPE_METADEX_CANCEL_PAIR ||
								mp_obj.getType() == EXODUS_TYPE_METADEX_CANCEL_ECOSYSTEM || mp_obj.getType() == EXODUS_TYPE_SEND_ALL) {
								omniAmountStr = QString::fromStdString("N/A");
							}

							// insert into cache
							OverviewCacheEntry newEntry;
							newEntry.valid = valid;
							newEntry.sendToSelf = exodusSendToSelf;
							newEntry.outbound = exodusOutbound;
							newEntry.address = address;
							newEntry.amount = exodusAmountStr;
							recentCache.insert(std::make_pair(hash, newEntry));
						}
					}
				}
			}
		}

		if (exodusOverride) {
			if (!valid) {
				icon = QIcon(":/icons/exodus_invalid");
			} else {
				icon = QIcon(":/icons/exodus_out");
				if (!exodusOutbound) icon = QIcon(":/icons/exodus_in");
				if (exodusSendToSelf) icon = QIcon(":/icons/exodus_inout");
			}
		}


        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top()+ypad+halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText;
        if (!exodusOverride) {
            amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        } else {
            amountText = exodusAmountStr;
        }

        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    currentWatchOnlyBalance(-1),
    currentWatchUnconfBalance(-1),
    currentWatchImmatureBalance(-1),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    // read config
    boost::filesystem::path pathTorSetting = GetDataDir()/"torsetting.dat";
    std::pair<bool,std::string> torEnabled = ReadBinaryFileTor(pathTorSetting.string().c_str());
    if(torEnabled.first){
		if(torEnabled.second == "1"){
			ui->checkboxEnabledTor->setChecked(true);
		}else{
			ui->checkboxEnabledTor->setChecked(false);
		}
    }

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = platformStyle->SingleColorIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    connect(ui->checkboxEnabledTor, SIGNAL(toggled(bool)), this, SLOT(handleEnabledTorChanged()));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("out of sync") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("out of sync") + ")");

    // make sure BTC is always first in the list by adding it first
    UpdatePropertyBalance(0,0,0);

    updateExodus();

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    // is this an Exodus transaction that has been clicked?  Use pending & cache to find out quickly
    uint256 hash;
    hash.SetHex(index.data(TransactionTableModel::TxIDRole).toString().toStdString());
    bool exodusTx = false;
    {
        LOCK(cs_pending);

        PendingMap::iterator it = my_pending.find(hash);
        if (it != my_pending.end()) omniTx = true;
    }
    std::map<uint256, OverviewCacheEntry>::iterator cacheIt = recentCache.find(hash);
    if (cacheIt != recentCache.end()) omniTx = true;

    // override if it's an Exodus transaction
    if (exodusTx) {
        // TODO emit exodusTransactionClicked(hash);
    } else {
        // TODO if (filter) emit transactionClicked(filter->mapToSource(index));
    }
}

void OverviewPage::handleEnabledTorChanged(){

	QMessageBox msgBox;
	boost::filesystem::path pathTorSetting = GetDataDir()/"torsetting.dat";

	if(ui->checkboxEnabledTor->isChecked()){
		if (WriteBinaryFileTor(pathTorSetting.string().c_str(), "1")) {
			msgBox.setText("Please restart the Zcoin wallet to route your connection to TOR to protect your IP address. \nSyncing your wallet might be slower with TOR.");
		} else {
			msgBox.setText("Anonymous communication cannot enable");
		}
	}else{
		if (WriteBinaryFileTor(pathTorSetting.string().c_str(), "0")) {
			msgBox.setText("Please restart the Zcoin wallet to disable route your connection to TOR to protect your IP address.");
		} else {
			msgBox.setText("Anonymous communication cannot disable");
		}
	}
	msgBox.exec();
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::UpdatePropertyBalance(unsigned int propertyId, uint64_t available, uint64_t reserved)
{
    // look for this property, does it already exist in overview and if so are the balances correct?
    int existingItem = -1;
    for(int i=0; i < ui->overviewLW->count(); i++) {
        uint64_t itemPropertyId = ui->overviewLW->item(i)->data(Qt::UserRole + 1).value<uint64_t>();
        if (itemPropertyId == propertyId) {
            uint64_t itemAvailableBalance = ui->overviewLW->item(i)->data(Qt::UserRole + 2).value<uint64_t>();
            uint64_t itemReservedBalance = ui->overviewLW->item(i)->data(Qt::UserRole + 3).value<uint64_t>();
            if ((available == itemAvailableBalance) && (reserved == itemReservedBalance)) {
                return; // norhing more to do, balance exists and is up to date
            } else {
                existingItem = i;
                break;
            }
        }
    }

    // this property doesn't exist in overview, create an entry for it
    QWidget *listItem = new QWidget();
    QVBoxLayout *vlayout = new QVBoxLayout();
    QHBoxLayout *hlayout = new QHBoxLayout();
    bool divisible = false;
    string tokenStr;
    // property label
    string spName = getPropertyName(propertyId).c_str();
    if(spName.size()>22) spName=spName.substr(0,22)+"...";
    spName += strprintf(" (#%d)", propertyId);
    QLabel *propLabel = new QLabel(QString::fromStdString(spName));
    propLabel->setStyleSheet("QLabel { font-weight:bold; }");
    vlayout->addWidget(propLabel);

    if (propertyId == 0) { // override for bitcoin
        divisible = true;
        tokenStr = " BTC";
    } else {
        divisible = isPropertyDivisible(propertyId);
        tokenStr = getTokenLabel(propertyId);
    }

    // Left Panel
    QVBoxLayout *vlayoutleft = new QVBoxLayout();
    QLabel *balReservedLabel = new QLabel;
    if(propertyId != 0) { balReservedLabel->setText("Reserved:"); } else { balReservedLabel->setText("Pending:"); propLabel->setText("Bitcoin"); } // override for bitcoin
    QLabel *balAvailableLabel = new QLabel("Available:");
    QLabel *balTotalLabel = new QLabel("Total:");
    vlayoutleft->addWidget(balReservedLabel);
    vlayoutleft->addWidget(balAvailableLabel);
    vlayoutleft->addWidget(balTotalLabel);
    // Right panel
    QVBoxLayout *vlayoutright = new QVBoxLayout();
    QLabel *balReservedLabelAmount = new QLabel();
    QLabel *balAvailableLabelAmount = new QLabel();
    QLabel *balTotalLabelAmount = new QLabel();
    if(divisible) {
        balReservedLabelAmount->setText(QString::fromStdString(FormatDivisibleMP(reserved) + tokenStr));
        balAvailableLabelAmount->setText(QString::fromStdString(FormatDivisibleMP(available) + tokenStr));
        balTotalLabelAmount->setText(QString::fromStdString(FormatDivisibleMP(available+reserved) + tokenStr));
    } else {
        balReservedLabelAmount->setText(QString::fromStdString(FormatIndivisibleMP(reserved) + tokenStr));
        balAvailableLabelAmount->setText(QString::fromStdString(FormatIndivisibleMP(available) + tokenStr));
        balTotalLabelAmount->setText(QString::fromStdString(FormatIndivisibleMP(available+reserved) + tokenStr));
    }
    balReservedLabelAmount->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    balAvailableLabelAmount->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    balTotalLabelAmount->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
    balReservedLabel->setStyleSheet("QLabel { font-size:12px; }");
    balAvailableLabel->setStyleSheet("QLabel { font-size:12px; }");
    balReservedLabelAmount->setStyleSheet("QLabel { font-size:12px;padding-right:2px; }");
    balAvailableLabelAmount->setStyleSheet("QLabel { font-size:12px;padding-right:2px; }");
    balTotalLabelAmount->setStyleSheet("QLabel { padding-right:2px; font-weight:bold; }");
    vlayoutright->addWidget(balReservedLabelAmount);
    vlayoutright->addWidget(balAvailableLabelAmount);
    vlayoutright->addWidget(balTotalLabelAmount);
    // put together
    vlayoutleft->addSpacerItem(new QSpacerItem(1,1,QSizePolicy::Fixed,QSizePolicy::Expanding));
    vlayoutright->addSpacerItem(new QSpacerItem(1,1,QSizePolicy::Fixed,QSizePolicy::Expanding));
    vlayoutleft->setContentsMargins(0,0,0,0);
    vlayoutright->setContentsMargins(0,0,0,0);
    vlayoutleft->setMargin(0);
    vlayoutright->setMargin(0);
    vlayoutleft->setSpacing(3);
    vlayoutright->setSpacing(3);
    hlayout->addLayout(vlayoutleft);
    hlayout->addSpacerItem(new QSpacerItem(1,1,QSizePolicy::Expanding,QSizePolicy::Fixed));
    hlayout->addLayout(vlayoutright);
    hlayout->setContentsMargins(0,0,0,0);
    vlayout->addLayout(hlayout);
    vlayout->addSpacerItem(new QSpacerItem(1,10,QSizePolicy::Fixed,QSizePolicy::Fixed));
    vlayout->setMargin(0);
    vlayout->setSpacing(3);
    listItem->setLayout(vlayout);
    listItem->setContentsMargins(0,0,0,0);
    listItem->layout()->setContentsMargins(0,0,0,0);
    // set data
    if(existingItem == -1) { // new
        QListWidgetItem *item = new QListWidgetItem();
        item->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(propertyId));
        item->setData(Qt::UserRole + 2, QVariant::fromValue<qulonglong>(available));
        item->setData(Qt::UserRole + 3, QVariant::fromValue<qulonglong>(reserved));
        item->setSizeHint(QSize(0,listItem->sizeHint().height())); // resize
        // add the entry
        ui->overviewLW->addItem(item);
        ui->overviewLW->setItemWidget(item, listItem);
    } else {
        ui->overviewLW->item(existingItem)->setData(Qt::UserRole + 2, QVariant::fromValue<qulonglong>(available));
        ui->overviewLW->item(existingItem)->setData(Qt::UserRole + 3, QVariant::fromValue<qulonglong>(reserved));
        ui->overviewLW->setItemWidget(ui->overviewLW->item(existingItem), listItem);
    }
}

void OverviewPage::reinitExodus()
{
    recentCache.clear();
    ui->overviewLW->clear();
    if (walletModel != NULL) {
        UpdatePropertyBalance(0, walletModel->getBalance(), walletModel->getUnconfirmedBalance());
    }
    UpdatePropertyBalance(1, 0, 0);
    updateExodus();
}

/** Loop through properties and update the overview - only properties with token balances will be displayed **/
void OverviewPage::updateExodus()
{
    LOCK(cs_tally);

    unsigned int propertyId;
    unsigned int maxPropIdMainEco = GetNextPropertyId(true);
    unsigned int maxPropIdTestEco = GetNextPropertyId(false);

    // main eco
    for (propertyId = 1; propertyId < maxPropIdMainEco; propertyId++) {
        if ((global_balance_money[propertyId] > 0) || (global_balance_reserved[propertyId] > 0)) {
            UpdatePropertyBalance(propertyId,global_balance_money[propertyId],global_balance_reserved[propertyId]);
        }
    }
    // test eco
    for (propertyId = 2147483647; propertyId < maxPropIdTestEco; propertyId++) {
        if ((global_balance_money[propertyId] > 0) || (global_balance_reserved[propertyId] > 0)) {
            UpdatePropertyBalance(propertyId,global_balance_money[propertyId],global_balance_reserved[propertyId]);
        }
    }
}

void OverviewPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance, const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, balance + unconfirmedBalance + immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance + watchUnconfBalance + watchImmatureBalance, false, BitcoinUnits::separatorAlways));

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance

    UpdatePropertyBalance(0,balance,unconfirmedBalance);
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());

        // Refresh Exodus info if there have been Exodus transactions with balances affecting wallet
        connect(model, SIGNAL(refreshExodusBalance()), this, SLOT(updateExodus()));

        // Reinit Exodus info if there has been a chain reorg
        connect(model, SIGNAL(reinitExodusState()), this, SLOT(reinitExodus()));

        // Refresh alerts when there has been a change to the Exodus State
        connect(model, SIGNAL(refreshExodusState()), this, SLOT(updateAlerts()));
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getImmatureBalance(),
                   model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)), this, SLOT(setBalance(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance,
                       currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);

    // get alert messages
    std::vector<std::string> exodusAlerts = GetExodusAlertMessages();
    for (std::vector<std::string>::iterator it = exodusAlerts.begin(); it != exodusAlerts.end(); it++) {
        if (!alertString.isEmpty()) alertString += "\n";
        alertString += QString::fromStdString(*it);
    }

    // get activations
    std::vector<FeatureActivation> vecPendingActivations = GetPendingActivations();
    for (std::vector<FeatureActivation>::iterator it = vecPendingActivations.begin(); it != vecPendingActivations.end(); ++it) {
        if (!alertString.isEmpty()) alertString += "\n";
        FeatureActivation pendingAct = *it;
        alertString += QString::fromStdString(strprintf("Feature %d ('%s') will go live at block %d",
                                                  pendingAct.featureId, pendingAct.featureName, pendingAct.activationBlock));
    }
    int currentHeight = GetHeight();
    std::vector<FeatureActivation> vecCompletedActivations = GetCompletedActivations();
    for (std::vector<FeatureActivation>::iterator it = vecCompletedActivations.begin(); it != vecCompletedActivations.end(); ++it) {
        if (currentHeight > (*it).activationBlock+1024) continue; // don't include after live+1024 blocks
        if (!alertString.isEmpty()) alertString += "\n";
        FeatureActivation completedAct = *it;
        alertString += QString::fromStdString(strprintf("Feature %d ('%s') is now live.", completedAct.featureId, completedAct.featureName));
    }

    if (!alertString.isEmpty()) {
        this->ui->labelAlerts->setVisible(true);
        this->ui->labelAlerts->setText(alertString);
    } else {
        this->ui->labelAlerts->setVisible(false);
        this->ui->labelAlerts->setText("");
    }

}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}
