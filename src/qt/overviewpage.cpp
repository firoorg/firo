// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../lelantus.h"
#include "../wallet/wallet.h"

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "sparkmodel.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "transactionrecord.h"
#include "walletmodel.h"
#include "validation.h"
#include "askpassphrasedialog.h"
#include "spatsburndialog.h"
#include "spatsuserconfirmationdialog.h"

#ifdef WIN32
#include <string.h>
#endif

#include "util.h"
#include "compat.h"

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QMenu>
#include <QGraphicsDropShadowEffect>
#include <QHeaderView>
#include <QButtonGroup>

#include "../spark/state.h"

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

namespace {

enum SparkAssetColumns {
   ColumnAssetType = 0,
   ColumnIdentifier,
   ColumnName,
   ColumnSymbol,
   ColumnAvailableBalance,
   ColumnPendingBalance,
   ColumnFungible,
   ColumnMetadata,
   ColumnDescription,
   ColumnCount
};

}

static quint32 MakeTypeMask(std::initializer_list<TransactionRecord::Type> types)
{
    quint32 mask = 0;
    for (auto t : types) {
        mask |= TransactionFilterProxy::TYPE(static_cast<int>(t));
    }
    return mask;
}

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcoinUnits::BTC),
        platformStyle(_platformStyle)
    {
    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const override
    {
        painter->save();
        if (option.state & QStyle::State_Selected) {
            painter->fillRect(option.rect, QColor("#FFFFFF"));
        } else {
            painter->fillRect(option.rect, QColor("#FFFFFF"));
        }

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect.adjusted(6, 6, -6, -6);
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 10;
        int ypad = 4;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
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
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE + 12);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include "overviewpage.moc"

auto &getSpatsManager()
{
    return spark::CSparkState::GetState()->GetSpatsManager();
}

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

    auto fixCapsule = [](QFrame* f){
        f->setFixedHeight(28);
        f->setContentsMargins(8, 0, 8, 0);
    };
    fixCapsule(ui->framePrivateAvailable);
    fixCapsule(ui->framePrivatePending);
    fixCapsule(ui->frameTransparentAvailable);
    fixCapsule(ui->frameTransparentPending);
    fixCapsule(ui->frameTransparentImmature);

    ui->labelPrimaryText->setStyleSheet(R"( QLabel { background: transparent; color:rgb(70, 75, 84); font-size: 18pt; font-weight: 700; } )");
    ui->sparkCard->setMaximumHeight(510);
    ui->activityCard->setMaximumHeight(510);
    ui->sparkCard->setStyleSheet(R"(
        QFrame#sparkCard {
            background: #FFFFFF;
            border-radius: 15px;
            border: 1px solidrgb(151, 149, 149);
            padding: 8px;
        }
    )");

    ui->activityCard->setStyleSheet(R"(
        QFrame#activityCard {
            background: #FFFFFF;
            border-radius: 15px;
            border: 1px solidrgb(151, 149, 149);
            padding: 8px;
        }
    )");

    ui->balancesCard->setStyleSheet(R"( QFrame#balancesCard { background: #FFFFFF; border-radius: 15px; border: 1px solidrgb(151, 149, 149); padding: 8px; } )");

    auto *filterGroup = new QButtonGroup(this);
    filterGroup->addButton(ui->btnFilterAll);
    filterGroup->addButton(ui->btnFilterFIRO);
    filterGroup->addButton(ui->btnFilterAssets);
    filterGroup->setExclusive(true);
    ui->btnFilterAll->setChecked(true);

    connect(filterGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), this, [this](QAbstractButton *button){
        if (!filter) { return; }
        if (button == ui->btnFilterAll) {
            filter->setTypeFilter(TransactionFilterProxy::ALL_TYPES);
        } else if (button == ui->btnFilterFIRO) {
            quint32 mask = MakeTypeMask({ TransactionRecord::Other,
                                          TransactionRecord::Generated,
                                          TransactionRecord::SendToAddress,
                                          TransactionRecord::SendToOther,
                                          TransactionRecord::RecvWithAddress,
                                          TransactionRecord::RecvFromOther,
                                          TransactionRecord::SendToSelf,
                                          TransactionRecord::SpendToAddress,
                                          TransactionRecord::SpendToSelf,
                                          TransactionRecord::Anonymize,
                                          TransactionRecord::SendToPcode,
                                          TransactionRecord::RecvWithPcode,
                                          TransactionRecord::MintSparkToSelf,
                                          TransactionRecord::SpendSparkToSelf,
                                          TransactionRecord::MintSparkTo,
                                          TransactionRecord::SpendSparkTo,
                                          TransactionRecord::RecvSpark });
            filter->setTypeFilter(mask);
        } else if (button == ui->btnFilterAssets) {
            quint32 mask = MakeTypeMask({ TransactionRecord::SpatsCreate,
                                          TransactionRecord::SpatsMint,
                                          TransactionRecord::SpatsModify,
                                          TransactionRecord::SpatsRevoke });
            filter->setTypeFilter(mask);
        }
    });

    connect(ui->searchSparkAsset, &QLineEdit::textChanged, this, [this](const QString &text) {
        const auto frames = ui->scrollWidgetSparkAssets->findChildren<QFrame*>("assetRow");
        for (auto *frame : frames) {
            bool match = false;
            for (auto *label : frame->findChildren<QLabel*>()) {
                if (label->text().contains(text, Qt::CaseInsensitive)) {
                    match = true;
                    break;
                }
            }
            frame->setVisible(match || text.isEmpty());
        }
    });

    connect(ui->sendButton, &QPushButton::clicked, this, [this]() { Q_EMIT gotoSendCoinsPage(); });
    connect(ui->receiveButton, &QPushButton::clicked, this, [this]() { Q_EMIT gotoReceiveCoinsPage(); });

    addShadow(ui->balancesCard);
    addShadow(ui->sparkCard);
    addShadow(ui->activityCard);
    addShadow(ui->warningFrame);

    {
        QFont totalFont;
        totalFont.setFamily("Segoe UI");
        totalFont.setPointSize(30);
        totalFont.setBold(true);
        QFont totalVal;
        totalVal.setFamily("Segoe UI");
        totalVal.setPointSize(30);
        totalVal.setBold(false);

        ui->labelTotalText->setFont(totalFont);
        ui->labelTotal->setFont(totalVal);
        ui->labelTotalText->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        ui->labelTotal->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    }

    QIcon icon = QIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled);

    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 16));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &QListView::clicked, this, &OverviewPage::handleTransactionClicked);
    connect(ui->checkboxEnabledTor, &QCheckBox::toggled, this, &OverviewPage::handleEnabledTorChanged);
    connect(&countDownTimer, &QTimer::timeout, this, &OverviewPage::countDown);
    countDownTimer.start(30000);

    connect(ui->migrateButton, &QPushButton::clicked, this, &OverviewPage::migrateClicked);
    connect(this, &OverviewPage::spatsRegistryChangedSignal, this, &OverviewPage::handleSpatsRegistryChangedSignal);

    showOutOfSyncWarning(true);

    bool torEnabled;
    if(IsArgSet("-torsetup")){
        torEnabled = GetBoolArg("-torsetup", DEFAULT_TOR_SETUP);
    }else{
        torEnabled = settings.value("fTorSetup").toBool();
    }
    ui->checkboxEnabledTor->setChecked(torEnabled);

    ui->labelTotalText->setStyleSheet(R"( QLabel { font-size: 22pt; font-weight: 700; color: #111827; } )");
    ui->labelTotal->setStyleSheet(R"( QLabel { font-size: 22pt; font-weight: 700; color: #111827; } )");

    ui->pageSparkAssets->setStyleSheet(R"( QWidget#pageSparkAssets { background: #FFFFFF; border: none; outline: none; margin: 0; padding: 0; } )");

    ui->miniBalancesRow->setSpacing(2);

    ui->anonymizeButton->setMinimumHeight(36);
    ui->sendButton->setMinimumHeight(36);
    ui->receiveButton->setMinimumHeight(36);
}

void OverviewPage::addShadow(QWidget *w)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(18);
    shadow->setOffset(0, 4);
    shadow->setColor(QColor(0, 0, 0, 60));
    w->setGraphicsEffect(shadow);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleEnabledTorChanged()
{
    QMessageBox msgBox;
    if(ui->checkboxEnabledTor->isChecked()){
        settings.setValue("fTorSetup", true);
        msgBox.setText(tr("Please restart the Firo wallet to route your connection through Tor to protect your IP address. <br>Syncing your wallet might be slower with Tor. <br>Note that -torsetup in firo.conf will always override any changes made here."));
    }else{
        settings.setValue("fTorSetup", false);
        msgBox.setText(tr("Please restart the Firo wallet to disable routing of your connection through Tor to protect your IP address. <br>Note that -torsetup in firo.conf will always override any changes made here."));
    }
    msgBox.exec();
}

void OverviewPage::handleOutOfSyncWarningClicks()
{
    Q_EMIT outOfSyncWarningClicked();
}

OverviewPage::~OverviewPage()
{
    getSpatsManager().remove_updates_observer( *this );
    delete ui;
}

void OverviewPage::on_anonymizeButton_clicked()
{
    if (!walletModel) {
        return;
    }
    if (spark::IsSparkAllowed()) {
        auto sparkModel = walletModel->getSparkModel();
        if (!sparkModel) {
            return;
        }
        sparkModel->mintSparkAll(AutoMintSparkMode::MintAll);
    }
}

void OverviewPage::setBalance(
    const CAmount& balance,
    const CAmount& unconfirmedBalance,
    const CAmount& immatureBalance,
    const CAmount& watchOnlyBalance,
    const CAmount& watchUnconfBalance,
    const CAmount& watchImmatureBalance,
    const spats::Wallet::asset_balances_t& spats_balances,
    const CAmount& anonymizableBalance)
{
    if (!walletModel || !walletModel->getOptionsModel()) return;

    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;

    if (currentSpatsBalances_ != spats_balances)
        currentSpatsBalances_ = std::move(spats_balances);

    currentAnonymizableBalance = anonymizableBalance;

    const auto [privateBalance, unconfirmedPrivateBalance] = currentSpatsBalances_[spats::base::universal_id];

    ui->labelTransparentAvailableText->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelTransparentPendingText->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTransparentImmatureText->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelPrivateAvailableText->setText(BitcoinUnits::formatWithUnit(unit, privateBalance.raw(), false, BitcoinUnits::separatorAlways));

    ui->labelTotal->setText(
        BitcoinUnits::formatWithUnit(
            unit,
            balance + unconfirmedBalance + immatureBalance + privateBalance.raw() + unconfirmedPrivateBalance.raw(),
            false,
            BitcoinUnits::separatorAlways
        )
    );

    ui->anonymizeButton->setEnabled(spark::IsSparkAllowed() && anonymizableBalance > 0);

    displaySpatsBalances();

    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;
    ui->labelTransparentImmatureText->setVisible(showImmature || showWatchOnlyImmature);
}

void OverviewPage::displaySpatsBalances()
{
    QLayoutItem *child;
    while ((child = ui->layoutSparkAssetsList->takeAt(0)) != nullptr) {
        if (auto *w = child->widget()) {
            w->deleteLater();
        }
        delete child;
    }

    for (const auto& [asset_id, balance] : currentSpatsBalances_) {
        QString idText = QString::number(static_cast<qulonglong>(asset_id.first)) + ":" + QString::number(static_cast<qulonglong>(asset_id.second));
        QString nameText = "Unknown";
        if (const auto* a = getSpatsDisplayAttributes(asset_id))
            nameText = QString::fromStdString(a->name);

        QString availableText = QString::fromStdString(boost::lexical_cast<std::string>(balance.available));

        auto *frame = new QFrame(ui->scrollWidgetSparkAssets);
        frame->setObjectName("assetRow");
        frame->setStyleSheet(R"( QFrame#assetRow { background: #FFFFFF; border: none; padding: 6px 10px; } )");

        auto *rowLayout = new QHBoxLayout(frame);
        rowLayout->setSpacing(16);
        rowLayout->setContentsMargins(12, 2, 12, 2);

        QString labelStyle = R"( QLabel { color: #6B7280; font-size: 13pt; font-weight: 500; background: transparent; } )";

        auto *idLabel = new QLabel(idText, frame);
        idLabel->setStyleSheet(QString(R"( QLabel { color: #6B7280; font-size: 13pt; font-weight: 600; background: transparent; padding-left: 20px; /* лёгкий сдвиг вправо под заголовок Asset ID */ } )"));

        auto *nameLabel = new QLabel(nameText, frame);
        nameLabel->setStyleSheet(QString(R"( QLabel { color: #6B7280; font-size: 13pt; font-weight: 500; background: transparent; padding-left: 40px; /* добавлено: смещение текста под заголовок Name */ } )"));

        auto *spacer = new QSpacerItem(20, 10, QSizePolicy::Expanding, QSizePolicy::Minimum);

        auto *balanceLabel = new QLabel(availableText, frame);
        balanceLabel->setStyleSheet(R"( QLabel { color: #6B7280; font-size: 13pt; font-weight: 600; background: transparent; } )");

        rowLayout->addWidget(idLabel);
        rowLayout->addSpacing(60);
        rowLayout->addWidget(nameLabel);
        rowLayout->addItem(spacer);
        rowLayout->addWidget(balanceLabel);

        ui->layoutSparkAssetsList->addWidget(frame);
    }
    ui->layoutSparkAssetsList->addStretch();
}

const spats::SparkAssetDisplayAttributes* OverviewPage::getSpatsDisplayAttributes( spats::universal_asset_id_t asset_id )
{
    auto it = spats_display_attributes_cache_.find( asset_id );
    if ( it == spats_display_attributes_cache_.end() ) {
        if ( const auto located_asset = getSpatsManager().registry().get_asset( asset_id.first, asset_id.second ) ) {
            const auto old_size = spats_display_attributes_cache_.size();
            it = spats_display_attributes_cache_.emplace( asset_id, spats::SparkAssetDisplayAttributes( located_asset->asset ) ).first;
            const auto new_size = spats_display_attributes_cache_.size();
            if ( old_size == 0 && new_size > 0 )
                getSpatsManager().add_updates_observer( *this );
        } else {
            LogPrintf( "Failed to find asset {%u, %u} in spats registry!\n", asset_id.first, asset_id.second );
            return nullptr;
        }
    }
    return &it->second;
}

void OverviewPage::process_spats_registry_changed( const admin_addresses_set_t &/*affected_asset_admin_addresses*/, const asset_ids_set_t &affected_asset_ids )
{
    {
        std::lock_guard lock( spats_registry_change_affected_asset_ids_mutex_ );
        spats_registry_change_affected_asset_ids_.insert( affected_asset_ids.begin(), affected_asset_ids.end() );
    }
    Q_EMIT spatsRegistryChangedSignal();
}

void OverviewPage::handleSpatsRegistryChangedSignal()
{
    {
        std::lock_guard lock( spats_registry_change_affected_asset_ids_mutex_ );
        erase_if( spats_display_attributes_cache_, [this]( const auto& entry ) {
            const auto [asset_type, identifier] = entry.first;
            return spats_registry_change_affected_asset_ids_.contains( { asset_type, std::nullopt } ) ||
                   spats_registry_change_affected_asset_ids_.contains( { asset_type, identifier } );
        } );
        spats_registry_change_affected_asset_ids_.clear();
    }
    displaySpatsBalances();
}

void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);
    ui->labelWatchonly->setVisible(showWatchOnly);
    ui->lineWatchBalance->setVisible(showWatchOnly);
    ui->labelWatchAvailable->setVisible(showWatchOnly);
    ui->labelWatchPending->setVisible(showWatchOnly);
    ui->labelWatchTotal->setVisible(showWatchOnly);
    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model) {
        connect(model, &ClientModel::numBlocksChanged, this, &OverviewPage::onRefreshClicked);
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    onRefreshClicked();

    if(model && model->getOptionsModel()) {
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);
        filter->setTypeFilter(TransactionFilterProxy::ALL_TYPES);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        setBalance(
            model->getBalance(),
            model->getUnconfirmedBalance(),
            model->getImmatureBalance(),
            model->getWatchBalance(),
            model->getWatchUnconfirmedBalance(),
            model->getWatchImmatureBalance(),
            walletModel->getSpatsBalances(),
            model->getAnonymizableBalance()
        );

        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);
        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, &WalletModel::notifyWatchonlyChanged, this, &OverviewPage::updateWatchOnlyLabels);
    }
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel()) {
        if(currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentImmatureBalance,
                       currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance,
                       currentSpatsBalances_, currentAnonymizableBalance);
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();
        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    // ui->labelWalletStatus->setVisible(fShow);
    // ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::countDown()
{
    secDelay--;
    if(secDelay <= 0) {
        if(walletModel->getAvailableLelantusCoins() && spark::IsSparkAllowed() && chainActive.Height() < ::Params().GetConsensus().nLelantusGracefulPeriod){
            MigrateLelantusToSparkDialog migrate(walletModel);
        }
        countDownTimer.stop();
    }
}

void OverviewPage::onRefreshClicked()
{
    if (!walletModel) return;

    size_t confirmed, unconfirmed;
    auto privateBalance = walletModel->getWallet()->GetPrivateBalance();

    auto lGracefulPeriod = ::Params().GetConsensus().nLelantusGracefulPeriod;
    int heightDifference = lGracefulPeriod - chainActive.Height();
    const int approxBlocksPerDay = 570;
    int daysUntilMigrationCloses = heightDifference / approxBlocksPerDay;

    if(privateBalance.first > 0 && chainActive.Height() < lGracefulPeriod && spark::IsSparkAllowed()) {
        ui->warningFrame->show();
        migrationWindowClosesIn = QString::fromStdString(std::to_string(daysUntilMigrationCloses));
        blocksRemaining = QString::fromStdString(std::to_string(heightDifference));
        migrateAmount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), privateBalance.first);
        migrateAmount.append("</b>");
        ui->textWarning1->setText(tr("We have detected Lelantus coins that have not been migrated to Spark. Migration window will close in %1 blocks (~ %2 days).").arg(blocksRemaining , migrationWindowClosesIn));
        ui->textWarning2->setText(tr("to migrate %1 ").arg(migrateAmount));
        QFont qFont = ui->migrateButton->font();
        qFont.setUnderline(true);
        ui->migrateButton->setFont(qFont);
    } else {
        ui->warningFrame->hide();
    }
}

void OverviewPage::migrateClicked()
{
    if (!walletModel) return;

    size_t confirmed, unconfirmed;
    auto privateBalance = walletModel->getWallet()->GetPrivateBalance();
    FIRO_UNUSED auto lGracefulPeriod = ::Params().GetConsensus().nLelantusGracefulPeriod;

    migrateAmount = "<b>" + BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), privateBalance.first);
    migrateAmount.append("</b>");
    QString info = tr("Your wallet needs to be unlocked to migrate your funds to Spark.");

    if(walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this, info);
        dlg.setModel(walletModel);
        dlg.exec();
    }
    if (walletModel->getEncryptionStatus() == WalletModel::Unlocked){
        if(walletModel->getAvailableLelantusCoins() && spark::IsSparkAllowed() && chainActive.Height() < ::Params().GetConsensus().nLelantusGracefulPeriod){
            MigrateLelantusToSparkDialog migrate(walletModel);
            if(!migrate.getClickedButton()){
                ui->warningFrame->hide();
            }
        }
    }
}

MigrateLelantusToSparkDialog::MigrateLelantusToSparkDialog(WalletModel *_model):QMessageBox()
{
    this->model = _model;
    QDialog::setWindowTitle("Migrate funds from Lelantus to Spark");
    QDialog::setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint);

    QLabel *ic = new QLabel();
    QIcon icon_;
    icon_.addFile(QString::fromUtf8(":/icons/ic_info"), QSize(), QIcon::Normal, QIcon::On);
    ic->setPixmap(icon_.pixmap(18, 18));
    ic->setFixedWidth(90);
    ic->setAlignment(Qt::AlignRight);
    ic->setStyleSheet("color:#92400E");

    QLabel *text = new QLabel();
    text->setText(tr("Firo is migrating to Spark. Please migrate your funds."));
    text->setAlignment(Qt::AlignLeft);
    text->setWordWrap(true);
    text->setStyleSheet("color:#92400E;text-align:center;word-wrap: break-word;");

    QPushButton *ignore = new QPushButton(this);
    ignore->setText("Ignore");
    ignore->setStyleSheet("margin-top:30px;margin-bottom:60px;margin-left:20px;margin-right:50px;");

    QPushButton *migrate = new QPushButton(this);
    migrate->setText("Migrate");
    migrate->setStyleSheet("color:#9b1c2e;background-color:none;margin-top:30px;margin-bottom:60px;margin-left:50px;margin-right:20px;border:1px solid #9b1c2e;");

    QHBoxLayout *groupButton = new QHBoxLayout(this);
    groupButton->addWidget(ignore);
    groupButton->addWidget(migrate);

    QHBoxLayout *hlayout = new QHBoxLayout(this);
    hlayout->addWidget(ic);
    hlayout->addWidget(text);

    QWidget *layout_ = new QWidget();
    layout_->setLayout(hlayout);
    layout_->setStyleSheet("background-color:#FEF3C7;");

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->addWidget(layout_);
    vlayout->addLayout(groupButton);
    vlayout->setContentsMargins(0,0,0,0);

    QWidget *wbody = new QWidget();
    wbody->setLayout(vlayout);
    layout()->addWidget(wbody);

    setContentsMargins(0, 0, 0, 0);
    setStyleSheet("margin-right:-30px;");
    setStandardButtons(StandardButtons());

    connect(ignore, &QPushButton::clicked, this, &MigrateLelantusToSparkDialog::onIgnoreClicked);
    connect(migrate, &QPushButton::clicked, this, &MigrateLelantusToSparkDialog::onMigrateClicked);

    exec();
}

void MigrateLelantusToSparkDialog::onIgnoreClicked()
{
    setVisible(false);
    clickedButton = true;
}

void MigrateLelantusToSparkDialog::onMigrateClicked()
{
    setVisible(false);
    clickedButton = false;
    model->migrateLelantusToSpark();
}

bool MigrateLelantusToSparkDialog::getClickedButton()
{
    return clickedButton;
}

void OverviewPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();
    const int maxWidth = 1920;
    const int maxHeight = 1200;

    if (newWidth > maxWidth || newHeight > maxHeight) {
        resize(std::min(newWidth, maxWidth), std::min(newHeight, maxHeight));
        return;
    }

    adjustTextSize(newWidth, newHeight);
}

void OverviewPage::adjustTextSize(int width, int /*height*/)
{
    const double fontScale = 133.0;
    int base = std::max(12, std::min(15, width / (int)fontScale));

    QFont baseFont("Segoe UI", base, QFont::Normal);
    QFont boldFont("Segoe UI", base, QFont::DemiBold);
    auto hintFont = baseFont;
    hintFont.setPointSize(std::max(11, base - 1));

    ui->textWarning1->setFont(baseFont);
    ui->textWarning2->setFont(baseFont);
    ui->anonymizeButton->setFont(boldFont);
    ui->labelAlerts->setFont(boldFont);

    ui->labelPrivateAvailableTitle->setFont(hintFont);
    ui->labelPrivateAvailableText->setFont(boldFont);
    ui->labelPrivatePendingTitle->setFont(hintFont);
    ui->labelPrivatePendingText->setFont(boldFont);
    ui->labelTransparentAvailableTitle->setFont(hintFont);
    ui->labelTransparentAvailableText->setFont(boldFont);
    ui->labelTransparentPendingTitle->setFont(hintFont);
    ui->labelTransparentPendingText->setFont(boldFont);
    ui->labelTransparentImmatureTitle->setFont(hintFont);
    ui->labelTransparentImmatureText->setFont(boldFont);

    QFont totalFont("Segoe UI", 30, QFont::Bold);
    QFont totalVal("Segoe UI", 30, QFont::Normal);

    ui->labelTotalText->setFont(totalFont);
    ui->labelTotal->setFont(totalVal);
}