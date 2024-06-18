// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../lelantus.h"

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "lelantusmodel.h"
#include "sparkmodel.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"
#include "validation.h"
#include "askpassphrasedialog.h"


#ifdef WIN32
#include <string.h>
#endif

#include "util.h"
#include "compat.h"

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5

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
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
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
    bool torEnabled;
    if(IsArgSet("-torsetup")){
        torEnabled = GetBoolArg("-torsetup", DEFAULT_TOR_SETUP);
    }else{
        torEnabled = settings.value("fTorSetup").toBool();
    }

    if(torEnabled){
        ui->checkboxEnabledTor->setChecked(true);
    }else{
        ui->checkboxEnabledTor->setChecked(false);
    }

    QIcon icon = QIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &QListView::clicked, this, &OverviewPage::handleTransactionClicked);
    connect(ui->checkboxEnabledTor, &QCheckBox::toggled, this, &OverviewPage::handleEnabledTorChanged);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);

    connect(&countDownTimer, &QTimer::timeout, this, &OverviewPage::countDown);
    countDownTimer.start(30000);
    connect(ui->migrateButton, &QPushButton::clicked, this, &OverviewPage::migrateClicked);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleEnabledTorChanged(){

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
    delete ui;
}

void OverviewPage::on_anonymizeButton_clicked()
{
    if (!walletModel) {
        return;
    }

    if(lelantus::IsLelantusAllowed()) {
        auto lelantusModel = walletModel->getLelantusModel();
        if (!lelantusModel) {
            return;
        }

        lelantusModel->mintAll(AutoMintMode::MintAll);
    } else if (spark::IsSparkAllowed()) {
        auto sparkModel = walletModel->getSparkModel();
        if (!sparkModel) {
            return;
        }

        sparkModel->mintSparkAll(AutoMintSparkMode::MintAll);
    }
}

void OverviewPage::setBalance(
    const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
    const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance,
    const CAmount& privateBalance, const CAmount& unconfirmedPrivateBalance, const CAmount& anonymizableBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    currentPrivateBalance = privateBalance;
    currentUnconfirmedPrivateBalance = unconfirmedPrivateBalance;
    currentAnonymizableBalance = anonymizableBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, balance + unconfirmedBalance + immatureBalance + currentPrivateBalance + currentUnconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance + watchUnconfBalance + watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelPrivate->setText(BitcoinUnits::formatWithUnit(unit, privateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmedPrivate->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelAnonymizable->setText(BitcoinUnits::formatWithUnit(unit, anonymizableBalance, false, BitcoinUnits::separatorAlways));

    ui->anonymizeButton->setEnabled((lelantus::IsLelantusAllowed() || spark::IsSparkAllowed()) && anonymizableBalance > 0);

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance
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
        connect(model, &ClientModel::numBlocksChanged, this, &OverviewPage::onRefreshClicked);
        // Show warning if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    onRefreshClicked();
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

        auto privateBalance = walletModel->getLelantusModel()->getPrivateBalance();
        std::pair<CAmount, CAmount> sparkBalance = walletModel->getSparkBalance();
        privateBalance = spark::IsSparkAllowed() ? sparkBalance : privateBalance;

        // Keep up to date with wallet
        setBalance(
                    model->getBalance(),
                    model->getUnconfirmedBalance(),
                    model->getImmatureBalance(),
                    model->getWatchBalance(),
                    model->getWatchUnconfirmedBalance(),
                    model->getWatchImmatureBalance(),
                    privateBalance.first,
                    privateBalance.second,
                    model->getAnonymizableBalance());
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, &WalletModel::notifyWatchonlyChanged, this, &OverviewPage::updateWatchOnlyLabels);
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
                       currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance,
                       currentPrivateBalance, currentUnconfirmedPrivateBalance, currentAnonymizableBalance);

        // Update txdelegate->unit with the current unit
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
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
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
    auto privateBalance = walletModel->getLelantusModel()->getPrivateBalance();
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
    auto privateBalance = walletModel->getLelantusModel()->getPrivateBalance();
    auto lGracefulPeriod = ::Params().GetConsensus().nLelantusGracefulPeriod;
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
        setStandardButtons(0);    

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

    // Retrieve new dimensions from the resize event
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();
    adjustTextSize(newWidth, newHeight);

    // Determine widths for specific widgets as percentages of total width
    int labelWidth = static_cast<int>(newWidth * 0.5);
    int labelMinWidth = static_cast<int>(newWidth * 0.15);
    int labelMaxWidth = static_cast<int>(newWidth * 0.35);
    const int labelHeight = 20;

    // Configure the dimensions and constraints of each widget
    ui->labelBalance->setFixedWidth(labelWidth);
    ui->labelBalance->setMinimumWidth(labelMinWidth);
    ui->labelBalance->setMaximumWidth(labelMaxWidth);
    ui->labelBalance->setFixedHeight(labelHeight);

    ui->labelUnconfirmed->setFixedWidth(labelWidth);
    ui->labelUnconfirmed->setMinimumWidth(labelMinWidth);
    ui->labelUnconfirmed->setMaximumWidth(labelMaxWidth);
    ui->labelUnconfirmed->setFixedHeight(labelHeight);

    int buttonWidth = static_cast<int>(newWidth * 0.15);
    int buttonHeight = static_cast<int>(newHeight * 0.05);
    int buttonMinHeight = static_cast<int>(20);
    int buttonMaxHeight = static_cast<int>(45);

    ui->anonymizeButton->setMinimumWidth(buttonWidth);
    ui->anonymizeButton->setMaximumWidth(buttonWidth * 2);
    ui->anonymizeButton->setMinimumHeight(buttonMinHeight);
    ui->anonymizeButton->setMaximumHeight(buttonMaxHeight);

    // Set the minimum width for all label widgets to ensure they maintain a consistent and readable size regardless of window resizing
    ui->labelAnonymizable->setMinimumWidth(labelMinWidth);
    ui->labelAlerts->setMinimumWidth(labelMinWidth);
    ui->label->setMinimumWidth(labelMinWidth);
    ui->labelWatchPending->setMinimumWidth(labelMinWidth);
    ui->labelBalance->setMinimumWidth(labelMinWidth);
    ui->labelSpendable->setMinimumWidth(labelMinWidth);
    ui->labelWatchAvailable->setMinimumWidth(labelMinWidth);
    ui->labelUnconfirmedPrivate->setMinimumWidth(labelMinWidth);
    ui->labelWatchonly->setMinimumWidth(labelMinWidth);
    ui->labelTotal->setMinimumWidth(labelMinWidth);
    ui->labelWatchTotal->setMinimumWidth(labelMinWidth);
    ui->labelUnconfirmed->setMinimumWidth(labelMinWidth);
    ui->labelImmature->setMinimumWidth(labelMinWidth);
    ui->labelPrivate->setMinimumWidth(labelMinWidth);
    ui->label_4->setMinimumWidth(labelMinWidth);
}
void OverviewPage::adjustTextSize(int width, int height){

    const double fontSizeScalingFactor = 133.0;
    int baseFontSize = width / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    
    // Font for regular text components(not bold)
    QFont textFont = ui->labelBalance->font();
    textFont.setPointSize(fontSize);
    textFont.setBold(false);

   // Font for text components that should be bold
    QFont labelFont = textFont;
    labelFont.setBold(true);

    ui->textWarning1->setFont(textFont);
    ui->textWarning2->setFont(textFont);
    ui->labelWalletStatus->setFont(textFont);
    ui->anonymizeButton->setFont(textFont);

    // Apply label font to all label components
    ui->labelAlerts->setFont(labelFont);
    ui->label_5->setFont(labelFont);
    ui->labelAnonymizableText->setFont(textFont);
    ui->label->setFont(labelFont);
    ui->labelAnonymizable->setFont(labelFont);
    ui->labelWatchPending->setFont(labelFont);
    ui->labelBalance->setFont(labelFont);
    ui->labelSpendable->setFont(labelFont);
    ui->labelWatchAvailable->setFont(labelFont);
    ui->labelPendingText->setFont(textFont);
    ui->labelUnconfirmedPrivate->setFont(labelFont);
    ui->labelUnconfirmedPrivateText->setFont(textFont);
    ui->labelTotalText->setFont(textFont);
    ui->labelWatchonly->setFont(labelFont);
    ui->labelBalanceText->setFont(textFont);
    ui->labelTotal->setFont(labelFont);
    ui->labelWatchTotal->setFont(labelFont);
    ui->labelUnconfirmed->setFont(labelFont);
    ui->labelImmatureText->setFont(textFont);
    ui->labelImmature->setFont(labelFont);
    ui->labelWatchImmature->setFont(labelFont);
    ui->labelPrivateText->setFont(textFont);
    ui->labelPrivate->setFont(labelFont);
    ui->label_4->setFont(labelFont);
   
}