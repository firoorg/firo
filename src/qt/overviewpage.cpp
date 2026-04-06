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
#include <QPainterPath>
#include <QMenu>
#include <QGraphicsDropShadowEffect>
#include <QHeaderView>
#include <QButtonGroup>
#include <QObject>
#include <QColor>
#include <QEvent>
#include <QRegion>

#include "../spark/state.h"

#define DECORATION_SIZE 54
#define NUM_ITEMS 5
#define ACTIVITY_ICON_SIZE 42
#define ACTIVITY_CARD_HEIGHT 72

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

class AssetCardHoverFilter : public QObject
{
public:
    explicit AssetCardHoverFilter(QObject *parent = nullptr) : QObject(parent) {}

protected:
    bool eventFilter(QObject *obj, QEvent *event) override
    {
        auto *widget = qobject_cast<QWidget*>(obj);
        if (!widget) {
            return QObject::eventFilter(obj, event);
        }
        auto *shadow = qobject_cast<QGraphicsDropShadowEffect*>(widget->graphicsEffect());
        if (!shadow) {
            return QObject::eventFilter(obj, event);
        }
        if (event->type() == QEvent::Enter) {
            if (!widget->property("assetBaseY").isValid()) {
                widget->setProperty("assetBaseY", widget->pos().y());
            }
            const int baseY = widget->property("assetBaseY").toInt();

            shadow->setBlurRadius(42);
            shadow->setOffset(0, 14);
            // Grey metallic highlight (less aggressive than red).
            shadow->setColor(QColor(110, 120, 130, 145));

            // "Move forward": small lift above layout position.
            widget->move(widget->x(), baseY - 4);
            widget->raise();
        } else if (event->type() == QEvent::Leave) {
            const int baseY = widget->property("assetBaseY").toInt();
            shadow->setBlurRadius(30);
            shadow->setOffset(0, 8);
            shadow->setColor(QColor(95, 105, 115, 105));
            widget->move(widget->x(), baseY);
        }
        return QObject::eventFilter(obj, event);
    }
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
        painter->setRenderHint(QPainter::Antialiasing, true);

        const bool mouseOver = (option.state & QStyle::State_MouseOver);
        const bool selected = (option.state & QStyle::State_Selected);

        const QRect mainRect = option.rect.adjusted(8, 6, -8, -6);
        if (mainRect.width() <= 0 || mainRect.height() <= 0) {
            painter->restore();
            return;
        }

        const int radius = 18;
        const int glossHeight = 14;
        const int shadowYOffset = mouseOver ? 3 : 2;

        // Light metallic grey palette (soft transition from white UI).
        const QColor start = (mouseOver || selected) ? QColor("#D1D8E2") : QColor("#E8EDF2");
        const QColor mid   = QColor("#B7C3D0");
        const QColor end   = QColor("#A3AFBA");

        // 3D-ish underlay shadow and main gradient card background.
        QPainterPath bgShadowPath;
        bgShadowPath.addRoundedRect(mainRect.translated(0, shadowYOffset), radius, radius);
        painter->setPen(Qt::NoPen);
        painter->setBrush(QColor(100, 110, 120, mouseOver ? 95 : 70));
        painter->drawPath(bgShadowPath);

        QLinearGradient bgGrad(mainRect.topLeft(), mainRect.bottomRight());
        bgGrad.setColorAt(0.0, start);
        bgGrad.setColorAt(0.52, mid);
        bgGrad.setColorAt(1.0, end);

        QPainterPath bgPath;
        bgPath.addRoundedRect(mainRect, radius, radius);
        painter->setBrush(bgGrad);
        painter->drawPath(bgPath);

        // Glass-like highlight on top.
        const QRect glossRect(mainRect.left(), mainRect.top(), mainRect.width(), glossHeight);
        QPainterPath glossPath;
        glossPath.addRoundedRect(glossRect, radius, radius);
        QLinearGradient glossGrad(glossRect.topLeft(), glossRect.bottomLeft());
        glossGrad.setColorAt(0.0, QColor(255, 255, 255, mouseOver ? 85 : 60));
        glossGrad.setColorAt(0.6, QColor(220, 228, 236, mouseOver ? 28 : 20));
        glossGrad.setColorAt(1.0, QColor(170, 180, 190, 0));
        painter->setBrush(glossGrad);
        painter->drawPath(glossPath);

        // Subtle border to keep the card crisp.
        painter->setBrush(Qt::NoBrush);
        painter->setPen(QColor(160, 170, 180, mouseOver ? 85 : 40));
        painter->drawPath(bgPath);

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect decorationRect(mainRect.topLeft(), QSize(ACTIVITY_ICON_SIZE, ACTIVITY_ICON_SIZE));
        int xspace = ACTIVITY_ICON_SIZE + 12;
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

        const QColor baseText = QColor(17, 24, 39, 200);
        QColor foreground = baseText;
        if(value.canConvert<QBrush>()) {
            // Keep the model's semantic color if it exists, but still ensure readability.
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }
        if (amount < 0) {
            foreground = QColor(255, 205, 205);
        } else if (!confirmed) {
            // Keep unconfirmed amounts readable but not blue.
            foreground = QColor(17, 24, 39, 200);
        }

        painter->setPen(baseText);
        QFont baseFont = painter->font();
        baseFont.setFamily("Segoe UI");
        baseFont.setPointSize(10);
        painter->setFont(baseFont);

        QRect boundingRect;

        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 6, mainRect.top()+ypad+halfheight, 14, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        // Amount row uses a slightly bolder font for readability.
        QFont amountFont = baseFont;
        amountFont.setPointSize(11);
        amountFont.setBold(true);
        painter->setFont(amountFont);
        painter->setPen(foreground);

        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setFont(baseFont);
        painter->setPen(QColor(17, 24, 39, 180));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem&, const QModelIndex&) const override
    {
        return QSize(ACTIVITY_ICON_SIZE, ACTIVITY_CARD_HEIGHT);
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

    // Private -> Transparent split bar under Total
    ui->privateTransparentBarFrame->setAttribute(Qt::WA_StyledBackground, true);
    ui->privateTransparentBarFrame->setAutoFillBackground(true);
    ui->privateTransparentBarFrame->setCursor(Qt::ArrowCursor);
    // Ensure the bar always renders as a proper pill (children can inherit 0 height otherwise).
    ui->privateTransparentBarFrame->setFixedHeight(22);
    ui->privateTransparentBarSegmentsLayout->setSpacing(0);
    ui->privateTransparentBarSegmentsLayout->setContentsMargins(0, 0, 0, 0);
    // Split is driven by explicit widths (see updatePrivateTransparentSplitBar), not layout stretch,
    // so the green/transparent ratio always matches the percentage labels.
    ui->privateTransparentBarSegmentsLayout->setStretch(0, 0);
    ui->privateTransparentBarSegmentsLayout->setStretch(1, 0);
    // Force both segments to have a non-zero height, so border-radius is visible.
    ui->privateBarSegment->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    ui->transparentBarSegment->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    ui->privateBarSegment->setFixedHeight(22);
    ui->transparentBarSegment->setFixedHeight(22);
    ui->privateBarSegment->setAttribute(Qt::WA_StyledBackground, true);
    ui->privateBarSegment->setAutoFillBackground(true);
    ui->transparentBarSegment->setAttribute(Qt::WA_StyledBackground, true);
    ui->transparentBarSegment->setAutoFillBackground(true);

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

    if (ui->btnViewAll) {
        connect(ui->btnViewAll, &QPushButton::clicked, this, [this]() {
            Q_EMIT gotoSparkAssetsPage();
        });
    }

    ui->balancesCard->setAttribute(Qt::WA_StyledBackground, true);
    ui->balancesCard->setAutoFillBackground(true);
    addShadow(ui->balancesCard, 34, 9, 95);
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
    ui->listTransactions->setIconSize(QSize(ACTIVITY_ICON_SIZE, ACTIVITY_ICON_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (ACTIVITY_CARD_HEIGHT + 10));
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

    if (ui->labelTransparentSplit)
        ui->labelTransparentSplit->setAutoFillBackground(false);

    if (ui->btnTabSpark && ui->btnTabNFT && ui->sparkContentStack) {
        auto setSparkTab = [this](int index) {
            ui->sparkContentStack->setCurrentIndex(index);
            ui->btnTabSpark->setChecked(index == 0);
            ui->btnTabNFT->setChecked(index == 1);
        };

        setSparkTab(0);

        connect(ui->btnTabSpark, &QPushButton::clicked, this, [setSparkTab]() { setSparkTab(0); });
        connect(ui->btnTabNFT, &QPushButton::clicked, this, [setSparkTab]() { setSparkTab(1); });
    }
}

void OverviewPage::addShadow(QWidget *w, int blurRadius, int yOffset, int alpha)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(blurRadius);
    shadow->setOffset(0, yOffset);
    shadow->setColor(QColor(0, 0, 0, alpha));
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

void OverviewPage::updatePrivateTransparentSplitBar()
{
    if (!ui->privateTransparentBarFrame || !ui->privateBarSegment || !ui->transparentBarSegment)
        return;

    const QMargins lm = ui->privateTransparentBarSegmentsLayout->contentsMargins();
    int w = ui->privateTransparentBarFrame->width() - lm.left() - lm.right();
    if (w < 0)
        w = 0;

    const int pct = privateBarSplitPercent_;
    int wPriv = 0;
    if (pct <= 0)
        wPriv = 0;
    else if (pct >= 100)
        wPriv = w;
    else
        wPriv = (w * pct + 50) / 100;

    if (wPriv > w)
        wPriv = w;
    const int wTransp = std::max(0, w - wPriv);

    ui->privateBarSegment->setFixedWidth(wPriv);
    ui->transparentBarSegment->setFixedWidth(wTransp);

    // Fully rounded pill ends; apply mask after layout applies new widths.
    QTimer::singleShot(0, this, [this]() {
        if (!ui->privateBarSegment)
            return;
        const int ww = ui->privateBarSegment->width();
        const int h = ui->privateBarSegment->height();
        if (ww <= 0 || h <= 0) {
            ui->privateBarSegment->setMask(QRegion());
            return;
        }

        const qreal radius = h / 2.0;
        QPainterPath path;
        path.addRoundedRect(QRectF(0, 0, ww, h), radius, radius);
        const QPolygon poly = path.toFillPolygon().toPolygon();
        ui->privateBarSegment->setMask(QRegion(poly));
    });
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

    const auto spatsIt = spats_balances.find( spats::base::universal_id );
    CAmount privateTotal = 0;
    if (spatsIt != spats_balances.end()) {
        privateTotal = spatsIt->second.available.raw() + spatsIt->second.pending.raw();
    }
    const CAmount transparentTotal = balance + unconfirmedBalance + immatureBalance;
    const CAmount totalAmount = privateTotal + transparentTotal;
    int privatePercent = 0;
    if (totalAmount > 0) {
        privatePercent = static_cast<int>((privateTotal * 100 + totalAmount / 2) / totalAmount);
        if (privatePercent < 0) privatePercent = 0;
        if (privatePercent > 100) privatePercent = 100;
    }

    ui->labelPrivateSplit->setText(
        QString("Private: %1 (%2%)")
            .arg(BitcoinUnits::formatWithUnit(unit, privateTotal, false, BitcoinUnits::separatorAlways))
            .arg(privatePercent)
    );

    const int transparentPercent = 100 - privatePercent;
    if (ui->labelTransparentSplit) {
        ui->labelTransparentSplit->setText(
            QString("Transparent: %1 (%2%)")
                .arg(BitcoinUnits::formatWithUnit(unit, transparentTotal, false, BitcoinUnits::separatorAlways))
                .arg(transparentPercent)
        );
    }

    privateBarSplitPercent_ = privatePercent;
    updatePrivateTransparentSplitBar();

    ui->labelTotal->setText(
        BitcoinUnits::formatWithUnit(
            unit,
            totalAmount,
            false,
            BitcoinUnits::separatorAlways
        )
    );

    ui->anonymizeButton->setEnabled(spark::IsSparkAllowed() && anonymizableBalance > 0);

    displaySpatsBalances();
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

    int shown = 0;
    for (const auto& [asset_id, balance] : currentSpatsBalances_) {
        if (shown >= NUM_ITEMS)
            break;
        ++shown;

        QString idText = QString::number(static_cast<qulonglong>(asset_id.first)) + ":" + QString::number(static_cast<qulonglong>(asset_id.second));
        QString nameText = "Unknown";
        if (const auto* a = getSpatsDisplayAttributes(asset_id))
            nameText = QString::fromStdString(a->name);

        QString availableText = QString::fromStdString(boost::lexical_cast<std::string>(balance.available));

        struct CardPalette {
            QString start;
            QString mid;
            QString end;
            QColor shadow;
        };

        const CardPalette palette{"#E8EDF2", "#B7C3D0", "#A3AFBA", QColor(100, 110, 120, 85)};

        auto *frame = new QFrame(ui->scrollWidgetSparkAssets);
        frame->setObjectName("assetRow");
        frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        frame->setFixedHeight(58);
        frame->setCursor(Qt::PointingHandCursor);
        frame->setAttribute(Qt::WA_Hover, true);
        frame->setStyleSheet(QString(R"(
            QFrame#assetRow {
                border: 1px solid rgba(255, 255, 255, 0);
                border-radius: 12px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 %1,
                                            stop:0.52 %2,
                                            stop:1 %3);
            }
            QFrame#assetRow:hover {
                border: 1px solid rgba(255, 255, 255, 0);
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #D1D8E2,
                                            stop:0.52 #C0CBD6,
                                            stop:1 #A3AFBA);
            }
        )").arg(palette.start, palette.mid, palette.end));

        auto *cardShadow = new QGraphicsDropShadowEffect(frame);
        cardShadow->setBlurRadius(10);
        cardShadow->setOffset(0, 2);
        cardShadow->setColor(palette.shadow);
        frame->setGraphicsEffect(cardShadow);
        frame->installEventFilter(new AssetCardHoverFilter(frame));

        auto *cardLayout = new QVBoxLayout(frame);
        cardLayout->setSpacing(0);
        cardLayout->setContentsMargins(0, 0, 0, 0);

        auto *glassHighlight = new QFrame(frame);
        glassHighlight->setObjectName("assetGloss");
        glassHighlight->setFixedHeight(6);
        glassHighlight->setStyleSheet(R"(
            QFrame#assetGloss {
                border: none;
                border-top-left-radius: 12px;
                border-top-right-radius: 12px;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 rgba(255, 255, 255, 48),
                                            stop:0.45 rgba(220, 228, 236, 14),
                                            stop:1 rgba(170, 180, 190, 5));
            }
        )");
        cardLayout->addWidget(glassHighlight);

        auto *rowLayout = new QHBoxLayout();
        rowLayout->setSpacing(14);
        rowLayout->setContentsMargins(14, 0, 12, 4);

        auto makeCaptionLabel = [frame](const QString &text) {
            auto *label = new QLabel(text, frame);
            label->setStyleSheet(R"(QLabel { color: rgba(17, 24, 39, 150); font-size: 8pt; font-weight: 600; background: transparent; })");
            return label;
        };

        auto makeValueLabel = [frame](const QString &text, bool wide = false) {
            auto *label = new QLabel(text, frame);
            label->setStyleSheet(R"(QLabel { color: #111827; font-size: 11pt; font-weight: 700; background: transparent; })");
            if (wide) {
                label->setMinimumWidth(120);
            }
            return label;
        };

        auto *idColumn = new QVBoxLayout();
        idColumn->setSpacing(1);
        idColumn->setContentsMargins(0, 0, 0, 0);
        idColumn->addWidget(makeCaptionLabel(tr("Asset ID")));
        idColumn->addWidget(makeValueLabel(idText));

        auto *nameColumn = new QVBoxLayout();
        nameColumn->setSpacing(1);
        nameColumn->setContentsMargins(0, 0, 0, 0);
        nameColumn->addWidget(makeCaptionLabel(tr("Name")));
        nameColumn->addWidget(makeValueLabel(nameText, true));

        auto *balanceColumn = new QVBoxLayout();
        balanceColumn->setSpacing(1);
        balanceColumn->setContentsMargins(0, 0, 0, 0);
        auto *availableCaption = makeCaptionLabel(tr("Available"));
        availableCaption->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto *availableValue = makeValueLabel(availableText);
        availableValue->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        balanceColumn->addWidget(availableCaption);
        balanceColumn->addWidget(availableValue);

        auto *leftColumnsLayout = new QHBoxLayout();
        leftColumnsLayout->setSpacing(16);
        leftColumnsLayout->setContentsMargins(0, 0, 0, 0);
        leftColumnsLayout->addLayout(idColumn, 1);
        leftColumnsLayout->addLayout(nameColumn, 2);
        leftColumnsLayout->addLayout(balanceColumn, 2);

        auto *leftColumnsWidget = new QWidget(frame);
        leftColumnsWidget->setStyleSheet("background: transparent;");
        leftColumnsWidget->setLayout(leftColumnsLayout);

        rowLayout->addWidget(leftColumnsWidget, 1);

        auto *sparkBadge = new QLabel(frame);
        sparkBadge->setPixmap(GUIUtil::sparkAssetBadgePixmap(18));
        sparkBadge->setStyleSheet(QStringLiteral("background: transparent; border: none; padding: 0px; margin: 0px;"));
        sparkBadge->setAlignment(Qt::AlignTop | Qt::AlignRight);
        rowLayout->addWidget(sparkBadge, 0, Qt::AlignTop);

        cardLayout->addLayout(rowLayout);

        ui->layoutSparkAssetsList->addWidget(frame);
    }
    ui->layoutSparkAssetsList->setAlignment(Qt::AlignTop);
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
    Q_UNUSED(showWatchOnly);
    // Per request: show only `Total` on the overview page, no separate watch-only balances.
    ui->labelSpendable->setVisible(false);
    ui->labelWatchonly->setVisible(false);
    ui->lineWatchBalance->setVisible(false);
    ui->labelWatchAvailable->setVisible(false);
    ui->labelWatchPending->setVisible(false);
    ui->labelWatchTotal->setVisible(false);
    ui->labelWatchImmature->setVisible(false);
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
    auto privateBalance = walletModel->getWallet()->GetPrivateBalance(confirmed, unconfirmed);
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
    auto privateBalance = walletModel->getWallet()->GetPrivateBalance(confirmed, unconfirmed);
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
    updatePrivateTransparentSplitBar();
}

void OverviewPage::adjustTextSize(int width, int /*height*/)
{
    const double fontScale = 133.0;
    int base = std::max(12, std::min(15, width / (int)fontScale));

    QFont baseFont("Segoe UI", base, QFont::Normal);
    QFont boldFont("Segoe UI", base, QFont::DemiBold);

    ui->textWarning1->setFont(baseFont);
    ui->textWarning2->setFont(baseFont);
    ui->anonymizeButton->setFont(boldFont);
    ui->labelAlerts->setFont(boldFont);

    // Mini-balance capsule fonts are intentionally NOT adjusted here.
    // They are set once to a fixed pixel size in the constructor to ensure
    // consistent typography across platforms and DPI settings.

    QFont totalFont("Segoe UI", 30, QFont::Bold);
    QFont totalVal("Segoe UI", 30, QFont::Normal);

    ui->labelTotalText->setFont(totalFont);
    ui->labelTotal->setFont(totalVal);
}