#include "masternodelist.h"
#include "ui_masternodelist.h"

#include "clientmodel.h"
#include "clientversion.h"
#include "coins.h"
#include "guitheme.h"
#include "guiutil.h"
#include "init.h"
#include "masternode-sync.h"
#include "netbase.h"
#include "sync.h"
#include "validation.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif // ENABLE_WALLET
#include "walletmodel.h"

#include <univalue.h>

#include "amount.h"
#include "base58.h"

#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QCursor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFrame>
#include <QGridLayout>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QListView>
#include <QLocale>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QScreen>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QTextDocument>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QtGui/QClipboard>
#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace {

QString formatBlockHeight(int height, bool none)
{
    if (none)
        return QStringLiteral("-");
    return QLocale::system().toString(height);
}

QString masternodeText(const char* sourceText)
{
    return QCoreApplication::translate("MasternodeList", sourceText);
}

QPixmap masternodeGlyph()
{
    QPixmap pm(36, 36);
    pm.fill(Qt::transparent);
    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    QLinearGradient g(0, 0, 0, 36);
    g.setColorAt(0, QColor(tc.wine));
    g.setColorAt(1, QColor(tc.wineDeep));
    p.setPen(Qt::NoPen);
    p.setBrush(g);
    p.drawRoundedRect(QRectF(0, 0, 36, 36), 10, 10);
    p.setBrush(QColor("#FFFFFF"));
    p.drawRoundedRect(QRectF(9, 11, 18, 5), 1.5, 1.5);
    p.drawRoundedRect(QRectF(9, 20, 18, 5), 1.5, 1.5);
    return pm;
}

enum MasternodeRole {
    ServiceRole = Qt::UserRole + 1,
    StatusRole,
    StatusKindRole,
    PoseScoreRole,
    MaxPoseRole,
    RegisteredHeightRole,
    LastPaidHeightRole,
    NextPaymentHeightRole,
    NextPaymentSortRole,
    PayoutAddressRole,
    OperatorRewardRole,
    OperatorRewardSortRole,
    CollateralAmountRole,
    CollateralAmountSortRole,
    CollateralAddressRole,
    OwnerAddressRole,
    ProTxHashRole,
    CollateralOutpointRole
};

class MasternodeCardDelegate final : public QStyledItemDelegate
{
public:
    explicit MasternodeCardDelegate(QObject* parent)
        : QStyledItemDelegate(parent)
    {
    }

    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        Q_UNUSED(option);
        Q_UNUSED(index);
        return QSize(0, 210);
    }

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
        const bool selected = option.state & QStyle::State_Selected;
        const QRect card = option.rect.adjusted(5, 4, -5, -4);
        painter->setPen(QPen(selected ? QColor(tc.wine) : QColor(tc.border), 1));
        painter->setBrush(QColor(selected ? tc.panelSoft : tc.panel));
        painter->drawRoundedRect(QRectF(card).adjusted(0.5, 0.5, -0.5, -0.5), 14, 14);

        painter->drawPixmap(QRect(card.left() + 14, card.top() + 12, 36, 36), glyph());

        const QString service = index.data(ServiceRole).toString();
        const QString status = index.data(StatusRole).toString();
        const int statusKind = index.data(StatusKindRole).toInt();
        QColor statusBackground(tc.tealTint);
        const QColor statusForeground(tc.ink);
        if (statusKind == 1) {
            statusBackground = QColor(tc.goldTint);
        } else if (statusKind == 2) {
            statusBackground = QColor(tc.wineTint);
        }

        QFont statusFont = option.font;
        statusFont.setPixelSize(12);
        statusFont.setBold(true);
        const QFontMetrics statusMetrics(statusFont);
        const int headerLeft = card.left() + 62;
        const int headerRight = card.right() - 14;
        const int headerWidth = std::max(0, headerRight - headerLeft);
        const int statusWidth = std::min(statusMetrics.horizontalAdvance(status) + 20,
                                         std::max(0, headerWidth / 3));
        const QRect statusRect(headerRight - statusWidth, card.top() + 18, statusWidth, 24);
        if (statusWidth > 0) {
            painter->setPen(Qt::NoPen);
            painter->setBrush(statusBackground);
            painter->drawRoundedRect(statusRect, 12, 12);
            painter->setFont(statusFont);
            painter->setPen(statusForeground);
            painter->drawText(statusRect.adjusted(6, 0, -6, 0), Qt::AlignCenter,
                              statusMetrics.elidedText(status, Qt::ElideRight,
                                                       std::max(0, statusRect.width() - 12)));
        }

        QFont titleFont = option.font;
        titleFont.setPixelSize(14);
        titleFont.setBold(true);
        painter->setFont(titleFont);
        painter->setPen(QColor(tc.ink));
        const bool showPose = headerWidth >= 300;
        const int poseWidth = showPose ? 80 : 0;
        const int titleRight = statusRect.left() - (showPose ? poseWidth + 16 : 8);
        const QRect titleRect(headerLeft, card.top() + 13,
                              std::max(0, titleRight - headerLeft), 24);
        if (titleRect.width() > 0) {
            painter->drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter,
                              QFontMetrics(titleFont).elidedText(service, Qt::ElideMiddle, titleRect.width()));

            QFont subtitleFont = option.font;
            subtitleFont.setPixelSize(11);
            painter->setFont(subtitleFont);
            painter->setPen(QColor(tc.inkSoft));
            const QString collateral = masternodeText(
                QT_TRANSLATE_NOOP("MasternodeList", "Collateral · %1"))
                .arg(index.data(CollateralOutpointRole).toString());
            const QRect subtitleRect(titleRect.left(), card.top() + 34, titleRect.width(), 18);
            painter->drawText(subtitleRect, Qt::AlignLeft | Qt::AlignVCenter,
                              QFontMetrics(subtitleFont).elidedText(collateral, Qt::ElideMiddle,
                                                                   subtitleRect.width()));
        }

        QFont poseFont = option.font;
        poseFont.setPixelSize(12);
        painter->setFont(poseFont);
        painter->setPen(QColor(tc.inkSoft));
        if (showPose) {
            const QRect poseRect(titleRight + 8, card.top() + 11, poseWidth, 24);
            painter->drawText(poseRect, Qt::AlignRight | Qt::AlignVCenter,
                              masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "PoSe %1"))
                                  .arg(index.data(PoseScoreRole).toInt()));

            const int trackWidth = std::min(64, poseRect.width());
            const QRect trackRect(poseRect.right() - trackWidth + 1, card.top() + 43, trackWidth, 4);
            painter->setPen(Qt::NoPen);
            painter->setBrush(QColor(tc.border));
            painter->drawRoundedRect(trackRect, 2, 2);

            const int poseScore = index.data(PoseScoreRole).toInt();
            const int maxPose = std::max(1, index.data(MaxPoseRole).toInt());
            const int fillWidth = statusKind == 2
                ? std::max(18, std::min(trackWidth, trackWidth * poseScore / maxPose))
                : (poseScore <= 0
                       ? std::min(22, trackWidth)
                       : std::max(10, std::min(trackWidth, trackWidth * poseScore / maxPose)));
            painter->setBrush(QColor(statusKind == 2 ? tc.wine : tc.teal));
            painter->drawRoundedRect(QRect(trackRect.left(), trackRect.top(), fillWidth, trackRect.height()), 2, 2);
        }

        painter->setPen(QPen(QColor(tc.border), 1));
        painter->drawLine(card.left() + 14, card.top() + 58,
                          card.right() - 14, card.top() + 58);

        const auto drawMetric = [&](const QRect& rect, const QString& caption, const QString& value) {
            QFont captionFont = option.font;
            captionFont.setPixelSize(11);
            captionFont.setBold(true);
            painter->setFont(captionFont);
            painter->setPen(QColor(tc.inkSoft));
            const QRect captionRect = rect.adjusted(0, 0, -8, -20);
            painter->drawText(captionRect, Qt::AlignLeft | Qt::AlignVCenter,
                              QFontMetrics(captionFont).elidedText(caption, Qt::ElideRight,
                                                                  std::max(0, captionRect.width())));

            QFont valueFont = option.font;
            valueFont.setPixelSize(12);
            valueFont.setBold(true);
            painter->setFont(valueFont);
            painter->setPen(QColor(tc.ink));
            const QRect valueRect = rect.adjusted(0, 19, -8, 0);
            painter->drawText(valueRect, Qt::AlignLeft | Qt::AlignVCenter,
                              QFontMetrics(valueFont).elidedText(value, Qt::ElideMiddle, valueRect.width()));
        };

        const int contentLeft = card.left() + 16;
        const int contentWidth = card.width() - 32;
        const int quarterWidth = contentWidth / 4;
        const int halfWidth = contentWidth / 2;
        const int rowOneTop = card.top() + 68;
        for (int column = 0; column < 4; ++column) {
            const QRect rect(contentLeft + column * quarterWidth, rowOneTop, quarterWidth, 40);
            if (column == 0)
                drawMetric(rect, masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "REGISTERED")), formatBlockHeight(index.data(RegisteredHeightRole).toInt(), false));
            else if (column == 1)
                drawMetric(rect, masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "LAST PAID")), formatBlockHeight(index.data(LastPaidHeightRole).toInt(), index.data(LastPaidHeightRole).toInt() < 0));
            else if (column == 2)
                drawMetric(rect, masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "NEXT PAYMENT")), formatBlockHeight(index.data(NextPaymentHeightRole).toInt(), index.data(NextPaymentHeightRole).toInt() < 0));
            else
                drawMetric(rect, masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "COLLATERAL")), index.data(CollateralAmountRole).toString());
        }

        drawMetric(QRect(contentLeft, card.top() + 114, halfWidth, 40),
                   masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "PAYOUT ADDRESS")), index.data(PayoutAddressRole).toString());
        drawMetric(QRect(contentLeft + halfWidth, card.top() + 114, halfWidth, 40),
                   masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "OPERATOR REWARD")), index.data(OperatorRewardRole).toString());
        drawMetric(QRect(contentLeft, card.top() + 160, halfWidth, 40),
                   masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "COLLATERAL ADDRESS")), index.data(CollateralAddressRole).toString());
        drawMetric(QRect(contentLeft + halfWidth, card.top() + 160, halfWidth, 40),
                   masternodeText(QT_TRANSLATE_NOOP("MasternodeList", "OWNER ADDRESS")), index.data(OwnerAddressRole).toString());

        painter->restore();
    }

private:
    const QPixmap& glyph() const
    {
        const bool dark = GUIUtil::isDarkMode();
        if (glyph_.isNull() || glyphDark_ != dark) {
            glyph_ = masternodeGlyph();
            glyphDark_ = dark;
        }
        return glyph_;
    }

    mutable QPixmap glyph_;
    mutable bool glyphDark_{false};
};

}

MasternodeList::MasternodeList(const PlatformStyle* platformStyle, QWidget* parent) :
    QWidget(parent),
    nTimeFilterUpdatedDIP3(0),
    nTimeUpdatedDIP3(0),
    fFilterUpdatedDIP3(true),
    ui(new Ui::MasternodeList),
    clientModel(0),
    walletModel(0),
    mnListChanged(true),
    emptyState(0),
    masternodeView(0),
    masternodeModel(0),
    masternodeProxy(0),
    masternodeSort(0),
    masternodeSortDirection(0)
{
    ui->setupUi(this);

    ui->topLayout->setContentsMargins(24, 20, 24, 20);
    ui->topLayout->setSpacing(14);
    ui->verticalLayoutCard->removeItem(ui->horizontalLayout_4);
    ui->verticalLayoutCard->setContentsMargins(14, 10, 14, 14);
    ui->verticalLayoutCard->setSpacing(8);

    auto* filterCard = new QFrame(this);
    filterCard->setObjectName(QStringLiteral("masternodeFilterCard"));
    auto* filterLayout = new QGridLayout(filterCard);
    filterLayout->setContentsMargins(14, 12, 14, 12);
    filterLayout->setHorizontalSpacing(12);
    filterLayout->setVerticalSpacing(10);
    filterLayout->setColumnStretch(0, 1);
    filterLayout->setColumnStretch(1, 1);
    filterLayout->setColumnStretch(2, 1);

    ui->label_filter_2->hide();
    ui->filterLineEditDIP3->setAccessibleName(tr("Filter masternodes"));
    filterLayout->addWidget(ui->filterLineEditDIP3, 0, 0, 1, 3);
    filterLayout->addWidget(ui->checkBoxMyMasternodesOnly, 1, 0);

    masternodeSort = new QComboBox(filterCard);
    masternodeSort->setMinimumSize(150, 34);
    masternodeSort->setAccessibleName(tr("Sort masternodes by"));
    masternodeSort->setToolTip(tr("Sort the masternode list"));
    const auto addSortOption = [this](const QString& text, int role, Qt::SortOrder order) {
        masternodeSort->addItem(text, QVariantList{role, static_cast<int>(order)});
    };
    addSortOption(tr("Service"), ServiceRole, Qt::AscendingOrder);
    addSortOption(tr("Status"), StatusRole, Qt::AscendingOrder);
    addSortOption(tr("PoSe score"), PoseScoreRole, Qt::DescendingOrder);
    addSortOption(tr("Registered"), RegisteredHeightRole, Qt::DescendingOrder);
    addSortOption(tr("Last paid"), LastPaidHeightRole, Qt::DescendingOrder);
    addSortOption(tr("Next payment"), NextPaymentSortRole, Qt::AscendingOrder);
    addSortOption(tr("Payout address"), PayoutAddressRole, Qt::AscendingOrder);
    addSortOption(tr("Operator reward"), OperatorRewardSortRole, Qt::DescendingOrder);
    addSortOption(tr("Collateral amount"), CollateralAmountSortRole, Qt::DescendingOrder);
    addSortOption(tr("Collateral address"), CollateralAddressRole, Qt::AscendingOrder);
    addSortOption(tr("Owner address"), OwnerAddressRole, Qt::AscendingOrder);
    filterLayout->addWidget(masternodeSort, 1, 1, 1, 2);

    masternodeSortDirection = new QToolButton(filterCard);
    masternodeSortDirection->setObjectName(QStringLiteral("masternodeSortDirection"));
    masternodeSortDirection->setFixedSize(36, 34);
    filterLayout->addWidget(masternodeSortDirection, 1, 3);

    auto* countPill = new QFrame(filterCard);
    countPill->setObjectName(QStringLiteral("nodeCountPill"));
    countPill->setFixedHeight(34);
    auto* countLayout = new QHBoxLayout(countPill);
    countLayout->setContentsMargins(12, 0, 12, 0);
    countLayout->setSpacing(4);
    countLayout->addWidget(ui->label_count_2);
    countLayout->addWidget(ui->countLabelDIP3);
    filterLayout->addWidget(countPill, 0, 3);

    ui->topLayout->insertWidget(0, filterCard);
    ui->masternodeContentCard->setMinimumHeight(420);
    ui->masternodeContentCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->topLayout->setStretchFactor(ui->masternodeContentCard, 1);

    if (ui->masternodeContentCard) {
        ui->masternodeContentCard->setAttribute(Qt::WA_StyledBackground, true);
    }

    masternodeModel = new QStandardItemModel(this);
    masternodeProxy = new QSortFilterProxyModel(this);
    masternodeProxy->setSourceModel(masternodeModel);
    masternodeProxy->setDynamicSortFilter(true);
    masternodeProxy->setSortCaseSensitivity(Qt::CaseInsensitive);

    masternodeView = new QListView(ui->masternodeContentCard);
    masternodeView->setObjectName(QStringLiteral("masternodeView"));
    masternodeView->setAccessibleName(tr("Masternode list"));
    masternodeView->setModel(masternodeProxy);
    masternodeView->setItemDelegate(new MasternodeCardDelegate(masternodeView));
    masternodeView->setSelectionMode(QAbstractItemView::SingleSelection);
    masternodeView->setVerticalScrollMode(QAbstractItemView::ScrollPerItem);
    masternodeView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    masternodeView->setUniformItemSizes(true);
    masternodeView->setResizeMode(QListView::Adjust);
    masternodeView->setWrapping(false);
    masternodeView->setSpacing(4);
    masternodeView->setFrameShape(QFrame::NoFrame);
    masternodeView->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->verticalLayoutCard->addWidget(masternodeView, 1);

    emptyState = new QWidget(masternodeView->viewport());
    emptyState->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* emptyLayout = new QVBoxLayout(emptyState);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    emptyLayout->setSpacing(5);
    emptyLayout->addStretch();

    emptyIcon_ = new QLabel(QStringLiteral("▤"), emptyState);
    emptyIcon_->setFixedSize(48, 48);
    emptyIcon_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyIcon_, 0, Qt::AlignHCenter);

    emptyTitle_ = new QLabel(tr("No masternodes found"), emptyState);
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyTitle_);

    emptyDescription_ = new QLabel(
        tr("Masternodes matching your filters will appear here"), emptyState);
    emptyDescription_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyDescription_);
    emptyLayout->addStretch();

    const auto addCardShadow = [](QWidget* card) {
        auto* shadow = new QGraphicsDropShadowEffect(card);
        shadow->setBlurRadius(20);
        shadow->setOffset(0, 5);
        shadow->setColor(QColor(65, 37, 52, 24));
        card->setGraphicsEffect(shadow);
    };
    addCardShadow(filterCard);

    QAction* copyProTxHashAction = new QAction(tr("Copy ProTx Hash"), this);
    QAction* copyCollateralOutpointAction = new QAction(tr("Copy Collateral Outpoint"), this);
    contextMenuDIP3 = new QMenu(this);
    contextMenuDIP3->addAction(copyProTxHashAction);
    contextMenuDIP3->addAction(copyCollateralOutpointAction);
    connect(copyProTxHashAction, &QAction::triggered, this, &MasternodeList::copyProTxHash_clicked);
    connect(copyCollateralOutpointAction, &QAction::triggered, this, &MasternodeList::copyCollateralOutpoint_clicked);
    connect(masternodeSort, qOverload<int>(&QComboBox::activated),
            this, &MasternodeList::sortMasternodes);
    connect(masternodeSortDirection, &QToolButton::clicked,
            this, &MasternodeList::toggleMasternodeSortOrder);
    connect(masternodeView, &QListView::customContextMenuRequested,
            this, &MasternodeList::showContextMenuDIP3);
    connect(masternodeView, &QListView::activated, this, [this](const QModelIndex& index) {
        updateSelection(index);
        extraInfoDIP3_clicked();
    });
    connect(masternodeView->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &MasternodeList::updateSelection);
    //always start with "my znodes only" checked
    ui->checkBoxMyMasternodesOnly->setChecked(true);
    sortMasternodes(masternodeSort->currentIndex());
    updateEmptyState();

    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MasternodeList::updateDIP3ListScheduled);
    timer->start(1000);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &MasternodeList::applyTheme);
    applyTheme();
}

void MasternodeList::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
QWidget#MasternodeList {
  background: $BG;
}
QFrame#masternodeFilterCard,
QFrame#masternodeContentCard {
  background: $PANEL;
  border: 1px solid $BORDER;
  border-radius: 16px;
}
QLineEdit#filterLineEditDIP3 {
  min-height: 34px;
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 9px;
  padding: 0 11px;
  color: $INK_SOFT;
  font-size: 12px;
  selection-background-color: $WINE;
}
QLineEdit#filterLineEditDIP3:focus {
  background: $PANEL;
  border-color: $WINE;
}
QCheckBox#checkBoxMyMasternodesOnly {
  color: $INK_SOFT;
  font-size: 12px;
  font-weight: 600;
  spacing: 7px;
  background: transparent;
}
QCheckBox#checkBoxMyMasternodesOnly::indicator {
  width: 14px;
  height: 14px;
  border: 1px solid $INK_FAINT;
  border-radius: 4px;
  background: $PANEL;
}
QCheckBox#checkBoxMyMasternodesOnly::indicator:checked {
  image: url(:/images/checkbox_checked_light);
  border: none;
}
QComboBox {
  min-height: 34px;
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 9px;
  padding: 0 10px;
  color: $INK_SOFT;
  font-size: 12px;
}
QComboBox:focus {
  background: $PANEL;
  border-color: $WINE;
}
QComboBox::drop-down {
  border: none;
  width: 24px;
}
QToolButton#masternodeSortDirection {
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 9px;
  color: $INK;
  font-size: 16px;
  font-weight: 700;
}
QToolButton#masternodeSortDirection:hover,
QToolButton#masternodeSortDirection:focus {
  background: $PANEL;
  border-color: $WINE;
}
QFrame#nodeCountPill {
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 9px;
}
QFrame#nodeCountPill QLabel {
  color: $INK_SOFT;
  background: transparent;
  font-size: 12px;
  font-weight: 600;
}
QListView#masternodeView,
QListView#masternodeView::viewport {
  background: transparent;
  border: none;
  outline: none;
}
QListView#masternodeView::item {
  background: transparent;
  border: none;
}
QScrollBar:vertical {
  background: $PANEL_SOFT;
  width: 12px;
  border-radius: 6px;
}
QScrollBar::handle:vertical {
  background: $INK_FAINT;
  border-radius: 6px;
  margin: 2px;
  min-height: 32px;
}
QScrollBar::handle:vertical:hover {
  background: $INK_SOFT;
}
QScrollBar::add-line,
QScrollBar::sub-line {
  width: 0;
  height: 0;
}
    )")));

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: $WINE_TINT; color: $WINE; border-radius: 12px;"
            "font-size: 20px; font-weight: 700;")));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: transparent; border: none;"
            "color: $INK_SOFT; font-size: 14px; font-weight: 700;")));
    }
    if (emptyDescription_) {
        emptyDescription_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: transparent; border: none;"
            "color: $INK_FAINT; font-size: 12px;")));
    }

    if (masternodeView && masternodeView->viewport())
        masternodeView->viewport()->update();
    QTimer::singleShot(0, this, &MasternodeList::updateEmptyState);
}

MasternodeList::~MasternodeList()
{
    delete ui;
}

void MasternodeList::setClientModel(ClientModel* model)
{
    if (clientModel == model)
        return;
    if (clientModel)
        disconnect(clientModel, nullptr, this, nullptr);

    this->clientModel = model;
    mnListChanged = true;
    if (model) {
        // try to update list when masternode count changes
        connect(clientModel, &ClientModel::masternodeListChanged,
                this, &MasternodeList::handleMasternodeListChanged,
                Qt::QueuedConnection);
    }
}

void MasternodeList::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    nTimeFilterUpdatedDIP3 = GetTime() - MASTERNODELIST_FILTER_COOLDOWN_SECONDS;
    fFilterUpdatedDIP3 = true;
}

void MasternodeList::showContextMenuDIP3(const QPoint& pos)
{
    if (!masternodeView)
        return;

    const bool keyboardRequest = pos.isNull() || pos.x() < 0 || pos.y() < 0;
    QModelIndex index = keyboardRequest ? masternodeView->currentIndex()
                                       : masternodeView->indexAt(pos);
    QPoint menuPosition = pos;
    if (!index.isValid())
        return;
    if (keyboardRequest)
        menuPosition = masternodeView->visualRect(index).center();

    masternodeView->setCurrentIndex(index);
    updateSelection(index);
    contextMenuDIP3->exec(masternodeView->viewport()->mapToGlobal(menuPosition));
}

void MasternodeList::updateSelection(const QModelIndex& index)
{
    selectedProTxHash = index.isValid() ? index.data(ProTxHashRole).toString() : QString();
}

void MasternodeList::sortMasternodes(int index)
{
    if (!masternodeSort || index < 0)
        return;

    const QVariantList sortSpec = masternodeSort->itemData(index).toList();
    if (sortSpec.size() != 2)
        return;

    masternodeSortOrder = static_cast<Qt::SortOrder>(sortSpec.at(1).toInt());
    updateSortDirectionButton();
    applyMasternodeSort();
}

void MasternodeList::applyMasternodeSort()
{
    if (!masternodeProxy || !masternodeSort || masternodeSort->currentIndex() < 0)
        return;

    const QVariantList sortSpec = masternodeSort->currentData().toList();
    if (sortSpec.size() != 2)
        return;

    masternodeProxy->setSortRole(sortSpec.at(0).toInt());
    masternodeProxy->sort(0, masternodeSortOrder);
}

void MasternodeList::toggleMasternodeSortOrder()
{
    masternodeSortOrder = masternodeSortOrder == Qt::AscendingOrder
        ? Qt::DescendingOrder
        : Qt::AscendingOrder;
    updateSortDirectionButton();
    applyMasternodeSort();
}

void MasternodeList::updateSortDirectionButton()
{
    if (!masternodeSortDirection)
        return;

    const bool ascending = masternodeSortOrder == Qt::AscendingOrder;
    masternodeSortDirection->setText(ascending ? QStringLiteral("↑") : QStringLiteral("↓"));
    const QString description = ascending ? tr("Sort ascending") : tr("Sort descending");
    masternodeSortDirection->setAccessibleName(description);
    masternodeSortDirection->setToolTip(description);
}

void MasternodeList::handleMasternodeListChanged()
{
    mnListChanged = true;
}

void MasternodeList::updateDIP3ListScheduled()
{
    if (!clientModel || ShutdownRequested()) {
        return;
    }

    // To prevent high cpu usage update only once in MASTERNODELIST_FILTER_COOLDOWN_SECONDS seconds
    // after filter was last changed unless we want to force the update.
    if (fFilterUpdatedDIP3) {
        int64_t nSecondsToWait = nTimeFilterUpdatedDIP3 - GetTime() + MASTERNODELIST_FILTER_COOLDOWN_SECONDS;
        if (nSecondsToWait <= 0) {
            if (updateDIP3List())
                fFilterUpdatedDIP3 = false;
        }
    } else if (mnListChanged) {
        int64_t nMnListUpdateSecods = masternodeSync.IsBlockchainSynced() ? MASTERNODELIST_UPDATE_SECONDS : MASTERNODELIST_UPDATE_SECONDS*10;
        int64_t nSecondsToWait = nTimeUpdatedDIP3 - GetTime() + nMnListUpdateSecods;

        if (nSecondsToWait <= 0) {
            if (updateDIP3List())
                mnListChanged = false;
        }
    }
}

bool MasternodeList::updateDIP3List()
{
    if (!clientModel || ShutdownRequested()) {
        return false;
    }

    CDeterministicMNList mnList;
    if (!clientModel->tryGetMasternodeList(mnList))
        return false;
    if (mnList.GetAllMNsCount() == 0) {
        clientModel->refreshMasternodeList();
        if (!clientModel->tryGetMasternodeList(mnList))
            return false;
    }
    std::map<uint256, CTxDestination> mapCollateralDests;
    std::map<uint256, CAmount> mapCollateralAmounts;

    {
        TRY_LOCK(cs_main, lock_main);
        if (!lock_main)
            return false;
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
            CTxDestination collateralDest;
            Coin coin;
            if (!GetUTXOCoin(dmn->collateralOutpoint, coin))
                return;
            mapCollateralAmounts.emplace(dmn->proTxHash, coin.out.nValue);
            if (ExtractDestination(coin.out.scriptPubKey, collateralDest)) {
                mapCollateralDests.emplace(dmn->proTxHash, collateralDest);
            }
        });
    }

    auto projectedPayees = mnList.GetProjectedMNPayees(mnList.GetValidMNsCount());
    std::map<uint256, int> nextPayments;
    for (size_t i = 0; i < projectedPayees.size(); ++i) {
        const auto& dmn = projectedPayees[i];
        nextPayments.emplace(dmn->proTxHash, mnList.GetHeight() + (int)i + 1);
    }

    std::set<COutPoint> setOutpts;
    std::set<CKeyID> setMyKeys;
    const bool filterMyMasternodes = walletModel && ui->checkBoxMyMasternodesOnly->isChecked();
    if (filterMyMasternodes) {
        std::vector<COutPoint> vOutpts;
        if (!walletModel->listProTxCoins(vOutpts))
            return false;
        for (const auto& outpt : vOutpts) {
            setOutpts.emplace(outpt);
        }
        if (CWallet* wallet = walletModel->getWallet())
            wallet->GetKeys(setMyKeys);
    }

    auto isScriptMine = [&](const CScript& script) {
        CTxDestination dest;
        if (ExtractDestination(script, dest)) {
            if (const CKeyID* keyID = boost::get<CKeyID>(&dest))
                return setMyKeys.count(*keyID) > 0;
        }
        return walletModel->IsSpendable(script);
    };

    const Consensus::Params& params = ::Params().GetConsensus();
    const int maxPose = std::max(100, mnList.CalcMaxPoSePenalty());
    QList<QStandardItem*> modelRows;
    int matched = 0;

    auto processMN = [&](const CDeterministicMNCPtr& dmn) {
        if (filterMyMasternodes) {
            bool fMyMasternode = setOutpts.count(dmn->collateralOutpoint) ||
                setMyKeys.count(dmn->pdmnState->keyIDOwner) ||
                isScriptMine(dmn->pdmnState->scriptPayout) ||
                isScriptMine(dmn->pdmnState->scriptOperatorPayout);
            if (!fMyMasternode) return;
        }

        const QString address = QString::fromStdString(dmn->pdmnState->addr.ToString());
        int statusKind = 1;
        QString status = tr("Pre-enabled");
        if (mnList.IsMNValid(dmn)) {
            statusKind = 0;
            status = tr("Enabled");
        } else if (mnList.IsMNPoSeBanned(dmn)) {
            statusKind = 2;
            status = tr("PoSe Banned");
        }

        const QString registered = formatBlockHeight(dmn->pdmnState->nRegisteredHeight, false);
        const bool lastPaidNone = dmn->pdmnState->nLastPaidHeight < params.DIP0003EnforcementHeight;
        const QString lastPaid = formatBlockHeight(dmn->pdmnState->nLastPaidHeight, lastPaidNone);
        const auto nextPaymentIt = nextPayments.find(dmn->proTxHash);
        const bool nextUnknown = nextPaymentIt == nextPayments.end();
        const QString nextPayment = formatBlockHeight(
            nextUnknown ? 0 : nextPaymentIt->second, nextUnknown);

        CTxDestination payeeDest;
        QString payeeStr = QStringLiteral("-");
        if (ExtractDestination(dmn->pdmnState->scriptPayout, payeeDest)) {
            payeeStr = QString::fromStdString(CBitcoinAddress(payeeDest).ToString());
        }

        const QString operatorRewardPercent =
            QString::number(dmn->nOperatorReward / 100.0, 'f', 2) + QLatin1Char('%');
        QString operatorReward = tr("None");
        if (dmn->nOperatorReward) {
            if (dmn->pdmnState->scriptOperatorPayout == CScript()) {
                operatorReward = tr("%1, not claimed").arg(operatorRewardPercent);
            } else {
                CTxDestination operatorDest;
                operatorReward = ExtractDestination(dmn->pdmnState->scriptOperatorPayout, operatorDest)
                    ? tr("%1 to %2").arg(operatorRewardPercent,
                        QString::fromStdString(CBitcoinAddress(operatorDest).ToString()))
                    : tr("%1 to unknown address").arg(operatorRewardPercent);
            }
        }

        QString collateralAddr = QStringLiteral("-");
        auto collateralDestIt = mapCollateralDests.find(dmn->proTxHash);
        if (collateralDestIt != mapCollateralDests.end()) {
            collateralAddr = QString::fromStdString(CBitcoinAddress(collateralDestIt->second).ToString());
        }

        QString collateralAmount = QStringLiteral("-");
        auto collateralAmountIt = mapCollateralAmounts.find(dmn->proTxHash);
        if (collateralAmountIt != mapCollateralAmounts.end()) {
            collateralAmount = QStringLiteral("%1 FIRO").arg(
                QLocale::system().toString(
                    static_cast<qlonglong>(collateralAmountIt->second / COIN)));
        }

        const QString ownerStr = QString::fromStdString(CBitcoinAddress(dmn->pdmnState->keyIDOwner).ToString());
        const QString proTxHash = QString::fromStdString(dmn->proTxHash.ToString());
        const QString collateralOutpoint = QString::fromStdString(dmn->collateralOutpoint.ToStringShort());

        if (strCurrentFilterDIP3 != "") {
            const QString strToFilter =
                address + QLatin1Char(' ') +
                status + QLatin1Char(' ') +
                QString::number(dmn->pdmnState->nPoSePenalty) + QLatin1Char(' ') +
                registered + QLatin1Char(' ') +
                QString::number(dmn->pdmnState->nRegisteredHeight) + QLatin1Char(' ') +
                lastPaid + QLatin1Char(' ') +
                (lastPaidNone ? QString() : QString::number(dmn->pdmnState->nLastPaidHeight)) + QLatin1Char(' ') +
                nextPayment + QLatin1Char(' ') +
                (nextUnknown ? QString() : QString::number(nextPaymentIt->second)) + QLatin1Char(' ') +
                payeeStr + QLatin1Char(' ') +
                operatorReward + QLatin1Char(' ') +
                collateralAmount + QLatin1Char(' ') +
                collateralAddr + QLatin1Char(' ') +
                ownerStr + QLatin1Char(' ') +
                proTxHash;
            if (!strToFilter.contains(strCurrentFilterDIP3, Qt::CaseInsensitive))
                return;
        }

        ++matched;
        auto* item = new QStandardItem(address);
        item->setEditable(false);
        item->setData(address, ServiceRole);
        item->setData(status, StatusRole);
        item->setData(statusKind, StatusKindRole);
        item->setData(dmn->pdmnState->nPoSePenalty, PoseScoreRole);
        item->setData(maxPose, MaxPoseRole);
        item->setData(dmn->pdmnState->nRegisteredHeight, RegisteredHeightRole);
        item->setData(lastPaidNone ? -1 : dmn->pdmnState->nLastPaidHeight, LastPaidHeightRole);
        item->setData(nextUnknown ? -1 : nextPaymentIt->second, NextPaymentHeightRole);
        item->setData(nextUnknown ? std::numeric_limits<int>::max() : nextPaymentIt->second,
                      NextPaymentSortRole);
        item->setData(payeeStr, PayoutAddressRole);
        item->setData(operatorReward, OperatorRewardRole);
        item->setData(dmn->nOperatorReward, OperatorRewardSortRole);
        item->setData(collateralAmount, CollateralAmountRole);
        item->setData(collateralAmountIt == mapCollateralAmounts.end()
                          ? static_cast<qlonglong>(-1)
                          : static_cast<qlonglong>(collateralAmountIt->second),
                      CollateralAmountSortRole);
        item->setData(collateralAddr, CollateralAddressRole);
        item->setData(ownerStr, OwnerAddressRole);
        item->setData(proTxHash, ProTxHashRole);
        item->setData(collateralOutpoint, CollateralOutpointRole);

        const QString tooltip = tr(
            "Service: %1\nStatus: %2\nPoSe score: %3\nRegistered: %4\nLast paid: %5\n"
            "Next payment: %6\nPayout address: %7\nOperator reward: %8\nCollateral: %9\n"
            "Collateral address: %10\nOwner address: %11\nProTx hash: %12\nCollateral outpoint: %13")
            .arg(address)
            .arg(status)
            .arg(dmn->pdmnState->nPoSePenalty)
            .arg(registered)
            .arg(lastPaid)
            .arg(nextPayment)
            .arg(payeeStr)
            .arg(operatorReward)
            .arg(collateralAmount)
            .arg(collateralAddr)
            .arg(ownerStr)
            .arg(proTxHash)
            .arg(collateralOutpoint);
        item->setToolTip(tooltip);
        item->setData(tr("%1, %2").arg(address, status), Qt::AccessibleTextRole);
        item->setData(tooltip, Qt::AccessibleDescriptionRole);
        modelRows.append(item);
    };

    mnList.ForEachMN(false, processMN);

    const QString selectionToRestore = selectedProTxHash;
    QString topRowToRestore;
    if (masternodeView) {
        const QModelIndex topIndex = masternodeView->indexAt(
            QPoint(1, masternodeView->spacing() + 1));
        if (topIndex.isValid())
            topRowToRestore = topIndex.data(ProTxHashRole).toString();
    }
    masternodeProxy->setDynamicSortFilter(false);
    masternodeModel->clear();
    if (!modelRows.isEmpty())
        masternodeModel->invisibleRootItem()->appendRows(modelRows);
    masternodeProxy->setDynamicSortFilter(true);
    applyMasternodeSort();

    ui->countLabelDIP3->setText(QString::number(matched));
    QModelIndex restoredSelection;
    QModelIndex restoredTopRow;
    for (int row = 0; row < masternodeModel->rowCount(); ++row) {
        const QModelIndex sourceIndex = masternodeModel->index(row, 0);
        const QString proTxHash = sourceIndex.data(ProTxHashRole).toString();
        if (proTxHash == selectionToRestore)
            restoredSelection = masternodeProxy->mapFromSource(sourceIndex);
        if (proTxHash == topRowToRestore)
            restoredTopRow = masternodeProxy->mapFromSource(sourceIndex);
    }
    if (restoredSelection.isValid()) {
        masternodeView->setCurrentIndex(restoredSelection);
        masternodeView->selectionModel()->select(
            restoredSelection, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    } else {
        selectedProTxHash.clear();
    }
    if (restoredTopRow.isValid())
        masternodeView->scrollTo(restoredTopRow, QAbstractItemView::PositionAtTop);
    nTimeUpdatedDIP3 = GetTime();
    updateEmptyState();
    return true;
}

void MasternodeList::on_filterLineEditDIP3_textChanged(const QString& strFilterIn)
{
    strCurrentFilterDIP3 = strFilterIn;
    nTimeFilterUpdatedDIP3 = GetTime();
    fFilterUpdatedDIP3 = true;
}

void MasternodeList::on_checkBoxMyMasternodesOnly_stateChanged(int state)
{
    // no cooldown
    nTimeFilterUpdatedDIP3 = GetTime() - MASTERNODELIST_FILTER_COOLDOWN_SECONDS;
    fFilterUpdatedDIP3 = true;
}

CDeterministicMNCPtr MasternodeList::GetSelectedDIP3MN()
{
    if (!clientModel || selectedProTxHash.isEmpty()) {
        return nullptr;
    }

    uint256 proTxHash;
    proTxHash.SetHex(selectedProTxHash.toStdString());

    CDeterministicMNList mnList;
    if (!clientModel->tryGetMasternodeList(mnList))
        return nullptr;
    return mnList.GetMN(proTxHash);
}

void MasternodeList::extraInfoDIP3_clicked()
{
    auto dmn = GetSelectedDIP3MN();
    if (!dmn) {
        return;
    }

    UniValue json(UniValue::VOBJ);
    dmn->ToJson(json);

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Additional information for DIP3 Masternode %1").arg(QString::fromStdString(dmn->proTxHash.ToString())));
    dialog.setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog { background: $BG; }
        QTextEdit#mnDetailText {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 14px;
            padding: 14px 16px;
            color: $INK;
            selection-background-color: $WINE_TINT;
            selection-color: $INK;
        }
    )")));

    auto *layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(14);

    auto *detailText = new QTextEdit(&dialog);
    detailText->setObjectName(QStringLiteral("mnDetailText"));
    detailText->setReadOnly(true);
    detailText->setFrameShape(QFrame::NoFrame);
    QFont monoFont(QStringLiteral("monospace"));
    monoFont.setStyleHint(QFont::Monospace);
    detailText->setFont(monoFont);
    detailText->setPlainText(QString::fromStdString(json.write(2)));
    layout->addWidget(detailText);

    auto *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &dialog);
    if (QPushButton *okButton = buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("8px 24px")));
        okButton->setCursor(Qt::PointingHandCursor);
    }
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    layout->addWidget(buttonBox);

    const QScreen *screen = this->screen();
    if (!screen) {
        screen = QGuiApplication::screenAt(QCursor::pos());
    }
    if (!screen) {
        screen = QGuiApplication::primaryScreen();
    }
    const QSize avail = screen ? screen->availableGeometry().size() : QSize(1200, 800);
    const int dialogWidth = qMin(640, avail.width() - 80);
    const int maxHeight = static_cast<int>(avail.height() * 0.85);

    dialog.resize(dialogWidth, 400);
    dialog.ensurePolished();
    layout->activate();

    const QMargins textMargins = detailText->contentsMargins();
    QTextDocument *doc = detailText->document();
    doc->setTextWidth(detailText->width() - textMargins.left() - textMargins.right());
    const int contentHeight = qRound(doc->size().height()) + textMargins.top() + textMargins.bottom();

    const int chrome = dialog.height() - detailText->height();
    const int dialogHeight = qBound(280, contentHeight + chrome, maxHeight);
    dialog.resize(dialogWidth, dialogHeight);

    dialog.exec();
}

void MasternodeList::copyProTxHash_clicked()
{
    const QModelIndex index = masternodeView ? masternodeView->currentIndex() : QModelIndex();
    if (!index.isValid()) {
        return;
    }

    QApplication::clipboard()->setText(index.data(ProTxHashRole).toString());
}

void MasternodeList::copyCollateralOutpoint_clicked()
{
    const QModelIndex index = masternodeView ? masternodeView->currentIndex() : QModelIndex();
    if (!index.isValid()) {
        return;
    }

    QApplication::clipboard()->setText(index.data(CollateralOutpointRole).toString());
}

void MasternodeList::updateEmptyState()
{
    if (!emptyState || !masternodeView)
        return;

    emptyState->setGeometry(masternodeView->viewport()->rect());
    emptyState->setVisible(!masternodeProxy || masternodeProxy->rowCount() == 0);
    if (emptyState->isVisible())
        emptyState->raise();
}

void MasternodeList::resizeEvent(QResizeEvent* event) 
{
    QWidget::resizeEvent(event);
    updateEmptyState();
}
