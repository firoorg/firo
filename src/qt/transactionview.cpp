// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionview.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactiondescdialog.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"


#include <QComboBox>
#include <QAbstractItemModel>
#include <QCoreApplication>
#include <QDateTimeEdit>
#include <QDesktopServices>
#include <QDoubleValidator>
#include <QEvent>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QPoint>
#include <QScrollBar>
#include <QSizePolicy>
#include <QTableView>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QPainter>
#include <QPainterPath>
#include <QCalendarWidget>
#include <QGraphicsDropShadowEffect>
#include <QGridLayout>
#include <QPushButton>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QDateTime>
#include <algorithm>

namespace {
char const * CopyLabelText{"Copy label"};
char const * CopyRapText{"Copy RAP address/label"};
}

namespace {
class TransactionRowCardDelegate final : public QStyledItemDelegate
{
public:
    explicit TransactionRowCardDelegate(QTableView* view)
        : QStyledItemDelegate(view)
        , view_(view)
    {
    }

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);
        painter->setClipRect(option.rect, Qt::IntersectClip);

        const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
        const bool selected = option.state & QStyle::State_Selected;
        const int txType = index.data(TransactionTableModel::TypeRole).toInt();
        const qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        const bool incoming = isIncoming(txType);
        const bool mined = txType == TransactionRecord::Generated;
        const bool positive = incoming || mined || amount > 0;

        painter->fillRect(option.rect, QColor(tc.panel));

        if (view_) {
            const QRect left = view_->visualRect(index.sibling(index.row(), TransactionTableModel::Date));
            const QRect right = view_->visualRect(index.sibling(index.row(), TransactionTableModel::Amount));
            const QRect card(left.left() + 4, option.rect.top() + 5,
                             std::max(40, right.right() - left.left() - 8),
                             option.rect.height() - 10);
            QPainterPath cardPath;
            cardPath.addRoundedRect(QRectF(card).adjusted(0.5, 0.5, -0.5, -0.5), 14, 14);
            painter->setPen(QPen(selected ? QColor(tc.wine) : QColor(tc.border), 1));
            painter->setBrush(selected ? QColor(tc.panelSoft) : QColor(tc.panel));
            painter->drawPath(cardPath);
        }

        switch (index.column()) {
        case TransactionTableModel::Date: {
            QRect icon(option.rect.left() + 14, option.rect.center().y() - 16, 32, 32);
            painter->setPen(Qt::NoPen);
            painter->setBrush(positive ? QColor(tc.tealTint) : QColor(tc.wineTint));
            painter->drawRoundedRect(icon, 10, 10);
            QFont iconFont = option.font;
            iconFont.setPixelSize(14);
            iconFont.setBold(true);
            painter->setFont(iconFont);
            painter->setPen(positive ? QColor(tc.teal) : QColor(tc.wine));
            painter->drawText(icon, Qt::AlignCenter,
                              mined ? QStringLiteral("↗")
                                    : incoming ? QStringLiteral("↙")
                                               : QStringLiteral("↗"));

            const QDateTime dt = index.data(TransactionTableModel::DateRole).toDateTime();
            QFont dateFont = option.font;
            dateFont.setPixelSize(12);
            dateFont.setBold(true);
            painter->setFont(dateFont);
            painter->setPen(QColor(tc.ink));
            const int metadataWidth = 30 +
                (index.data(TransactionTableModel::InstantSendRole).toBool() ? 20 : 0) +
                (index.data(TransactionTableModel::WatchonlyRole).toBool() ? 20 : 0);
            const QRect dateRect(icon.right() + 10, option.rect.top() + 14,
                                 option.rect.right() - icon.right() - metadataWidth, 18);
            painter->drawText(dateRect, Qt::AlignLeft | Qt::AlignVCenter,
                              dt.isValid() ? QLocale::system().toString(dt.date(), QLocale::ShortFormat)
                                           : index.data(Qt::DisplayRole).toString());

            QFont timeFont = option.font;
            timeFont.setPixelSize(12);
            timeFont.setBold(false);
            painter->setFont(timeFont);
            painter->setPen(QColor(tc.inkFaint));
            const QRect timeRect(dateRect.left(), dateRect.bottom() - 2, dateRect.width(), 16);
            painter->drawText(timeRect, Qt::AlignLeft | Qt::AlignVCenter,
                              dt.isValid() ? QLocale::system().toString(dt.time(), QLocale::ShortFormat) : QString());

            int iconRight = option.rect.right() - 6;
            const auto paintMetadataIcon = [&](const QVariant& decoration) {
                const QRect rect(iconRight - 16, option.rect.center().y() - 8, 16, 16);
                if (paintDecorationIcon(painter, decoration, rect))
                    iconRight -= 20;
            };
            paintMetadataIcon(index.sibling(index.row(), TransactionTableModel::Status)
                                  .data(TransactionTableModel::RawDecorationRole));
            paintMetadataIcon(index.data(TransactionTableModel::InstantSendDecorationRole));
            paintMetadataIcon(index.data(TransactionTableModel::WatchonlyDecorationRole));
            break;
        }
        case TransactionTableModel::Type: {
            const QString displayText = index.data(Qt::DisplayRole).toString();
            QFont badgeFont = option.font;
            badgeFont.setPixelSize(12);
            badgeFont.setBold(true);
            painter->setFont(badgeFont);
            const QFontMetrics fm(badgeFont);
            const QString text = fm.elidedText(displayText, Qt::ElideRight,
                                                std::max(0, option.rect.width() - 34));
            const int w = std::min(option.rect.width() - 16, fm.boundingRect(text).width() + 18);
            const QRect badge(option.rect.left() + 6,
                              option.rect.center().y() - 11, w, 22);
            painter->setPen(Qt::NoPen);
            painter->setBrush(positive ? QColor(tc.tealTint) : QColor(tc.wineTint));
            painter->drawRoundedRect(badge, 11, 11);
            painter->setPen(positive ? QColor(tc.teal) : QColor(tc.wine));
            painter->drawText(badge, Qt::AlignCenter, text);
            break;
        }
        case TransactionTableModel::ToAddress: {
            const QString text = index.data(Qt::DisplayRole).toString();
            const QRect iconRect(option.rect.left() + 10, option.rect.center().y() - 7, 14, 14);
            painter->setPen(QPen(QColor(tc.inkFaint), 1.2));
            painter->setBrush(Qt::NoBrush);
            painter->drawRoundedRect(iconRect, 3, 3);
            painter->drawLine(iconRect.left() + 3, iconRect.top() + 4,
                              iconRect.right() - 3, iconRect.top() + 4);
            painter->drawLine(iconRect.left() + 3, iconRect.top() + 8,
                              iconRect.right() - 3, iconRect.top() + 8);

            QFont addrFont = GUIUtil::fixedPitchFont();
            addrFont.setPixelSize(12);
            painter->setFont(addrFont);
            painter->setPen(QColor(tc.ink));
            const QRect textRect(iconRect.right() + 8, option.rect.top(),
                                 option.rect.right() - iconRect.right() - 16,
                                 option.rect.height());
            painter->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft,
                              QFontMetrics(addrFont).elidedText(text, Qt::ElideMiddle, textRect.width()));
            break;
        }
        case TransactionTableModel::Amount: {
            const QString caption = positive
                ? QCoreApplication::translate("TransactionView", "RECEIVED")
                : QCoreApplication::translate("TransactionView", "SENT");
            QFont capFont = option.font;
            capFont.setPixelSize(12);
            capFont.setBold(true);
            painter->setFont(capFont);
            painter->setPen(QColor(tc.inkFaint));
            const QRect capRect = option.rect.adjusted(8, 12, -14, -28);
            painter->drawText(capRect, Qt::AlignRight | Qt::AlignVCenter, caption);

            QString amountText = index.data(Qt::DisplayRole).toString();
            amountText.replace(QLatin1Char('('), QString());
            amountText.replace(QLatin1Char(')'), QString());
            if (amount > 0 && !amountText.startsWith(QLatin1Char('+')))
                amountText.prepend(QLatin1Char('+'));
            QFont amtFont = option.font;
            amtFont.setPixelSize(14);
            amtFont.setBold(true);
            painter->setFont(amtFont);
            painter->setPen(amount < 0 ? QColor(tc.wine) : QColor(tc.teal));
            const QRect amtRect = option.rect.adjusted(8, 28, -14, -12);
            painter->drawText(amtRect, Qt::AlignRight | Qt::AlignVCenter, amountText);
            break;
        }
        default:
            break;
        }

        painter->restore();
    }

private:
    static bool isIncoming(int txType)
    {
        switch (txType) {
        case TransactionRecord::Generated:
        case TransactionRecord::RecvWithAddress:
        case TransactionRecord::RecvFromOther:
        case TransactionRecord::RecvWithPcode:
        case TransactionRecord::RecvSpark:
            return true;
        default:
            return false;
        }
    }

    static bool paintDecorationIcon(QPainter* painter, const QVariant& decoration, const QRect& rect)
    {
        if (!decoration.canConvert<QIcon>())
            return false;
        const QIcon icon = qvariant_cast<QIcon>(decoration);
        if (icon.isNull())
            return false;
        GUIUtil::paintThemedStatusIcon(painter, icon, rect);
        return true;
    }

    QTableView* view_;
};

}

TransactionView::TransactionView(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    model(0),
    transactionProxyModel(0),
    transactionView(0),
    sortDirectionButton(0),
    exportButton(0),
    emptyState(0),
    abandonAction(0)
{
    setObjectName(QStringLiteral("TransactionView"));
    setContentsMargins(0,0,0,0);

    QFrame* filterCard = new QFrame(this);
    filterCard->setObjectName("filterCard");

    headerLayout = new QGridLayout(filterCard);
    headerLayout->setContentsMargins(14,14,14,14);
    headerLayout->setHorizontalSpacing(12);
    headerLayout->setVerticalSpacing(10);

    auto pillify = [](QComboBox* cb){ cb->setMinimumHeight(36); cb->setIconSize(QSize(16,16)); };

    watchOnlyWidget = new QComboBox(this);
    pillify(watchOnlyWidget);
    watchOnlyWidget->setFixedWidth(48);
    watchOnlyWidget->setToolTip(tr("Filter by watch-only involvement"));
    watchOnlyWidget->addItem("", TransactionFilterProxy::WatchOnlyFilter_All);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_plus"), "", TransactionFilterProxy::WatchOnlyFilter_Yes);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_minus"), "", TransactionFilterProxy::WatchOnlyFilter_No);
    headerLayout->addWidget(watchOnlyWidget, 0, 0);

    instantsendWidget = new QComboBox(this);
    pillify(instantsendWidget);
    instantsendWidget->setMinimumWidth(110);
    instantsendWidget->setToolTip(tr("Filter by InstantSend status"));
    instantsendWidget->addItem(tr("Any InstantSend status"), TransactionFilterProxy::InstantSendFilter_All);
    instantsendWidget->addItem(tr("Locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_Yes);
    instantsendWidget->addItem(tr("Not locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_No);
    headerLayout->addWidget(instantsendWidget, 0, 1);

    dateWidget = new QComboBox(this);
    pillify(dateWidget);
    dateWidget->setMinimumWidth(110);
    dateWidget->setToolTip(tr("Filter by date"));
    dateWidget->addItem(tr("Any date"), All);
    dateWidget->addItem(tr("Today"), Today);
    dateWidget->addItem(tr("This week"), ThisWeek);
    dateWidget->addItem(tr("This month"), ThisMonth);
    dateWidget->addItem(tr("Last month"), LastMonth);
    dateWidget->addItem(tr("This year"), ThisYear);
    dateWidget->addItem(tr("Range..."), Range);
    headerLayout->addWidget(dateWidget, 0, 2);

    typeWidget = new QComboBox(this);
    pillify(typeWidget);
    typeWidget->setMinimumWidth(110);
    typeWidget->setToolTip(tr("Filter by transaction type"));
    typeWidget->addItem(tr("Any type"), TransactionFilterProxy::ALL_TYPES);
    typeWidget->addItem(tr("Received with"),
                        TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress) |
                        TransactionFilterProxy::TYPE(TransactionRecord::RecvFromOther));
    typeWidget->addItem(tr("Sent to"),
                        TransactionFilterProxy::TYPE(TransactionRecord::SendToAddress) |
                        TransactionFilterProxy::TYPE(TransactionRecord::SendToOther));
    typeWidget->addItem(tr("To yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SendToSelf));
    typeWidget->addItem(tr("Mined"), TransactionFilterProxy::TYPE(TransactionRecord::Generated));
    typeWidget->addItem(tr("Other"), TransactionFilterProxy::TYPE(TransactionRecord::Other));
    typeWidget->addItem(tr("Spend to"), TransactionFilterProxy::TYPE(TransactionRecord::SpendToAddress));
    typeWidget->addItem(tr("Spend to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SpendToSelf));
    typeWidget->addItem(tr("Anonymize"), TransactionFilterProxy::TYPE(TransactionRecord::Anonymize));
    typeWidget->addItem(tr("Sent to RAP address"), TransactionFilterProxy::TYPE(TransactionRecord::SendToPcode));
    typeWidget->addItem(tr("Received with RAP address"), TransactionFilterProxy::TYPE(TransactionRecord::RecvWithPcode));
    typeWidget->addItem(tr("Mint spark to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::MintSparkToSelf));
    typeWidget->addItem(tr("Spend spark to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SpendSparkToSelf));
    typeWidget->addItem(tr("Mint spark to"), TransactionFilterProxy::TYPE(TransactionRecord::MintSparkTo));
    typeWidget->addItem(tr("Spend spark to"), TransactionFilterProxy::TYPE(TransactionRecord::SpendSparkTo));
    typeWidget->addItem(tr("Received Spark"), TransactionFilterProxy::TYPE(TransactionRecord::RecvSpark));
    headerLayout->addWidget(typeWidget, 0, 3);

    addressWidget = new QLineEdit(this);
    addressWidget->setMinimumHeight(36);
    addressWidget->setPlaceholderText(tr("Enter address or label to search"));
    headerLayout->addWidget(addressWidget, 1, 0, 1, 3);

    amountWidget = new QLineEdit(this);
    amountWidget->setMinimumHeight(36);
    amountWidget->setMinimumWidth(110);
    amountWidget->setPlaceholderText(tr("Min amount"));
    amountWidget->setValidator(new QDoubleValidator(0, 1e20, 8, this));
    headerLayout->addWidget(amountWidget, 1, 3);

    headerLayout->setColumnStretch(1, 1);
    headerLayout->setColumnStretch(2, 1);
    headerLayout->setColumnStretch(3, 1);

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->setContentsMargins(24,20,24,20);
    vlayout->setSpacing(14);

    vlayout->addWidget(filterCard);
    filterCard->setMinimumHeight(116);
    filterCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    dateRangeWidget = createDateRangeWidget();
    dateRangeWidget->setObjectName("dateRangeWidget");
    vlayout->addWidget(dateRangeWidget);

    QFrame* tableCard = new QFrame(this);
    tableCard->setObjectName("tableCard");

    QVBoxLayout* tableLayout = new QVBoxLayout(tableCard);
    tableLayout->setContentsMargins(14,10,14,14);
    tableLayout->setSpacing(8);

    QTableView *view = new QTableView(this);
    transactionView = view;

    transactionView->setVerticalScrollMode(QAbstractItemView::ScrollPerItem);
    transactionView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    transactionView->setShowGrid(false);
    transactionView->setAlternatingRowColors(false);
    transactionView->setSelectionBehavior(QAbstractItemView::SelectRows);
    transactionView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    transactionView->setCornerButtonEnabled(false);
    transactionView->setFrameShape(QFrame::NoFrame);
    transactionView->setMouseTracking(true);
    transactionView->verticalHeader()->setDefaultSectionSize(78);

    view->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    view->horizontalHeader()->setHighlightSections(false);

    tableLayout->addWidget(view);

    auto *exportLayout = new QHBoxLayout();
    exportLayout->setContentsMargins(0, 0, 0, 0);
    auto* sortLabel = new QLabel(tr("Sort by"), tableCard);
    exportLayout->addWidget(sortLabel);
    sortWidget = new QComboBox(tableCard);
    sortWidget->setMinimumSize(160, 28);
    sortWidget->setAccessibleName(tr("Sort transactions by"));
    sortWidget->setToolTip(tr("Sort the transaction history"));
    const auto addSortOption = [this](const QString& text, int column, Qt::SortOrder order) {
        sortWidget->addItem(text, QVariantList{column, static_cast<int>(order)});
    };
    addSortOption(tr("Date"), TransactionTableModel::Date, Qt::DescendingOrder);
    addSortOption(tr("Status"), TransactionTableModel::Status, Qt::AscendingOrder);
    addSortOption(tr("Transaction type"), TransactionTableModel::Type, Qt::AscendingOrder);
    addSortOption(tr("Address"), TransactionTableModel::ToAddress, Qt::AscendingOrder);
    addSortOption(tr("Amount"), TransactionTableModel::Amount, Qt::DescendingOrder);
    addSortOption(tr("InstantSend"), TransactionTableModel::InstantSend, Qt::DescendingOrder);
    addSortOption(tr("Watch-only"), TransactionTableModel::Watchonly, Qt::DescendingOrder);
    exportLayout->addWidget(sortWidget);

    sortDirectionButton = new QToolButton(tableCard);
    sortDirectionButton->setObjectName(QStringLiteral("transactionSortDirection"));
    sortDirectionButton->setFixedSize(32, 28);
    exportLayout->addWidget(sortDirectionButton);
    updateSortDirectionButton(Qt::DescendingOrder);
    exportLayout->addStretch();
    exportButton = new QPushButton(tr("Export"), tableCard);
    exportButton->setFixedSize(80, 28);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    exportLayout->addWidget(exportButton);
    tableLayout->addLayout(exportLayout);

    tableCard->setMinimumHeight(420);
    tableCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    vlayout->addWidget(tableCard, 1);

    view->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    view->setContextMenuPolicy(Qt::CustomContextMenu);
    view->setTabKeyNavigation(false);
    auto* cardDelegate = new TransactionRowCardDelegate(view);
    view->setItemDelegate(cardDelegate);
    view->installEventFilter(this);
    view->viewport()->installEventFilter(this);

    emptyState = new QWidget(view->viewport());
    emptyState->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto *emptyLayout = new QVBoxLayout(emptyState);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    emptyLayout->setSpacing(5);
    emptyLayout->addStretch();

    emptyIcon_ = new QLabel(QStringLiteral("≡"), emptyState);
    emptyIcon_->setAlignment(Qt::AlignCenter);
    emptyIcon_->setFixedSize(48, 48);
    emptyLayout->addWidget(emptyIcon_, 0, Qt::AlignHCenter);

    emptyTitle_ = new QLabel(tr("No transactions yet"), emptyState);
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyTitle_);

    emptyDescription_ = new QLabel(
        tr("Your history will appear here after the first transfer"), emptyState);
    emptyDescription_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyDescription_);
    emptyLayout->addStretch();

    abandonAction = new QAction(tr("Abandon transaction"), this);
    resendAction  = new QAction(tr("Re-broadcast transaction"), this);

    QAction *copyAddressAction   = new QAction(tr("Copy address"), this);
    copyLabelAction              = new QAction(tr(CopyLabelText), this);
    QAction *copyAmountAction    = new QAction(tr("Copy amount"), this);
    QAction *copyTxIDAction      = new QAction(tr("Copy transaction ID"), this);
    QAction *copyTxHexAction     = new QAction(tr("Copy raw transaction"), this);
    QAction *copyTxPlainText     = new QAction(tr("Copy full transaction details"), this);
    QAction *editLabelAction     = new QAction(tr("Edit label"), this);
    QAction *showDetailsAction   = new QAction(tr("Show transaction details"), this);

    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTxIDAction);
    contextMenu->addAction(copyTxHexAction);
    contextMenu->addAction(copyTxPlainText);
    contextMenu->addAction(showDetailsAction);
    contextMenu->addSeparator();
    contextMenu->addAction(abandonAction);
    contextMenu->addAction(editLabelAction);
    contextMenu->addAction(resendAction);

    connect(dateWidget,         qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseDate);
    connect(typeWidget,         qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseType);
    connect(watchOnlyWidget,    qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseWatchonly);
    connect(instantsendWidget,  qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseInstantSend);
    connect(addressWidget,      &QLineEdit::textChanged,               this, &TransactionView::changedPrefix);
    connect(amountWidget,       &QLineEdit::textChanged,               this, &TransactionView::changedAmount);
    connect(sortWidget,         qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseSort);
    connect(sortDirectionButton, &QToolButton::clicked,                this, &TransactionView::toggleSortOrder);
    connect(exportButton,       &QPushButton::clicked,                 this, &TransactionView::exportClicked);

    connect(view->horizontalHeader(), &QHeaderView::sortIndicatorChanged,
            this, [this](int column, Qt::SortOrder order) {
                for (int i = 0; i < sortWidget->count(); ++i) {
                    const QVariantList sortSpec = sortWidget->itemData(i).toList();
                    if (sortSpec.size() == 2 && sortSpec.at(0).toInt() == column) {
                        sortWidget->setCurrentIndex(i);
                        break;
                    }
                }
                updateSortDirectionButton(order);
            });

    connect(view, &QTableView::doubleClicked, this, &TransactionView::doubleClicked);
    connect(view, &QTableView::customContextMenuRequested, this, &TransactionView::contextualMenu);
    connect(abandonAction,      &QAction::triggered, this, &TransactionView::abandonTx);
    connect(copyAddressAction,  &QAction::triggered, this, &TransactionView::copyAddress);
    connect(copyLabelAction,    &QAction::triggered, this, &TransactionView::copyLabel);
    connect(copyAmountAction,   &QAction::triggered, this, &TransactionView::copyAmount);
    connect(copyTxIDAction,     &QAction::triggered, this, &TransactionView::copyTxID);
    connect(copyTxHexAction,    &QAction::triggered, this, &TransactionView::copyTxHex);
    connect(copyTxPlainText,    &QAction::triggered, this, &TransactionView::copyTxPlainText);
    connect(editLabelAction,    &QAction::triggered, this, &TransactionView::editLabel);
    connect(showDetailsAction,  &QAction::triggered, this, &TransactionView::showDetails);
    connect(this,               &TransactionView::doubleClicked, this, &TransactionView::openTransaction);
    connect(resendAction,       &QAction::triggered, this, &TransactionView::rebroadcastTx);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &TransactionView::applyTheme);
    applyTheme();

    addShadow(filterCard);

    auto *exportShadow = new QGraphicsDropShadowEffect(exportButton);
    exportShadow->setBlurRadius(20);
    exportShadow->setOffset(0, 6);
    exportShadow->setColor(QColor(139, 26, 58, 70));
    exportButton->setGraphicsEffect(exportShadow);
    updateEmptyState();
}

void TransactionView::applyTheme()
{
    setStyleSheet(GUIUtil::themed(
        "QWidget#TransactionView {"
        " background: $BG;"
        " color: $INK;"
        "}"

        "QFrame#filterCard, QFrame#tableCard, QFrame#dateRangeWidget {"
        "   background: $PANEL;"
        "   border-radius: 16px;"
        "   border: 1px solid $BORDER;"
        "}"

        "QLabel { color: $INK; background: transparent; }"

        "QLineEdit, QComboBox {"
        "   background: $PANEL_SOFT;"
        "   border-radius: 9px;"
        "   border: 1px solid $BORDER;"
        "   padding: 0 11px;"
        "   font-size: 13px;"
        "   color: $INK_SOFT;"
        "}"
        "QLineEdit:!focus { color: $INK_FAINT; }"
        "QLineEdit:focus, QComboBox:focus { border: 1px solid $WINE; }"

        "QComboBox QAbstractItemView {"
        "   background: $PANEL;"
        "   border-radius: 9px;"
        "   border: 1px solid $BORDER;"
        "   padding: 4px;"
        "   outline: 0;"
        "}"
        "QComboBox::item {"
        "   padding: 7px 10px;"
        "   border-radius: 7px;"
        "   color: $INK;"
        "}"
        "QComboBox::item:alternate {"
        "   background: $PANEL;"
        "   color: $INK;"
        "}"
        "QComboBox::item:selected {"
        "   background: $WINE;"
        "   color: #FFFFFF;"
        "}"

        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox::down-arrow { width: 12px; height: 12px; image: url(:/icons/arrow_down); }"

        "QToolButton#transactionSortDirection {"
        " background:$PANEL_SOFT; border:1px solid $BORDER; border-radius:9px;"
        " color:$INK_SOFT; font-size:15px; font-weight:700;"
        "}"
        "QToolButton#transactionSortDirection:hover, QToolButton#transactionSortDirection:focus {"
        " border-color:$WINE; color:$WINE;"
        "}"

        "QDateTimeEdit { background:$PANEL; border-radius:10px; border:1px solid $BORDER; padding:7px 11px; }"

        "QCalendarWidget QWidget { background:$PANEL; }"
        "QCalendarWidget QAbstractItemView { selection-background-color:$PANEL_SOFT; border:none; }"
        "QCalendarWidget QToolButton { color:$INK_SOFT; background:transparent; font-weight:600; }"

        "QTableView {"
        "   background: $PANEL;"
        "   border: none;"
        "   font-size: 12px;"
        "   gridline-color: transparent;"
        "   selection-background-color: transparent;"
        "   outline: 0;"
        "}"

        "QHeaderView::section {"
        " background:$PANEL; padding:9px 6px; border:none;"
        " font-size:12px; font-weight:700; color:$INK_SOFT;"
        "}"
        "QHeaderView::section:hover { background:$PANEL; }"
        "QTableView::item { background: transparent; border: none; padding: 0; }"
        "QTableView::item:hover { background: transparent; }"
        "QTableView::item:selected { background: transparent; color: $INK; }"

        "QScrollBar:vertical { background:$PANEL_SOFT; width:12px; border-radius:6px; }"
        "QScrollBar::handle:vertical { background:$INK_FAINT; border-radius:6px; margin:2px; min-height:32px; }"
        "QScrollBar::handle:vertical:hover { background:$INK_SOFT; }"
        "QScrollBar::add-line, QScrollBar::sub-line { width:0; height:0; }"
        "QScrollBar:horizontal { background:$PANEL_SOFT; height:12px; border-radius:6px; }"
        "QScrollBar::handle:horizontal { background:$INK_FAINT; border-radius:6px; margin:2px; min-width:32px; }"

        "QMenu { background:$PANEL; border:1px solid $BORDER; padding:6px; font-size:10pt; border-radius:10px; }"
        "QMenu::item:selected { background:$PANEL_SOFT; color:$INK; }"

        "QPushButton {"
        "   color:#FFFFFF;"
        "   font-weight:700;"
        "   border:none;"
        "   border-radius:12px;"
        "   padding:10px 20px;"
        "   font-size:13px;"
        "   min-height:38px;"
        "   background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        "                               stop:0 $WINE, stop:1 $WINE_DEEP);"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
        "                               stop:0 $WINE, stop:1 $WINE_DEEP);"
        "}"
        "QPushButton:pressed { background:$WINE_DEEP; }"
        "QPushButton:disabled { background:$PANEL_SOFT; color:$INK_FAINT; border:1px solid $BORDER; }"
    ));

    if (exportButton) {
        exportButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("4px 8px")) +
            QStringLiteral("QPushButton { font-size: 12px; }"));
    }

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(GUIUtil::themed(
            "background: $WINE_TINT; color: $WINE; border-radius: 12px;"
            "font-size: 20px; font-weight: 700;"));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed("color: $INK; font-size: 14px; font-weight: 700;"));
    }
    if (emptyDescription_) {
        emptyDescription_->setStyleSheet(GUIUtil::themed("color: $INK_SOFT; font-size: 12px;"));
    }

    if (transactionView && transactionView->viewport())
        transactionView->viewport()->update();
}

void TransactionView::addShadow(QWidget* w)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(20);
    shadow->setOffset(0, 5);
    shadow->setColor(QColor(65, 37, 52, 24));
    w->setGraphicsEffect(shadow);
}

void TransactionView::updateEmptyState()
{
    if (!emptyState || !transactionView)
        return;

    emptyState->setGeometry(transactionView->viewport()->rect());

    const bool noRows = !transactionProxyModel || transactionProxyModel->rowCount() == 0;
    emptyState->setVisible(noRows);
    if (!noRows)
        return;

    if (emptyTitle_ && emptyDescription_) {
        const bool walletEmpty = !transactionProxyModel || !transactionProxyModel->sourceModel()
            || transactionProxyModel->sourceModel()->rowCount() == 0;
        if (walletEmpty) {
            emptyTitle_->setText(tr("No transactions yet"));
            emptyDescription_->setText(tr("Your history will appear here after the first transfer"));
        } else {
            emptyTitle_->setText(tr("No matching transactions"));
            emptyDescription_->setText(tr("Try adjusting the filters above"));
        }
    }
    emptyState->raise();
}

void TransactionView::updateTableColumnWidths()
{
    if (!transactionView || !transactionView->model())
        return;

    const int tableWidth = transactionView->viewport()->width();
    if (tableWidth < 400)
        return;

    transactionView->setColumnWidth(
        TransactionTableModel::Date, static_cast<int>(tableWidth * 0.22));
    transactionView->setColumnWidth(
        TransactionTableModel::Type, static_cast<int>(tableWidth * 0.16));
    transactionView->setColumnWidth(
        TransactionTableModel::Amount, static_cast<int>(tableWidth * 0.20));
}

void TransactionView::setModel(WalletModel *_model)
{
    this->model = _model;
    if(_model)
    {
        transactionProxyModel = new TransactionFilterProxy(this);
        transactionProxyModel->setSourceModel(_model->getTransactionTableModel());
        connect(transactionProxyModel, &QAbstractItemModel::dataChanged,
                this, [this](const QModelIndex& topLeft, const QModelIndex& bottomRight) {
                    if (topLeft.column() <= TransactionTableModel::InstantSend &&
                        bottomRight.column() >= TransactionTableModel::Status) {
                        // The row delegate paints this metadata in the Date cell.
                        transactionView->viewport()->update();
                    }
                });
        transactionProxyModel->setDynamicSortFilter(true);
        transactionProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
        transactionProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

        transactionProxyModel->setSortRole(Qt::EditRole);

        transactionView->setModel(transactionProxyModel);
        transactionView->setAlternatingRowColors(false);
        transactionView->setSelectionBehavior(QAbstractItemView::SelectRows);
        transactionView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        transactionView->horizontalHeader()->setSortIndicator(TransactionTableModel::Date, Qt::DescendingOrder);
        transactionView->setSortingEnabled(true);
        transactionView->verticalHeader()->hide();

        transactionView->setColumnWidth(TransactionTableModel::Status, STATUS_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Watchonly, WATCHONLY_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::InstantSend, INSTANTSEND_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Date, DATE_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Type, TYPE_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::ToAddress, ADDRESS_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Amount, 160);
        transactionView->setColumnHidden(TransactionTableModel::Status, true);
        transactionView->setColumnHidden(TransactionTableModel::Watchonly, true);
        transactionView->setColumnHidden(TransactionTableModel::InstantSend, true);
        transactionView->horizontalHeader()->setSectionResizeMode(
            TransactionTableModel::ToAddress, QHeaderView::Stretch);
        transactionView->horizontalHeader()->setSectionResizeMode(TransactionTableModel::Amount, QHeaderView::Fixed);
        transactionView->horizontalHeader()->setMinimumSectionSize(80);
        transactionView->horizontalHeader()->setStretchLastSection(false);
        transactionView->horizontalHeader()->setMaximumSectionSize(QWIDGETSIZE_MAX);

        connect(transactionProxyModel, &QAbstractItemModel::rowsInserted,
                this, &TransactionView::updateEmptyState);
        connect(transactionProxyModel, &QAbstractItemModel::rowsRemoved,
                this, &TransactionView::updateEmptyState);
        connect(transactionProxyModel, &QAbstractItemModel::modelReset,
                this, &TransactionView::updateEmptyState);
        updateEmptyState();
        QTimer::singleShot(0, this, &TransactionView::updateTableColumnWidths);

        if (_model->getOptionsModel())
        {
            // Add third party transaction URLs to context menu
            QStringList listUrls = _model->getOptionsModel()->getThirdPartyTxUrls().split("|", Qt::SkipEmptyParts);
            for (int i = 0; i < listUrls.size(); ++i)
            {
                QString url = listUrls[i].trimmed();
                QString host = QUrl(url, QUrl::StrictMode).host();
                if (!host.isEmpty())
                {
                    QAction *thirdPartyTxUrlAction = new QAction(host, this); // use host as menu item label
                    if (i == 0)
                        contextMenu->addSeparator();
                    contextMenu->addAction(thirdPartyTxUrlAction);
                    connect(thirdPartyTxUrlAction, &QAction::triggered, [this, url] { openThirdPartyTxUrl(url); });
                }
            }
        }

        // show/hide column Watch-only
        updateWatchOnlyColumn(_model->haveWatchOnly());

        // Watch-only signal
        connect(_model, &WalletModel::notifyWatchonlyChanged, this, &TransactionView::updateWatchOnlyColumn);
    }
}

void TransactionView::chooseDate(int idx)
{
    if(!transactionProxyModel)
        return;
    QDate current = QDate::currentDate();
    dateRangeWidget->setVisible(false);
    switch(dateWidget->itemData(idx).toInt())
    {
    case All:
        transactionProxyModel->setDateRange(
                TransactionFilterProxy::MIN_DATE,
                TransactionFilterProxy::MAX_DATE);
        break;
    case Today:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(current)),
                TransactionFilterProxy::MAX_DATE);
        break;
    case ThisWeek: {
        // Find last Monday
        QDate startOfWeek = current.addDays(-(current.dayOfWeek()-1));
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(startOfWeek)),
                TransactionFilterProxy::MAX_DATE);

        } break;
    case ThisMonth:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1))),
                TransactionFilterProxy::MAX_DATE);
        break;
    case LastMonth:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1).addMonths(-1))),
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1))));
        break;
    case ThisYear:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), 1, 1))),
                TransactionFilterProxy::MAX_DATE);
        break;
    case Range:
        dateRangeWidget->setVisible(true);
        dateRangeChanged();
        break;
    }
}

void TransactionView::chooseType(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setTypeFilter(
        typeWidget->itemData(idx).toInt());
}

void TransactionView::chooseWatchonly(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setWatchOnlyFilter(
        (TransactionFilterProxy::WatchOnlyFilter)watchOnlyWidget->itemData(idx).toInt());
}

void TransactionView::chooseInstantSend(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setInstantSendFilter(
        (TransactionFilterProxy::InstantSendFilter)instantsendWidget->itemData(idx).toInt());
}

void TransactionView::chooseSort(int idx)
{
    if (!transactionView || idx < 0)
        return;

    const QVariantList sortSpec = sortWidget->itemData(idx).toList();
    if (sortSpec.size() != 2)
        return;

    const Qt::SortOrder order = static_cast<Qt::SortOrder>(sortSpec.at(1).toInt());
    transactionView->sortByColumn(sortSpec.at(0).toInt(), order);
    updateSortDirectionButton(order);
}

void TransactionView::toggleSortOrder()
{
    if (!transactionView)
        return;

    QHeaderView *header = transactionView->horizontalHeader();
    const Qt::SortOrder order = header->sortIndicatorOrder() == Qt::AscendingOrder
        ? Qt::DescendingOrder
        : Qt::AscendingOrder;
    transactionView->sortByColumn(header->sortIndicatorSection(), order);
    updateSortDirectionButton(order);
}

void TransactionView::updateSortDirectionButton(Qt::SortOrder order)
{
    if (!sortDirectionButton)
        return;

    const bool ascending = order == Qt::AscendingOrder;
    sortDirectionButton->setText(ascending ? QStringLiteral("↑") : QStringLiteral("↓"));
    const QString description = ascending ? tr("Sort ascending") : tr("Sort descending");
    sortDirectionButton->setAccessibleName(description);
    sortDirectionButton->setToolTip(description);
}

void TransactionView::changedPrefix(const QString &prefix)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setAddressPrefix(prefix);
}

void TransactionView::changedAmount(const QString &amount)
{
    if(!transactionProxyModel)
        return;
    CAmount amount_parsed = 0;
    if(BitcoinUnits::parse(model->getOptionsModel()->getDisplayUnit(), amount, &amount_parsed))
    {
        transactionProxyModel->setMinAmount(amount_parsed);
    }
    else
    {
        transactionProxyModel->setMinAmount(0);
    }
}

void TransactionView::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export Transaction History"), QString(),
        tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(transactionProxyModel);
    writer.addColumn(tr("Confirmed"), 0, TransactionTableModel::ConfirmedRole);
    if (model && model->haveWatchOnly())
        writer.addColumn(tr("Watch-only"), TransactionTableModel::Watchonly);
    writer.addColumn(tr("Date"), 0, TransactionTableModel::DateRole);
    writer.addColumn(tr("Type"), TransactionTableModel::Type, Qt::EditRole);
    writer.addColumn(tr("Label"), 0, TransactionTableModel::LabelRole);
    writer.addColumn(tr("Address"), 0, TransactionTableModel::AddressRole);
    writer.addColumn(BitcoinUnits::getAmountColumnTitle(model->getOptionsModel()->getDisplayUnit()), 0, TransactionTableModel::FormattedAmountRole);
    writer.addColumn(tr("ID"), 0, TransactionTableModel::TxIDRole);

    if(!writer.write()) {
        Q_EMIT message(tr("Exporting Failed"), tr("There was an error trying to save the transaction history to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
    }
    else {
        Q_EMIT message(tr("Exporting Successful"), tr("The transaction history was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void TransactionView::contextualMenu(const QPoint &point)
{
    QModelIndex index = transactionView->indexAt(point);
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if (selection.empty())
        return;

    // check if transaction can be abandoned, disable context menu action in case it doesn't
    uint256 hash;
    hash.SetHex(selection.at(0).data(TransactionTableModel::TxHashRole).toString().toStdString());
    if(selection.at(0).data(TransactionTableModel::PcodeRole).toString().size() > 0)
        copyLabelAction->setText(tr(CopyRapText));
    else
        copyLabelAction->setText(tr(CopyLabelText));
    abandonAction->setEnabled(model->transactionCanBeAbandoned(hash));
    resendAction->setEnabled(model->transactionCanBeRebroadcast(hash));

    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void TransactionView::abandonTx()
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if (selection.isEmpty())
        return;

    // get the hash from the TxHashRole (QVariant / QString)
    uint256 hash;
    QString hashQStr = selection.at(0).data(TransactionTableModel::TxHashRole).toString();
    hash.SetHex(hashQStr.toStdString());

    // Abandon the wallet transaction over the walletModel
    model->abandonTransaction(hash);

    // Update the table
    model->getTransactionTableModel()->updateTransaction(hashQStr, CT_UPDATED, false);
}

void TransactionView::rebroadcastTx()
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if (selection.isEmpty())
        return;

    // get the hash from the TxHashRole (QVariant / QString)
    uint256 hash;
    QString hashQStr = selection.at(0).data(TransactionTableModel::TxHashRole).toString();
    hash.SetHex(hashQStr.toStdString());

    CValidationState state;
    if (model->rebroadcastTransaction(hash, state))
        Q_EMIT message(tr("Re-broadcast"), tr("Broadcast succeeded"), CClientUIInterface::MSG_INFORMATION);
    else
        Q_EMIT message(tr("Re-broadcast"), tr("There was an error trying to broadcast the message: %1").arg(QString::fromUtf8(state.GetDebugMessage().c_str())),
            CClientUIInterface::MSG_ERROR);

    // Update the table
    model->getTransactionTableModel()->updateTransaction(hashQStr, CT_UPDATED, true);
}

void TransactionView::copyAddress()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::AddressRole);
}

void TransactionView::copyLabel()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::LabelRole);
}

void TransactionView::copyAmount()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::FormattedAmountRole);
}

void TransactionView::copyTxID()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxIDRole);
}

void TransactionView::copyTxHex()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxHexRole);
}

void TransactionView::copyTxPlainText()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxPlainTextRole);
}

void TransactionView::editLabel()
{
    if(!transactionView->selectionModel() ||!model)
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        AddressTableModel *addressBook;
        EditAddressDialog::Mode mode;
        QString address = selection.at(0).data(TransactionTableModel::PcodeRole).toString();

        if(!address.isEmpty())
        {
            addressBook = model->getPcodeAddressTableModel();
            mode = EditAddressDialog::NewPcode;
        }
        else
        {
            address = selection.at(0).data(TransactionTableModel::AddressRole).toString();
            addressBook = model->getAddressTableModel();
            mode = model->validateAddress(address) ? EditAddressDialog::NewSendingAddress : EditAddressDialog::NewSparkSendingAddress;
        }

        if(!addressBook || address.isEmpty())
            return;
        // Is address in address book? Address book can miss address when a transaction is
        // sent from outside the UI.
        int idx = addressBook->lookupAddress(address);
        if(idx != -1)
        {
            // Edit sending / receiving address
            QModelIndex modelIdx = addressBook->index(idx, 0, QModelIndex());
            // Determine type of address, launch appropriate editor dialog type
            QString type = modelIdx.data(AddressTableModel::TypeRole).toString();

            if(mode == EditAddressDialog::NewSendingAddress)
            {
                mode = type == AddressTableModel::Receive
                    ? EditAddressDialog::EditReceivingAddress
                    : EditAddressDialog::EditSendingAddress;
            }
            else if(mode == EditAddressDialog::NewSparkSendingAddress)
            {
                mode = type == AddressTableModel::Receive
                    ? EditAddressDialog::EditSparkReceivingAddress
                    : EditAddressDialog::EditSparkSendingAddress;
            }
            else
                mode = EditAddressDialog::EditPcode;

            EditAddressDialog dlg(mode, this);
            dlg.setModel(addressBook);
            dlg.loadRow(idx);
            dlg.exec();
        }
        else
        {
            // Add sending address
            EditAddressDialog dlg(mode, this);
            dlg.setModel(addressBook);
            dlg.setAddress(address);
            dlg.exec();
        }
    }
}

void TransactionView::showDetails()
{
    if(!transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        TransactionDescDialog *dlg = new TransactionDescDialog(selection.at(0), this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }
}

void TransactionView::openTransaction(const QModelIndex &index)
{
    if (!index.isValid())
        return;

    TransactionDescDialog *dlg = new TransactionDescDialog(index, this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

void TransactionView::openThirdPartyTxUrl(QString url)
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if(!selection.isEmpty())
         QDesktopServices::openUrl(QUrl::fromUserInput(url.replace("%s", selection.at(0).data(TransactionTableModel::TxHashRole).toString())));
}

QWidget *TransactionView::createDateRangeWidget()
{
    dateRangeWidget = new QWidget(this);
    dateRangeWidget->setObjectName("dateRangeWidget");

    QFrame* frame = new QFrame(dateRangeWidget);
    frame->setObjectName("filterCard");
    frame->setContentsMargins(10, 10, 10, 10);

    QHBoxLayout* outer = new QHBoxLayout(dateRangeWidget);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(frame);

    QHBoxLayout* layout = new QHBoxLayout(frame);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(10);

    layout->addSpacing(23);
    layout->addWidget(new QLabel(tr("Range:")));

    dateFrom = new QDateTimeEdit(this);
    dateFrom->setDisplayFormat("dd/MM/yy");
    dateFrom->setCalendarPopup(true);
    dateFrom->setMinimumWidth(100);
    dateFrom->setDate(QDate::currentDate().addDays(-7));
    layout->addWidget(dateFrom);
    layout->addWidget(new QLabel(tr("to")));

    dateTo = new QDateTimeEdit(this);
    dateTo->setDisplayFormat("dd/MM/yy");
    dateTo->setCalendarPopup(true);
    dateTo->setMinimumWidth(100);
    dateTo->setDate(QDate::currentDate());
    layout->addWidget(dateTo);
    layout->addStretch();

    dateRangeWidget->setVisible(false);
    QObject::connect(dateFrom, &QDateTimeEdit::dateChanged, this, &TransactionView::dateRangeChanged);
    QObject::connect(dateTo, &QDateTimeEdit::dateChanged, this, &TransactionView::dateRangeChanged);

    updateCalendarWidgets();
    addShadow(frame);

    return dateRangeWidget;
}

void TransactionView::dateRangeChanged()
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setDateRange(
            GUIUtil::StartOfDay(dateFrom->date()),
            GUIUtil::StartOfDay(dateTo->date()).addDays(1));
}

void TransactionView::updateCalendarWidgets()
{
    auto adjustWeekEndColors = [](QCalendarWidget* w) {
        QTextCharFormat format = w->weekdayTextFormat(Qt::Saturday);
        format.setForeground(QBrush(QColor(61,57,57), Qt::SolidPattern));

        w->setWeekdayTextFormat(Qt::Saturday, format);
        w->setWeekdayTextFormat(Qt::Sunday, format);
    };

    adjustWeekEndColors(dateFrom->calendarWidget());
    adjustWeekEndColors(dateTo->calendarWidget());
}

void TransactionView::focusTransaction(const QModelIndex &idx)
{
    if(!transactionProxyModel)
        return;
    QModelIndex targetIdx = transactionProxyModel->mapFromSource(idx);
    transactionView->scrollTo(targetIdx);
    transactionView->setCurrentIndex(targetIdx);
    transactionView->setFocus();
}

// Need to override default Ctrl+C action for amount as default behaviour is just to copy DisplayRole text
bool TransactionView::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == transactionView->viewport()
        && (event->type() == QEvent::Resize || event->type() == QEvent::Show)) {
        updateEmptyState();
        updateTableColumnWidths();
    }

    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_C && ke->modifiers().testFlag(Qt::ControlModifier))
        {
             GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxPlainTextRole);
             return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

// show/hide column Watch-only
void TransactionView::updateWatchOnlyColumn(bool fHaveWatchOnly)
{
    watchOnlyWidget->setVisible(fHaveWatchOnly);
    transactionView->setColumnHidden(TransactionTableModel::Watchonly, true);
}

// Handles resize events for the TransactionView widget by adjusting internal component sizes.
void TransactionView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);

    updateTableColumnWidths();
    updateEmptyState();
}
