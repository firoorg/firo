// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionview.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactiondescdialog.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"


#include <QComboBox>
#include <QDateTimeEdit>
#include <QDesktopServices>
#include <QDoubleValidator>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPoint>
#include <QScrollBar>
#include <QTableView>
#include <QUrl>
#include <QVBoxLayout>
#include <QPainter>
#include <QPainterPath>
#include <QCalendarWidget>
#include <QGraphicsDropShadowEffect>
#include <QPushButton>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>

namespace {
char const * CopyLabelText{"Copy label"};
char const * CopyRapText{"Copy RAP address/label"};
}

namespace {
static QColor pillColorForType(int txType)
{
    // Base mapping for "soft pill" colors.
    switch (txType) {
    case TransactionRecord::Generated:
        return QColor("#B24040");
    case TransactionRecord::RecvWithAddress:
    case TransactionRecord::RecvFromOther:
    case TransactionRecord::RecvWithPcode:
    case TransactionRecord::RecvSpark:
        return QColor("#10B981"); // green
    case TransactionRecord::SendToSelf:
    case TransactionRecord::SpendToSelf:
    case TransactionRecord::Anonymize:
    case TransactionRecord::MintSparkToSelf:
    case TransactionRecord::SpendSparkToSelf:
    case TransactionRecord::SendToAddress:
    case TransactionRecord::SendToOther:
    case TransactionRecord::SpendToAddress:
    case TransactionRecord::SendToPcode:
    case TransactionRecord::MintSparkTo:
    case TransactionRecord::SpendSparkTo:
    case TransactionRecord::SpatsCreate:
    case TransactionRecord::SpatsMint:
    case TransactionRecord::SpatsModify:
    case TransactionRecord::SpatsRevoke:
        return QColor("#B24040");
    default:
        return QColor("#E5E7EB"); // neutral
    }
}

static QLinearGradient pillGradient(const QColor& base, const QRect& r)
{
    // Left = darker, right = lighter (soft loading-like gradient).
    const QColor left = base.darker(115);
    const QColor right = base.lighter(135);
    QLinearGradient g(r.topLeft(), r.topRight());
    g.setColorAt(0, left);
    g.setColorAt(1, right);
    return g;
}

class TypePillDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);

        const bool selected = option.state & QStyle::State_Selected;
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        const QString text = index.data(Qt::DisplayRole).toString();
        const int txType = index.data(TransactionTableModel::TypeRole).toInt();
        const QColor base = pillColorForType(txType);

        const QRect r = option.rect.adjusted(6, 7, -6, -7);

        const QColor fg = (base.lightness() > 180) ? QColor("#111827") : QColor("#FFFFFF");

        // Rounded rectangle tag (not a full pill) for clearer transaction type labels.
        painter->setPen(QPen(base.darker(120), 1));
        painter->setBrush(pillGradient(base, r));
        painter->drawRoundedRect(r, 6, 6);

        // Text
        QFont f = option.font;
        f.setWeight(QFont::DemiBold);
        f.setPointSizeF(9.0);
        painter->setFont(f);
        painter->setPen(fg);
        painter->drawText(r, Qt::AlignCenter, text);

        painter->restore();
    }
};

class DatePillDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        const QString text = index.data(Qt::DisplayRole).toString();
        const QRect r = option.rect.adjusted(6, 8, -6, -8);

        const bool selected = option.state & QStyle::State_Selected;
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        const QColor bg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        const QColor border = selected ? QColor("#C7D2FE") : QColor("#E5E7EB");
        const QColor fg = QColor("#111827");

        painter->setPen(QPen(border, selected ? 1.5 : 1));
        painter->setBrush(bg);
        painter->drawRoundedRect(r, 6, 6);

        QFont f = option.font;
        f.setWeight(QFont::DemiBold);
        f.setPointSizeF(9.5);
        painter->setFont(f);
        painter->setPen(fg);

        const QFontMetrics fm(f);
        const QString elided = fm.elidedText(text, Qt::ElideRight, r.width());
        painter->drawText(r, Qt::AlignCenter, elided);

        painter->restore();
    }
};

class AddressPillDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        const bool selected = option.state & QStyle::State_Selected;
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        const QString text = index.data(Qt::DisplayRole).toString();
        const QRect r = option.rect.adjusted(6, 8, -6, -8);

        const QColor fg = option.palette.color(QPalette::Text);

        // Only draw a subtle frame when the row is selected (avoids a long grey-outlined pill).
        if (selected) {
            painter->setPen(QPen(QColor("#C7D2FE"), 1.5));
            painter->setBrush(QColor("#EEF2FF"));
            painter->drawRoundedRect(r, 6, 6);
        }

        // Optional icon on the left (ToAddress column provides icon via Qt::DecorationRole).
        QIcon icon;
        const QVariant dec = index.data(Qt::DecorationRole);
        if (dec.canConvert<QIcon>()) {
            icon = qvariant_cast<QIcon>(dec);
        }

        int x = r.left() + 10;
        const int yCenter = r.center().y();

        int iconSize = 0;
        if (!icon.isNull()) {
            iconSize = 16;
            const QRect iconRect(x, yCenter - iconSize / 2, iconSize, iconSize);
            painter->drawPixmap(iconRect, icon.pixmap(iconSize, iconSize));
            x += iconSize + 6;
        }

        QFont f = option.font;
        f.setWeight(QFont::DemiBold);
        f.setPointSizeF(9.5);
        painter->setFont(f);
        painter->setPen(fg);

        const QFontMetrics fm(f);
        const QRect textRect = QRect(x, r.top(), r.right() - x, r.height());
        const QString elided = fm.elidedText(text, Qt::ElideRight, textRect.width());
        painter->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft, elided);

        painter->restore();
    }
};

class AmountPillDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        const QString text = index.data(Qt::DisplayRole).toString();
        const qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        const bool negative = amount < 0;

        const bool selected = option.state & QStyle::State_Selected;
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        // No grey "pill" behind amount — only row background + plain text.
        QFont f = option.font;
        f.setWeight(QFont::DemiBold);
        f.setPointSizeF(9.5);
        painter->setFont(f);
        const QColor fg = negative ? QColor("#EF4444") : QColor("#111827");
        painter->setPen(fg);

        const QRect textRect = option.rect.adjusted(8, 0, -8, 0);
        const QFontMetrics fm(f);
        const QString elided = fm.elidedText(text, Qt::ElideRight, textRect.width());
        painter->drawText(textRect, Qt::AlignRight | Qt::AlignVCenter, elided);

        painter->restore();
    }
};

class StatusIconDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        // Status is from TransactionTableModel::StatusRole.
        const int statusInt = index.data(TransactionTableModel::StatusRole).toInt();
        const TransactionStatus::Status status = static_cast<TransactionStatus::Status>(statusInt);

        const bool selected = option.state & QStyle::State_Selected;

        // Prevent Qt's default item background from "showing through" around our marker.
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        QColor fill = QColor("#F3F4F6"); // neutral
        QColor stroke = QColor("#D1D5DB");

        switch (status) {
        case TransactionStatus::Confirmed:
            fill = QColor("#ECFDF5");
            stroke = QColor("#10B981");
            break;
        case TransactionStatus::Unconfirmed:
            fill = QColor("#FFFBEB");
            stroke = QColor("#F59E0B");
            break;
        case TransactionStatus::Confirming:
            fill = QColor("#FFFBEB");
            stroke = QColor("#F59E0B");
            break;
        case TransactionStatus::Immature:
            fill = QColor("#F3F4F6");
            stroke = QColor("#9CA3AF");
            break;
        case TransactionStatus::Abandoned:
            fill = QColor("#FEF2F2");
            stroke = QColor("#EF4444");
            break;
        case TransactionStatus::Conflicted:
            fill = QColor("#FEF2F2");
            stroke = QColor("#EF4444");
            break;
        case TransactionStatus::OpenUntilBlock:
        case TransactionStatus::OpenUntilDate:
            fill = QColor("#EFF6FF");
            stroke = QColor("#3B82F6");
            break;
        default:
            break;
        }

        if (selected) {
            stroke = stroke.lighter(110);
            fill = fill.lighter(105);
        }

        // Draw marker circle with soft outline.
        const QRect r = option.rect.adjusted(10, 6, -10, -6);
        const QPoint c = r.center();
        const int rad = std::min(r.width(), r.height()) / 2;
        const QRect circle(c.x() - rad, c.y() - rad, rad * 2, rad * 2);

        painter->setPen(QPen(stroke, 2));
        painter->setBrush(fill);
        painter->drawEllipse(circle);

        // Draw inner glyph.
        painter->setPen(QPen(stroke, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter->setBrush(Qt::NoBrush);

        auto xr = [&](double k) { return c.x() + rad * k; };
        auto yr = [&](double k) { return c.y() + rad * k; };

        if (status == TransactionStatus::Confirmed) {
            // checkmark
            QPainterPath p;
            p.moveTo(xr(-0.25), yr(0.05));
            p.lineTo(xr(-0.05), yr(0.25));
            p.lineTo(xr(0.28), yr(-0.18));
            painter->drawPath(p);
        } else if (status == TransactionStatus::Unconfirmed || status == TransactionStatus::Confirming || status == TransactionStatus::Immature) {
            // Hourglass instead of clock — clearer "waiting / in progress" metaphor.
            double sandFill = 0.36;
            if (status == TransactionStatus::Unconfirmed)
                sandFill = 0.22;
            else if (status == TransactionStatus::Confirming)
                sandFill = 0.52;
            else if (status == TransactionStatus::Immature)
                sandFill = 0.34;

            const double yb = 0.30;
            const double yt = qMax(0.05, yb - sandFill * 0.24);
            const double edgeSlope = 0.19 / yb;
            const double xLeftAt = -0.06 - yt * edgeSlope;
            const double xRightAt = 0.06 + yt * edgeSlope;

            QPainterPath hg;
            hg.moveTo(xr(-0.25), yr(-0.30));
            hg.lineTo(xr(0.25), yr(-0.30));
            hg.lineTo(xr(0.06), yr(0.0));
            hg.lineTo(xr(0.25), yr(yb));
            hg.lineTo(xr(-0.25), yr(yb));
            hg.lineTo(xr(-0.06), yr(0.0));
            hg.closeSubpath();

            QPolygonF sand;
            sand << QPointF(xr(xLeftAt), yr(yt)) << QPointF(xr(xRightAt), yr(yt))
                 << QPointF(xr(0.25), yr(yb)) << QPointF(xr(-0.25), yr(yb));

            QColor sandColor = stroke;
            sandColor.setAlpha(150);
            painter->setPen(Qt::NoPen);
            painter->setBrush(sandColor);
            painter->drawPolygon(sand);

            painter->setPen(QPen(stroke, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
            painter->setBrush(Qt::NoBrush);
            painter->drawPath(hg);
        } else if (status == TransactionStatus::Abandoned || status == TransactionStatus::Conflicted) {
            painter->drawLine(QPointF(xr(-0.22), yr(-0.22)), QPointF(xr(0.22), yr(0.22)));
            painter->drawLine(QPointF(xr(0.22), yr(-0.22)), QPointF(xr(-0.22), yr(0.22)));
        } else if (status == TransactionStatus::OpenUntilBlock || status == TransactionStatus::OpenUntilDate) {
            painter->drawLine(QPointF(xr(-0.02), yr(-0.18)), QPointF(xr(-0.02), yr(0.12)));
            painter->setPen(QPen(stroke, 2));
            painter->setBrush(stroke);
            painter->drawEllipse(QPointF(xr(-0.02), yr(-0.26)), rad * 0.06, rad * 0.06);
        } else {
            painter->drawLine(QPointF(xr(-0.18), yr(0.0)), QPointF(xr(0.18), yr(0.0)));
        }

        painter->restore();
    }
};

class DecorationIconDelegate final : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);

        const bool selected = option.state & QStyle::State_Selected;
        const QColor cellBg = selected ? QColor("#EEF2FF") : QColor("#FFFFFF");
        painter->setPen(Qt::NoPen);
        painter->setBrush(cellBg);
        painter->drawRect(option.rect);

        // The table model provides an icon via Qt::DecorationRole for these columns.
        const QVariant dec = index.data(Qt::DecorationRole);
        QIcon icon;
        if (dec.canConvert<QIcon>()) {
            icon = qvariant_cast<QIcon>(dec);
        } else if (dec.canConvert<QPixmap>()) {
            const QPixmap pm = qvariant_cast<QPixmap>(dec);
            const int iconSize = std::min(16, std::min(option.rect.width(), option.rect.height()) - 8);
            const QRect iconRect(QPoint(option.rect.center().x() - iconSize / 2, option.rect.center().y() - iconSize / 2), QSize(iconSize, iconSize));
            painter->drawPixmap(iconRect, pm.scaled(iconSize, iconSize, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            painter->restore();
            return;
        }

        if (icon.isNull()) {
            painter->restore();
            return;
        }

        const int iconSize = std::min(16, std::min(option.rect.width(), option.rect.height()) - 8);
        if (iconSize > 0) {
            const QRect iconRect(QPoint(option.rect.center().x() - iconSize / 2, option.rect.center().y() - iconSize / 2), QSize(iconSize, iconSize));
            painter->drawPixmap(iconRect, icon.pixmap(iconSize, iconSize));
        }

        painter->restore();
    }
};
} // namespace

TransactionView::TransactionView(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    model(0),
    transactionProxyModel(0),
    transactionView(0),
    abandonAction(0)
{
    setContentsMargins(0,0,0,0);

    QFrame* filterCard = new QFrame(this);
    filterCard->setObjectName("filterCard");

    headerLayout = new QHBoxLayout(filterCard);
    headerLayout->setContentsMargins(14,14,14,14);
    headerLayout->setSpacing(12);

    // Pills-like comboboxes
    auto pillify = [](QComboBox* cb){ cb->setMinimumHeight(36); cb->setIconSize(QSize(16,16)); };

    watchOnlyWidget = new QComboBox(this);
    pillify(watchOnlyWidget);
    watchOnlyWidget->setFixedWidth(48);
    watchOnlyWidget->addItem("", TransactionFilterProxy::WatchOnlyFilter_All);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_plus"), "", TransactionFilterProxy::WatchOnlyFilter_Yes);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_minus"), "", TransactionFilterProxy::WatchOnlyFilter_No);
    headerLayout->addWidget(watchOnlyWidget);

    instantsendWidget = new QComboBox(this);
    pillify(instantsendWidget);
    instantsendWidget->addItem(tr("All"), TransactionFilterProxy::InstantSendFilter_All);
    instantsendWidget->addItem(tr("Locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_Yes);
    instantsendWidget->addItem(tr("Not locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_No);
    headerLayout->addWidget(instantsendWidget);

    dateWidget = new QComboBox(this);
    pillify(dateWidget);
    dateWidget->setFixedWidth(120);
    dateWidget->addItem(tr("All"), All);
    dateWidget->addItem(tr("Today"), Today);
    dateWidget->addItem(tr("This week"), ThisWeek);
    dateWidget->addItem(tr("This month"), ThisMonth);
    dateWidget->addItem(tr("Last month"), LastMonth);
    dateWidget->addItem(tr("This year"), ThisYear);
    dateWidget->addItem(tr("Range..."), Range);
    headerLayout->addWidget(dateWidget);

    typeWidget = new QComboBox(this);
    pillify(typeWidget);
    typeWidget->setFixedWidth(120);
    typeWidget->addItem(tr("All"), TransactionFilterProxy::ALL_TYPES);
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
    headerLayout->addWidget(typeWidget);

    addressWidget = new QLineEdit(this);
    addressWidget->setMinimumHeight(36);
    addressWidget->setPlaceholderText(tr("Enter address or label to search"));
    headerLayout->addWidget(addressWidget);

    amountWidget = new QLineEdit(this);
    amountWidget->setMinimumHeight(36);
    amountWidget->setPlaceholderText(tr("Min amount"));
    amountWidget->setFixedWidth(140);
    amountWidget->setValidator(new QDoubleValidator(0, 1e20, 8, this));
    headerLayout->addWidget(amountWidget);

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->setContentsMargins(10,10,10,10);
    vlayout->setSpacing(10);

    vlayout->addWidget(filterCard);

    dateRangeWidget = createDateRangeWidget();
    dateRangeWidget->setObjectName("dateRangeWidget");
    vlayout->addWidget(dateRangeWidget);

    QFrame* tableCard = new QFrame(this);
    tableCard->setObjectName("tableCard");

    QVBoxLayout* tableLayout = new QVBoxLayout(tableCard);
    tableLayout->setContentsMargins(10,10,10,10);

    QTableView *view = new QTableView(this);
    transactionView = view;

    // Modern interaction and appearance tweaks
    transactionView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    transactionView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    transactionView->setShowGrid(false);
    transactionView->setAlternatingRowColors(false);
    transactionView->setSelectionBehavior(QAbstractItemView::SelectRows);
    transactionView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    transactionView->setCornerButtonEnabled(false);
    transactionView->setFrameShape(QFrame::NoFrame);
    transactionView->setMouseTracking(true);
    transactionView->verticalHeader()->setDefaultSectionSize(44); // row height

    // Soft header look
    view->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    view->horizontalHeader()->setHighlightSections(false);

    tableLayout->addWidget(view);
    vlayout->addWidget(tableCard);

    view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    view->setContextMenuPolicy(Qt::CustomContextMenu);
    view->setTabKeyNavigation(false);
    view->setItemDelegateForColumn(
        TransactionTableModel::Date,
        new DatePillDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::ToAddress,
        new AddressPillDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::Amount,
        new AmountPillDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::Type,
        new TypePillDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::Status,
        new StatusIconDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::Watchonly,
        new DecorationIconDelegate(view)
    );
    view->setItemDelegateForColumn(
        TransactionTableModel::InstantSend,
        new DecorationIconDelegate(view)
    );
    view->installEventFilter(this);

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

    connect(view, &QTableView::doubleClicked, this, &TransactionView::doubleClicked);
    connect(view, &QTableView::customContextMenuRequested, this, &TransactionView::contextualMenu);
    connect(view->horizontalHeader(), &QHeaderView::sectionResized, this, &TransactionView::updateHeaderSizes);

    connect(abandonAction,      &QAction::triggered, this, &TransactionView::abandonTx);
    connect(copyAddressAction,  &QAction::triggered, this, &TransactionView::copyAddress);
    connect(copyLabelAction,    &QAction::triggered, this, &TransactionView::copyLabel);
    connect(copyAmountAction,   &QAction::triggered, this, &TransactionView::copyAmount);
    connect(copyTxIDAction,     &QAction::triggered, this, &TransactionView::copyTxID);
    connect(copyTxHexAction,    &QAction::triggered, this, &TransactionView::copyTxHex);
    connect(copyTxPlainText,    &QAction::triggered, this, &TransactionView::copyTxPlainText);
    connect(editLabelAction,    &QAction::triggered, this, &TransactionView::editLabel);
    connect(showDetailsAction,  &QAction::triggered, this, &TransactionView::showDetails);
    connect(resendAction,       &QAction::triggered, this, &TransactionView::rebroadcastTx);

    setStyleSheet(
        "QWidget { background: #F7F8FA; font-family: 'Segoe UI'; color: #1F2937; font-size: 11pt; }"

        "QFrame#filterCard, QFrame#tableCard, QFrame#dateRangeWidget {"
        "   background: #FFFFFF;"
        "   border-radius: 14px;"
        "   border: 1px solid #E6E8EC;"
        "   padding: 6px;"
        "}"

        "QLabel { font-size: 11pt; color: #374151; background: transparent; }"

        "QLineEdit, QComboBox {"
        "   background: #FFFFFF;"
        "   border-radius: 10px;"
        "   border: 1px solid #DFE2E7;"
        "   padding: 7px 11px;"
        "   font-size: 10pt;"
        "   color: #374151;"
        "}"
        "QLineEdit:!focus { color: #6B7280; }"
        "QLineEdit:focus, QComboBox:focus { border: 1px solid #C9CDD3; }"

        "QComboBox QAbstractItemView {"
        "   background: #FFFFFF;"
        "   border-radius: 10px;"
        "   border: 1px solid #DFE2E7;"
        "   selection-background-color: #F2F5FF;"
        "   padding: 4px;"
        "}"

        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox::down-arrow { width: 12px; height: 12px; image: url(:/icons/arrow_down); }"

        "QDateTimeEdit { background:#FFFFFF; border-radius:10px; border:1px solid #DFE2E7; padding:7px 11px; }"

        "QCalendarWidget QWidget { background:#FFFFFF; }"
        "QCalendarWidget QAbstractItemView { selection-background-color:#EFF2F6; border:none; }"
        "QCalendarWidget QToolButton { color:#374151; background:transparent; font-weight:600; }"

        "QTableView {"
        "   background: #FFFFFF;"
        "   border-radius: 14px;"
        "   border: 1px solid #E6E8EC;"
        "   font-size: 10pt;"
        "   gridline-color: transparent;"
        "   selection-background-color: #F2F5FF;"
        "   outline: 0;"
        "}"

        "QHeaderView::section { background:#FFFFFF; padding:10px; border:none; font-weight:600; color:#6B7280; }"
        "QHeaderView::section:hover { background:#FAFBFC; }"
        "QTableView::item:hover { background:#FAFBFC; }"
        "QTableView::item:selected { background:#E9EDFF; color:#1F2937; }"

        "QScrollBar:vertical { background:#F3F4F6; width:12px; border-radius:6px; }"
        "QScrollBar::handle:vertical { background:#D4D7DD; border-radius:6px; margin:2px; }"
        "QScrollBar::handle:vertical:hover { background:#C6CAD1; }"
        "QScrollBar::add-line, QScrollBar::sub-line { width:0; height:0; }"
        "QScrollBar:horizontal { background:#F3F4F6; height:12px; border-radius:6px; }"
        "QScrollBar::handle:horizontal { background:#D4D7DD; border-radius:6px; margin:2px; }"

        "QMenu { background:#FFFFFF; border:1px solid #E6E8EC; padding:6px; font-size:10pt; border-radius:10px; }"
        "QMenu::item:selected { background:#F2F5FF; color:#1F2937; }"

        "QPushButton {"
        "   color:#FFFFFF;"
        "   font-weight:600;"
        "   border:none;"
        "   border-radius:12px;"
        "   padding:6px 18px;"
        "   font-size:10pt;"
        "   background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #C62839, stop:1 #7A1736);"
        "}"
        "QPushButton:hover {"
        "   background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #D23245, stop:1 #7A1736);"
        "}"
        "QPushButton:pressed {"
        "   background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #9F1E34, stop:1 #6A132E);"
        "}"
        "QPushButton:disabled { background:#F3F4F6; color:#9CA3AF; }"
    );

    addShadow(filterCard);
    addShadow(tableCard);
    addShadow(dateRangeWidget);
}

void TransactionView::addShadow(QWidget* w)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(18);
    shadow->setOffset(0, 4);
    shadow->setColor(QColor(0, 0, 0, 60));
    w->setGraphicsEffect(shadow);
}

void TransactionView::setModel(WalletModel *_model)
{
    this->model = _model;
    if(_model)
    {
        transactionProxyModel = new TransactionFilterProxy(this);
        transactionProxyModel->setSourceModel(_model->getTransactionTableModel());
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
        transactionView->horizontalHeader()->setSectionResizeMode(TransactionTableModel::Amount, QHeaderView::Fixed);
        transactionView->horizontalHeader()->setMinimumSectionSize(23);
        transactionView->horizontalHeader()->setStretchLastSection(true);
        transactionView->horizontalHeader()->setMaximumSectionSize(300);

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

void TransactionView::updateHeaderSizes(int logicalIndex, int oldSize, int newSize)
{
    static std::vector<std::pair<int, QWidget*>> const headerWidgets{
        {TransactionTableModel::Watchonly, watchOnlyWidget},
        {TransactionTableModel::InstantSend, instantsendWidget},
        {TransactionTableModel::Date, dateWidget},
        {TransactionTableModel::Type, typeWidget},
        {TransactionTableModel::ToAddress, addressWidget},
        {TransactionTableModel::Amount, amountWidget}
    };

    if(logicalIndex <= TransactionTableModel::Amount)
        return;

    for(std::pair<int, QWidget*> const & p : headerWidgets) {
        int const w = transactionView->columnWidth(p.first) - headerLayout->spacing() / 2;
        if(p.second->width() != w)
            p.second->setFixedWidth(w);
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
        TransactionDescDialog *dlg = new TransactionDescDialog(selection.at(0));
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }
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
    transactionView->setColumnHidden(TransactionTableModel::Watchonly, !fHaveWatchOnly);
}

// Handles resize events for the TransactionView widget by adjusting internal component sizes.
void TransactionView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event); 

    // Retrieve new dimensions from the resize event
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();

    adjustTextSize(newWidth, newHeight);

    int headerHeight = newHeight * 0.1; 

    // Calculate the height of widgets in the header subtracting a small margin
    int widgetHeight = headerHeight - 5; 

    // Determine widths for specific widgets as percentages of total width
    int comboBoxesWidgetWidth = newWidth * 0.10; 
    int addressWidgetWidth = newWidth * 0.25; 

    dateWidget->setFixedWidth(comboBoxesWidgetWidth);
    typeWidget->setFixedWidth(comboBoxesWidgetWidth);
    amountWidget->setFixedWidth(comboBoxesWidgetWidth);
    instantsendWidget->setFixedWidth(comboBoxesWidgetWidth);

    int tableViewHeight = newHeight - headerHeight; 
    
    // Calculate and set column widths based on new width, keeping proportions
    int statusColumnWidth = newWidth * 0.05;
    int watchOnlyColumnWidth = newWidth * 0.05;
    int instantSendColumnWidth = newWidth * 0.05;
    int dateColumnWidth = newWidth * 0.08;
    int typeColumnWidth = newWidth * 0.10;
    int addressColumnWidth = newWidth * 0.25; 

    transactionView->setColumnWidth(TransactionTableModel::Status, statusColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Watchonly, watchOnlyColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::InstantSend, instantSendColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Date, dateColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Type, typeColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::ToAddress, addressColumnWidth);
}
void TransactionView::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 65.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    // Set font size for all labels
    transactionView->setFont(font);
    transactionView->horizontalHeader()->setFont(font);
    transactionView->verticalHeader()->setFont(font);
    dateWidget->setFont(font);
    typeWidget->setFont(font);
    amountWidget->setFont(font);
    instantsendWidget->setFont(font);
    addressWidget->setFont(font);
}