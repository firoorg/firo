#include "sparknamespage.h"
#include "ui_sparknamespage.h"

#include "addresstablemodel.h"
#include "clientmodel.h"
#include "createsparknamepage.h"
#include "guitheme.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "sparkname.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

QString elideMiddle(const QString& text, int keepLeft, int keepRight)
{
    if (text.size() <= keepLeft + keepRight + 2)
        return text;
    return text.left(keepLeft) + QStringLiteral("..") + text.right(keepRight);
}

QPainterPath sparklePath(const QPointF& center, qreal outerR, qreal innerR)
{
    QPainterPath star;
    for (int i = 0; i < 8; ++i) {
        const qreal angle = i * M_PI / 4.0 - M_PI / 2.0;
        const qreal r = (i % 2 == 0) ? outerR : innerR;
        const QPointF pt(center.x() + r * std::cos(angle), center.y() + r * std::sin(angle));
        if (i == 0)
            star.moveTo(pt);
        else
            star.lineTo(pt);
    }
    star.closeSubpath();
    return star;
}

QPixmap sparkNameGlyph(int size = 36)
{
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);
    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    QLinearGradient g(0, 0, 0, size);
    g.setColorAt(0, QColor(tc.wine));
    g.setColorAt(1, QColor(tc.wineDeep));
    p.setPen(Qt::NoPen);
    p.setBrush(g);
    const qreal radius = size * 0.28;
    p.drawRoundedRect(QRectF(0, 0, size, size), radius, radius);

    p.setBrush(QColor("#FFFFFF"));

    const QPointF mainCenter(size * 0.42, size * 0.44);
    QPainterPath mainStar = sparklePath(mainCenter, size * 0.30, size * 0.105);
    QPainterPath hole;
    hole.addEllipse(mainCenter, size * 0.075, size * 0.075);
    p.drawPath(mainStar.subtracted(hole));

    const QPointF smallCenter(size * 0.76, size * 0.24);
    p.drawPath(sparklePath(smallCenter, size * 0.135, size * 0.045));

    const qreal badgeSize = size * 0.4;
    const qreal badgeMargin = size * 0.06;
    QRectF badgeRect(size - badgeSize - badgeMargin, size - badgeSize - badgeMargin, badgeSize, badgeSize);
    p.setBrush(QColor(tc.wineDeep));
    p.drawEllipse(badgeRect);
    QFont font = p.font();
    font.setPixelSize(qRound(badgeSize * 0.6));
    font.setBold(true);
    p.setFont(font);
    p.setPen(QColor("#FFFFFF"));
    p.drawText(badgeRect, Qt::AlignCenter, QStringLiteral("@"));

    return pm;
}

QToolButton* cardActionButton(const QString& text, const QString& icon, const QString& tooltip, QWidget* parent)
{
    auto* btn = new QToolButton(parent);
    btn->setObjectName(QStringLiteral("cardActionButton"));
    btn->setText(text);
    btn->setToolTip(tooltip);
    btn->setIcon(QIcon(icon));
    btn->setIconSize(QSize(13, 13));
    btn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setAutoRaise(true);
    return btn;
}

QLabel* metricCaption(const QString& text, QWidget* parent)
{
    auto* lab = new QLabel(text, parent);
    lab->setObjectName(QStringLiteral("cardMetricCaption"));
    return lab;
}

QLabel* metricValue(const QString& text, QWidget* parent)
{
    auto* lab = new QLabel(text, parent);
    lab->setObjectName(QStringLiteral("cardMetricValue"));
    lab->setWordWrap(true);
    return lab;
}

QWidget* metricColumn(const QString& caption, const QString& value, QWidget* parent)
{
    auto* wrap = new QWidget(parent);
    wrap->setStyleSheet(QStringLiteral("background: transparent; border: none;"));
    auto* lay = new QVBoxLayout(wrap);
    lay->setContentsMargins(0, 0, 10, 0);
    lay->setSpacing(3);
    lay->addWidget(metricCaption(caption, wrap));
    lay->addWidget(metricValue(value, wrap));
    return wrap;
}

void clearLayout(QLayout* layout)
{
    if (!layout)
        return;
    while (layout->count() > 0) {
        QLayoutItem* item = layout->takeAt(0);
        if (QWidget* w = item->widget()) {
            w->hide();
            w->setParent(nullptr);
            w->deleteLater();
        }
        delete item;
    }
}

}

SparkNamesPage::SparkNamesPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SparkNamesPage),
    platformStyle(_platformStyle),
    model(nullptr),
    addressModel(nullptr),
    refreshScheduled(false),
    emptyState(nullptr),
    namesScroll(nullptr),
    namesCardsHost(nullptr),
    namesCardsLayout(nullptr)
{
    ui->setupUi(this);

    ui->sparkNamesContentCard->setMinimumHeight(420);
    ui->sparkNamesContentCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->topLayout->setStretchFactor(ui->sparkNamesContentCard, 1);
    ui->sparkNamesContentCard->setAttribute(Qt::WA_StyledBackground, true);

    namesScroll = new QScrollArea(ui->sparkNamesContentCard);
    namesScroll->setObjectName(QStringLiteral("sparkNamesScroll"));
    namesScroll->setWidgetResizable(true);
    namesScroll->setFrameShape(QFrame::NoFrame);
    namesScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    namesCardsHost = new QWidget(namesScroll);
    namesCardsHost->setObjectName(QStringLiteral("sparkNamesCardsHost"));
    namesCardsLayout = new QVBoxLayout(namesCardsHost);
    namesCardsLayout->setContentsMargins(0, 0, 4, 0);
    namesCardsLayout->setSpacing(10);
    namesCardsLayout->setAlignment(Qt::AlignTop);
    namesScroll->setWidget(namesCardsHost);
    ui->verticalLayoutCard->insertWidget(1, namesScroll, 1);

    emptyState = new QWidget(namesScroll->viewport());
    emptyState->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto* emptyLayout = new QVBoxLayout(emptyState);
    emptyLayout->setContentsMargins(0, 0, 0, 0);
    emptyLayout->setSpacing(5);
    emptyLayout->addStretch();

    emptyIcon_ = new QLabel(emptyState);
    emptyIcon_->setFixedSize(48, 48);
    emptyIcon_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyIcon_, 0, Qt::AlignHCenter);

    emptyTitle_ = new QLabel(tr("No Spark Names yet"), emptyState);
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyLayout->addWidget(emptyTitle_);

    emptyDescription_ = new QLabel(
        tr("Register a Spark Name to give your Spark address a memorable, human-readable name."), emptyState);
    emptyDescription_->setAlignment(Qt::AlignCenter);
    emptyDescription_->setWordWrap(true);
    emptyLayout->addWidget(emptyDescription_);
    emptyLayout->addStretch();

    const auto addCardShadow = [](QWidget* card) {
        auto* shadow = new QGraphicsDropShadowEffect(card);
        shadow->setBlurRadius(20);
        shadow->setOffset(0, 5);
        shadow->setColor(QColor(65, 37, 52, 24));
        card->setGraphicsEffect(shadow);
    };
    addCardShadow(ui->sparkNamesContentCard);

    ui->createSparkNameButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    GUIUtil::applyPrimaryButtonShadow(ui->createSparkNameButton);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &SparkNamesPage::applyTheme);
    applyTheme();
    updateEmptyState();
}

SparkNamesPage::~SparkNamesPage()
{
    delete ui;
}

void SparkNamesPage::setModel(WalletModel *_model)
{
    if (addressModel)
        disconnect(addressModel, nullptr, this, nullptr);

    this->model = _model;
    addressModel = model ? model->getAddressTableModel() : nullptr;
    if (addressModel) {
        connect(addressModel, &QAbstractItemModel::rowsInserted,
                this, &SparkNamesPage::scheduleRefreshList);
        connect(addressModel, &QAbstractItemModel::rowsRemoved,
                this, &SparkNamesPage::scheduleRefreshList);
        connect(addressModel, &QAbstractItemModel::dataChanged,
                this, &SparkNamesPage::scheduleRefreshList);
        connect(addressModel, &QAbstractItemModel::modelReset,
                this, &SparkNamesPage::scheduleRefreshList);
    }
    refreshList();
}

void SparkNamesPage::scheduleRefreshList()
{
    if (refreshScheduled)
        return;

    refreshScheduled = true;
    QTimer::singleShot(0, this, [this]() {
        refreshScheduled = false;
        refreshList();
    });
}

void SparkNamesPage::on_createSparkNameButton_clicked()
{
    if (!model)
        return;

    CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model);
    dialog->show();
}

void SparkNamesPage::refreshList()
{
    clearLayout(namesCardsLayout);

    if (!model) {
        updateEmptyState();
        return;
    }

    if (!addressModel) {
        updateEmptyState();
        return;
    }

    struct SparkNameDisplayData {
        QString name;
        QString address;
        uint64_t validityHeight;
        QString additionalInfo;
    };

    std::vector<SparkNameDisplayData> sparkNames;
    CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();
    for (int row = 0; row < addressModel->rowCount(QModelIndex()); ++row) {
        const QModelIndex labelIndex = addressModel->index(row, AddressTableModel::Label, QModelIndex());
        if (labelIndex.data(AddressTableModel::AddressTypeRole).toString() != AddressTableModel::SparkName ||
            !labelIndex.data(AddressTableModel::IsMineRole).toBool()) {
            continue;
        }

        const QString displayName = labelIndex.data(Qt::DisplayRole).toString();
        const QString rawName = displayName.startsWith('@') ? displayName.mid(1) : displayName;
        try {
            sparkNames.push_back({
                displayName,
                addressModel->index(row, AddressTableModel::Address, QModelIndex()).data(Qt::DisplayRole).toString(),
                sparkNameManager->GetSparkNameBlockHeight(rawName.toStdString()),
                QString::fromStdString(sparkNameManager->GetSparkNameAdditionalData(rawName.toStdString()))});
        } catch (const std::runtime_error&) {
            // The address cache may briefly outlive a name removed by a new block or reorg.
        }
    }

    std::sort(sparkNames.begin(), sparkNames.end(), [](const auto& left, const auto& right) {
        return QString::localeAwareCompare(left.name, right.name) < 0;
    });

    const ClientModel *clientModel = model->getClientModel();
    const int currentHeight = clientModel ? clientModel->getNumBlocks() : 0;

    constexpr int nBlocksPerHour = 24;
    constexpr int nBlocksPerMonth = nBlocksPerHour * 24 * 30;

    for (const auto &entry : sparkNames) {
        const qint64 remainingBlocks = static_cast<qint64>(entry.validityHeight) - currentHeight;
        QString expiry;
        int statusKind;
        if (remainingBlocks <= 0) {
            expiry = tr("Expired");
            statusKind = 2;
        } else {
            const QDateTime expiryDate = QDateTime::currentDateTime().addSecs(
                (qint64)remainingBlocks * 3600 / nBlocksPerHour);
            expiry = QLocale::system().toString(expiryDate.date(), QLocale::LongFormat);
            statusKind = remainingBlocks < nBlocksPerMonth ? 1 : 0;
        }

        QFrame *card = createSparkNameCard(
            entry.name, entry.address, expiry, statusKind, entry.additionalInfo);
        namesCardsLayout->addWidget(card);
    }

    updateEmptyState();
}

QFrame *SparkNamesPage::createSparkNameCard(const QString &name, const QString &address, const QString &expiry,
                                             int statusKind, const QString &additionalInfo)
{
    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    auto* frame = new QFrame(namesCardsHost);
    frame->setObjectName(QStringLiteral("sparkNameCard"));
    frame->setAttribute(Qt::WA_StyledBackground, true);
    frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    frame->setMinimumHeight(126);

    auto* shadow = new QGraphicsDropShadowEffect(frame);
    shadow->setBlurRadius(16);
    shadow->setOffset(0, 3);
    shadow->setColor(QColor(65, 37, 52, 18));
    frame->setGraphicsEffect(shadow);

    auto* root = new QVBoxLayout(frame);
    root->setContentsMargins(16, 14, 16, 14);
    root->setSpacing(0);

    auto* header = new QHBoxLayout();
    header->setContentsMargins(0, 0, 0, 0);
    header->setSpacing(12);

    auto* icon = new QLabel(frame);
    icon->setObjectName(QStringLiteral("cardIcon"));
    icon->setFixedSize(36, 36);
    icon->setPixmap(sparkNameGlyph());
    icon->setStyleSheet(QStringLiteral("background: transparent; border: none;"));
    header->addWidget(icon, 0, Qt::AlignVCenter);

    auto* titleCol = new QVBoxLayout();
    titleCol->setContentsMargins(0, 0, 0, 0);
    titleCol->setSpacing(2);
    auto* nameLab = new QLabel(name, frame);
    nameLab->setObjectName(QStringLiteral("cardTitle"));
    auto* addressLab = new QLabel(elideMiddle(address, 12, 8), frame);
    addressLab->setObjectName(QStringLiteral("cardSubtitle"));
    titleCol->addWidget(nameLab);
    titleCol->addWidget(addressLab);
    header->addLayout(titleCol, 1);

    QString badgeBg = tc.tealTint;
    QString badgeFg = tc.teal;
    QString statusText = tr("Active");
    if (statusKind == 1) {
        badgeBg = tc.goldTint;
        badgeFg = tc.gold;
        statusText = tr("Expiring Soon");
    } else if (statusKind == 2) {
        badgeBg = tc.wineTint;
        badgeFg = tc.wine;
        statusText = tr("Expired");
    }
    auto* statusLab = new QLabel(statusText, frame);
    statusLab->setObjectName(QStringLiteral("cardStatusBadge"));
    statusLab->setAlignment(Qt::AlignCenter);
    statusLab->setMinimumHeight(22);
    statusLab->setStyleSheet(QStringLiteral(
        "QLabel { background: %1; color: %2; border: none; border-radius: 11px;"
        " padding: 2px 10px; font-size: 10px; font-weight: 700; }")
                                 .arg(badgeBg, badgeFg));
    header->addWidget(statusLab, 0, Qt::AlignVCenter);

    root->addLayout(header);
    root->addSpacing(12);

    auto* divider = new QFrame(frame);
    divider->setObjectName(QStringLiteral("cardDivider"));
    divider->setAttribute(Qt::WA_StyledBackground, true);
    divider->setFixedHeight(1);
    root->addWidget(divider);
    root->addSpacing(12);

    auto* grid = new QHBoxLayout();
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setSpacing(4);
    grid->addWidget(metricColumn(tr("EXPIRES"), expiry, frame), 1);
    if (!additionalInfo.isEmpty())
        grid->addWidget(metricColumn(tr("ADDITIONAL INFO"), additionalInfo, frame), 2);
    grid->addStretch(additionalInfo.isEmpty() ? 2 : 0);
    root->addLayout(grid);
    root->addSpacing(10);

    auto* actionsRow = new QHBoxLayout();
    actionsRow->setContentsMargins(0, 0, 0, 0);
    actionsRow->setSpacing(6);
    actionsRow->addStretch();

    auto* copyNameBtn = cardActionButton(tr("Copy Name"), QStringLiteral(":/icons/editcopy"),
                                          tr("Copy the Spark Name to the clipboard"), frame);
    connect(copyNameBtn, &QToolButton::clicked, this, [name]() { GUIUtil::setClipboard(name); });
    actionsRow->addWidget(copyNameBtn);

    auto* copyAddressBtn = cardActionButton(tr("Copy Address"), QStringLiteral(":/icons/editcopy"),
                                             tr("Copy the resolved Spark address to the clipboard"), frame);
    connect(copyAddressBtn, &QToolButton::clicked, this, [address]() { GUIUtil::setClipboard(address); });
    actionsRow->addWidget(copyAddressBtn);

    auto* extendBtn = cardActionButton(tr("Extend"), QStringLiteral(":/icons/refresh"),
                                        tr("Extend the validity of this Spark Name"), frame);
    const QString rawName = name.startsWith('@') ? name.mid(1) : name;
    connect(extendBtn, &QToolButton::clicked, this, [this, rawName, address]() { extendSparkName(rawName, address); });
    actionsRow->addWidget(extendBtn);

    root->addLayout(actionsRow);

    return frame;
}

void SparkNamesPage::extendSparkName(const QString &name, const QString &address)
{
    if (!model)
        return;

    CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model);
    dialog->setExtendMode(name, address);
    dialog->show();
}

void SparkNamesPage::updateEmptyState()
{
    const bool hasEntries = namesCardsLayout && namesCardsLayout->count() > 0;
    if (emptyState) {
        emptyState->setVisible(!hasEntries);
        if (namesScroll)
            emptyState->setGeometry(namesScroll->viewport()->rect());
    }
    if (namesCardsHost)
        namesCardsHost->setVisible(hasEntries);
}

void SparkNamesPage::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
QWidget#SparkNamesPage {
  background: $BG;
}
QFrame#sparkNamesContentCard {
  background: $PANEL;
  border: 1px solid $BORDER;
  border-radius: 16px;
}
QLabel#headerLabel {
  color: $INK_SOFT;
  background: transparent;
  font-size: 11px;
  font-weight: 600;
}
QScrollArea#sparkNamesScroll,
QScrollArea#sparkNamesScroll > QWidget,
QWidget#sparkNamesCardsHost {
  background: transparent;
  border: none;
}
QFrame#sparkNameCard {
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 16px;
}
QFrame#sparkNameCard QLabel#cardTitle {
  color: $INK; font-size: 13px; font-weight: 700;
  background: transparent; border: none;
}
QFrame#sparkNameCard QLabel#cardSubtitle {
  color: $INK_SOFT; font-size: 10px; font-weight: 500;
  background: transparent; border: none;
}
QFrame#sparkNameCard QFrame#cardDivider {
  background: $BORDER; border: none;
}
QFrame#sparkNameCard QLabel#cardMetricCaption {
  color: $INK_SOFT; font-size: 9px; font-weight: 700; letter-spacing: 0.4px;
  background: transparent; border: none;
}
QFrame#sparkNameCard QLabel#cardMetricValue {
  color: $INK; font-size: 12px; font-weight: 700;
  background: transparent; border: none;
}
QFrame#sparkNameCard QToolButton#cardActionButton {
  color: $INK_SOFT; background: $PANEL; border: 1px solid $BORDER; border-radius: 8px;
  padding: 4px 10px; font-size: 10px; font-weight: 600;
}
QFrame#sparkNameCard QToolButton#cardActionButton:hover {
  color: $WINE; border-color: $WINE;
}
    )")));

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(QStringLiteral("background: transparent; border: none;"));
        emptyIcon_->setPixmap(sparkNameGlyph(48));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: transparent; border: none;"
            "color: $INK_SOFT; font-size: 11px; font-weight: 700;")));
    }
    if (emptyDescription_) {
        emptyDescription_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: transparent; border: none;"
            "color: $INK_FAINT; font-size: 10px;")));
    }
}
