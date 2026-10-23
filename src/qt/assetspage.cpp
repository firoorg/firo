// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2018-2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assetspage.h"

#include "bitcoinunits.h"
#include "chainparams.h"
#include "clientmodel.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "sendcoinsdialog.h"
#include "spark/sparkasset.h"
#include "spark/state.h"
#include "txmempool.h"
#include "validation.h"
#include "univalue.h"
#include "utilstrencodings.h"
#include "walletmodel.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QPolygon>
#include <QPushButton>
#include <QSizePolicy>
#include <QSplitter>
#include <QTableWidget>
#include <QDateTime>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <exception>
#include <string>

#define SEND_CONFIRM_DELAY 3

namespace
{
QString FormatAssetUnits(std::uint64_t amount, int precision)
{
    if (precision < 0)
        precision = 0;
    if (precision > 8)
        precision = 8;
    if (precision == 0)
        return QString::number(static_cast<qulonglong>(amount));

    std::uint64_t scale = 1;
    for (int i = 0; i < precision; ++i) {
        if (scale > std::numeric_limits<std::uint64_t>::max() / 10)
            break;
        scale *= 10;
    }
    const std::uint64_t whole = amount / scale;
    const std::uint64_t frac = amount % scale;
    QString fracText = QString::number(static_cast<qulonglong>(frac));
    if (fracText.size() < precision)
        fracText.prepend(QString(precision - fracText.size(), QLatin1Char('0')));
    return QString::number(static_cast<qulonglong>(whole)) + QLatin1Char('.') + fracText;
}

struct ListedAsset
{
    std::string name;
    std::string symbol;
    std::string description;
    std::string metadata;
    std::string admin;
    std::uint8_t kind = 0;
    std::uint8_t precision = 0;
    std::uint64_t identifier = 0;
    std::uint64_t maxSupply = 0;
    std::uint64_t circulating = 0;
    std::uint64_t pendingMint = 0;
    std::uint64_t assetType = 0;
    std::uint64_t balance = 0;
    bool owned = false;
    bool pending = false;
    bool unconfirmed = false;
    QString pendingNote;
};

constexpr int RoleAssetType = Qt::UserRole;
constexpr int RoleIdentifier = Qt::UserRole + 1;
constexpr int RolePrecision = Qt::UserRole + 2;
constexpr int RoleMaxSupply = Qt::UserRole + 3;
constexpr int RoleCirculating = Qt::UserRole + 4;
constexpr int RolePendingMint = Qt::UserRole + 5;
constexpr int RoleKind = Qt::UserRole + 6;
constexpr int RoleSymbol = Qt::UserRole + 7;
constexpr int RoleName = Qt::UserRole + 8;
constexpr int RoleAdmin = Qt::UserRole + 9;
constexpr int RolePendingReg = Qt::UserRole + 10;
constexpr int RoleBalance = Qt::UserRole + 11;
constexpr int RoleDescription = Qt::UserRole + 12;
constexpr int RoleMetadata = Qt::UserRole + 13;
constexpr int RoleUnconfirmed = Qt::UserRole + 14;
constexpr int RoleOwned = Qt::UserRole + 15;
}

AssetsPage::AssetsPage(const PlatformStyle *, QWidget *parent) :
    QWidget(parent),
    clientModel(nullptr),
    model(nullptr),
    assetsRefreshScheduled(false),
    fungible(nullptr),
    symbol(nullptr),
    name(nullptr),
    precision(nullptr),
    supply(nullptr),
    resupply(nullptr),
    description(nullptr),
    metadata(nullptr),
    useDefaultAdmin(nullptr),
    adminAddress(nullptr),
    customAdmin(nullptr),
    customAdminField(nullptr),
    adminError(nullptr),
    createAssetButton(nullptr),
    mintButton(nullptr),
    burnButton(nullptr),
    editButton(nullptr),
    transferButton(nullptr),
    sendButton(nullptr),
    receiveButton(nullptr),
    receiveAssetButton(nullptr),
    createdAssetsTable(nullptr),
    createdAssetsCount(nullptr),
    createdAssetsEmpty(nullptr),
    createdEmptyTitle(nullptr),
    createdEmptyHint(nullptr),
    createdSearch(nullptr),
    createdFilters{nullptr, nullptr},
    createdFilter(0),
    createdSelectionShown(false),
    activityTable(nullptr),
    activityEmpty(nullptr),
    activitySubtitle(nullptr),
    portfolioSearch(nullptr),
    portfolioTable(nullptr),
    portfolioCount(nullptr),
    portfolioEmpty(nullptr),
    portfolioDetails{nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr}
{
    setObjectName(QStringLiteral("assetsPage"));

    auto *assetsLayout = new QVBoxLayout(this);
    assetsLayout->setContentsMargins(20, 16, 20, 16);
    auto *assetsTabs = new QTabWidget(this);
    assetsTabs->setObjectName(QStringLiteral("assetsTabs"));
    assetsTabs->tabBar()->setExpanding(false);
    assetsTabs->tabBar()->setUsesScrollButtons(false);
    assetsTabs->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QTabWidget#assetsTabs::pane { border: none; }
        QTabWidget#assetsTabs::tab-bar { alignment: left; }
        QTabWidget#assetsTabs QTabBar { qproperty-drawBase: 0; background: $PANEL_SOFT; border-radius: 12px; padding: 4px; }
        QTabWidget#assetsTabs QTabBar::tab {
            min-width: 112px; min-height: 32px; padding: 0 16px; margin: 0 2px;
            color: $INK_SOFT; background: transparent; border: none;
            border-radius: 9px; font-weight: 600;
        }
        QTabWidget#assetsTabs QTabBar::tab:selected { color: #FFFFFF; background: $WINE_DEEP; }
        QTabWidget#assetsTabs QTabBar::tab:hover:!selected { background: $PANEL; }
    )")));
    assetsLayout->addWidget(assetsTabs);

    auto styleButton = [](QPushButton *button) {
        button->setMinimumHeight(28);
        button->setMinimumWidth(0);
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        button->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QPushButton { background: $WINE; color: #FFFFFF; border: none; border-radius: 7px; padding: 3px 7px; font-size: 11px; font-weight: 600; }
            QPushButton:hover { background: $WINE_DEEP; }
            QPushButton:pressed { background: $WINE_DEEP; }
            QPushButton:disabled { background: $PANEL_SOFT; color: $INK_FAINT; border: 1px solid $BORDER; }
        )")));
    };
    auto configureTable = [](QTableWidget *table) {
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        table->horizontalHeader()->setFixedHeight(42);
        table->horizontalHeader()->setHighlightSections(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->hide();
        table->verticalHeader()->setDefaultSectionSize(52);
        table->setShowGrid(false);
        table->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QTableWidget { background: $PANEL; alternate-background-color: $PANEL_SOFT; border: none; color: $INK; selection-background-color: $WINE_TINT; selection-color: $INK; }
            QTableWidget::item { padding: 8px; border-bottom: 1px solid $BORDER; }
            QTableWidget::item:hover { background: $PANEL_SOFT; }
            QHeaderView { background: $PANEL_SOFT; border: none; border-radius: 10px; }
            QHeaderView::section { background: transparent; color: $INK_SOFT; border: none; padding: 8px 12px; font-size: 11px; font-weight: 700; }
            QTableCornerButton::section { background: transparent; border: none; }
        )")));
    };

    auto *portfolio = new QWidget(assetsTabs);
    auto *portfolioLayout = new QVBoxLayout(portfolio);
    auto *filterRow = new QHBoxLayout();
    filterRow->setSpacing(12);
    portfolioSearch = new QLineEdit(portfolio);
    portfolioSearch->setPlaceholderText(tr("Search assets, symbol, identifier…"));
    portfolioSearch->setMinimumHeight(36);
    portfolioSearch->setMinimumWidth(300);
    portfolioSearch->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QLineEdit { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 8px; padding: 0 10px; }
        QLineEdit:focus { border-color: $WINE; }
    )")));
    filterRow->addWidget(portfolioSearch, 1);
    auto *refreshAssets = new QPushButton(tr("Refresh"), portfolio);
    QPixmap refreshPixmap(28, 28);
    refreshPixmap.fill(Qt::transparent);
    QPainter refreshPainter(&refreshPixmap);
    refreshPainter.setRenderHint(QPainter::Antialiasing);
    const QColor refreshColor(QStringLiteral("#A51C3D"));
    refreshPainter.setPen(QPen(refreshColor, 2.6, Qt::SolidLine, Qt::RoundCap));
    refreshPainter.drawArc(QRect(5, 5, 18, 18), 45 * 16, 285 * 16);
    refreshPainter.setPen(Qt::NoPen);
    refreshPainter.setBrush(refreshColor);
    refreshPainter.drawPolygon(QPolygon{QPoint(15, 1), QPoint(26, 4), QPoint(18, 12)});
    refreshAssets->setIcon(QIcon(refreshPixmap));
    refreshAssets->setIconSize(QSize(26, 26));
    refreshAssets->setStyleSheet(GUIUtil::themed(QStringLiteral("QPushButton { background: $PANEL; color: $WINE; border: 1px solid $BORDER; border-radius: 9px; padding: 0 12px; font-weight: 600; } QPushButton:hover { background: $PANEL_SOFT; border-color: $WINE; }")));
    refreshAssets->setFixedSize(124, 36);
    connect(refreshAssets, &QPushButton::clicked, this, &AssetsPage::scheduleRefreshAssets);
    connect(portfolioSearch, &QLineEdit::textChanged, this, &AssetsPage::applyPortfolioFilter);
    filterRow->addWidget(refreshAssets);
    portfolioLayout->addLayout(filterRow);
    auto *portfolioSplit = new QSplitter(Qt::Horizontal, portfolio);
    auto *assetsCard = new QFrame(portfolioSplit);
    assetsCard->setObjectName(QStringLiteral("assetPortfolioCard"));
    assetsCard->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame#assetPortfolioCard { background: $PANEL; border: 1px solid $BORDER; border-radius: 16px; }")));
    auto *assetsCardLayout = new QVBoxLayout(assetsCard);
    assetsCardLayout->setContentsMargins(18, 15, 18, 0);
    assetsCardLayout->setSpacing(12);
    auto *assetHeading = new QHBoxLayout();
    auto *assetTitle = new QLabel(tr("Assets"), assetsCard);
    assetTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 19px; font-weight: 700; background: transparent; border: none;")));
    portfolioCount = new QLabel(QStringLiteral("0"), assetsCard);
    portfolioCount->setAlignment(Qt::AlignCenter);
    portfolioCount->setMinimumWidth(32);
    portfolioCount->setFixedHeight(28);
    portfolioCount->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 14px; font-weight: 700;")));
    assetHeading->addWidget(assetTitle);
    assetHeading->addWidget(portfolioCount);
    assetHeading->addStretch(1);
    assetsCardLayout->addLayout(assetHeading);
    portfolioTable = new QTableWidget(0, 4, assetsCard);
    portfolioTable->setHorizontalHeaderLabels({tr("ASSET ID"), tr("NAME"), tr("SYMBOL"), tr("AVAILABLE")});
    configureTable(portfolioTable);
    portfolioTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    portfolioTable->hide();
    assetsCardLayout->addWidget(portfolioTable, 1);
    portfolioEmpty = new QWidget(assetsCard);
    auto *emptyLayout = new QVBoxLayout(portfolioEmpty);
    emptyLayout->setAlignment(Qt::AlignCenter);
    auto *emptyIcon = new QLabel(QStringLiteral("⬡"), portfolioEmpty);
    emptyIcon->setAlignment(Qt::AlignCenter);
    emptyIcon->setFixedSize(72, 72);
    emptyIcon->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 36px; font-size: 30px; font-weight: 600;")));
    auto *emptyTitle = new QLabel(tr("No assets yet"), portfolioEmpty);
    emptyTitle->setAlignment(Qt::AlignCenter);
    emptyTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 17px; font-weight: 700; background: transparent; border: none;")));
    auto *emptyDescription = new QLabel(tr("Assets you can spend show up here."), portfolioEmpty);
    emptyDescription->setAlignment(Qt::AlignCenter);
    emptyDescription->setWordWrap(true);
    emptyDescription->setMaximumWidth(380);
    emptyDescription->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    emptyLayout->addWidget(emptyIcon, 0, Qt::AlignHCenter);
    emptyLayout->addSpacing(12);
    emptyLayout->addWidget(emptyTitle);
    emptyLayout->addWidget(emptyDescription);
    assetsCardLayout->addWidget(portfolioEmpty, 1);
    auto *actionsFooter = new QFrame(assetsCard);
    actionsFooter->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame { background: transparent; border-top: 1px solid $BORDER; }")));
    auto *portfolioActions = new QHBoxLayout(actionsFooter);
    portfolioActions->setContentsMargins(0, 12, 0, 12);
    portfolioActions->setSpacing(8);
    const auto makePortfolioButton = [assetsCard, &styleButton](const QString& label, const QString& style, int width) {
        auto *button = new QPushButton(label, assetsCard);
        styleButton(button);
        button->setFixedSize(width, 42);
        button->setStyleSheet(style + QStringLiteral(" QPushButton { font-size: 12px; padding: 0 12px; border-radius: 9px; }"));
        return button;
    };
    sendButton = makePortfolioButton(tr("Send"), GUIUtil::primaryButtonStyle(QStringLiteral("0 12px")), 90);
    sendButton->setEnabled(false);
    portfolioActions->addWidget(sendButton);
    receiveButton = makePortfolioButton(tr("Receive"), GUIUtil::primaryButtonStyle(QStringLiteral("0 12px")), 100);
    portfolioActions->addWidget(receiveButton);
    portfolioActions->addStretch(1);
    assetsCardLayout->addWidget(actionsFooter);

    auto *detailsCard = new QFrame(portfolioSplit);
    detailsCard->setObjectName(QStringLiteral("assetDetailsCard"));
    detailsCard->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame#assetDetailsCard { background: $PANEL; border: 1px solid $BORDER; border-radius: 16px; }")));
    auto *detailsCardLayout = new QVBoxLayout(detailsCard);
    detailsCardLayout->setContentsMargins(0, 0, 0, 0);
    detailsCardLayout->setSpacing(0);
    auto *detailsTitle = new QLabel(tr("Asset Details"), detailsCard);
    detailsTitle->setContentsMargins(20, 14, 16, 12);
    detailsTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 20px; font-weight: 700; background: transparent; border: none;")));
    detailsCardLayout->addWidget(detailsTitle);
    auto *detailsRows = new QWidget(detailsCard);
    detailsRows->setStyleSheet(QStringLiteral("background: transparent;"));
    auto *detailsLayout = new QVBoxLayout(detailsRows);
    detailsLayout->setContentsMargins(12, 4, 12, 12);
    detailsLayout->setSpacing(8);
    const QStringList detailLabels{tr("Name"), tr("Symbol"), tr("Identifier"), tr("Precision"), tr("Circulating supply"), tr("Supply cap"), tr("Type"), tr("Description"), tr("Metadata")};
    for (qsizetype i = 0; i < detailLabels.size(); ++i) {
        const QString& label = detailLabels.at(i);
        auto *row = new QWidget(detailsRows);
        row->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $PANEL_SOFT; border: none; border-radius: 9px;")));
        auto *rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(12, 8, 14, 8);
        rowLayout->setSpacing(24);
        row->setMinimumHeight(52);
        auto *caption = new QLabel(label, row);
        caption->setFixedWidth(180);
        caption->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        caption->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; border: none; padding: 0; color: $INK_SOFT; font-size: 13px; font-weight: 600;")));
        portfolioDetails[i] = new QLabel(QStringLiteral("—"), row);
        auto *value = portfolioDetails[i];
        value->setWordWrap(true);
        value->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        value->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $INK; border: none; padding: 0;")));
        rowLayout->addWidget(caption);
        rowLayout->addWidget(value, 1);
        detailsLayout->addWidget(row);
    }
    detailsCardLayout->addWidget(detailsRows, 1);
    portfolioSplit->addWidget(assetsCard); portfolioSplit->addWidget(detailsCard); portfolioSplit->setStretchFactor(0, 1); portfolioSplit->setStretchFactor(1, 1);
    portfolioSplit->setChildrenCollapsible(false);
    assetsCard->setMinimumWidth(320);
    detailsCard->setMinimumWidth(320);
    portfolioSplit->setSizes({600, 600});
    portfolioLayout->addWidget(portfolioSplit, 1);
    assetsTabs->addTab(portfolio, tr("Portfolio"));

    auto *created = new QWidget(assetsTabs);
    auto *createdLayout = new QVBoxLayout(created);
    createdLayout->setContentsMargins(0, 18, 0, 0);
    createdLayout->setSpacing(18);
    auto *createdCard = new QFrame(created);
    createdCard->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame { background: $PANEL; border: 1px solid $BORDER; border-radius: 16px; }")));
    auto *createdCardLayout = new QVBoxLayout(createdCard);
    createdCardLayout->setContentsMargins(20, 16, 20, 0);
    createdCardLayout->setSpacing(12);
    auto *createdHeading = new QHBoxLayout();
    auto *createdTitle = new QLabel(tr("Assets"), createdCard);
    createdTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 19px; font-weight: 700; background: transparent; border: none;")));
    createdAssetsCount = new QLabel(QStringLiteral("0"), createdCard);
    createdAssetsCount->setAlignment(Qt::AlignCenter);
    createdAssetsCount->setMinimumWidth(32);
    createdAssetsCount->setFixedHeight(28);
    createdAssetsCount->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 14px; font-weight: 700;")));
    createdHeading->addWidget(createdTitle);
    createdHeading->addWidget(createdAssetsCount);
    createdHeading->addStretch(1);
    createdCardLayout->addLayout(createdHeading);
    auto *createdFilterRow = new QHBoxLayout();
    createdFilterRow->setSpacing(12);
    createdSearch = new QLineEdit(createdCard);
    createdSearch->setPlaceholderText(tr("Search name, symbol, identifier…"));
    createdSearch->setMinimumHeight(36);
    createdSearch->setClearButtonEnabled(true);
    createdSearch->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QLineEdit { background: $PANEL_SOFT; color: $INK; border: 1px solid $BORDER; border-radius: 8px; padding: 0 10px; }
        QLineEdit:focus { border-color: $WINE; }
    )")));
    createdFilterRow->addWidget(createdSearch, 1);
    auto *createdFilterGroup = new QFrame(createdCard);
    createdFilterGroup->setFixedWidth(152);
    auto *createdFilterLayout = new QHBoxLayout(createdFilterGroup);
    createdFilterLayout->setContentsMargins(0, 0, 0, 0);
    createdFilterLayout->setSpacing(12);
    int createdFilterIndex = 0;
    for (const QString& label : {tr("Own"), tr("All")}) {
        createdFilters[createdFilterIndex] = new QPushButton(label, createdFilterGroup);
        auto *button = createdFilters[createdFilterIndex];
        button->setFixedSize(70, 36);
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        createdFilterLayout->addWidget(button);
        ++createdFilterIndex;
    }
    createdFilterRow->addWidget(createdFilterGroup);
    createdCardLayout->addLayout(createdFilterRow);
    createdAssetsTable = new QTableWidget(0, 9, createdCard);
    createdAssetsTable->setHorizontalHeaderLabels({QString(), tr("NAME"), tr("SYMBOL"), tr("DESCRIPTION"), tr("METADATA"), tr("TYPE"), tr("SUPPLY"), tr("MAX SUPPLY"), tr("IDENTIFIER")});
    configureTable(createdAssetsTable);
    createdAssetsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    createdAssetsTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    createdAssetsTable->hide();
    createdCardLayout->addWidget(createdAssetsTable, 1);
    createdAssetsEmpty = new QWidget(createdCard);
    auto *createdEmptyLayout = new QVBoxLayout(createdAssetsEmpty);
    createdEmptyLayout->setAlignment(Qt::AlignCenter);
    auto *createdEmptyIcon = new QLabel(QStringLiteral("⬡"), createdAssetsEmpty);
    createdEmptyIcon->setAlignment(Qt::AlignCenter);
    createdEmptyIcon->setFixedSize(48, 48);
    createdEmptyIcon->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $WINE; font-size: 32px; font-weight: 600;")));
    createdEmptyTitle = new QLabel(tr("You haven’t created any assets"), createdAssetsEmpty);
    createdEmptyTitle->setAlignment(Qt::AlignCenter);
    createdEmptyTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 16px; font-weight: 700; background: transparent; border: none;")));
    createdEmptyHint = new QLabel(tr("Use the Create Asset tab to issue your first one."), createdAssetsEmpty);
    createdEmptyHint->setAlignment(Qt::AlignCenter);
    createdEmptyHint->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    createdEmptyLayout->addWidget(createdEmptyIcon, 0, Qt::AlignHCenter);
    createdEmptyLayout->addSpacing(8);
    createdEmptyLayout->addWidget(createdEmptyTitle);
    createdEmptyLayout->addWidget(createdEmptyHint);
    createdCardLayout->addWidget(createdAssetsEmpty, 1);
    auto *creationFooter = new QFrame(createdCard);
    creationFooter->setObjectName(QStringLiteral("creationFooter"));
    creationFooter->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame#creationFooter { background: transparent; border: none; }")));
    auto *creationActions = new QHBoxLayout(creationFooter);
    creationActions->setContentsMargins(0, 10, 0, 10);
    creationActions->setSpacing(8);
    mintButton = new QPushButton(tr("Mint…"), creationFooter);
    mintButton->setEnabled(false);
    mintButton->setFixedHeight(42);
    mintButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    mintButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("0 10px")));
    creationActions->addWidget(mintButton);
    burnButton = new QPushButton(tr("Burn…"), creationFooter);
    burnButton->setEnabled(false);
    burnButton->setFixedHeight(42);
    burnButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    burnButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("0 10px")));
    creationActions->addWidget(burnButton);
    editButton = new QPushButton(tr("Edit Asset…"), creationFooter);
    editButton->setEnabled(false);
    editButton->setFixedHeight(42);
    editButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    editButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("0 10px")));
    creationActions->addWidget(editButton);
    transferButton = new QPushButton(tr("Transfer…"), creationFooter);
    transferButton->setEnabled(false);
    transferButton->setFixedHeight(42);
    transferButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    transferButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("0 10px")));
    creationActions->addWidget(transferButton);
    receiveAssetButton = new QPushButton(tr("Receive Asset"), creationFooter);
    receiveAssetButton->setEnabled(false);
    receiveAssetButton->setFixedHeight(42);
    receiveAssetButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    receiveAssetButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("0 10px")));
    creationActions->addWidget(receiveAssetButton);
    createdCardLayout->addWidget(creationFooter);
    createdLayout->addWidget(createdCard, 3);

    auto *activityCard = new QFrame(created);
    activityCard->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame { background: $PANEL; border: 1px solid $BORDER; border-radius: 16px; }")));
    auto *activityLayout = new QVBoxLayout(activityCard);
    activityLayout->setContentsMargins(20, 16, 20, 12);
    activityLayout->setSpacing(12);
    auto *activityHeading = new QHBoxLayout();
    auto *activityTitle = new QLabel(tr("Activity"), activityCard);
    activityTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 19px; font-weight: 700; background: transparent; border: none;")));
    activitySubtitle = new QLabel(tr("selected asset"), activityCard);
    activitySubtitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 12px; font-weight: 600; background: transparent; border: none;")));
    activityHeading->addWidget(activityTitle);
    activityHeading->addWidget(activitySubtitle);
    activityHeading->addStretch(1);
    activityLayout->addLayout(activityHeading);
    activityTable = new QTableWidget(0, 4, activityCard);
    activityTable->setHorizontalHeaderLabels({tr("DATE"), tr("TYPE"), tr("TXID"), tr("NOTES")});
    configureTable(activityTable);
    activityTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    activityTable->hide();
    activityLayout->addWidget(activityTable, 1);
    activityEmpty = new QLabel(tr("Select an asset above to see its activity."), activityCard);
    activityEmpty->setAlignment(Qt::AlignCenter);
    activityEmpty->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    activityLayout->addWidget(activityEmpty, 1);
    createdLayout->addWidget(activityCard, 2);
    assetsTabs->addTab(created, tr("Assets"));

    auto *create = new QWidget(assetsTabs);
    auto *createLayout = new QHBoxLayout(create);
    createLayout->setContentsMargins(0, 18, 0, 0);
    createLayout->setSpacing(16);
    const auto makeFormCard = [](QWidget *parent) {
        auto *card = new QFrame(parent);
        card->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame { background: $PANEL; border: 1px solid $BORDER; border-radius: 16px; }")));
        return card;
    };
    const auto makeCardTitle = [](QWidget *parent, const QString& title) {
        auto *label = new QLabel(title, parent);
        label->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $INK; border: none; font-size: 19px; font-weight: 700;")));
        return label;
    };
    const auto styleField = [](QWidget *field) {
        field->setMinimumHeight(46);
        field->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QLineEdit, QComboBox { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 10px; padding: 0 13px; selection-background-color: $WINE_TINT; }
            QLineEdit:hover, QComboBox:hover { border-color: $INK_FAINT; }
            QLineEdit:focus, QComboBox:focus { border: 1px solid $WINE; }
            QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 32px; border: none; }
            QComboBox QAbstractItemView { background: $PANEL; color: $INK; border: 1px solid $BORDER; selection-background-color: $WINE_TINT; selection-color: $INK; padding: 4px; }
            QTextEdit { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 10px; padding: 12px 13px; selection-background-color: $WINE_TINT; }
            QTextEdit:hover { border-color: $INK_FAINT; }
            QTextEdit:focus { border: 1px solid $WINE; }
        )")));
    };
    const auto styleFieldLabel = [](QLabel *label, int fontSize) {
        label->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $INK_SOFT; border: none; font-size: %1px; font-weight: 600;").arg(fontSize)));
    };
    const auto makeField = [&styleFieldLabel](QWidget *parent, const QString& title, QWidget *input) {
        auto *field = new QWidget(parent);
        field->setStyleSheet(QStringLiteral("background: transparent;"));
        auto *fieldLayout = new QVBoxLayout(field);
        fieldLayout->setContentsMargins(0, 0, 0, 0);
        fieldLayout->setSpacing(6);
        auto *label = new QLabel(title, field);
        styleFieldLabel(label, 13);
        input->setParent(field);
        fieldLayout->addWidget(label);
        fieldLayout->addWidget(input);
        return field;
    };

    auto *essentials = makeFormCard(create);
    auto *essentialsLayout = new QVBoxLayout(essentials);
    essentialsLayout->setContentsMargins(22, 20, 22, 18);
    essentialsLayout->setSpacing(16);
    essentialsLayout->addWidget(makeCardTitle(essentials, tr("Essentials")));
    auto *fungiblePanel = new QFrame(essentials);
    fungiblePanel->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame { background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 12px; }")));
    auto *fungibleLayout = new QHBoxLayout(fungiblePanel);
    fungibleLayout->setContentsMargins(14, 12, 14, 12);
    fungibleLayout->setSpacing(12);
    fungible = new QCheckBox(fungiblePanel);
    fungible->setChecked(true);
    fungible->setCursor(Qt::PointingHandCursor);
    fungible->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QCheckBox { spacing: 8px; color: $INK; font-size: 14px; font-weight: 700; background: transparent; }
        QCheckBox::indicator { width: 22px; height: 22px; border: 1px solid $BORDER; border-radius: 6px; background: $PANEL; }
        QCheckBox::indicator:checked { image: url(:/images/checkbox_checked_$ASSET_THEME); border: none; }
    )")));
    auto *fungibleDescription = new QWidget(fungiblePanel);
    auto *fungibleDescriptionLayout = new QVBoxLayout(fungibleDescription);
    fungibleDescriptionLayout->setContentsMargins(0, 0, 0, 0);
    fungibleDescriptionLayout->setSpacing(3);
    auto *fungibleTitle = new QLabel(tr("Fungible token"), fungibleDescription);
    fungibleTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 14px; font-weight: 700; background: transparent; border: none;")));
    auto *fungibleHint = new QLabel(tr("Turn off for a unique asset (NFT). A fungible token has a supply cap and decimal places. Creating the asset does not mint any coins."), fungibleDescription);
    fungibleHint->setWordWrap(true);
    fungibleHint->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 12px; background: transparent; border: none;")));
    fungibleDescriptionLayout->addWidget(fungibleTitle);
    fungibleDescriptionLayout->addWidget(fungibleHint);
    fungibleLayout->addWidget(fungible);
    fungibleLayout->addWidget(fungibleDescription, 1);
    essentialsLayout->addWidget(fungiblePanel);

    symbol = new QLineEdit();
    symbol->setPlaceholderText(tr("e.g. MTK"));
    styleField(symbol);

    name = new QLineEdit();
    name->setPlaceholderText(tr("e.g. My Token"));
    styleField(name);

    precision = new QComboBox();
    for (int i = 0; i <= 8; ++i) {
        precision->addItem(QString::number(i));
    }
    precision->setCurrentIndex(8);
    styleField(precision);

    supply = new QLineEdit();
    supply->setPlaceholderText(tr("e.g. 1000000"));
    styleField(supply);

    resupply = new QComboBox();
    resupply->addItems({tr("Unlimited"), tr("Fixed")});
    styleField(resupply);
    auto *form = new QGridLayout();
    form->setContentsMargins(0, 0, 0, 0);
    form->setHorizontalSpacing(14);
    form->setVerticalSpacing(12);
    form->addWidget(makeField(essentials, tr("Symbol"), symbol), 0, 0);
    form->addWidget(makeField(essentials, tr("Name"), name), 0, 1);
    form->addWidget(makeField(essentials, tr("Decimal places"), precision), 1, 0);
    form->addWidget(makeField(essentials, tr("Supply cap"), supply), 1, 1);
    form->addWidget(makeField(essentials, tr("Cap"), resupply), 2, 0);
    form->setColumnStretch(0, 1);
    form->setColumnStretch(1, 1);
    essentialsLayout->addLayout(form);
    useDefaultAdmin = new QCheckBox(tr("Use default private address"), essentials);
    useDefaultAdmin->setChecked(true);
    useDefaultAdmin->setCursor(Qt::PointingHandCursor);
    useDefaultAdmin->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QCheckBox { spacing: 8px; color: $INK; font-size: 13px; font-weight: 600; background: transparent; }
        QCheckBox::indicator { width: 22px; height: 22px; border: 1px solid $BORDER; border-radius: 6px; background: $PANEL; }
        QCheckBox::indicator:checked { image: url(:/images/checkbox_checked_$ASSET_THEME); border: none; }
    )")));
    essentialsLayout->addWidget(useDefaultAdmin);
    adminAddress = new QLabel(essentials);
    adminAddress->setWordWrap(true);
    adminAddress->setTextInteractionFlags(Qt::TextSelectableByMouse);
    styleFieldLabel(adminAddress, 12);
    adminAddress->setText(tr("Admin: the wallet's default Spark address"));
    essentialsLayout->addWidget(adminAddress);
    customAdmin = new QLineEdit();
    customAdmin->setPlaceholderText(tr("Spark or transparent address"));
    styleField(customAdmin);
    customAdminField = makeField(essentials, tr("Admin address"), customAdmin);
    essentialsLayout->addWidget(customAdminField);
    adminError = new QLabel(essentials);
    adminError->setWordWrap(true);
    adminError->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $ERROR; border: none; font-size: 12px; font-weight: 600;")));
    adminError->hide();
    essentialsLayout->addWidget(adminError);
    essentialsLayout->addStretch(1);

    auto *essentialActions = new QHBoxLayout();
    essentialActions->setSpacing(8);
    auto *clearButton = new QPushButton(tr("Clear"), essentials);
    clearButton->setFixedSize(86, 44);
    clearButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("6px 14px")));
    auto *estimateButton = new QPushButton(tr("Estimate fee →"), essentials);
    estimateButton->setFixedSize(146, 44);
    estimateButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("6px 14px")));
    essentialActions->addWidget(clearButton);
    essentialActions->addWidget(estimateButton);
    essentialActions->addStretch(1);
    essentialsLayout->addLayout(essentialActions);

    auto *metadataCard = makeFormCard(create);
    auto *metadataLayout = new QVBoxLayout(metadataCard);
    metadataLayout->setContentsMargins(22, 20, 22, 18);
    metadataLayout->setSpacing(12);
    metadataLayout->addWidget(makeCardTitle(metadataCard, tr("Details & metadata")));
    auto *descriptionLabel = new QLabel(tr("Description"), metadataCard);
    styleFieldLabel(descriptionLabel, 12);
    metadataLayout->addWidget(descriptionLabel);
    description = new QTextEdit(metadataCard);
    description->setPlaceholderText(tr("Optional short description shown with the asset"));
    styleField(description);
    description->setMinimumHeight(170);
    metadataLayout->addWidget(description, 1);
    auto *metadataLabel = new QLabel(tr("Metadata (JSON)"), metadataCard);
    styleFieldLabel(metadataLabel, 12);
    metadataLayout->addWidget(metadataLabel);
    metadata = new QTextEdit(metadataCard);
    metadata->setPlaceholderText(tr("Optional JSON, e.g. { \"website\": \"https://…\" }"));
    styleField(metadata);
    metadata->setMinimumHeight(150);
    metadataLayout->addWidget(metadata, 1);
    createAssetButton = new QPushButton(tr("Create Asset"), metadataCard);
    createAssetButton->setFixedHeight(44);
    createAssetButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("6px 16px")));
    metadataLayout->addWidget(createAssetButton);
    createLayout->addWidget(essentials, 1); createLayout->addWidget(metadataCard, 1);
    assetsTabs->addTab(create, tr("Create Asset"));

    applyCreateFieldState();
    connect(fungible, &QCheckBox::toggled, this, &AssetsPage::applyCreateFieldState);
    connect(resupply, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &AssetsPage::applyCreateFieldState);
    connect(clearButton, &QPushButton::clicked, this, &AssetsPage::clearCreateForm);
    connect(estimateButton, &QPushButton::clicked, this, &AssetsPage::estimateCreateFee);
    connect(createAssetButton, &QPushButton::clicked, this, &AssetsPage::submitCreateAsset);
    connect(useDefaultAdmin, &QCheckBox::toggled, this, &AssetsPage::updateAdminField);
    connect(customAdmin, &QLineEdit::textChanged, this, &AssetsPage::updateAdminField);
    connect(portfolioTable, &QTableWidget::itemSelectionChanged, this, &AssetsPage::updatePortfolioDetails);
    connect(sendButton, &QPushButton::clicked, this, &AssetsPage::sendSelectedAsset);
    connect(receiveButton, &QPushButton::clicked, this, &AssetsPage::receiveSelectedAsset);
    connect(createdSearch, &QLineEdit::textChanged, this, [this] { applyCreatedFilter(); });
    for (int i = 0; i < 2; ++i)
        connect(createdFilters[i], &QPushButton::clicked, this, [this, i] { createdFilter = i; applyCreatedFilter(); });
    applyCreatedFilter();
    connect(createdAssetsTable, &QTableWidget::itemSelectionChanged, this, [this] {
        updateMintButton();
        updateBurnButton();
        updateEditButton();
        updateTransferButton();
        updateReceiveAssetButton();
        refreshActivity();
    });
    connect(mintButton, &QPushButton::clicked, this, &AssetsPage::mintSelectedAsset);
    connect(burnButton, &QPushButton::clicked, this, &AssetsPage::burnSelectedAsset);
    connect(editButton, &QPushButton::clicked, this, &AssetsPage::editSelectedAsset);
    connect(transferButton, &QPushButton::clicked, this, &AssetsPage::transferSelectedAsset);
    connect(receiveAssetButton, &QPushButton::clicked, this, &AssetsPage::receiveCreatedAsset);
    updateAdminField();
}

void AssetsPage::setModel(WalletModel *model_)
{
    if (model)
        disconnect(model, &WalletModel::balanceChanged, this, nullptr);

    model = model_;
    if (model) {
        connect(model, &WalletModel::balanceChanged, this, [this] {
            scheduleRefreshAssets();
        });
    }
    QString adminText = tr("Admin: the wallet's default Spark address");
    if (model && model->getWallet() && model->getWallet()->sparkWallet) {
        try {
            const std::string address = model->getWallet()->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType());
            adminText = tr("Admin: %1").arg(QString::fromStdString(address));
        } catch (const std::exception&) {
        }
    }
    if (adminAddress)
        adminAddress->setText(adminText);
    if (useDefaultAdmin)
        updateAdminField();
    scheduleRefreshAssets();
}

void AssetsPage::setClientModel(ClientModel *clientModel_)
{
    if (clientModel)
        disconnect(clientModel, &ClientModel::numBlocksChanged, this, nullptr);

    clientModel = clientModel_;
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, this, [this](int, const QDateTime&, double, bool header) {
            if (!header && clientModel && !clientModel->inInitialBlockDownload())
                scheduleRefreshAssets();
        });
    }
    scheduleRefreshAssets();
}

void AssetsPage::scheduleRefreshAssets()
{
    if (assetsRefreshScheduled || !createdAssetsTable)
        return;
    assetsRefreshScheduled = true;
    QTimer::singleShot(0, this, [this] {
        assetsRefreshScheduled = false;
        refreshAssets();
    });
}

bool AssetsPage::walletControlsAddress(const std::string& admin) const
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet)
        return false;
    CWallet* wallet = model->getWallet();
    try {
        spark::Address sparkAdmin(spark::Params::get_default());
        if (sparkAdmin.decode(admin) == spark::GetNetworkType())
            return wallet->sparkWallet->isAddressMine(sparkAdmin);
    } catch (const std::exception&) {
    }
    CBitcoinAddress address(admin);
    CKeyID keyID;
    if (!address.IsValid() || !address.GetKeyID(keyID))
        return false;
    return wallet->IsMine(CTxOut(0, GetScriptForDestination(address.Get()))) & ISMINE_SPENDABLE;
}

void AssetsPage::refreshAssets()
{
    if (!createdAssetsTable || !createdAssetsEmpty || !createdAssetsCount)
        return;

    std::vector<ListedAsset> copied;
    if (model && model->getWallet() && model->getWallet()->sparkWallet) {
        LOCK2(cs_main, mempool.cs);
        const spark::CAssetState& registry = spark::CSparkState::GetState()->GetAssetState();
        std::map<std::string, std::size_t> bySymbol;
        for (const auto& item : registry.Entries()) {
            if (item.second.empty())
                continue;
            const spark::CSparkAssetDBEntry& entry = item.second.front();
            ListedAsset row;
            row.name = entry.name;
            row.symbol = entry.symbol;
            row.description = entry.description;
            row.metadata = entry.metadata;
            row.admin = entry.adminPublicAddress;
            row.kind = entry.assetKind;
            row.precision = entry.precision;
            row.identifier = entry.identifier;
            row.maxSupply = entry.maxSupply;
            row.circulating = registry.GetCirculatingSupply(item.first, entry.identifier);
            row.assetType = item.first;
            bySymbol.emplace(spark::NormalizeSymbol(entry.symbol), copied.size());
            copied.push_back(std::move(row));
        }
        for (const auto& item : mempool.sparkAssetTxs) {
            const spark::CSparkAssetTxEffects& effects = item.second;
            if (!effects.op)
                continue;
            const spark::CSparkAssetTxData& op = *effects.op;
            const std::string symbol = spark::NormalizeSymbol(op.getSymbol());
            const auto existing = bySymbol.find(symbol);
            if (op.isRegister()) {
                if (existing != bySymbol.end())
                    continue;
                ListedAsset row;
                row.name = op.getName();
                row.symbol = op.getSymbol();
                row.description = op.getDescription();
                row.metadata = op.getMetadata();
                row.admin = op.getAdminPublicAddress();
                row.kind = static_cast<std::uint8_t>(op.getAssetKind());
                row.precision = op.getPrecision();
                row.identifier = op.getIdentifier();
                row.maxSupply = op.getMaxSupply();
                row.pending = true;
                row.unconfirmed = true;
                row.pendingNote = tr("Registration is waiting for confirmation");
                bySymbol.emplace(symbol, copied.size());
                copied.push_back(std::move(row));
                continue;
            }
            if (existing == bySymbol.end())
                continue;
            ListedAsset& row = copied[existing->second];
            if (op.isNameModify()) {
                row.name = op.getName();
                row.pendingNote = tr("Name change is waiting for confirmation: %1").arg(QString::fromStdString(row.name));
            } else if (op.isDescriptionModify()) {
                row.description = op.getDescription();
                row.pendingNote = tr("Description change is waiting for confirmation: %1").arg(QString::fromStdString(row.description));
            } else if (op.isMetadataModify()) {
                row.metadata = op.getMetadata();
                row.pendingNote = tr("Metadata change is waiting for confirmation: %1").arg(QString::fromStdString(row.metadata));
            } else if (op.isTransfer()) {
                row.pendingNote = tr("Transfer is waiting for confirmation");
            } else {
                continue;
            }
            row.unconfirmed = true;
        }
        for (const auto& item : mempool.sparkAssetTxs) {
            for (const auto& minted : item.second.minted) {
                for (ListedAsset& existing : copied) {
                    if (existing.pending || existing.assetType != minted.first.first || existing.identifier != minted.first.second)
                        continue;
                    if (existing.pendingMint > std::numeric_limits<std::uint64_t>::max() - minted.second)
                        existing.pendingMint = std::numeric_limits<std::uint64_t>::max();
                    else
                        existing.pendingMint += minted.second;
                }
            }
        }
    }

    for (ListedAsset& row : copied)
        row.owned = walletControlsAddress(row.admin);
    std::sort(copied.begin(), copied.end(), [](const ListedAsset& a, const ListedAsset& b) {
        return a.symbol < b.symbol;
    });
    if (model && model->getWallet() && model->getWallet()->sparkWallet) {
        CSparkWallet* sparkWallet = model->getWallet()->sparkWallet.get();
        for (ListedAsset& row : copied) {
            if (row.pending || row.assetType == 0 || row.kind == static_cast<std::uint8_t>(spark::AssetKind::NonFungible))
                continue;
            const CAmount available = sparkWallet->GetAvailableSparkBalance(
                std::make_pair(Scalar(row.assetType), Scalar(uint64_t(0))));
            row.balance = available > 0 ? static_cast<std::uint64_t>(available) : 0;
        }
    }

    QString selectedSymbol;
    if (const int current = createdAssetsTable->currentRow(); current >= 0) {
        if (const QTableWidgetItem* currentItem = createdAssetsTable->item(current, 0))
            selectedSymbol = currentItem->data(RoleSymbol).toString();
    }
    createdAssetsTable->blockSignals(true);
    createdAssetsTable->clearContents();
    createdAssetsTable->setRowCount(static_cast<int>(copied.size()));
    for (int i = 0; i < static_cast<int>(copied.size()); ++i) {
        const ListedAsset& row = copied[static_cast<std::size_t>(i)];
        const bool nft = row.kind == static_cast<std::uint8_t>(spark::AssetKind::NonFungible);
        const int precision = row.precision > 8 ? 8 : static_cast<int>(row.precision);
        QString supply;
        QString maxSupply;
        if (nft) {
            if (row.pending || (row.circulating == 0 && row.pendingMint > 0))
                supply = tr("Pending");
            else
                supply = row.circulating == 0 ? tr("Not minted") : tr("Minted");
            maxSupply = QStringLiteral("—");
        } else if (row.pending) {
            supply = tr("Pending");
            maxSupply = row.maxSupply == 0 ? tr("Unlimited") : FormatAssetUnits(row.maxSupply, precision);
        } else {
            supply = FormatAssetUnits(row.circulating, precision);
            if (row.pendingMint > 0)
                supply += tr(" (+%1 pending)").arg(FormatAssetUnits(row.pendingMint, precision));
            maxSupply = row.maxSupply == 0 ? tr("Unlimited") : FormatAssetUnits(row.maxSupply, precision);
        }

        const QString description = QString::fromStdString(row.description);
        const QString metadata = QString::fromStdString(row.metadata);
        const QString columns[] = {
            row.unconfirmed ? QStringLiteral("?") : QStringLiteral("✓"),
            QString::fromStdString(row.name),
            QString::fromStdString(row.symbol),
            description,
            metadata,
            nft ? tr("NFT") : tr("Fungible"),
            supply,
            maxSupply,
            QString::number(static_cast<qulonglong>(row.identifier)),
        };
        for (int column = 0; column < 9; ++column) {
            auto *cell = new QTableWidgetItem(columns[column]);
            cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            if (column == 0) {
                cell->setTextAlignment(Qt::AlignCenter);
                cell->setToolTip(row.unconfirmed ? row.pendingNote : tr("Confirmed"));
                cell->setData(RoleAssetType, static_cast<qulonglong>(row.assetType));
                cell->setData(RoleIdentifier, static_cast<qulonglong>(row.identifier));
                cell->setData(RolePrecision, static_cast<int>(row.precision));
                cell->setData(RoleMaxSupply, static_cast<qulonglong>(row.maxSupply));
                cell->setData(RoleCirculating, static_cast<qulonglong>(row.circulating));
                cell->setData(RolePendingMint, static_cast<qulonglong>(row.pendingMint));
                cell->setData(RoleKind, static_cast<int>(row.kind));
                cell->setData(RoleSymbol, QString::fromStdString(row.symbol));
                cell->setData(RoleName, QString::fromStdString(row.name));
                cell->setData(RoleAdmin, QString::fromStdString(row.admin));
                cell->setData(RolePendingReg, row.pending);
                cell->setData(RoleBalance, static_cast<qulonglong>(row.balance));
                cell->setData(RoleDescription, QString::fromStdString(row.description));
                cell->setData(RoleMetadata, QString::fromStdString(row.metadata));
                cell->setData(RoleUnconfirmed, row.unconfirmed);
                cell->setData(RoleOwned, row.owned);
            }
            if (column == 3)
                cell->setToolTip(description);
            if (column == 4)
                cell->setToolTip(metadata);
            createdAssetsTable->setItem(i, column, cell);
        }
    }
    createdAssetsTable->blockSignals(false);
    if (!selectedSymbol.isEmpty()) {
        for (int i = 0; i < createdAssetsTable->rowCount(); ++i) {
            const QTableWidgetItem* restored = createdAssetsTable->item(i, 0);
            if (restored && restored->data(RoleSymbol).toString() == selectedSymbol) {
                createdAssetsTable->selectRow(i);
                break;
            }
        }
    }

    applyCreatedFilter(true);
    refreshPortfolio();
}

void AssetsPage::applyCreatedFilter(bool refreshSelectionActivity)
{
    for (int i = 0; i < 2; ++i) {
        if (!createdFilters[i])
            continue;
        const bool selected = i == createdFilter;
        const QString widthRule = QStringLiteral(" min-width: 70px; max-width: 70px;");
        createdFilters[i]->setStyleSheet(GUIUtil::themed(selected
            ? QStringLiteral("QPushButton { background: $WINE_DEEP; color: #FFFFFF; border: 1px solid $WINE_DEEP; border-radius: 8px; padding: 0 6px; font-size: 11px; font-weight: 700;") + widthRule + QStringLiteral(" }")
            : QStringLiteral("QPushButton { background: $PANEL; color: $INK_SOFT; border: 1px solid $BORDER; border-radius: 8px; padding: 0 6px; font-size: 11px; font-weight: 600;") + widthRule + QStringLiteral(" } QPushButton:hover { background: $PANEL_SOFT; color: $INK; border-color: $WINE; }")));
    }
    if (!createdAssetsTable || !createdAssetsCount || !createdAssetsEmpty)
        return;

    const QString query = createdSearch ? createdSearch->text().trimmed() : QString();
    int visible = 0;
    for (int i = 0; i < createdAssetsTable->rowCount(); ++i) {
        const QTableWidgetItem* statusItem = createdAssetsTable->item(i, 0);
        const QTableWidgetItem* nameItem = createdAssetsTable->item(i, 1);
        const QTableWidgetItem* symbolItem = createdAssetsTable->item(i, 2);
        const QTableWidgetItem* descriptionItem = createdAssetsTable->item(i, 3);
        bool show = createdFilter == 1 || (statusItem && statusItem->data(RoleOwned).toBool());
        if (show && !query.isEmpty() && statusItem && nameItem && symbolItem) {
            const QString identifier = statusItem->data(RoleIdentifier).toString();
            const QString description = descriptionItem ? descriptionItem->text() : QString();
            show = nameItem->text().contains(query, Qt::CaseInsensitive) ||
                symbolItem->text().contains(query, Qt::CaseInsensitive) ||
                identifier.contains(query, Qt::CaseInsensitive) ||
                description.contains(query, Qt::CaseInsensitive);
        }
        createdAssetsTable->setRowHidden(i, !show);
        if (show)
            ++visible;
    }
    createdAssetsCount->setText(QString::number(visible));
    createdAssetsTable->setVisible(visible > 0);
    createdAssetsEmpty->setVisible(visible == 0);
    if (createdEmptyTitle && createdEmptyHint) {
        if (!query.isEmpty()) {
            createdEmptyTitle->setText(tr("No matching assets"));
            createdEmptyHint->setText(tr("Try another name, symbol, or identifier."));
        } else if (createdFilter == 0) {
            createdEmptyTitle->setText(tr("You haven’t created any assets"));
            createdEmptyHint->setText(tr("Use the Create Asset tab to issue your first one."));
        } else {
            createdEmptyTitle->setText(tr("No assets yet"));
            createdEmptyHint->setText(tr("Registered assets show up here."));
        }
    }
    updateMintButton();
    updateBurnButton();
    updateEditButton();
    updateTransferButton();
    updateReceiveAssetButton();
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    const bool showSelection = item && !createdAssetsTable->isRowHidden(row);
    if (refreshSelectionActivity || showSelection != createdSelectionShown)
        refreshActivity();
}

void AssetsPage::refreshPortfolio()
{
    if (!portfolioTable || !portfolioEmpty || !portfolioCount)
        return;

    struct HeldAsset {
        std::uint64_t assetType = 0;
        std::uint64_t identifier = 0;
        std::uint64_t maxSupply = 0;
        std::uint64_t circulating = 0;
        std::uint64_t balance = 0;
        std::uint8_t kind = 0;
        std::uint8_t precision = 0;
        std::string name;
        std::string symbol;
        std::string description;
        std::string metadata;
    };
    std::vector<HeldAsset> held;
    if (model && model->getWallet() && model->getWallet()->sparkWallet) {
        std::vector<HeldAsset> registryRows;
        {
            LOCK(cs_main);
            const spark::CAssetState& registry = spark::CSparkState::GetState()->GetAssetState();
            for (const auto& item : registry.Entries()) {
                if (item.second.empty())
                    continue;
                const spark::CSparkAssetDBEntry& entry = item.second.front();
                HeldAsset row;
                row.assetType = item.first;
                row.identifier = entry.identifier;
                row.maxSupply = entry.maxSupply;
                row.circulating = registry.GetCirculatingSupply(item.first, entry.identifier);
                row.kind = entry.assetKind;
                row.precision = entry.precision;
                row.name = entry.name;
                row.symbol = entry.symbol;
                row.description = entry.description;
                row.metadata = entry.metadata;
                registryRows.push_back(std::move(row));
            }
        }
        CSparkWallet* sparkWallet = model->getWallet()->sparkWallet.get();
        for (HeldAsset& row : registryRows) {
            const CAmount available = sparkWallet->GetAvailableSparkBalance(
                std::make_pair(Scalar(row.assetType), Scalar(row.identifier)));
            if (available <= 0)
                continue;
            row.balance = static_cast<std::uint64_t>(available);
            held.push_back(std::move(row));
        }
    }
    std::sort(held.begin(), held.end(), [](const HeldAsset& a, const HeldAsset& b) {
        return a.symbol < b.symbol;
    });

    QString selectedKey;
    if (const int current = portfolioTable->currentRow(); current >= 0) {
        if (const QTableWidgetItem* currentItem = portfolioTable->item(current, 0))
            selectedKey = currentItem->data(RoleSymbol).toString() + QLatin1Char(':') + currentItem->data(RoleIdentifier).toString();
    }
    portfolioTable->blockSignals(true);
    portfolioTable->clearContents();
    portfolioTable->setRowCount(static_cast<int>(held.size()));
    for (int i = 0; i < static_cast<int>(held.size()); ++i) {
        const HeldAsset& row = held[static_cast<std::size_t>(i)];
        const int precision = row.precision > 8 ? 8 : static_cast<int>(row.precision);
        const bool nft = row.kind == static_cast<std::uint8_t>(spark::AssetKind::NonFungible);
        const QString columns[] = {
            QString::number(static_cast<qulonglong>(row.assetType)),
            QString::fromStdString(row.name),
            QString::fromStdString(row.symbol),
            FormatAssetUnits(row.balance, precision),
        };
        for (int column = 0; column < 4; ++column) {
            auto *cell = new QTableWidgetItem(columns[column]);
            cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            if (column == 0) {
                cell->setData(RoleAssetType, static_cast<qulonglong>(row.assetType));
                cell->setData(RoleIdentifier, static_cast<qulonglong>(row.identifier));
                cell->setData(RolePrecision, precision);
                cell->setData(RoleMaxSupply, static_cast<qulonglong>(row.maxSupply));
                cell->setData(RoleCirculating, static_cast<qulonglong>(row.circulating));
                cell->setData(RoleKind, static_cast<int>(row.kind));
                cell->setData(RoleSymbol, QString::fromStdString(row.symbol));
                cell->setData(RoleName, QString::fromStdString(row.name));
                cell->setData(RoleDescription, QString::fromStdString(row.description));
                cell->setData(RoleMetadata, QString::fromStdString(row.metadata));
                cell->setData(RoleBalance, static_cast<qulonglong>(row.balance));
            }
            portfolioTable->setItem(i, column, cell);
        }
        Q_UNUSED(nft);
    }
    portfolioTable->blockSignals(false);
    if (!selectedKey.isEmpty()) {
        for (int i = 0; i < portfolioTable->rowCount(); ++i) {
            const QTableWidgetItem* restored = portfolioTable->item(i, 0);
            if (!restored)
                continue;
            const QString key = restored->data(RoleSymbol).toString() + QLatin1Char(':') + restored->data(RoleIdentifier).toString();
            if (key == selectedKey) {
                portfolioTable->selectRow(i);
                break;
            }
        }
    }
    applyPortfolioFilter();
}

void AssetsPage::applyPortfolioFilter()
{
    if (!portfolioTable || !portfolioCount || !portfolioEmpty)
        return;

    const QString query = portfolioSearch ? portfolioSearch->text().trimmed() : QString();
    int visible = 0;
    for (int i = 0; i < portfolioTable->rowCount(); ++i) {
        const QTableWidgetItem* idItem = portfolioTable->item(i, 0);
        const QTableWidgetItem* nameItem = portfolioTable->item(i, 1);
        const QTableWidgetItem* symbolItem = portfolioTable->item(i, 2);
        bool show = true;
        if (!query.isEmpty() && idItem && nameItem && symbolItem) {
            const QString identifier = idItem->data(RoleIdentifier).toString();
            show = idItem->text().contains(query, Qt::CaseInsensitive) ||
                nameItem->text().contains(query, Qt::CaseInsensitive) ||
                symbolItem->text().contains(query, Qt::CaseInsensitive) ||
                identifier.contains(query, Qt::CaseInsensitive);
        }
        portfolioTable->setRowHidden(i, !show);
        if (show)
            ++visible;
    }
    portfolioCount->setText(QString::number(visible));
    portfolioTable->setVisible(visible > 0);
    portfolioEmpty->setVisible(visible == 0);
    updatePortfolioDetails();
}

void AssetsPage::updateSendButton()
{
    if (!sendButton || !portfolioTable)
        return;
    bool enable = false;
    const int row = portfolioTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? portfolioTable->item(row, 0) : nullptr;
    if (item && !portfolioTable->isRowHidden(row)) {
        const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
        const std::uint64_t balance = item->data(RoleBalance).toULongLong();
        enable = assetType != 0 && balance > 0;
    }
    sendButton->setEnabled(enable);
}

void AssetsPage::updatePortfolioDetails()
{
    updateSendButton();
    auto clearDetails = [this] {
        for (QLabel* value : portfolioDetails) {
            if (value)
                value->setText(QStringLiteral("—"));
        }
    };
    if (!portfolioTable) {
        clearDetails();
        return;
    }
    const int row = portfolioTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? portfolioTable->item(row, 0) : nullptr;
    if (!item || portfolioTable->isRowHidden(row)) {
        clearDetails();
        return;
    }
    const int precision = item->data(RolePrecision).toInt();
    const std::uint64_t maxSupply = item->data(RoleMaxSupply).toULongLong();
    const std::uint64_t circulating = item->data(RoleCirculating).toULongLong();
    const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
    const QString values[] = {
        item->data(RoleName).toString(),
        item->data(RoleSymbol).toString(),
        item->data(RoleIdentifier).toString(),
        QString::number(precision),
        FormatAssetUnits(circulating, precision),
        nft ? QStringLiteral("—") : (maxSupply == 0 ? tr("Unlimited") : FormatAssetUnits(maxSupply, precision)),
        nft ? tr("NFT") : tr("Fungible"),
        item->data(RoleDescription).toString(),
        item->data(RoleMetadata).toString(),
    };
    for (int i = 0; i < 9; ++i) {
        if (portfolioDetails[i])
            portfolioDetails[i]->setText(values[i].isEmpty() ? QStringLiteral("—") : values[i]);
    }
}

void AssetsPage::refreshActivity()
{
    if (!activityTable || !activityEmpty || !activitySubtitle)
        return;

    const int row = createdAssetsTable ? createdAssetsTable->currentRow() : -1;
    const QTableWidgetItem* item = row >= 0 && createdAssetsTable ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || !model || !model->getWallet()) {
        activitySubtitle->setText(tr("selected asset"));
        activityTable->hide();
        activityEmpty->setText(tr("Select an asset above to see its activity."));
        activityEmpty->show();
        createdSelectionShown = false;
        return;
    }
    createdSelectionShown = true;

    const QString symbol = item->data(RoleSymbol).toString();
    const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
    const std::uint64_t identifier = item->data(RoleIdentifier).toULongLong();
    const int precision = std::min(8, std::max(0, item->data(RolePrecision).toInt()));
    activitySubtitle->setText(symbol);

    struct ActivityRow {
        int64_t time = 0;
        QString type;
        QString txid;
        QString notes;
    };
    std::vector<ActivityRow> rows;
    const std::string symbolNorm = spark::NormalizeSymbol(symbol.toStdString());
    {
        LOCK2(cs_main, model->getWallet()->cs_wallet);
        for (const auto& entry : model->getWallet()->mapWallet) {
            const CWalletTx& wtx = entry.second;
            if (wtx.isAbandoned() || !wtx.tx)
                continue;
            const bool confirmed = !wtx.hashUnset();
            const QString txid = QString::fromStdString(wtx.GetHash().ToString());
            const int64_t time = wtx.GetTxTime();
            const auto add = [&](const QString& type, const QString& notes) {
                QString full = notes;
                if (!confirmed) {
                    if (!full.isEmpty())
                        full.append(QStringLiteral(" · "));
                    full.append(tr("Unconfirmed"));
                }
                rows.push_back({time, type, txid, full});
            };
            try {
                if (const auto op = spark::GetSparkAssetTxData(*wtx.tx)) {
                    if (spark::NormalizeSymbol(op->getSymbol()) == symbolNorm) {
                        if (op->isRegister())
                            add(tr("Register"), QString::fromStdString(op->getAdminPublicAddress()));
                        else if (op->isNameModify())
                            add(tr("Name"), QString::fromStdString(op->getName()));
                        else if (op->isDescriptionModify())
                            add(tr("Description"), QString::fromStdString(op->getDescription()));
                        else if (op->isMetadataModify())
                            add(tr("Metadata"), QString::fromStdString(op->getMetadata()));
                        else if (op->isTransfer())
                            add(tr("Transfer"), QString::fromStdString(op->getTransferAddress()));
                    }
                }
            } catch (const std::exception&) {
            }
            if (assetType == 0)
                continue;
            for (const CTxOut& txout : wtx.tx->vout) {
                if (txout.scriptPubKey.IsSpatsMint()) {
                    try {
                        spark::MintTransaction mint(spark::Params::get_default());
                        spark::OwnershipProof proof;
                        spark::ParseSpatsMintTransaction(txout.scriptPubKey, mint, proof, nullptr);
                        std::vector<spark::Coin> coins;
                        mint.getCoins(coins);
                        for (const spark::Coin& coin : coins) {
                            const auto mintedType = spark::GetSpatsScalarAsUint64(coin.a);
                            const auto mintedId = spark::GetSpatsScalarAsUint64(coin.iota);
                            if (mintedType && mintedId && *mintedType == assetType && *mintedId == identifier)
                                add(tr("Mint"), FormatAssetUnits(coin.v, precision));
                        }
                    } catch (const std::exception&) {
                    }
                } else if (txout.scriptPubKey.IsSpatsBurn()) {
                    std::pair<Scalar, Scalar> assetId;
                    CAmount amount = 0;
                    if (!spark::ParseSpatsBurn(txout.scriptPubKey, assetId, amount))
                        continue;
                    const auto burnedType = spark::GetSpatsScalarAsUint64(assetId.first);
                    const auto burnedId = spark::GetSpatsScalarAsUint64(assetId.second);
                    if (burnedType && burnedId && *burnedType == assetType && *burnedId == identifier)
                        add(tr("Burn"), FormatAssetUnits(static_cast<std::uint64_t>(amount), precision));
                }
            }
        }
    }

    std::sort(rows.begin(), rows.end(), [](const ActivityRow& a, const ActivityRow& b) {
        return a.time > b.time;
    });
    activityTable->clearContents();
    activityTable->setRowCount(static_cast<int>(rows.size()));
    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const ActivityRow& activity = rows[static_cast<std::size_t>(i)];
        const QString columns[] = {
            GUIUtil::dateTimeStr(static_cast<qint64>(activity.time)),
            activity.type,
            activity.txid,
            activity.notes,
        };
        for (int column = 0; column < 4; ++column) {
            auto *cell = new QTableWidgetItem(columns[column]);
            cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            cell->setToolTip(columns[column]);
            activityTable->setItem(i, column, cell);
        }
    }
    const bool empty = rows.empty();
    activityTable->setVisible(!empty);
    activityEmpty->setVisible(empty);
    if (empty)
        activityEmpty->setText(tr("No activity for this asset yet."));
}

void AssetsPage::updateMintButton()
{
    if (!mintButton || !createdAssetsTable) {
        return;
    }
    bool enable = false;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (item && !createdAssetsTable->isRowHidden(row) && item->data(RoleOwned).toBool() && !item->data(RolePendingReg).toBool()) {
        const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
        const std::uint64_t maxSupply = item->data(RoleMaxSupply).toULongLong();
        const std::uint64_t circulating = item->data(RoleCirculating).toULongLong();
        const std::uint64_t pendingMint = item->data(RolePendingMint).toULongLong();
        const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
        const std::uint64_t used = circulating > std::numeric_limits<std::uint64_t>::max() - pendingMint
            ? std::numeric_limits<std::uint64_t>::max()
            : circulating + pendingMint;
        if (assetType != 0) {
            if (nft)
                enable = used == 0;
            else if (maxSupply == 0)
                enable = used < static_cast<std::uint64_t>(spark::MAX_ASSET_MONEY);
            else
                enable = used < maxSupply;
        }
    }
    mintButton->setEnabled(enable);
}

void AssetsPage::updateBurnButton()
{
    if (!burnButton || !createdAssetsTable)
        return;
    bool enable = false;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (item && !createdAssetsTable->isRowHidden(row) && !item->data(RolePendingReg).toBool()) {
        const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
        const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
        const std::uint64_t balance = item->data(RoleBalance).toULongLong();
        enable = !nft && assetType != 0 && balance > 0;
    }
    burnButton->setEnabled(enable);
}

void AssetsPage::updateEditButton()
{
    if (!editButton || !createdAssetsTable)
        return;
    bool enable = false;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (item && !createdAssetsTable->isRowHidden(row) && item->data(RoleOwned).toBool() && !item->data(RolePendingReg).toBool() && !item->data(RoleUnconfirmed).toBool())
        enable = item->data(RoleAssetType).toULongLong() != 0;
    editButton->setEnabled(enable);
}

void AssetsPage::updateTransferButton()
{
    if (!transferButton || !createdAssetsTable)
        return;
    bool enable = false;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (item && !createdAssetsTable->isRowHidden(row) && item->data(RoleOwned).toBool() && !item->data(RolePendingReg).toBool() && !item->data(RoleUnconfirmed).toBool())
        enable = item->data(RoleAssetType).toULongLong() != 0;
    transferButton->setEnabled(enable);
}

void AssetsPage::mintSelectedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !createdAssetsTable)
        return;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || !item->data(RoleOwned).toBool() || item->data(RolePendingReg).toBool())
        return;

    const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
    const std::uint64_t identifier = item->data(RoleIdentifier).toULongLong();
    const int precision = std::min(8, std::max(0, item->data(RolePrecision).toInt()));
    const std::uint64_t maxSupply = item->data(RoleMaxSupply).toULongLong();
    const std::uint64_t circulating = item->data(RoleCirculating).toULongLong();
    const std::uint64_t pendingMint = item->data(RolePendingMint).toULongLong();
    const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
    const QString symbolText = item->data(RoleSymbol).toString();
    const QString nameText = item->data(RoleName).toString();
    const std::string admin = item->data(RoleAdmin).toString().toStdString();
    const std::uint64_t used = circulating > std::numeric_limits<std::uint64_t>::max() - pendingMint
        ? std::numeric_limits<std::uint64_t>::max()
        : circulating + pendingMint;
    const std::uint64_t room = nft ? (used == 0 ? 1 : 0)
        : (maxSupply == 0 ? static_cast<std::uint64_t>(spark::MAX_ASSET_MONEY) : maxSupply);
    if (assetType == 0 || used >= room) {
        updateMintButton();
        return;
    }

    CWallet* wallet = model->getWallet();
    QString defaultAddress;
    try {
        defaultAddress = QString::fromStdString(wallet->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType()));
    } catch (const std::exception&) {
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Mint"));
    auto *layout = new QFormLayout(&dialog);
    auto *addressEdit = new QLineEdit(defaultAddress, &dialog);
    addressEdit->setPlaceholderText(tr("Spark address that will own the minted coin"));
    layout->addRow(tr("Receive address"), addressEdit);
    auto *amountEdit = new QLineEdit(&dialog);
    amountEdit->setPlaceholderText(tr("Amount in the asset's decimal places"));
    if (!nft)
        layout->addRow(tr("Amount"), amountEdit);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;

    spark::Address recipient(spark::Params::get_default());
    try {
        if (recipient.decode(addressEdit->text().trimmed().toStdString()) != spark::GetNetworkType())
            throw std::runtime_error("wrong network");
    } catch (const std::exception&) {
        QMessageBox::warning(this, tr("Mint"), tr("Enter a Spark address on this network. That address will own the minted coin."));
        return;
    }

    std::uint64_t rawAmount = 1;
    if (!nft) {
        CAmount parsed = 0;
        const QString amountText = amountEdit->text().trimmed();
        if (amountText.isEmpty() ||
                !ParseFixedPoint(amountText.toStdString(), precision, &parsed) ||
                parsed <= 0) {
            QMessageBox::warning(this, tr("Mint"), tr("Enter an amount in the asset's decimal places."));
            return;
        }
        rawAmount = static_cast<std::uint64_t>(parsed);
    }
    if (rawAmount > room - used) {
        QMessageBox::warning(this, tr("Mint"), tr("That amount would exceed the max supply."));
        return;
    }

    spark::MintedCoinData mintData;
    mintData.address = recipient;
    mintData.v = rawAmount;
    mintData.a = Scalar(assetType);
    mintData.iota = Scalar(identifier);

    WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to mint this asset.")));
    if (!unlockContext.isValid())
        return;

    CWalletTx wtx;
    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            spark::Address sparkAdmin(spark::Params::get_default());
            bool adminIsSpark = false;
            try {
                if (sparkAdmin.decode(admin) == spark::GetNetworkType())
                    adminIsSpark = true;
            } catch (const std::exception&) {
            }
            if (adminIsSpark) {
                if (!wallet->sparkWallet->isAddressMine(sparkAdmin))
                    throw std::runtime_error("Asset admin address doesn't belong to the wallet");
                wtx = wallet->sparkWallet->CreateSpatsMintTransaction({mintData, sparkAdmin}, txFee, nullptr);
                return;
            }

            CBitcoinAddress transparent(admin);
            if (!transparent.IsValid())
                throw std::runtime_error("Invalid asset admin address");
            const CTxDestination adminDest = transparent.Get();
            if (wallet->IsMine(CTxOut(0, GetScriptForDestination(adminDest))) != ISMINE_SPENDABLE)
                throw std::runtime_error("Asset admin address doesn't belong to wallet");

            CCoinControl control;
            control.fAllowOtherInputs = true;
            bool foundAdminInput = false;
            {
                LOCK2(cs_main, wallet->cs_wallet);
                std::vector<COutput> coins;
                wallet->AvailableCoins(coins, true, &control);
                for (const COutput& out : coins) {
                    CTxDestination dest;
                    if (!out.fSpendable || !ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest) || dest != adminDest)
                        continue;
                    control.Select(COutPoint(out.tx->GetHash(), out.i));
                    foundAdminInput = true;
                    break;
                }
            }
            if (!foundAdminInput)
                throw std::runtime_error("Asset admin address has no available output");
            wtx = wallet->CreateSpatsMintTransparentTransaction(mintData, txFee, &control);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Mint"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    const QString amountText = nft
        ? tr("1 NFT")
        : FormatAssetUnits(rawAmount, precision);
    QString question = tr("Are you sure you want to mint?");
    question.append("<br /><br />");
    question.append(tr("Asset: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    if (!nameText.isEmpty()) {
        question.append("<br />");
        question.append(tr("Name: %1").arg(GUIUtil::HtmlEscape(nameText)));
    }
    question.append("<br />");
    question.append(tr("Amount: %1").arg("<b>" + GUIUtil::HtmlEscape(amountText) + "</b>"));
    question.append("<br />");
    question.append(tr("Recipient: %1").arg("<b>" + GUIUtil::HtmlEscape(addressEdit->text().trimmed()) + "</b>"));
    question.append("<hr /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, txFee));
    question.append("</span> ");
    question.append(tr("added as transaction fee"));
    if (wtx.tx)
        question.append(" (" + QString::number(static_cast<double>(wtx.tx->GetTotalSize()) / 1000) + " kB)");

    SendConfirmationDialog confirmationDialog(tr("Confirm mint"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    try {
        GUIUtil::runWalletOperation([&] {
            wallet->CommitWalletTransaction(wtx);
        });
        scheduleRefreshAssets();
        QMessageBox::information(this, tr("Mint"),
            tr("Mint submitted.\n\nTransaction: %1\nFee: %2")
                .arg(QString::fromStdString(wtx.GetHash().ToString()))
                .arg(BitcoinUnits::formatWithUnit(unit, txFee)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Mint"), QString::fromStdString(e.what()));
    }
}

void AssetsPage::sendSelectedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !portfolioTable)
        return;
    const int row = portfolioTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? portfolioTable->item(row, 0) : nullptr;
    if (!item || portfolioTable->isRowHidden(row))
        return;

    const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
    const std::uint64_t identifier = item->data(RoleIdentifier).toULongLong();
    const int precision = std::min(8, std::max(0, item->data(RolePrecision).toInt()));
    const std::uint64_t balance = item->data(RoleBalance).toULongLong();
    const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
    const QString symbolText = item->data(RoleSymbol).toString();
    const QString nameText = item->data(RoleName).toString();
    if (assetType == 0 || balance == 0) {
        updateSendButton();
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Send"));
    auto *layout = new QFormLayout(&dialog);
    auto *addressEdit = new QLineEdit(&dialog);
    addressEdit->setPlaceholderText(tr("Spark address that will receive this asset"));
    layout->addRow(tr("Spark address"), addressEdit);
    auto *amountEdit = new QLineEdit(&dialog);
    amountEdit->setPlaceholderText(tr("Amount in the asset's decimal places"));
    if (!nft)
        layout->addRow(tr("Amount"), amountEdit);
    layout->addRow(tr("Your balance"), new QLabel(nft ? tr("1 NFT") : FormatAssetUnits(balance, precision), &dialog));
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;

    const QString addressText = addressEdit->text().trimmed();
    spark::Address recipient(spark::Params::get_default());
    try {
        if (recipient.decode(addressText.toStdString()) != spark::GetNetworkType())
            throw std::runtime_error("wrong network");
    } catch (const std::exception&) {
        QMessageBox::warning(this, tr("Send"), tr("Enter a Spark address on this network."));
        return;
    }

    std::uint64_t rawAmount = balance;
    if (!nft) {
        CAmount parsed = 0;
        const QString amountText = amountEdit->text().trimmed();
        if (amountText.isEmpty() ||
                !ParseFixedPoint(amountText.toStdString(), precision, &parsed) ||
                parsed <= 0) {
            QMessageBox::warning(this, tr("Send"), tr("Enter an amount in the asset's decimal places."));
            return;
        }
        rawAmount = static_cast<std::uint64_t>(parsed);
    }
    if (rawAmount > balance) {
        QMessageBox::warning(this, tr("Send"),
            tr("That amount exceeds your balance of %1.").arg(FormatAssetUnits(balance, precision)));
        return;
    }

    CWallet* wallet = model->getWallet();
    WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to send this asset.")));
    if (!unlockContext.isValid())
        return;

    CWalletTx wtx;
    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            spark::OutputCoinData output;
            output.address = recipient;
            output.v = rawAmount;
            output.a = Scalar(assetType);
            output.iota = Scalar(identifier);
            const std::pair<CAmount, std::pair<Scalar, Scalar>> noBurn;
            wtx = wallet->CreateSparkSpendTransaction({}, {}, {output}, txFee, noBurn, nullptr);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Send"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    const QString amountLabel = nft ? tr("1 NFT") : FormatAssetUnits(rawAmount, precision);
    QString question = tr("Are you sure you want to send?");
    question.append("<br /><br />");
    question.append(tr("Asset: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    if (!nameText.isEmpty()) {
        question.append("<br />");
        question.append(tr("Name: %1").arg(GUIUtil::HtmlEscape(nameText)));
    }
    question.append("<br />");
    question.append(tr("Amount: %1").arg("<b>" + GUIUtil::HtmlEscape(amountLabel) + "</b>"));
    question.append("<br />");
    question.append(tr("Recipient: %1").arg("<b>" + GUIUtil::HtmlEscape(addressText) + "</b>"));
    question.append("<hr /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, txFee));
    question.append("</span> ");
    question.append(tr("added as transaction fee"));
    if (wtx.tx)
        question.append(" (" + QString::number(static_cast<double>(wtx.tx->GetTotalSize()) / 1000) + " kB)");

    SendConfirmationDialog confirmationDialog(tr("Confirm send"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    try {
        GUIUtil::runWalletOperation([&] {
            wallet->CommitWalletTransaction(wtx);
        });
        scheduleRefreshAssets();
        QMessageBox::information(this, tr("Send"),
            tr("Send submitted.\n\nTransaction: %1\nFee: %2")
                .arg(QString::fromStdString(wtx.GetHash().ToString()))
                .arg(BitcoinUnits::formatWithUnit(unit, txFee)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Send"), QString::fromStdString(e.what()));
    }
}

void AssetsPage::showReceiveAddress(const QString& symbol, const QString& name)
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet) {
        QMessageBox::warning(this, tr("Receive"), tr("This wallet has no Spark address."));
        return;
    }

    QString address;
    try {
        address = QString::fromStdString(
            model->getWallet()->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType()));
    } catch (const std::exception&) {
        QMessageBox::warning(this, tr("Receive"), tr("This wallet has no Spark address."));
        return;
    }

    QString assetLine = tr("This address can receive any Spark asset.");
    if (!symbol.isEmpty())
        assetLine = tr("Give this address to receive %1.").arg(symbol);
    if (!name.isEmpty())
        assetLine.append(QStringLiteral("\n")).append(name);

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Receive"));
    dialog.setMinimumWidth(520);
    auto *layout = new QVBoxLayout(&dialog);
    auto *intro = new QLabel(assetLine, &dialog);
    intro->setWordWrap(true);
    layout->addWidget(intro);
    auto *note = new QLabel(tr("No transaction is created. The sender mints or sends the asset to this Spark address. Only this wallet can spend what arrives."), &dialog);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto *addressEdit = new QLineEdit(address, &dialog);
    addressEdit->setReadOnly(true);
    addressEdit->setCursorPosition(0);
    layout->addWidget(addressEdit);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *copyButton = buttons->addButton(tr("Copy address"), QDialogButtonBox::ActionRole);
    layout->addWidget(buttons);
    connect(copyButton, &QPushButton::clicked, &dialog, [this, address, copyButton] {
        GUIUtil::setClipboard(address);
        copyButton->setText(tr("Copied"));
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}

void AssetsPage::receiveSelectedAsset()
{
    QString symbol;
    QString name;
    const int row = portfolioTable ? portfolioTable->currentRow() : -1;
    const QTableWidgetItem* item = row >= 0 && portfolioTable ? portfolioTable->item(row, 0) : nullptr;
    if (item && !portfolioTable->isRowHidden(row)) {
        symbol = item->data(RoleSymbol).toString();
        name = item->data(RoleName).toString();
    }
    showReceiveAddress(symbol, name);
}

void AssetsPage::updateReceiveAssetButton()
{
    if (!receiveAssetButton || !createdAssetsTable)
        return;
    bool enable = false;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (item && !createdAssetsTable->isRowHidden(row) && !item->data(RoleOwned).toBool() && !item->data(RolePendingReg).toBool())
        enable = item->data(RoleAssetType).toULongLong() != 0 && !item->data(RoleSymbol).toString().isEmpty();
    receiveAssetButton->setEnabled(enable);
}

void AssetsPage::receiveCreatedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !createdAssetsTable)
        return;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || item->data(RoleOwned).toBool() || item->data(RolePendingReg).toBool()) {
        updateReceiveAssetButton();
        return;
    }
    const QString symbolText = item->data(RoleSymbol).toString();
    if (symbolText.isEmpty() || item->data(RoleAssetType).toULongLong() == 0) {
        updateReceiveAssetButton();
        return;
    }

    CWallet* wallet = model->getWallet();
    QString defaultAddress;
    try {
        defaultAddress = QString::fromStdString(wallet->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType()));
    } catch (const std::exception&) {
        QMessageBox::warning(this, tr("Receive Asset"), tr("The default Spark address is unavailable."));
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Receive Asset"));
    dialog.setMinimumWidth(520);
    auto *layout = new QVBoxLayout(&dialog);
    auto *help = new QLabel(tr("Generate receive data for %1. Give that data to the current admin so they can transfer the asset to the address you select.").arg(symbolText), &dialog);
    help->setWordWrap(true);
    layout->addWidget(help);
    auto *useDefault = new QCheckBox(tr("Use default private address"), &dialog);
    useDefault->setChecked(true);
    layout->addWidget(useDefault);
    auto *defaultLabel = new QLabel(defaultAddress, &dialog);
    defaultLabel->setWordWrap(true);
    defaultLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(defaultLabel);
    auto *customAddress = new QLineEdit(&dialog);
    customAddress->setPlaceholderText(tr("Spark or transparent address"));
    layout->addWidget(customAddress);
    auto *addressError = new QLabel(&dialog);
    addressError->setWordWrap(true);
    addressError->hide();
    layout->addWidget(addressError);
    auto *result = new QTextEdit(&dialog);
    result->setReadOnly(true);
    result->setPlaceholderText(tr("Receive data appears here"));
    result->setMinimumHeight(90);
    layout->addWidget(result);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto *generateButton = buttons->addButton(tr("Generate"), QDialogButtonBox::ActionRole);
    auto *copyButton = buttons->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    copyButton->setEnabled(false);
    layout->addWidget(buttons);

    const auto chosenAddress = [this, wallet, useDefault, defaultAddress, customAddress](QString& errorOut) {
        errorOut.clear();
        if (useDefault->isChecked())
            return defaultAddress.toStdString();
        const std::string text = customAddress->text().trimmed().toStdString();
        if (text.empty()) {
            errorOut = tr("Enter a Spark or transparent address.");
            return std::string();
        }
        try {
            spark::Address sparkAddr(spark::Params::get_default());
            if (sparkAddr.decode(text) != spark::GetNetworkType()) {
                errorOut = tr("This Spark address is for a different network.");
                return std::string();
            }
            if (!wallet->sparkWallet->isAddressMine(sparkAddr)) {
                errorOut = tr("This address does not belong to this wallet.");
                return std::string();
            }
            return text;
        } catch (const std::exception&) {
        }
        CBitcoinAddress address(text);
        if (address.IsValid()) {
            CKeyID keyID;
            if (!address.GetKeyID(keyID)) {
                errorOut = tr("A transparent address must be a P2PKH address.");
                return std::string();
            }
            const isminetype mine = wallet->IsMine(CTxOut(0, GetScriptForDestination(address.Get())));
            if (mine & ISMINE_SPENDABLE)
                return text;
            if (mine & ISMINE_WATCH_ONLY) {
                errorOut = tr("This address is watch-only. The wallet cannot sign with it.");
                return std::string();
            }
            errorOut = tr("This address does not belong to this wallet.");
            return std::string();
        }
        errorOut = tr("This address is not a Spark or transparent address on this network.");
        return std::string();
    };
    const auto refreshAddress = [=] {
        const bool useWalletDefault = useDefault->isChecked();
        defaultLabel->setVisible(useWalletDefault);
        customAddress->setVisible(!useWalletDefault);
        QString error;
        const bool ok = useWalletDefault || !chosenAddress(error).empty();
        addressError->setVisible(!useWalletDefault && !ok && !customAddress->text().trimmed().isEmpty());
        if (addressError->isVisible())
            addressError->setText(error);
        generateButton->setEnabled(ok);
    };
    connect(useDefault, &QCheckBox::toggled, &dialog, refreshAddress);
    connect(customAddress, &QLineEdit::textChanged, &dialog, refreshAddress);
    refreshAddress();
    connect(copyButton, &QPushButton::clicked, &dialog, [this, result, copyButton] {
        GUIUtil::setClipboard(result->toPlainText());
        copyButton->setText(tr("Copied"));
    });
    connect(generateButton, &QPushButton::clicked, &dialog, [this, &dialog, wallet, symbolText, chosenAddress, addressError, result, copyButton] {
        QString error;
        const std::string address = chosenAddress(error);
        if (address.empty()) {
            addressError->setText(error);
            addressError->show();
            return;
        }
        WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to generate receive data.")));
        if (!unlockContext.isValid())
            return;
        std::string receiveData;
        try {
            GUIUtil::runWalletOperation([&] {
                receiveData = wallet->sparkWallet->CreateSpatsAssetReceiveData(symbolText.toStdString(), address);
            });
        } catch (const std::exception& e) {
            QMessageBox::warning(&dialog, tr("Receive Asset"), QString::fromStdString(e.what()));
            return;
        }
        result->setPlainText(QString::fromStdString(receiveData));
        copyButton->setEnabled(true);
        copyButton->setText(tr("Copy"));
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    dialog.exec();
}

void AssetsPage::burnSelectedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !createdAssetsTable)
        return;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || item->data(RolePendingReg).toBool())
        return;

    const std::uint64_t assetType = item->data(RoleAssetType).toULongLong();
    const int precision = std::min(8, std::max(0, item->data(RolePrecision).toInt()));
    const std::uint64_t balance = item->data(RoleBalance).toULongLong();
    const bool nft = item->data(RoleKind).toInt() == static_cast<int>(spark::AssetKind::NonFungible);
    const QString symbolText = item->data(RoleSymbol).toString();
    const QString nameText = item->data(RoleName).toString();
    if (nft || assetType == 0 || balance == 0) {
        updateBurnButton();
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Burn"));
    auto *layout = new QFormLayout(&dialog);
    auto *amountEdit = new QLineEdit(&dialog);
    amountEdit->setPlaceholderText(tr("Amount in the asset's decimal places"));
    layout->addRow(tr("Amount"), amountEdit);
    layout->addRow(tr("Your balance"), new QLabel(FormatAssetUnits(balance, precision), &dialog));
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;

    CAmount parsed = 0;
    const QString amountText = amountEdit->text().trimmed();
    if (amountText.isEmpty() ||
            !ParseFixedPoint(amountText.toStdString(), precision, &parsed) ||
            parsed <= 0) {
        QMessageBox::warning(this, tr("Burn"), tr("Enter an amount in the asset's decimal places."));
        return;
    }
    const std::uint64_t rawAmount = static_cast<std::uint64_t>(parsed);
    if (rawAmount > balance) {
        QMessageBox::warning(this, tr("Burn"),
            tr("That amount exceeds your balance of %1.").arg(FormatAssetUnits(balance, precision)));
        return;
    }

    CWallet* wallet = model->getWallet();
    WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to burn this asset.")));
    if (!unlockContext.isValid())
        return;

    CWalletTx wtx;
    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            wtx = wallet->CreateSparkSpendTransaction(
                {},
                {},
                {},
                txFee,
                std::make_pair(static_cast<CAmount>(rawAmount), std::make_pair(Scalar(assetType), Scalar(uint64_t(0)))),
                nullptr);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Burn"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    QString question = tr("Are you sure you want to burn?");
    question.append("<br /><br />");
    question.append(tr("Asset: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    if (!nameText.isEmpty()) {
        question.append("<br />");
        question.append(tr("Name: %1").arg(GUIUtil::HtmlEscape(nameText)));
    }
    question.append("<br />");
    question.append(tr("Amount: %1").arg("<b>" + GUIUtil::HtmlEscape(FormatAssetUnits(rawAmount, precision)) + "</b>"));
    question.append("<hr /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, txFee));
    question.append("</span> ");
    question.append(tr("added as transaction fee"));
    if (wtx.tx)
        question.append(" (" + QString::number(static_cast<double>(wtx.tx->GetTotalSize()) / 1000) + " kB)");

    SendConfirmationDialog confirmationDialog(tr("Confirm burn"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    try {
        GUIUtil::runWalletOperation([&] {
            wallet->CommitWalletTransaction(wtx);
        });
        scheduleRefreshAssets();
        QMessageBox::information(this, tr("Burn"),
            tr("Burn submitted.\n\nTransaction: %1\nFee: %2")
                .arg(QString::fromStdString(wtx.GetHash().ToString()))
                .arg(BitcoinUnits::formatWithUnit(unit, txFee)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Burn"), QString::fromStdString(e.what()));
    }
}

void AssetsPage::editSelectedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !createdAssetsTable)
        return;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || !item->data(RoleOwned).toBool() || item->data(RolePendingReg).toBool() || item->data(RoleUnconfirmed).toBool())
        return;
    if (item->data(RoleAssetType).toULongLong() == 0)
        return;

    const QString symbolText = item->data(RoleSymbol).toString();
    const QString currentName = item->data(RoleName).toString();
    const QString currentDescription = item->data(RoleDescription).toString();
    const QString currentMetadata = item->data(RoleMetadata).toString();

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Edit Asset"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *symbolLabel = new QLabel(tr("Symbol: %1. The symbol, decimal places, and supply cap stay as they are. Each changed field is submitted as its own transaction.").arg(symbolText), &dialog);
    symbolLabel->setWordWrap(true);
    layout->addWidget(symbolLabel);
    auto *form = new QFormLayout();
    auto *nameEdit = new QLineEdit(currentName, &dialog);
    auto *descriptionEdit = new QTextEdit(currentDescription, &dialog);
    descriptionEdit->setMinimumHeight(80);
    auto *metadataEdit = new QTextEdit(currentMetadata, &dialog);
    metadataEdit->setMinimumHeight(80);
    metadataEdit->setPlaceholderText(tr("JSON object or array, or empty"));
    form->addRow(tr("Name"), nameEdit);
    form->addRow(tr("Description"), descriptionEdit);
    form->addRow(tr("Metadata"), metadataEdit);
    layout->addLayout(form);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;

    const QString newName = nameEdit->text().trimmed();
    const QString newDescription = descriptionEdit->toPlainText().trimmed();
    const QString newMetadata = metadataEdit->toPlainText().trimmed();
    if (newName.isEmpty()) {
        QMessageBox::warning(this, tr("Edit Asset"), tr("Name is required."));
        return;
    }
    if (!newMetadata.isEmpty()) {
        UniValue parsed;
        if (!parsed.read(newMetadata.toStdString()) ||
                (parsed.getType() != UniValue::VOBJ && parsed.getType() != UniValue::VARR)) {
            QMessageBox::warning(this, tr("Edit Asset"), tr("Metadata must be a JSON object or array, or left empty."));
            return;
        }
    }

    struct EditChange {
        spark::CSparkAssetTxData::OperationType operation;
        QString label;
        std::string value;
    };
    std::vector<EditChange> edits;
    if (newName != currentName)
        edits.push_back({spark::CSparkAssetTxData::opModifyName, tr("Name"), newName.toStdString()});
    if (newDescription != currentDescription)
        edits.push_back({spark::CSparkAssetTxData::opModifyDescription, tr("Description"), newDescription.toStdString()});
    if (newMetadata != currentMetadata)
        edits.push_back({spark::CSparkAssetTxData::opModifyMetadata, tr("Metadata"), newMetadata.toStdString()});
    if (edits.empty()) {
        QMessageBox::information(this, tr("Edit Asset"), tr("Nothing was changed."));
        return;
    }
    if (edits.size() > 1) {
        QMessageBox::warning(this, tr("Edit Asset"),
            tr("Change one field at a time. Name, description, and metadata are separate transactions, and the next change has to wait until the previous one is confirmed."));
        return;
    }

    const std::string symbol = symbolText.toStdString();
    CWallet* wallet = model->getWallet();
    WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to edit this asset.")));
    if (!unlockContext.isValid())
        return;

    struct BuiltEdit {
        QString label;
        CWalletTx wtx;
        CAmount fee = 0;
    };
    std::vector<BuiltEdit> built;
    try {
        GUIUtil::runWalletOperation([&] {
            for (const EditChange& edit : edits) {
                spark::CSparkAssetTxData assetData;
                assetData.setSymbol(symbol);
                assetData.setOperationType(edit.operation);
                if (edit.operation == spark::CSparkAssetTxData::opModifyName)
                    assetData.setName(edit.value);
                else if (edit.operation == spark::CSparkAssetTxData::opModifyDescription)
                    assetData.setDescription(edit.value);
                else
                    assetData.setMetadata(edit.value);

                std::optional<spark::CSparkAssetDBEntry> entry;
                {
                    LOCK(cs_main);
                    spark::CSparkState* sparkState = spark::CSparkState::GetState();
                    const std::optional<std::uint64_t> assetType = sparkState->GetAssetState().GetAssetTypeBySymbol(symbol);
                    if (!assetType)
                        throw std::runtime_error("Asset by this symbol does not exist");
                    entry = sparkState->GetAssetState().Get(*assetType);
                }
                if (!entry)
                    throw std::runtime_error("Asset by this symbol does not exist");
                assetData.setDataFromDBentry(*entry);
                std::string verifyError;
                if (!assetData.Verify(verifyError))
                    throw std::runtime_error(verifyError);

                BuiltEdit ready;
                ready.label = edit.label;
                ready.wtx = wallet->CreateOrModifyAsset(assetData, ready.fee);
                built.push_back(std::move(ready));
            }
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Edit Asset"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    CAmount totalFee = 0;
    QString question = tr("Are you sure you want to edit this asset?");
    question.append("<br /><br />");
    question.append(tr("Symbol: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    for (const BuiltEdit& edit : built) {
        question.append("<br />");
        question.append(tr("%1: %2").arg(edit.label, BitcoinUnits::formatHtmlWithUnit(unit, edit.fee)));
        totalFee += edit.fee;
    }
    question.append("<hr />");
    question.append(tr("Total fee %1").arg(BitcoinUnits::formatHtmlWithUnit(unit, totalFee)));
    if (built.size() > 1)
        question.append("<br />" + tr("Each change is a separate transaction."));

    SendConfirmationDialog confirmationDialog(tr("Confirm asset edit"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    std::vector<std::string> submitted;
    try {
        GUIUtil::runWalletOperation([&] {
            for (BuiltEdit& edit : built) {
                wallet->CommitWalletTransaction(edit.wtx);
                submitted.push_back(edit.wtx.GetHash().ToString());
            }
        });
    } catch (const std::exception& e) {
        scheduleRefreshAssets();
        QString message = QString::fromStdString(e.what());
        if (!submitted.empty()) {
            message.prepend(tr("Some changes were submitted, then a later one failed.\n\n"));
            for (const std::string& txid : submitted)
                message.append("\n" + QString::fromStdString(txid));
        }
        QMessageBox::warning(this, tr("Edit Asset"), message);
        return;
    }

    scheduleRefreshAssets();
    QStringList txids;
    for (const std::string& txid : submitted)
        txids.append(QString::fromStdString(txid));
    QMessageBox::information(this, tr("Edit Asset"),
        tr("Edit submitted.\n\nFee: %1\n\n%2")
            .arg(BitcoinUnits::formatWithUnit(unit, totalFee))
            .arg(txids.join("\n")));
}

void AssetsPage::transferSelectedAsset()
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet || !createdAssetsTable)
        return;
    const int row = createdAssetsTable->currentRow();
    const QTableWidgetItem* item = row >= 0 ? createdAssetsTable->item(row, 0) : nullptr;
    if (!item || createdAssetsTable->isRowHidden(row) || !item->data(RoleOwned).toBool() || item->data(RolePendingReg).toBool() || item->data(RoleUnconfirmed).toBool())
        return;
    if (item->data(RoleAssetType).toULongLong() == 0)
        return;

    const QString symbolText = item->data(RoleSymbol).toString();
    const QString currentAdmin = item->data(RoleAdmin).toString();

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Transfer"));
    auto *layout = new QVBoxLayout(&dialog);
    auto *help = new QLabel(tr("Transfer admin of %1. Paste the receive data from the new admin, or enter a Spark or transparent address controlled by this wallet.").arg(symbolText), &dialog);
    help->setWordWrap(true);
    layout->addWidget(help);
    auto *receiveEdit = new QTextEdit(&dialog);
    receiveEdit->setPlaceholderText(tr("address:proof, or an address this wallet controls"));
    receiveEdit->setMinimumHeight(90);
    layout->addWidget(receiveEdit);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted)
        return;

    const QString receiveText = receiveEdit->toPlainText().trimmed();
    if (receiveText.isEmpty()) {
        QMessageBox::warning(this, tr("Transfer"), tr("Enter receive data or an address this wallet controls."));
        return;
    }

    std::string receiveAddress;
    std::vector<unsigned char> receiveProof;
    const bool parsed = spark::ParseSpatsAssetReceiveData(receiveText.toStdString(), receiveAddress, receiveProof);
    const bool ownAddress = !parsed && spark::IsValidAssetAdminAddress(receiveText.toStdString()) && walletControlsAddress(receiveText.toStdString());
    if (!parsed && !ownAddress) {
        QMessageBox::warning(this, tr("Transfer"),
            tr("Paste the receive data created by the new admin, or enter a Spark or transparent address controlled by this wallet."));
        return;
    }
    if (ownAddress)
        receiveAddress = receiveText.toStdString();
    if (QString::fromStdString(receiveAddress) == currentAdmin) {
        QMessageBox::warning(this, tr("Transfer"), tr("That address is already the admin."));
        return;
    }

    if (parsed) {
        bool proofOk = false;
        {
            LOCK(cs_main);
            spark::CSparkState* sparkState = spark::CSparkState::GetState();
            const std::optional<std::uint64_t> assetType = sparkState->GetAssetState().GetAssetTypeBySymbol(symbolText.toStdString());
            const std::optional<spark::CSparkAssetDBEntry> entry = assetType ? sparkState->GetAssetState().Get(*assetType) : std::nullopt;
            proofOk = entry && spark::VerifySpatsAssetReceiverProof(*assetType, entry->adminPublicAddress, receiveAddress, receiveProof);
        }
        if (!proofOk) {
            QMessageBox::warning(this, tr("Transfer"), tr("The receive data does not match this asset or its current admin."));
            return;
        }
    }

    CWallet* wallet = model->getWallet();
    WalletModel::UnlockContext unlockContext(model->requestUnlock(tr("Enter the wallet passphrase to transfer this asset.")));
    if (!unlockContext.isValid())
        return;

    if (ownAddress) {
        try {
            const std::string created = wallet->sparkWallet->CreateSpatsAssetReceiveData(symbolText.toStdString(), receiveAddress);
            if (!spark::ParseSpatsAssetReceiveData(created, receiveAddress, receiveProof))
                throw std::runtime_error("Unable to create receive data");
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Transfer"), QString::fromStdString(e.what()));
            return;
        }
    }

    CWalletTx wtx;
    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            spark::CSparkAssetTxData assetData;
            assetData.setSymbol(symbolText.toStdString());
            assetData.setOperationType(spark::CSparkAssetTxData::opTransfer);
            assetData.setTransferAddress(receiveAddress);
            assetData.setRecieverProof(receiveProof);

            std::optional<spark::CSparkAssetDBEntry> entry;
            {
                LOCK(cs_main);
                spark::CSparkState* sparkState = spark::CSparkState::GetState();
                const std::optional<std::uint64_t> assetType = sparkState->GetAssetState().GetAssetTypeBySymbol(symbolText.toStdString());
                if (!assetType)
                    throw std::runtime_error("Asset by this symbol does not exist");
                entry = sparkState->GetAssetState().Get(*assetType);
            }
            if (!entry)
                throw std::runtime_error("Asset by this symbol does not exist");
            assetData.setDataFromDBentry(*entry);
            std::string verifyError;
            if (!assetData.Verify(verifyError))
                throw std::runtime_error(verifyError);
            wtx = wallet->CreateOrModifyAsset(assetData, txFee);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Transfer"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    QString question = tr("Are you sure you want to transfer admin of this asset?");
    question.append("<br /><br />");
    question.append(tr("Symbol: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    question.append("<br />");
    question.append(tr("New admin: %1").arg("<b>" + GUIUtil::HtmlEscape(QString::fromStdString(receiveAddress)) + "</b>"));
    question.append("<br />");
    question.append(tr("You will no longer be able to mint or edit this asset after the transfer confirms."));
    question.append("<hr /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, txFee));
    question.append("</span> ");
    question.append(tr("added as transaction fee"));
    if (wtx.tx)
        question.append(" (" + QString::number(static_cast<double>(wtx.tx->GetTotalSize()) / 1000) + " kB)");

    SendConfirmationDialog confirmationDialog(tr("Confirm transfer"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    try {
        GUIUtil::runWalletOperation([&] {
            wallet->CommitWalletTransaction(wtx);
        });
        scheduleRefreshAssets();
        QMessageBox::information(this, tr("Transfer"),
            tr("Transfer submitted.\n\nTransaction: %1\nFee: %2")
                .arg(QString::fromStdString(wtx.GetHash().ToString()))
                .arg(BitcoinUnits::formatWithUnit(unit, txFee)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Transfer"), QString::fromStdString(e.what()));
    }
}

void AssetsPage::applyCreateFieldState()
{
    const bool isFungible = fungible->isChecked();
    const bool unlimited = resupply->currentIndex() == 0;
    precision->setEnabled(isFungible);
    resupply->setEnabled(isFungible);
    supply->setEnabled(isFungible && !unlimited);
}

void AssetsPage::clearCreateForm()
{
    fungible->setChecked(true);
    symbol->clear();
    name->clear();
    precision->setCurrentIndex(8);
    supply->clear();
    resupply->setCurrentIndex(0);
    description->clear();
    metadata->clear();
    useDefaultAdmin->setChecked(true);
    customAdmin->clear();
    applyCreateFieldState();
    updateAdminField();
}

bool AssetsPage::resolveAdminAddress(std::string& addressOut, QString& errorOut) const
{
    errorOut.clear();
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet) {
        errorOut = tr("Spark wallet is not available.");
        return false;
    }
    CWallet* wallet = model->getWallet();
    if (useDefaultAdmin->isChecked()) {
        try {
            addressOut = wallet->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType());
            return true;
        } catch (const std::exception&) {
            errorOut = tr("The default Spark address is unavailable.");
            return false;
        }
    }

    const std::string text = customAdmin->text().trimmed().toStdString();
    if (text.empty()) {
        errorOut = tr("Enter a Spark or transparent address.");
        return false;
    }

    try {
        spark::Address sparkAddr(spark::Params::get_default());
        const unsigned char network = sparkAddr.decode(text);
        if (network != spark::GetNetworkType()) {
            errorOut = tr("This Spark address is for a different network.");
            return false;
        }
        if (wallet->sparkWallet->isAddressMine(sparkAddr)) {
            addressOut = text;
            return true;
        }
        errorOut = tr("This address does not belong to this wallet.");
        return false;
    } catch (const std::exception&) {
    }

    CBitcoinAddress address(text);
    if (address.IsValid()) {
        CKeyID keyID;
        if (!address.GetKeyID(keyID)) {
            errorOut = tr("A transparent admin must be a P2PKH address.");
            return false;
        }
        const isminetype mine = wallet->IsMine(CTxOut(0, GetScriptForDestination(address.Get())));
        if (mine & ISMINE_SPENDABLE) {
            addressOut = text;
            return true;
        }
        if (mine & ISMINE_WATCH_ONLY) {
            errorOut = tr("This address is watch-only. The wallet cannot sign with it.");
            return false;
        }
        errorOut = tr("This address does not belong to this wallet.");
        return false;
    }

    errorOut = tr("This address is not a Spark or transparent address on this network.");
    return false;
}

void AssetsPage::updateAdminField()
{
    const bool useDefault = useDefaultAdmin->isChecked();
    adminAddress->setVisible(useDefault);
    customAdminField->setVisible(!useDefault);
    if (useDefault) {
        adminError->hide();
        adminError->clear();
        customAdmin->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QLineEdit { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 10px; padding: 0 13px; selection-background-color: $WINE_TINT; }
            QLineEdit:hover { border-color: $INK_FAINT; }
            QLineEdit:focus { border: 1px solid $WINE; }
        )")));
        if (createAssetButton)
            createAssetButton->setEnabled(true);
        return;
    }

    const bool empty = customAdmin->text().trimmed().isEmpty();
    std::string address;
    QString error;
    const bool ok = !empty && resolveAdminAddress(address, error);
    customAdmin->setStyleSheet(GUIUtil::themed(empty || ok
        ? QStringLiteral(R"(
            QLineEdit { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 10px; padding: 0 13px; selection-background-color: $WINE_TINT; }
            QLineEdit:hover { border-color: $INK_FAINT; }
            QLineEdit:focus { border: 1px solid $WINE; }
        )")
        : QStringLiteral(R"(
            QLineEdit { background: $PANEL; color: $INK; border: 1px solid $ERROR; border-radius: 10px; padding: 0 13px; selection-background-color: $WINE_TINT; }
            QLineEdit:focus { border: 1px solid $ERROR; }
        )")));
    if (empty || ok) {
        adminError->hide();
        adminError->clear();
    } else {
        adminError->setText(error);
        adminError->show();
    }
    if (createAssetButton)
        createAssetButton->setEnabled(ok);
}

bool AssetsPage::readCreateForm(spark::CSparkAssetTxData& assetData, QString& errorOut) const
{
    if (!model || !model->getWallet() || !model->getWallet()->sparkWallet) {
        errorOut = tr("Spark wallet is not available.");
        return false;
    }
    CWallet* wallet = model->getWallet();

    const QString symbolText = symbol->text().trimmed();
    const QString nameText = name->text().trimmed();
    if (symbolText.isEmpty() || nameText.isEmpty()) {
        errorOut = tr("Symbol and name are required.");
        return false;
    }

    const bool isFungible = fungible->isChecked();
    const int precisionValue = isFungible ? precision->currentIndex() : 0;
    const bool unlimited = isFungible && resupply->currentIndex() == 0;
    const QString metadataText = metadata->toPlainText().trimmed();
    if (!metadataText.isEmpty()) {
        UniValue parsed;
        if (!parsed.read(metadataText.toStdString()) ||
                (parsed.getType() != UniValue::VOBJ && parsed.getType() != UniValue::VARR)) {
            errorOut = tr("Metadata must be a JSON object or array, or left empty.");
            return false;
        }
    }

    std::uint64_t maxSupply = 0;
    if (isFungible && !unlimited) {
        const QString supplyText = supply->text().trimmed();
        CAmount rawSupply = 0;
        if (supplyText.isEmpty() ||
            !ParseFixedPoint(supplyText.toStdString(), precisionValue, &rawSupply) ||
            rawSupply <= 0 ||
            static_cast<std::uint64_t>(rawSupply) > static_cast<std::uint64_t>(spark::MAX_ASSET_MONEY)) {
            errorOut = tr("Enter a supply cap in the selected decimal places, or choose Unlimited.");
            return false;
        }
        maxSupply = static_cast<std::uint64_t>(rawSupply);
    }

    assetData = spark::CSparkAssetTxData();
    assetData.setOperationType(spark::CSparkAssetTxData::opRegister);
    assetData.setSymbol(symbolText.toStdString());
    assetData.setName(nameText.toStdString());
    assetData.setDescription(description->toPlainText().trimmed().toStdString());
    assetData.setMetadata(metadataText.toStdString());
    assetData.setPrecision(static_cast<uint8_t>(precisionValue));
    assetData.setMaxSupply(maxSupply);
    std::string adminAddressText;
    if (!resolveAdminAddress(adminAddressText, errorOut))
        return false;
    assetData.setAdminPublicAddress(adminAddressText);
    if (!isFungible) {
        assetData.setAssetKind(spark::AssetKind::NonFungible);
        assetData.setIdentifier(wallet->sparkWallet->GetNFTIdentifier(symbolText.toStdString()));
    }

    std::string verifyError;
    if (!assetData.Verify(verifyError)) {
        errorOut = QString::fromStdString(verifyError);
        return false;
    }
    return true;
}

void AssetsPage::estimateCreateFee()
{
    const QString symbolText = symbol->text().trimmed();
    const std::string symbolBytes = symbolText.toStdString();
    const bool lettersOnly = !symbolBytes.empty() && std::all_of(symbolBytes.begin(), symbolBytes.end(), [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    });
    // Matches spark::MAX_SYMBOL_BYTES. The fee schedule is longer, but longer tickers are rejected.
    constexpr std::size_t maxSymbolBytes = 16;
    const auto& regFees = Params().GetConsensus().nSpatsRegFee;
    if (!lettersOnly || symbolBytes.size() > maxSymbolBytes ||
            symbolBytes.size() >= regFees.size() || regFees[symbolBytes.size()] < 0) {
        QMessageBox::warning(this, tr("Estimate fee"),
            tr("Enter a symbol of 1–16 Latin letters to estimate the registration fee."));
        return;
    }

    const int unit = model && model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    const CAmount registrationFee = static_cast<CAmount>(regFees[symbolBytes.size()]) * COIN;
    const QString registrationText = BitcoinUnits::formatWithUnit(unit, registrationFee);

    spark::CSparkAssetTxData assetData;
    QString formError;
    if (!readCreateForm(assetData, formError)) {
        QMessageBox::information(this, tr("Estimate fee"),
            tr("Registration fee for a %1-letter symbol: %2\n\nThe Spark transaction fee was not calculated.\n\n%3")
                .arg(QString::number(symbolBytes.size()))
                .arg(registrationText)
                .arg(formError));
        return;
    }

    WalletModel::UnlockContext unlockContext(model->requestUnlock(
        tr("Enter the wallet passphrase to estimate the transaction fee.")));
    if (!unlockContext.isValid()) {
        QMessageBox::information(this, tr("Estimate fee"),
            tr("Registration fee for a %1-letter symbol: %2\n\nUnlock the wallet to calculate the Spark transaction fee.")
                .arg(QString::number(symbolBytes.size()))
                .arg(registrationText));
        return;
    }

    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            model->getWallet()->CreateOrModifyAsset(assetData, txFee);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Estimate fee"),
            tr("Registration fee for a %1-letter symbol: %2\n\nThe Spark transaction fee was not calculated.\n\n%3")
                .arg(QString::number(symbolBytes.size()))
                .arg(registrationText)
                .arg(QString::fromStdString(e.what())));
        return;
    }

    QMessageBox::information(this, tr("Estimate fee"),
        tr("Registration fee for a %1-letter symbol: %2\nTransaction fee: %3\nTotal: %4")
            .arg(QString::number(symbolBytes.size()))
            .arg(registrationText)
            .arg(BitcoinUnits::formatWithUnit(unit, txFee))
            .arg(BitcoinUnits::formatWithUnit(unit, registrationFee + txFee)));
}

void AssetsPage::submitCreateAsset()
{
    if (!model || !model->getWallet()) {
        QMessageBox::warning(this, tr("Create Asset"), tr("No wallet is loaded."));
        return;
    }
    CWallet* wallet = model->getWallet();
    if (!wallet->sparkWallet) {
        QMessageBox::warning(this, tr("Create Asset"), tr("Spark wallet is not available."));
        return;
    }

    spark::CSparkAssetTxData assetData;
    QString formError;
    if (!readCreateForm(assetData, formError)) {
        updateAdminField();
        QMessageBox::warning(this, tr("Create Asset"), formError);
        return;
    }

    const QString symbolText = symbol->text().trimmed();
    const QString nameText = name->text().trimmed();
    const bool isFungible = fungible->isChecked();
    const int precisionValue = isFungible ? precision->currentIndex() : 0;
    const bool unlimited = isFungible && resupply->currentIndex() == 0;

    WalletModel::UnlockContext unlockContext(model->requestUnlock(
        tr("Enter the wallet passphrase to create this asset.")));
    if (!unlockContext.isValid())
        return;

    CWalletTx wtx;
    CAmount txFee = 0;
    try {
        GUIUtil::runWalletOperation([&] {
            wtx = wallet->CreateOrModifyAsset(assetData, txFee);
        });
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Create Asset"), QString::fromStdString(e.what()));
        return;
    }

    const int unit = model->getOptionsModel()
        ? model->getOptionsModel()->getDisplayUnit()
        : BitcoinUnits::BTC;
    const auto& regFees = Params().GetConsensus().nSpatsRegFee;
    const std::size_t symbolSize = assetData.getSymbol().size();
    const CAmount registrationFee =
        (symbolSize < regFees.size() && regFees[symbolSize] > 0)
            ? static_cast<CAmount>(regFees[symbolSize]) * COIN
            : 0;

    QString question = tr("Are you sure you want to register this asset?");
    question.append("<br /><br />");
    question.append(tr("Symbol: %1").arg("<b>" + GUIUtil::HtmlEscape(symbolText) + "</b>"));
    question.append("<br />");
    question.append(tr("Name: %1").arg("<b>" + GUIUtil::HtmlEscape(nameText) + "</b>"));
    question.append("<br />");
    question.append(tr("Type: %1").arg(isFungible ? tr("Fungible") : tr("NFT")));
    question.append("<br />");
    question.append(tr("Admin (%1): %2")
        .arg(assetData.isValidRegularAddress() ? tr("transparent") : tr("Spark"))
        .arg("<b>" + GUIUtil::HtmlEscape(QString::fromStdString(assetData.getAdminPublicAddress())) + "</b>"));
    if (assetData.isValidRegularAddress()) {
        question.append("<br />");
        question.append(tr("The registration fee is still paid from Spark."));
    }
    if (isFungible) {
        question.append("<br />");
        question.append(tr("Decimal places: %1").arg(precisionValue));
        question.append("<br />");
        question.append(unlimited
            ? tr("Supply cap: %1").arg(tr("Unlimited"))
            : tr("Supply cap: %1").arg("<b>" + GUIUtil::HtmlEscape(supply->text().trimmed()) + "</b>"));
    } else {
        question.append("<br />");
        question.append(tr("Identifier: %1").arg(QString::number(static_cast<qulonglong>(assetData.getIdentifier()))));
    }
    question.append("<br />");
    question.append(tr("This registration does not mint any coins."));
    question.append("<hr /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, registrationFee));
    question.append("</span> ");
    question.append(tr("registration fee"));
    question.append("<br /><span style='font-weight: 700;'>");
    question.append(BitcoinUnits::formatHtmlWithUnit(unit, txFee));
    question.append("</span> ");
    question.append(tr("added as transaction fee"));
    if (wtx.tx)
        question.append(" (" + QString::number(static_cast<double>(wtx.tx->GetTotalSize()) / 1000) + " kB)");
    question.append("<hr />");
    question.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(unit, registrationFee + txFee)));

    SendConfirmationDialog confirmationDialog(tr("Confirm asset registration"), question, SEND_CONFIRM_DELAY, this);
    confirmationDialog.exec();
    if (static_cast<QMessageBox::StandardButton>(confirmationDialog.result()) != QMessageBox::Yes)
        return;

    try {
        GUIUtil::runWalletOperation([&] {
            wallet->CommitWalletTransaction(wtx);
        });
        clearCreateForm();
        scheduleRefreshAssets();
        QMessageBox::information(this, tr("Create Asset"),
            tr("Asset registration submitted.\n\nTransaction: %1\nRegistration fee: %2\nTransaction fee: %3")
                .arg(QString::fromStdString(wtx.GetHash().ToString()))
                .arg(BitcoinUnits::formatWithUnit(unit, registrationFee))
                .arg(BitcoinUnits::formatWithUnit(unit, txFee)));
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Create Asset"), QString::fromStdString(e.what()));
    }
}
