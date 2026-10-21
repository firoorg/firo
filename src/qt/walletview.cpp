// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletview.h"

#include "addressbookpage.h"
#include "askpassphrasedialog.h"
#include "automintdialog.h"
#include "automintmodel.h"
#include "bitcoingui.h"
#include "clientmodel.h"
#include "exportviewkeydialog.h"
#include "guiutil.h"
#include "guitheme.h"
#include "sparkmodel.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "sparknamespage.h"
#include "transactiontablemodel.h"
#include "transactionview.h"
#include "walletmodel.h"


#include <QAbstractItemView>
#include <QAction>
#include <QActionGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QDebug>
#include <QDialog>
#include <QFileDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPixmap>
#include <QPolygon>
#include <QProgressDialog>
#include <QPushButton>
#include <QSplitter>
#include <QTableView>
#include <QTableWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    overviewPage(0),
    platformStyle(_platformStyle)
{
    overviewPage = new OverviewPage(platformStyle);
    transactionsPage = new QWidget(this);
    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    sparkNamesPage = new SparkNamesPage(platformStyle);
    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this, false);

    sendCoinsPage = new QWidget(this);
    masternodeListPage = new MasternodeList(platformStyle);
    assetsPage = new QWidget(this);
    assetsPage->setObjectName(QStringLiteral("assetsPage"));

    automintSparkNotification = new AutomintSparkNotification(this);
    automintSparkNotification->setWindowModality(Qt::NonModal);

    setupTransactionPage();
    setupSendCoinPage();

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sparkNamesPage);
    addWidget(sendCoinsPage);
    addWidget(masternodeListPage);
    addWidget(assetsPage);

    auto *assetsLayout = new QVBoxLayout(assetsPage);
    assetsLayout->setContentsMargins(20, 16, 20, 16);
    auto *assetsTabs = new QTabWidget(assetsPage);
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
    auto *searchAssets = new QLineEdit(portfolio);
    searchAssets->setPlaceholderText(tr("Search assets, symbol, identifier…"));
    searchAssets->setMinimumHeight(36);
    searchAssets->setMinimumWidth(300);
    searchAssets->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QLineEdit { background: $PANEL; color: $INK; border: 1px solid $BORDER; border-radius: 8px; padding: 0 10px; }
        QLineEdit:focus { border-color: $WINE; }
    )")));
    filterRow->addWidget(searchAssets, 1);
    auto *filterGroup = new QFrame(portfolio);
    filterGroup->setObjectName(QStringLiteral("assetFilterGroup"));
    filterGroup->setFixedWidth(326);
    filterGroup->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    filterGroup->setStyleSheet(QStringLiteral("QFrame#assetFilterGroup { background: transparent; border: none; }"));
    auto *filterGroupLayout = new QHBoxLayout(filterGroup);
    filterGroupLayout->setContentsMargins(0, 0, 0, 0);
    filterGroupLayout->setSpacing(12);
    int filterIndex = 0;
    for (const QString& label : {tr("All"), tr("Held"), tr("Watch-only")}) {
        auto *button = new QPushButton(label, filterGroup);
        const int buttonWidth = label == tr("Watch-only") ? 118 : 70;
        const QString widthRule = QStringLiteral(" min-width: %1px; max-width: %1px;").arg(buttonWidth);
        button->setStyleSheet(GUIUtil::themed(filterIndex == 0
            ? QStringLiteral("QPushButton { background: $WINE_DEEP; color: #FFFFFF; border: 1px solid $WINE_DEEP; border-radius: 8px; padding: 0 6px; font-size: 11px; font-weight: 700;") + widthRule + QStringLiteral(" }")
            : QStringLiteral("QPushButton { background: $PANEL; color: $INK_SOFT; border: 1px solid $BORDER; border-radius: 8px; padding: 0 6px; font-size: 11px; font-weight: 600;") + widthRule + QStringLiteral(" } QPushButton:hover { background: $PANEL_SOFT; color: $INK; border-color: $WINE; }")));
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        button->setFixedSize(buttonWidth, 36);
        filterGroupLayout->addWidget(button);
        ++filterIndex;
    }
    filterRow->addWidget(filterGroup);
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
    auto *assetCount = new QLabel(QStringLiteral("0"), assetsCard);
    assetCount->setAlignment(Qt::AlignCenter);
    assetCount->setFixedSize(32, 28);
    assetCount->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 14px; font-weight: 700;")));
    assetHeading->addWidget(assetTitle);
    assetHeading->addWidget(assetCount);
    assetHeading->addStretch(1);
    assetsCardLayout->addLayout(assetHeading);
    auto *assetTable = new QTableWidget(0, 4, assetsCard);
    assetTable->setHorizontalHeaderLabels({tr("ASSET ID"), tr("NAME"), tr("SYMBOL"), tr("AVAILABLE")}); configureTable(assetTable);
    assetTable->setColumnWidth(0, 120);
    assetTable->setColumnWidth(2, 110);
    assetTable->setFixedHeight(48);
    assetTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    assetTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    assetsCardLayout->addWidget(assetTable);
    auto *emptyState = new QWidget(assetsCard);
    auto *emptyLayout = new QVBoxLayout(emptyState);
    emptyLayout->setAlignment(Qt::AlignCenter);
    auto *emptyIcon = new QLabel(QStringLiteral("⬡"), emptyState);
    emptyIcon->setAlignment(Qt::AlignCenter);
    emptyIcon->setFixedSize(72, 72);
    emptyIcon->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 36px; font-size: 30px; font-weight: 600;")));
    auto *emptyTitle = new QLabel(tr("No assets yet"), emptyState);
    emptyTitle->setAlignment(Qt::AlignCenter);
    emptyTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 17px; font-weight: 700; background: transparent; border: none;")));
    auto *emptyDescription = new QLabel(tr("Add a watch asset by its identifier or create your own to see it in your portfolio."), emptyState);
    emptyDescription->setAlignment(Qt::AlignCenter);
    emptyDescription->setWordWrap(true);
    emptyDescription->setMaximumWidth(380);
    emptyDescription->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    emptyLayout->addWidget(emptyIcon, 0, Qt::AlignHCenter);
    emptyLayout->addSpacing(12);
    emptyLayout->addWidget(emptyTitle);
    emptyLayout->addWidget(emptyDescription);
    assetsCardLayout->addWidget(emptyState, 1);
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
    portfolioActions->addWidget(makePortfolioButton(tr("Send"), GUIUtil::primaryButtonStyle(QStringLiteral("0 12px")), 90));
    portfolioActions->addWidget(makePortfolioButton(tr("Receive"), GUIUtil::primaryButtonStyle(QStringLiteral("0 12px")), 100));
    portfolioActions->addWidget(makePortfolioButton(tr("Add Watch Asset"), GUIUtil::secondaryButtonStyle(QStringLiteral("0 12px")), 154));
    portfolioActions->addStretch(1);
    portfolioActions->addWidget(makePortfolioButton(tr("Export…"), GUIUtil::secondaryButtonStyle(QStringLiteral("0 12px")), 98));
    portfolioActions->addWidget(makePortfolioButton(tr("Remove"), GUIUtil::themed(QStringLiteral("QPushButton { color: $WINE; background: $WINE_TINT; border: none; padding: 0 12px; font-weight: 600; } QPushButton:hover { background: $WINE; color: #FFFFFF; }")), 90));
    auto *footerLayout = new QVBoxLayout(actionsFooter);
    footerLayout->setContentsMargins(0, 0, 0, 0);
    footerLayout->addLayout(portfolioActions);
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
    const QStringList detailLabels{tr("Name"), tr("Symbol"), tr("Identifier"), tr("Precision"), tr("Total Supply"), tr("Type"), tr("Resupplyable"), tr("Description"), tr("Metadata")};
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
        auto *value = new QLabel(QStringLiteral("—"), row);
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
    auto *createdTitle = new QLabel(tr("My Created Assets"), createdCard);
    createdTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 19px; font-weight: 700; background: transparent; border: none;")));
    auto *createdCount = new QLabel(QStringLiteral("0"), createdCard);
    createdCount->setAlignment(Qt::AlignCenter);
    createdCount->setFixedSize(32, 28);
    createdCount->setStyleSheet(GUIUtil::themed(QStringLiteral("background: $WINE_TINT; color: $WINE; border-radius: 14px; font-weight: 700;")));
    createdHeading->addWidget(createdTitle);
    createdHeading->addWidget(createdCount);
    createdHeading->addStretch(1);
    createdCardLayout->addLayout(createdHeading);
    auto *createdTable = new QTableWidget(0, 5, createdCard);
    createdTable->setHorizontalHeaderLabels({tr("NAME"), tr("SYMBOL"), tr("TYPE"), tr("SUPPLY"), tr("IDENTIFIER")});
    configureTable(createdTable);
    createdTable->setFixedHeight(48);
    createdTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    createdTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    createdCardLayout->addWidget(createdTable);
    auto *createdEmpty = new QWidget(createdCard);
    auto *createdEmptyLayout = new QVBoxLayout(createdEmpty);
    createdEmptyLayout->setAlignment(Qt::AlignCenter);
    auto *createdEmptyIcon = new QLabel(QStringLiteral("⬡"), createdEmpty);
    createdEmptyIcon->setAlignment(Qt::AlignCenter);
    createdEmptyIcon->setFixedSize(48, 48);
    createdEmptyIcon->setStyleSheet(GUIUtil::themed(QStringLiteral("background: transparent; color: $WINE; font-size: 32px; font-weight: 600;")));
    auto *createdEmptyTitle = new QLabel(tr("You haven’t created any assets"), createdEmpty);
    createdEmptyTitle->setAlignment(Qt::AlignCenter);
    createdEmptyTitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK; font-size: 16px; font-weight: 700; background: transparent; border: none;")));
    auto *createdEmptyHint = new QLabel(tr("Use the Create Asset tab to issue your first one."), createdEmpty);
    createdEmptyHint->setAlignment(Qt::AlignCenter);
    createdEmptyHint->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    createdEmptyLayout->addWidget(createdEmptyIcon, 0, Qt::AlignHCenter);
    createdEmptyLayout->addSpacing(8);
    createdEmptyLayout->addWidget(createdEmptyTitle);
    createdEmptyLayout->addWidget(createdEmptyHint);
    createdCardLayout->addWidget(createdEmpty, 1);
    auto *creationFooter = new QFrame(createdCard);
    creationFooter->setObjectName(QStringLiteral("creationFooter"));
    creationFooter->setStyleSheet(GUIUtil::themed(QStringLiteral("QFrame#creationFooter { background: transparent; border: none; }")));
    auto *creationActions = new QHBoxLayout(creationFooter);
    creationActions->setContentsMargins(0, 10, 0, 10);
    creationActions->setSpacing(8);
    for (const QString& label : {tr("Mint…"), tr("Burn…"), tr("Change Metadata…"), tr("Resupply Settings…"), tr("Revoke / Retire…")}) {
        auto *button = new QPushButton(label, creationFooter);
        button->setEnabled(false);
        styleButton(button);
        button->setFixedHeight(42);
        button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        button->setStyleSheet(GUIUtil::themed(QStringLiteral("QPushButton:disabled { background: $PANEL_SOFT; color: $INK_FAINT; border: none; border-radius: 9px; padding: 0 10px; font-size: 11px; font-weight: 600; }")));
        creationActions->addWidget(button);
    }
    auto *creationFooterLayout = new QVBoxLayout(creationFooter);
    creationFooterLayout->setContentsMargins(0, 0, 0, 0);
    creationFooterLayout->addLayout(creationActions);
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
    auto *activitySubtitle = new QLabel(tr("selected asset"), activityCard);
    activitySubtitle->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 12px; font-weight: 600; background: transparent; border: none;")));
    activityHeading->addWidget(activityTitle);
    activityHeading->addWidget(activitySubtitle);
    activityHeading->addStretch(1);
    activityLayout->addLayout(activityHeading);
    auto *activityTable = new QTableWidget(0, 4, activityCard);
    activityTable->setHorizontalHeaderLabels({tr("DATE"), tr("TYPE"), tr("TXID"), tr("NOTES")});
    configureTable(activityTable);
    activityTable->setFixedHeight(48);
    activityTable->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    activityTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    activityLayout->addWidget(activityTable);
    auto *activityEmpty = new QLabel(tr("Select an asset above to see its activity."), activityCard);
    activityEmpty->setAlignment(Qt::AlignCenter);
    activityEmpty->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 13px; background: transparent; border: none;")));
    activityLayout->addWidget(activityEmpty, 1);
    createdLayout->addWidget(activityCard, 2);
    assetsTabs->addTab(created, tr("My Creations"));

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
    auto *fungible = new QCheckBox(fungiblePanel);
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
    auto *fungibleHint = new QLabel(tr("Turn off for a unique asset (NFT). Supply and decimal places apply to fungible tokens."), fungibleDescription);
    fungibleHint->setWordWrap(true);
    fungibleHint->setStyleSheet(GUIUtil::themed(QStringLiteral("color: $INK_SOFT; font-size: 12px; background: transparent; border: none;")));
    fungibleDescriptionLayout->addWidget(fungibleTitle);
    fungibleDescriptionLayout->addWidget(fungibleHint);
    fungibleLayout->addWidget(fungible);
    fungibleLayout->addWidget(fungibleDescription, 1);
    essentialsLayout->addWidget(fungiblePanel);

    auto *symbol = new QLineEdit();
    symbol->setPlaceholderText(tr("e.g. MTK"));
    styleField(symbol);

    auto *name = new QLineEdit();
    name->setPlaceholderText(tr("e.g. My Token"));
    styleField(name);

    auto *precision = new QComboBox();
    for (int i = 0; i <= 8; ++i) {
        precision->addItem(QString::number(i));
    }
    styleField(precision);

    auto *supply = new QLineEdit();
    supply->setPlaceholderText(tr("e.g. 1000000"));
    styleField(supply);

    auto *resupply = new QComboBox();
    resupply->addItems({tr("Yes"), tr("No")});
    styleField(resupply);
    auto *form = new QGridLayout();
    form->setContentsMargins(0, 0, 0, 0);
    form->setHorizontalSpacing(14);
    form->setVerticalSpacing(12);
    form->addWidget(makeField(essentials, tr("Symbol"), symbol), 0, 0);
    form->addWidget(makeField(essentials, tr("Name"), name), 0, 1);
    form->addWidget(makeField(essentials, tr("Decimal places"), precision), 1, 0);
    form->addWidget(makeField(essentials, tr("Total supply"), supply), 1, 1);
    form->addWidget(makeField(essentials, tr("Allow resupply"), resupply), 2, 0);
    form->setColumnStretch(0, 1);
    form->setColumnStretch(1, 1);
    essentialsLayout->addLayout(form);
    essentialsLayout->addStretch(1);

    auto *essentialActions = new QHBoxLayout();
    essentialActions->setSpacing(8);
    auto *primaryCreateButton = new QPushButton(tr("Create Asset"), essentials);
    primaryCreateButton->setFixedSize(176, 44);
    primaryCreateButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("6px 16px")));
    auto *clearButton = new QPushButton(tr("Clear"), essentials);
    clearButton->setFixedSize(86, 44);
    clearButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("6px 14px")));
    auto *estimateButton = new QPushButton(tr("Estimate fee →"), essentials);
    estimateButton->setFixedSize(146, 44);
    estimateButton->setStyleSheet(GUIUtil::secondaryButtonStyle(QStringLiteral("6px 14px")));
    essentialActions->addWidget(primaryCreateButton);
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
    auto *description = new QTextEdit(metadataCard);
    description->setPlaceholderText(tr("Optional short description shown with the asset"));
    styleField(description);
    description->setMinimumHeight(170);
    metadataLayout->addWidget(description, 1);
    auto *metadataLabel = new QLabel(tr("Metadata (JSON)"), metadataCard);
    styleFieldLabel(metadataLabel, 12);
    metadataLayout->addWidget(metadataLabel);
    auto *metadata = new QTextEdit(metadataCard);
    metadata->setPlaceholderText(tr("Optional JSON, e.g. { \"website\": \"https://…\" }"));
    styleField(metadata);
    metadata->setMinimumHeight(150);
    metadataLayout->addWidget(metadata, 1);
    auto *createAssetButton = new QPushButton(tr("Create Asset"), metadataCard);
    createAssetButton->setFixedHeight(44);
    createAssetButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("6px 16px")));
    metadataLayout->addWidget(createAssetButton);
    createLayout->addWidget(essentials, 1); createLayout->addWidget(metadataCard, 1);
    assetsTabs->addTab(create, tr("Create Asset"));

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::focusBitcoinHistoryTab);
}

WalletView::~WalletView()
{
}

void WalletView::setupTransactionPage()
{
    // Create Firo transactions list
    firoTransactionList = new TransactionView(platformStyle);

    connect(firoTransactionList, &TransactionView::message, this, &WalletView::message);

    connect(overviewPage, &OverviewPage::transactionClicked, firoTransactionList, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));
    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::requestedSyncWarningInfo);

    // Set layout for transaction page
    auto pageLayout = new QVBoxLayout();
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->addWidget(firoTransactionList);

    transactionsPage->setLayout(pageLayout);
}

void WalletView::setupSendCoinPage()
{
    sendFiroView = new SendCoinsDialog(platformStyle);

    connect(sendFiroView, &SendCoinsDialog::message, this, &WalletView::message);

    // Set layout for send coin page
    auto pageLayout = new QVBoxLayout();
        pageLayout->addWidget(sendFiroView);

    sendCoinsPage->setLayout(pageLayout);
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, &OverviewPage::transactionClicked, gui, &BitcoinGUI::gotoHistoryPage);

        connect(overviewPage, &OverviewPage::gotoSendCoinsPage, gui, [gui] { gui->gotoSendCoinsPage(); });
        connect(overviewPage, &OverviewPage::gotoReceiveCoinsPage, gui, &BitcoinGUI::gotoReceiveCoinsPage);

        // Receive and report messages
        connect(this, &WalletView::message, [gui](const QString &title, const QString &message, unsigned int style) {
            gui->message(title, message, style);
        });

        // Pass through encryption status changed signals
        connect(this, &WalletView::encryptionStatusChanged, gui, &BitcoinGUI::setEncryptionStatus);

        // Pass through transaction notifications
        connect(this, &WalletView::incomingTransaction, gui, &BitcoinGUI::incomingTransaction);

        // Connect HD enabled state signal
        connect(this, &WalletView::hdEnabledStatusChanged, gui, &BitcoinGUI::setHDStatus);
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(clientModel);
    sendFiroView->setClientModel(clientModel);
    masternodeListPage->setClientModel(clientModel);
    sparkNamesPage->setClientModel(clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;
    walletModel->setClientModel(clientModel);

    // Put transaction list in tabs
    firoTransactionList->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    sparkNamesPage->setModel(_walletModel);
    // TODO: fix this
    //sendCoinsPage->setModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel->getAddressTableModel());
    usedSendingAddressesPage->setModel(_walletModel->getAddressTableModel());
    masternodeListPage->setWalletModel(_walletModel);
    sendFiroView->setModel(_walletModel);
    automintSparkNotification->setModel(_walletModel);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, &WalletModel::message, this, &WalletView::message);

        // Handle changes in encryption status
        connect(_walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged(_walletModel->hdEnabled());

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

        // Ask for passphrase if needed
        connect(_walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

        // Show progress dialog
        connect(_walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);

        // Check mintable amount
        connect(_walletModel, &WalletModel::balanceChanged, this, &WalletView::checkMintableSparkAmount);

        auto sparkModel = _walletModel->getSparkModel();
        if (sparkModel) {
            connect(sparkModel, &SparkModel::askMintSparkAll, this, &WalletView::askMintSparkAll);
            auto autoMintSparkModel = sparkModel->getAutoMintSparkModel();
            connect(autoMintSparkModel, &AutoMintSparkModel::message, this, &WalletView::message);
            connect(autoMintSparkModel, &AutoMintSparkModel::requireShowAutomintSparkNotification, this, &WalletView::showAutomintSparkNotification);
            connect(autoMintSparkModel, &AutoMintSparkModel::closeAutomintSparkNotification, this, &WalletView::closeAutomintSparkNotification);
        }
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->inInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label);
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoBitcoinHistoryTab()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::focusBitcoinHistoryTab(const QModelIndex &idx)
{
    gotoBitcoinHistoryTab();
    firoTransactionList->focusTransaction(idx);
}

void WalletView::gotoMasternodePage()
{
    setCurrentWidget(masternodeListPage);
}

void WalletView::gotoAssetsPage()
{
    setCurrentWidget(assetsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSparkNamesPage()
{
    setCurrentWidget(sparkNamesPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty()){
        sendFiroView->setAddress(addr);
    }
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendFiroView->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
    firoTransactionList->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged(walletModel->getEncryptionStatus());
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), NULL);

    if (filename.isEmpty())
        return;

    if (!walletModel->backupWallet(filename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::exportViewKey()
{
    ExportViewKeyDialog dlg(this, walletModel->getWallet()->GetSparkViewKeyStr());
    dlg.exec();
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet(const QString &info)
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this, info);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    usedSendingAddressesPage->show();
    usedSendingAddressesPage->raise();
    usedSendingAddressesPage->activateWindow();
}

bool WalletView::updateAddressbook()
{
    const bool receivingUpdated = usedReceivingAddressesPage->updateSpark();
    const bool sendingUpdated = usedSendingAddressesPage->updateSpark();
    return receivingUpdated || sendingUpdated;
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    usedReceivingAddressesPage->show();
    usedReceivingAddressesPage->raise();
    usedReceivingAddressesPage->activateWindow();
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}

void WalletView::showAutomintSparkNotification()
{
    auto sparkModel = walletModel->getSparkModel();
    auto wallet = walletModel->getWallet();
   if (!sparkModel || !wallet || !wallet->sparkWallet) {
        return;
    }

    if (!isActiveWindow() || !underMouse()) {
        sparkModel->sendAckMintSparkAll(AutoMintSparkAck::WaitUserToActive);
        return;
    }

    automintSparkNotification->setWindowFlags(automintSparkNotification->windowFlags() | Qt::Popup | Qt::FramelessWindowHint);

    QRect rect(this->mapToGlobal(QPoint(0, 0)), this->size());
    auto pos = QStyle::alignedRect(
        Qt::LeftToRight,
        Qt::AlignRight | Qt::AlignBottom,
        automintSparkNotification->size(),
        rect).topLeft();

    pos.setX(pos.x());
    pos.setY(pos.y());
    automintSparkNotification->move(pos);

    automintSparkNotification->show();
    automintSparkNotification->raise();
}

void WalletView::repositionAutomintSparkNotification()
{
    if (automintSparkNotification->isVisible()) {
        QRect rect(this->mapToGlobal(QPoint(0, 0)), this->size());
        auto pos = QStyle::alignedRect(
            Qt::LeftToRight,
            Qt::AlignRight | Qt::AlignBottom,
            automintSparkNotification->size(),
            rect).topLeft();

        pos.setX(pos.x());
        pos.setY(pos.y());
        automintSparkNotification->move(pos);
    }
}

void WalletView::checkMintableSparkAmount(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount anonymizableBalance)
{
    if (automintSparkNotification->isVisible() && anonymizableBalance == 0) {
        // hide if notification is showing but there no any fund to anonymize
        closeAutomintSparkNotification();
    }
}

void WalletView::closeAutomintSparkNotification()
{
    automintSparkNotification->close();
}

void WalletView::askMintSparkAll(AutoMintSparkMode mode)
{
    automintSparkNotification->setVisible(false);

    if (!walletModel) {
        return;
    }

    AutoMintSparkDialog dlg(mode, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

bool WalletView::eventFilter(QObject *watched, QEvent *event)
{
    switch (event->type()) {
    case QEvent::Type::Resize:
    case QEvent::Type::Move:
        repositionAutomintSparkNotification();
        break;
    default:
        break;
    }

    return QStackedWidget::eventFilter(watched, event);
}
