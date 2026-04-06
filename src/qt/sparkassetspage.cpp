#include "sparkassetspage.h"
#include "ui_sparkassetspage.h"

#include <QGraphicsDropShadowEffect>
#include <QHeaderView>
#include <QAbstractItemView>
#include <QEvent>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QMouseEvent>
#include <QLayoutItem>
#include <QMessageBox>
#include <QFont>
#include <QClipboard>
#include <QFileDialog>
#include <QGuiApplication>
#include <QLineEdit>
#include <QLabel>
#include <QSizePolicy>
#include <QJsonObject>
#include <QJsonDocument>
#include <QDialogButtonBox>
#include <QTimer>
#include <QMetaObject>
#include <QDebug>
#include <cassert>
#include <algorithm>
#include <ranges>
#include "random.h"
#include "../spats/manager.hpp"

#include "../spark/state.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"
#include "../net.h" // for g_connman
#include "spatsburndialog.h"

#include "walletmodel.h"
#include "sparkassetdialog.h" // NewSparkAssetCreationContext
#include "spatsmintdialog.h"
#include "spatsuserconfirmationdialog.h"
#include "guiutil.h"

#include <boost/numeric/conversion/cast.hpp>
#include <boost/lexical_cast.hpp>
#include "../utils/math.hpp"


namespace {

static spats::universal_asset_id_t spark_asset_uid(const spats::SparkAsset& a)
{
    const spats::SparkAssetBase& b = spats::get_base(a);
    const spats::identifier_t id = spats::get_identifier(a).value_or(spats::identifier_t{});
    return { b.asset_type(), id };
}

/** Matches Overview Spark asset cards (hover shadow lift). */
class PortfolioAssetCardHoverFilter : public QObject
{
public:
    explicit PortfolioAssetCardHoverFilter(QObject* parent = nullptr) : QObject(parent) {}

protected:
    bool eventFilter(QObject* obj, QEvent* event) override
    {
        auto* widget = qobject_cast<QWidget*>(obj);
        if (!widget)
            return QObject::eventFilter(obj, event);
        auto* shadow = qobject_cast<QGraphicsDropShadowEffect*>(widget->graphicsEffect());
        if (!shadow)
            return QObject::eventFilter(obj, event);
        if (event->type() == QEvent::Enter) {
            if (!widget->property("assetBaseY").isValid())
                widget->setProperty("assetBaseY", widget->pos().y());
            const int baseY = widget->property("assetBaseY").toInt();
            shadow->setBlurRadius(36);
            shadow->setOffset(0, 11);
            shadow->setColor(QColor(110, 120, 130, 145));
            widget->move(widget->x(), baseY - 3);
            widget->raise();
        } else if (event->type() == QEvent::Leave) {
            const int baseY = widget->property("assetBaseY").toInt();
            shadow->setBlurRadius(18);
            shadow->setOffset(0, 5);
            shadow->setColor(QColor(100, 110, 120, 85));
            widget->move(widget->x(), baseY);
        }
        return QObject::eventFilter(obj, event);
    }
};

static QString portfolioCardFrameQss(bool selected)
{
    const QString border =
        selected ? QStringLiteral("2px solid #C62839") : QStringLiteral("1px solid rgba(255, 255, 255, 0)");
    return QStringLiteral(
               R"(
            QFrame#portfolioAssetRow {
                border: %1;
                border-radius: 18px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #E8EDF2,
                                            stop:0.52 #B7C3D0,
                                            stop:1 #A3AFBA);
            }
            QFrame#portfolioAssetRow:hover {
                border: 1px solid rgba(255, 255, 255, 0);
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #D1D8E2,
                                            stop:0.52 #C0CBD6,
                                            stop:1 #A3AFBA);
            }
        )")
        .arg(border);
}

static QString myCreationCardFrameQss(bool selected)
{
    const QString border =
        selected ? QStringLiteral("2px solid #C62839") : QStringLiteral("1px solid rgba(255, 255, 255, 0)");
    return QStringLiteral(
               R"(
            QFrame#myCreationAssetRow {
                border: %1;
                border-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #E8EDF2,
                                            stop:0.52 #B7C3D0,
                                            stop:1 #A3AFBA);
            }
            QFrame#myCreationAssetRow:hover {
                border: 1px solid rgba(255, 255, 255, 0);
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                            stop:0 #D1D8E2,
                                            stop:0.52 #C0CBD6,
                                            stop:1 #A3AFBA);
            }
        )")
        .arg(border);
}

// Button visuals come from firo.css (Overview-aligned). Only behaviour / cursor here.
static void applyPrimaryButtonStyle(QPushButton* b) {
    if (!b) return;
    b->setMinimumHeight(28);
    b->setCursor(Qt::PointingHandCursor);
}

/** Portfolio / My Creations toolbar — tighter min height to match compact QSS padding */
static void applyCompactPrimaryButtonStyle(QPushButton* b) {
    if (!b) return;
    b->setMinimumHeight(26);
    b->setCursor(Qt::PointingHandCursor);
}

static void applySecondaryButtonStyle(QPushButton* b) {
    if (!b) return;
    b->setMinimumHeight(28);
    b->setCursor(Qt::PointingHandCursor);
}

static void applyToggleTabButtonStyle(QPushButton* b) {
    if (!b) return;
    b->setMinimumHeight(28);
    b->setCheckable(true);
    b->setCursor(Qt::PointingHandCursor);
}

static void applyCardStyle(QWidget* w) {
    if (!w) return;
    const QString id = w->objectName();
    if (id.isEmpty()) return;
    w->setStyleSheet(QStringLiteral(
        "QWidget#%1 {"
        "  background: #ffffff;"
        "  border: none;"
        "  border-radius: 12px;"
        "}"
    ).arg(id));
}

static void applyTableStyle(QTableWidget* t) {
    if (!t) return;
    t->setStyleSheet(
        "QHeaderView::section {"
        "  background: #f9fafb;"
        "  color: #111827;"
        "  padding: 8px;"
        "  border: none;"                   // remove header line
        "  font-weight: 600;"
        "}"
        "QTableWidget {"
        "  background: #ffffff;"
        "  border: none;"                   // remove table outer border
        "  gridline-color: transparent;"    // hide inner grid lines
        "  selection-background-color: #FEE2E2;"   // red-100
        "  selection-color: #111827;"
        "}"
        "QTableWidget::item {"
        "  padding: 6px;"
        "}"
    );
}

static void applySearchFieldStyle(QLineEdit* e) {
    if (!e) return;
    e->setMinimumHeight(34);
    e->setStyleSheet(
        "QLineEdit {"
        "  background: #ffffff;"
        "  color: #111827;"
        "  border: 1px solid #e5e7eb;"
        "  border-radius: 8px;"
        "  padding: 6px 10px;"
        "}"
        "QLineEdit:focus {"
        "  border-color: #93c5fd;"
        "}"
    );
}

}

namespace spats {

SparkAssetsPage::SparkAssetsPage(const PlatformStyle *platform_style, QWidget *parent)
    : QWidget(parent)
    , platform_style_(platform_style)
    , ui(new Ui::SparkAssetsPage)
{
    ui->setupUi(this);

    if (ui->createCardsRow) {
        ui->createCardsRow->setStretch(0, 1);
        ui->createCardsRow->setStretch(1, 1);
    }
    if (ui->layoutEssentialsColumns) {
        ui->layoutEssentialsColumns->setStretch(0, 1);
        ui->layoutEssentialsColumns->setStretch(1, 1);
    }
    if (ui->createMainCardBodyLayout) {
        ui->createMainCardBodyLayout->setAlignment(Qt::AlignTop);
    }
    if (ui->layoutEssentialsColumns && ui->layoutEssentialsColLeft && ui->layoutEssentialsColRight) {
        ui->layoutEssentialsColumns->setAlignment(ui->layoutEssentialsColLeft, Qt::AlignTop);
        ui->layoutEssentialsColumns->setAlignment(ui->layoutEssentialsColRight, Qt::AlignTop);
    }

    if (ui->frameCreateMainCard) {
        ui->frameCreateMainCard->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->frameEssentialsBanner) {
        ui->frameEssentialsBanner->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->frameDetailsBanner) {
        ui->frameDetailsBanner->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->frameCreateDetailsBody) {
        ui->frameCreateDetailsBody->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->lineEssentialsSep) {
        ui->lineEssentialsSep->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->lineDetailsSep) {
        ui->lineDetailsSep->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->createRoot) {
        ui->createRoot->setStretch(0, 0);
        ui->createRoot->setStretch(1, 1);
    }
    if (ui->createDetailsRoot) {
        ui->createDetailsRoot->setStretch(0, 0);
        ui->createDetailsRoot->setStretch(1, 1);
    }
    if (ui->frameCreateMainCardBody) {
        ui->frameCreateMainCardBody->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->frameCreateDetailsCard) {
        ui->frameCreateDetailsCard->setAttribute(Qt::WA_StyledBackground, true);
    }
    if (ui->labelCreateSubtitle) {
        ui->labelCreateSubtitle->setContentsMargins(0, 0, 0, 0);
        ui->labelCreateSubtitle->setMargin(0);
        ui->labelCreateSubtitle->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    }

    // Apply unified modern styles to the page
    applyCardStyle(ui->assetsCard);
    applyCardStyle(ui->detailsCard);
    applyCardStyle(ui->frameMyCreated);
    applyCardStyle(ui->frameActivity);

    applyTableStyle(ui->tableActivity);

    applySearchFieldStyle(ui->searchAssets);

    // Navigation tab buttons
    applyToggleTabButtonStyle(ui->btnPortfolio);
    applyToggleTabButtonStyle(ui->btnMyCreations);
    applyToggleTabButtonStyle(ui->btnCreateAsset);

    // Create Asset row (larger controls)
    applyPrimaryButtonStyle(ui->btnDoCreate);
    applyPrimaryButtonStyle(ui->btnDoCreateWide);
    applyPrimaryButtonStyle(ui->btnClear);
    applyPrimaryButtonStyle(ui->btnEstimate);

    // Portfolio + My Creations (compact toolbar)
    applyCompactPrimaryButtonStyle(ui->btnSend);
    applyCompactPrimaryButtonStyle(ui->btnReceive);
    applyCompactPrimaryButtonStyle(ui->btnMint);
    applyCompactPrimaryButtonStyle(ui->btnBurn);
    applyCompactPrimaryButtonStyle(ui->btnCopy);
    applyCompactPrimaryButtonStyle(ui->btnExport);
    applyCompactPrimaryButtonStyle(ui->btnAddWatch);
    applyCompactPrimaryButtonStyle(ui->btnRemove);
    applyCompactPrimaryButtonStyle(ui->btnRefresh);
    applyCompactPrimaryButtonStyle(ui->btnMetadata);
    applyCompactPrimaryButtonStyle(ui->btnResupply);
    applyCompactPrimaryButtonStyle(ui->btnRevoke);
    applyCompactPrimaryButtonStyle(ui->btnAll);
    applyCompactPrimaryButtonStyle(ui->btnHeld);
    applyCompactPrimaryButtonStyle(ui->btnWatchOnly);
    applySecondaryButtonStyle(ui->btnAutoId);
    applySecondaryButtonStyle(ui->btnGenerateId);

    // --- existing connections and logic ---
    
    connect(ui->chkFungible, &QCheckBox::toggled, this, [this](bool fungible){
        ui->labelSupply->setVisible(fungible);
        ui->editSupply->setVisible(fungible);

        ui->labelPrecision->setVisible(fungible);
        ui->comboPrecision->setVisible(fungible);

        ui->labelResupply->setVisible(fungible);
        ui->comboResupply->setVisible(fungible);

        ui->labelIdentifier->setVisible(!fungible);
        ui->editIdentifier->setVisible(!fungible);
        ui->btnAutoId->setVisible(!fungible);
        ui->btnGenerateId->setVisible(!fungible);
    });

    ui->chkFungible->setChecked(true);
    ui->chkFungible->toggled(true);

    if (ui->scrollPortfolioAssets) {
        ui->scrollPortfolioAssets->setWidgetResizable(true);
        ui->scrollPortfolioAssets->setFrameShape(QFrame::NoFrame);
        ui->scrollPortfolioAssets->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    }

    ui->btnPortfolio->setCheckable(true);
    ui->btnMyCreations->setCheckable(true);
    ui->btnCreateAsset->setCheckable(true);

    connect(ui->btnPortfolio, &QPushButton::clicked, this, &SparkAssetsPage::switchToPortfolioTab);


    connect(ui->btnMyCreations, &QPushButton::clicked, this, [this]() {
        ui->stackedAssets->setCurrentWidget(ui->pageMyCreations);
        ui->searchContainer->hide();
        ui->btnPortfolio->setChecked(false);
        ui->btnMyCreations->setChecked(true);
        ui->btnCreateAsset->setChecked(false);
    });

    connect(ui->btnAll, &QPushButton::clicked, this, [this]() { setPortfolioFilter(PortfolioFilterKind::All); });
    connect(ui->btnHeld, &QPushButton::clicked, this, [this]() { setPortfolioFilter(PortfolioFilterKind::Held); });
    connect(ui->btnWatchOnly, &QPushButton::clicked, this, [this]() { setPortfolioFilter(PortfolioFilterKind::WatchOnly); });

    connect(ui->btnCreateAsset, &QPushButton::clicked, this, [this]() {
        ui->stackedAssets->setCurrentWidget(ui->pageCreateAsset);
        ui->searchContainer->hide();
        ui->btnPortfolio->setChecked(false);
        ui->btnMyCreations->setChecked(false);
        ui->btnCreateAsset->setChecked(true);
    });

    connect(ui->searchAssets, &QLineEdit::textChanged,
        this, &SparkAssetsPage::filterPortfolioTable);
    
    connect(ui->btnRefresh, &QPushButton::clicked,
        this, &SparkAssetsPage::onRefreshButtonClicked);

    connect(ui->btnClear, &QPushButton::clicked,
        this, &SparkAssetsPage::onClearCreateForm);

    // Connect missing asset action buttons
    connect(ui->btnSend, &QPushButton::clicked, this, &SparkAssetsPage::onSendButtonClicked);
    connect(ui->btnReceive, &QPushButton::clicked, this, &SparkAssetsPage::onReceiveButtonClicked);
    connect(ui->btnExport, &QPushButton::clicked, this, &SparkAssetsPage::onExportButtonClicked);
    connect(ui->btnRemove, &QPushButton::clicked, this, &SparkAssetsPage::onRemoveButtonClicked);
    connect(ui->btnCopy, &QPushButton::clicked, this, &SparkAssetsPage::onCopyButtonClicked);

    ui->tableActivity->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableActivity->verticalHeader()->setVisible(false);

    if (ui->scrollMyCreations) {
        ui->scrollMyCreations->setWidgetResizable(true);
        ui->scrollMyCreations->setFrameShape(QFrame::NoFrame);
        ui->scrollMyCreations->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        ui->scrollMyCreations->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        ui->scrollMyCreations->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }
    if (ui->layoutMyCreationsList) {
        ui->layoutMyCreationsList->setAlignment(Qt::AlignTop);
    }

    addShadow(ui->btnMint);
    addShadow(ui->btnBurn);
    addShadow(ui->btnMetadata);
    addShadow(ui->btnResupply);
    addShadow(ui->btnRevoke);

    addShadow(ui->frameMyCreated);
    addShadow(ui->frameActivity);

    addShadow(ui->assetsCard);
    addShadow(ui->detailsCard);

    addShadow(ui->btnSend);
    addShadow(ui->btnReceive);
    addShadow(ui->btnAddWatch);
    addShadow(ui->btnRemove);
    addShadow(ui->btnExport);
    addShadow(ui->btnCopy);
    addShadow(ui->btnPortfolio);
    addShadow(ui->btnMyCreations);
    addShadow(ui->btnCreateAsset);

    addShadow(ui->btnAll);
    addShadow(ui->btnHeld);
    addShadow(ui->btnWatchOnly);
    addShadow(ui->btnRefresh);
    addShadow(ui->frameCreateMainCard);
    addShadow(ui->frameCreateDetailsCard);

    connect(ui->btnDoCreate,  &QPushButton::clicked, this, &SparkAssetsPage::onCreateButtonClicked);
    connect(ui->btnDoCreateWide, &QPushButton::clicked, this, &SparkAssetsPage::onCreateButtonClicked);
    connect(ui->btnMint,      &QPushButton::clicked, this, &SparkAssetsPage::onMintButtonClicked);
    connect(ui->btnMetadata,  &QPushButton::clicked, this, &SparkAssetsPage::onModifyButtonClicked);
    connect(ui->btnResupply,  &QPushButton::clicked, this, &SparkAssetsPage::onModifyButtonClicked);
    connect(ui->btnRevoke,    &QPushButton::clicked, this, &SparkAssetsPage::onUnregisterButtonClicked);
    connect(ui->btnBurn, &QPushButton::clicked, this, &SparkAssetsPage::onBurnButtonClicked);

    connect(ui->btnAutoId, &QPushButton::clicked, this, [this]() {
        ui->editIdentifier->setText("0");
    });

    connect(ui->btnGenerateId, &QPushButton::clicked, this, [this]() {
        uint64_t new_id = GetRand(UINT64_MAX);

        ui->editIdentifier->setText(QString::number(new_id));
    });
    ui->chkFungible->setChecked(true);
    ui->chkFungible->toggled(true);

    updateButtonStates();

    switchToPortfolioTab();
}

void SparkAssetsPage::switchToPortfolioTab()
{
    if (!ui->stackedAssets || !ui->pagePortfolio)
        return;
    ui->stackedAssets->setCurrentWidget(ui->pagePortfolio);
    if (ui->searchContainer)
        ui->searchContainer->show();

    ui->btnPortfolio->setChecked(true);
    ui->btnMyCreations->setChecked(false);
    ui->btnCreateAsset->setChecked(false);

    if (ui->btnSend)
        ui->btnSend->setVisible(true);
    if (ui->btnReceive)
        ui->btnReceive->setVisible(true);
    if (ui->btnAddWatch)
        ui->btnAddWatch->setVisible(true);

    display_all_assets();
    if (ui->searchAssets)
        filterPortfolioTable(ui->searchAssets->text());
}

void SparkAssetsPage::showPortfolioTabOnEntry()
{
    switchToPortfolioTab();
}

SparkAssetsPage::~SparkAssetsPage()
{
    spark::CSparkState::GetState()->GetSpatsManager().remove_updates_observer(*this);
    delete ui;
}

void SparkAssetsPage::applyPortfolioCardChrome(QFrame* frame, bool selected) const
{
    if (!frame)
        return;
    frame->setStyleSheet(portfolioCardFrameQss(selected));
}

void SparkAssetsPage::setPortfolioFilter(PortfolioFilterKind kind)
{
    portfolio_filter_ = kind;
    refreshPortfolioCardsVisibility();
}

void SparkAssetsPage::refreshPortfolioCardsVisibility()
{
    auto* lay = ui->layoutPortfolioAssetsList;
    if (!lay)
        return;

    const QString q = ui->searchAssets->text().trimmed().toLower();
    for (int i = 0; i < lay->count(); ++i) {
        QLayoutItem* item = lay->itemAt(i);
        if (!item)
            continue;
        auto* frame = qobject_cast<QFrame*>(item->widget());
        if (!frame || frame->objectName() != QLatin1String("portfolioAssetRow"))
            continue;

        const QString blob = frame->property("searchBlob").toString();
        const bool searchOk = q.isEmpty() || blob.contains(q);
        bool filterOk = true;
        if (portfolio_filter_ == PortfolioFilterKind::Held)
            filterOk = frame->property("hasBalance").toBool();
        else if (portfolio_filter_ == PortfolioFilterKind::WatchOnly)
            filterOk = !frame->property("hasBalance").toBool();
        frame->setVisible(searchOk && filterOk);
    }

    if (selected_portfolio_card_ && !selected_portfolio_card_->isVisible()) {
        applyPortfolioCardChrome(selected_portfolio_card_, false);
        selected_portfolio_card_ = nullptr;
        selected_portfolio_uid_.reset();
    }
}

bool SparkAssetsPage::eventFilter(QObject* watched, QEvent* event)
{
    if (event->type() == QEvent::MouseButtonRelease) {
        auto* me = static_cast<QMouseEvent*>(event);
        if (me->button() == Qt::LeftButton) {
            auto* frame = qobject_cast<QFrame*>(watched);
            if (frame && frame->objectName() == QLatin1String("portfolioAssetRow")) {
                onPortfolioCardClicked(frame);
                return true;
            }
            if (frame && frame->objectName() == QLatin1String("myCreationAssetRow")) {
                onMyCreationCardClicked(frame);
                return true;
            }
        }
    }
    return QWidget::eventFilter(watched, event);
}

void SparkAssetsPage::onPortfolioCardClicked(QFrame* frame)
{
    if (!frame)
        return;

    const QVariant vt = frame->property("assetType");
    const QVariant vi = frame->property("assetIdentifier");
    if (!vt.isValid() || !vi.isValid())
        return;

    bool okType = false;
    bool okId = false;
    const qulonglong typeVal = vt.toULongLong(&okType);
    const qulonglong idVal = vi.toULongLong(&okId);
    if (!okType || !okId)
        return;

    const spats::asset_type_t at{typeVal};
    const spats::identifier_t ident{idVal};

    if (selected_portfolio_card_ != frame) {
        applyPortfolioCardChrome(selected_portfolio_card_, false);
        selected_portfolio_card_ = frame;
        selected_portfolio_uid_ = std::make_pair(at, ident);
        applyPortfolioCardChrome(selected_portfolio_card_, true);
    }

    auto& registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    std::optional<spats::SparkAsset> found;
    {
        std::shared_lock lock(registry.mutex_);
        if (is_fungible_asset_type(at)) {
            auto it = registry.fungible_assets_.find(at);
            if (it != registry.fungible_assets_.end())
                found = it->second;
        } else {
            auto lineIt = registry.nft_lines_.find(at);
            if (lineIt != registry.nft_lines_.end()) {
                auto idIt = lineIt->second.find(ident);
                if (idIt != lineIt->second.end())
                    found = idIt->second;
            }
        }
    }

    if (!found)
        return;

    showAssetDetails(spats::SparkAssetDisplayAttributes(*found));
}

void SparkAssetsPage::applyMyCreationCardChrome(QFrame* frame, bool selected) const
{
    if (!frame)
        return;
    frame->setStyleSheet(myCreationCardFrameQss(selected));
}

void SparkAssetsPage::onMyCreationCardClicked(QFrame* frame)
{
    if (!frame)
        return;

    const QVariant vt = frame->property("assetType");
    const QVariant vi = frame->property("assetIdentifier");
    if (!vt.isValid() || !vi.isValid())
        return;

    bool okType = false;
    bool okId = false;
    const qulonglong typeVal = vt.toULongLong(&okType);
    const qulonglong idVal = vi.toULongLong(&okId);
    if (!okType || !okId)
        return;

    const spats::asset_type_t at{typeVal};
    const spats::identifier_t ident{idVal};

    if (selected_my_creation_card_ != frame) {
        applyMyCreationCardChrome(selected_my_creation_card_, false);
        selected_my_creation_card_ = frame;
        selected_my_creation_uid_ = spats::universal_asset_id_t{at, ident};
        applyMyCreationCardChrome(selected_my_creation_card_, true);
    }

    updateButtonStates();
}

void SparkAssetsPage::addShadow(QWidget *w)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(18);
    shadow->setOffset(0, 4);
    shadow->setColor(QColor(0, 0, 0, 60));
    w->setGraphicsEffect(shadow);
}

// --- Re-implemented actions ---

void SparkAssetsPage::onSendButtonClicked()
{
    if (!wallet_model_) {
        QMessageBox::warning(this, tr("Wallet"), tr("Wallet model not ready."));
        return;
    }

    // Selected asset
    auto uid = getSelectedPortfolioAssetUID();
    if (!uid) {
        QMessageBox::information(this, tr("Send"), tr("Please select an asset to send."));
        return;
    }

    // Combined dialog: ask for address and amount in one window
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Send Asset"));
    QFormLayout *form = new QFormLayout(&dlg);

    QLineEdit *addrEdit = new QLineEdit(&dlg);
    addrEdit->setPlaceholderText(tr("Recipient Spark address"));
    QDoubleSpinBox *amountSpin = new QDoubleSpinBox(&dlg);
    amountSpin->setDecimals(8);
    amountSpin->setRange(0.0, 9e18);
    amountSpin->setValue(0.0);

    form->addRow(tr("Address"), addrEdit);
    form->addRow(tr("Amount"), amountSpin);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(buttons);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) return;

    const QString toAddr = addrEdit->text().trimmed();
    const double amountD = amountSpin->value();
    if (toAddr.isEmpty() || amountD <= 0.0) {
        QMessageBox::warning(this, tr("Send"), tr("Please enter a valid address and amount."));
        return;
    }

    // Convert amount to asset supply amount respecting precision from registry
    const auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    std::optional<unsigned> precision;
    {
        std::shared_lock lock(registry.mutex_);
        if (is_fungible_asset_type(uid->first)) {
            auto it = registry.fungible_assets_.find(uid->first);
            if (it != registry.fungible_assets_.end()) {
                precision = get_precision(it->second.asset());
            }
        } else {
            auto lineIt = registry.nft_lines_.find(uid->first);
            if (lineIt != registry.nft_lines_.end()) {
                auto idIt = lineIt->second.find(uid->second);
                if (idIt != lineIt->second.end()) {
                    precision = get_precision(idIt->second.asset());
                }
            }
        }
    }
    if (!precision) {
        QMessageBox::critical(this, tr("Send"), tr("Unknown asset precision. Try again after registry sync."));
        return;
    }

    // Build spats recipient output
    spark::OutputCoinData assetOut;
    try {
        const auto recvAddr = wallet_model_->getWallet()->sparkWallet->decodeAddress(toAddr.toStdString());
        assetOut.address = recvAddr;
    } catch (const std::exception &e) {
        QMessageBox::critical(this, tr("Send"), tr("Invalid recipient address."));
        return;
    }

    // Amount conversion: integer units per precision
    const auto units = static_cast<int64_t>(std::llround(amountD * std::pow(10.0, static_cast<int>(*precision))));
    if (units <= 0) {
        QMessageBox::critical(this, tr("Send"), tr("Amount too small for asset precision."));
        return;
    }

    assetOut.v = boost::numeric_cast<CAmount>(units);
    assetOut.memo = std::string{"asset send"};
    assetOut.a = utils::to_underlying(uid->first);
    assetOut.iota = utils::to_underlying(uid->second);

    // Create transaction
    CAmount fee = 0;
    std::vector<CRecipient> recipients; // no transparent outputs
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients; // none
    std::vector<spark::OutputCoinData> spatsRecipients{ assetOut };
    const std::pair<CAmount, std::pair<Scalar, Scalar>> burnAsset{}; // no burn
    const CCoinControl *coinControl = nullptr;

    CWalletTx wtx;
    try {
        wtx = wallet_model_->getWallet()->sparkWallet->CreateSparkSpendTransaction(
            recipients,
            privateRecipients,
            spatsRecipients,
            fee,
            burnAsset,
            coinControl,
            /*additionalTxSize*/ 0);
    } catch (const std::exception &e) {
        QMessageBox::critical(this, tr("Send"), tr("Failed to build transaction: %1").arg(e.what()));
        return;
    }

    // Commit the transaction using the correct signature
    try {
        CReserveKey reserveKey(wallet_model_->getWallet());
        CValidationState state;
        if (!wallet_model_->getWallet()->CommitTransaction(wtx, reserveKey, g_connman.get(), state)) {
            QMessageBox::critical(this, tr("Send"), tr("Transaction commit failed."));
            return;
        }
    } catch (const std::exception &e) {
        QMessageBox::critical(this, tr("Send"), tr("Commit error: %1").arg(e.what()));
        return;
    }

    QMessageBox::information(this, tr("Send"), tr("Asset sent. Fee: %1").arg(QString::number(fee)));
}

void SparkAssetsPage::onReceiveButtonClicked()
{
    if (!wallet_model_) {
        QMessageBox::warning(this, tr("Wallet"), tr("Wallet model not ready."));
        return;
    }
    try {
        const auto address = wallet_model_->getWallet()->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType());
        // No editReceiveAddress in UI; copy to clipboard and show to user
        QGuiApplication::clipboard()->setText(QString::fromStdString(address));
        QMessageBox::information(this, tr("Receive"), tr("Your Spark address has been copied to the clipboard:\n%1").arg(QString::fromStdString(address)));
    } catch (...) {
        QMessageBox::critical(this, tr("Receive"), tr("Failed to get default address."));
    }
}

void SparkAssetsPage::onCopyButtonClicked()
{
    // Copy selected asset identifier (for NFT) or asset type:identifier text from table
    if (!ui) {
        QMessageBox::information(this, tr("Copy"), tr("Nothing to copy."));
        return;
    }

    // Try to copy Identifier value from details pane if visible
    if (ui->labelIdentifierValue && ui->labelIdentifierValue->isVisible()) {
        const QString idText = ui->labelIdentifierValue->text().trimmed();
        if (!idText.isEmpty() && idText != "-") {
            QGuiApplication::clipboard()->setText(idText);
            QMessageBox::information(this, tr("Copy"), tr("Identifier copied to clipboard."));
            return;
        }
    }

    // Fallback: copy the UID from the selected row (asset_type:identifier)
    auto uid = getSelectedPortfolioAssetUID();
    if (uid) {
        const QString uidText = QString("%1:%2")
            .arg(QString::number(utils::to_underlying(uid->first)))
            .arg(QString::number(utils::to_underlying(uid->second)));
        QGuiApplication::clipboard()->setText(uidText);
        QMessageBox::information(this, tr("Copy"), tr("Asset ID copied to clipboard."));
        return;
    }

    QMessageBox::information(this, tr("Copy"), tr("Nothing to copy."));
}

void SparkAssetsPage::onExportButtonClicked()
{
    auto uid = getSelectedPortfolioAssetUID();
    if (!uid) {
        QMessageBox::information(this, tr("Export"), tr("Please select an asset first."));
        return;
    }
    QString fileName = QFileDialog::getSaveFileName(this, tr("Export Asset"), QString(), tr("JSON (*.json)"));
    if (fileName.isEmpty()) return;

    // Minimal export payload
    QJsonObject obj;
    obj["asset_type"] = QString::number(utils::to_underlying(uid->first));
    obj["identifier"] = QString::number(utils::to_underlying(uid->second));

    QFile f(fileName);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QMessageBox::critical(this, tr("Export"), tr("Failed to write file."));
        return;
    }
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    f.close();
    QMessageBox::information(this, tr("Export"), tr("Asset exported."));
}

void SparkAssetsPage::setClientModel(ClientModel *model)
{
    client_model_ = model;
}

void SparkAssetsPage::setWalletModel(WalletModel *model)
{
    wallet_model_ = model;

    if (!model) {
        pending_local_created_assets_.clear();
        return;
    }

    spark::CSparkState::GetState()->GetSpatsManager().add_updates_observer(*this);
    display_my_own_spats();
    display_all_assets();
}

void SparkAssetsPage::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    adjustTextSize(width(), height());
}

void SparkAssetsPage::adjustTextSize(int width, int height)
{
    const double font_size_scaling_factor = 70.0;
    const int base_font_size = std::min(width, height) / font_size_scaling_factor;
    const int font_size = std::min(15, std::max(12, base_font_size));
    QFont font = this->font();
    font.setPointSize(font_size);

    ui->labelMyAssetsTitle->setFont(font);
    ui->labelActivityTitle->setFont(font);
    ui->tableActivity->setFont(font);
    ui->tableActivity->horizontalHeader()->setFont(font);
    ui->tableActivity->verticalHeader()->setFont(font);
}

void SparkAssetsPage::showAssetDetails(const spats::SparkAssetDisplayAttributes& d)
{
    // Fill modern details panel widgets
    if (ui->labelNameValue)
        ui->labelNameValue->setText(QString::fromStdString(d.name));
    if (ui->labelSymbolValue)
        ui->labelSymbolValue->setText(QString::fromStdString(d.symbol));
    if (ui->labelTypeBadge)
        ui->labelTypeBadge->setText(d.fungible ? tr("Fungible") : tr("NFT"));

    // Identifier: show only for NFT, hide for fungible
    if (ui->labelIdentifierCaption)
        ui->labelIdentifierCaption->setVisible(!d.fungible);
    if (ui->labelIdentifierValue) {
        ui->labelIdentifierValue->setVisible(!d.fungible);
        ui->labelIdentifierValue->setText(d.fungible ? QString("-") : QString::number(d.identifier));
    }

    if (ui->labelPrecisionValue)
        ui->labelPrecisionValue->setText(QString::number(d.precision));

    if (ui->labelSupplyValue)
        ui->labelSupplyValue->setText(QString::fromStdString(d.total_supply));

    if (ui->labelResupplyBadge)
        ui->labelResupplyBadge->setText(d.resupplyable ? tr("Resupplyable") : tr("Fixed supply"));

    if (ui->labelDescriptionValue)
        ui->labelDescriptionValue->setText(QString::fromStdString(d.description));

    if (ui->metadataView)
        ui->metadataView->setPlainText(QString::fromStdString(d.metadata));

    // Keep legacy hidden text container updated (if needed for Copy fallback)
    if (ui->textDetails) {
        QString txt;
        txt += "<b>Name:</b> " + QString::fromStdString(d.name) + "<br>";
        txt += "<b>Symbol:</b> " + QString::fromStdString(d.symbol) + "<br>";
        if (!d.fungible)
            txt += "<b>Identifier:</b> " + QString::number(d.identifier) + "<br>";
        txt += "<b>Type:</b> " + QString(d.fungible ? "Fungible" : "NFT") + "<br>";
        txt += "<b>Precision:</b> " + QString::number(d.precision) + "<br>";
        txt += "<b>Total Supply:</b> " + QString::fromStdString(d.total_supply) + "<br>";
        txt += "<b>Resupplyable:</b> " + QString(d.resupplyable ? "Yes" : "No") + "<br>";
        txt += "<br><b>Description:</b><br>" + QString::fromStdString(d.description) + "<br><br>";
        txt += "<b>Metadata (read-only)</b><br><pre style='font-size:10pt;'>" + QString::fromStdString(d.metadata) + "</pre>";
        ui->textDetails->setHtml(txt);
    }

    // Only Copy button under asset details
    if (ui->btnCopy) {
        ui->btnCopy->setVisible(true);
        ui->btnCopy->setEnabled(true);
    }
    // Keep portfolio action buttons visible in their row (Send next to Receive)
    // The layout for these buttons is defined in the .ui (portfolioBtnsRow).
    if (ui->btnSend) ui->btnSend->setVisible(true);
    if (ui->btnReceive) ui->btnReceive->setVisible(true);
    if (ui->btnAddWatch) ui->btnAddWatch->setVisible(true);
}

void SparkAssetsPage::display_my_own_spats()
{
    if (!wallet_model_)
        return;

    const auto saved_uid = selected_my_creation_uid_;

    applyMyCreationCardChrome(selected_my_creation_card_, false);
    selected_my_creation_card_ = nullptr;
    selected_my_creation_uid_.reset();

    auto* lay = ui->layoutMyCreationsList;
    QWidget* host = ui->scrollWidgetMyCreations;
    if (!lay || !host)
        return;

    QLayoutItem* ch;
    while ((ch = lay->takeAt(0)) != nullptr) {
        if (QWidget* w = ch->widget())
            w->deleteLater();
        delete ch;
    }
    lay->setAlignment(Qt::AlignTop);

    const auto& my_public_address =
        wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();

    const auto my_own_assets_from_registry = spark::CSparkState::GetState()
                                                  ->GetSpatsManager()
                                                  .registry()
                                                  .get_assets_administered_by(my_public_address);

    pending_local_created_assets_.erase(
        std::remove_if(pending_local_created_assets_.begin(), pending_local_created_assets_.end(),
            [&](const spats::SparkAsset& p) {
                return std::ranges::any_of(my_own_assets_from_registry, [&](const spats::SparkAsset& a) {
                    return spark_asset_uid(a) == spark_asset_uid(p);
                });
            }),
        pending_local_created_assets_.end());

    std::vector<spats::SparkAsset> my_own_assets = my_own_assets_from_registry;
    my_own_assets.insert(my_own_assets.end(), pending_local_created_assets_.begin(),
        pending_local_created_assets_.end());

    my_own_assets_map_.clear();

    int cards_built = 0;

    for (const auto& asset : my_own_assets) {
        QFrame* frame = nullptr;
        try {
            const spats::SparkAssetDisplayAttributes a(asset);

            const spats::universal_asset_id_t uid{spats::asset_type_t{a.asset_type},
                                                  spats::identifier_t{a.identifier}};

            frame = new QFrame(host);
            frame->setObjectName(QStringLiteral("myCreationAssetRow"));
            frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            frame->setFixedHeight(42);
            frame->setCursor(Qt::PointingHandCursor);
            frame->setAttribute(Qt::WA_Hover, true);
            frame->setStyleSheet(myCreationCardFrameQss(false));

            frame->setProperty("assetType",
                QVariant::fromValue<qulonglong>(static_cast<qulonglong>(a.asset_type)));
            frame->setProperty(
                "assetIdentifier",
                QVariant::fromValue<qulonglong>(
                    a.fungible ? 0ull : static_cast<qulonglong>(a.identifier)));
            frame->setProperty("resupplyable", a.fungible && a.resupplyable);

            // No QGraphicsDropShadowEffect here: it often breaks painting inside QScrollArea
            // (blank rows) on some platforms after repaints / chain updates.

            frame->installEventFilter(new PortfolioAssetCardHoverFilter(frame));
            frame->installEventFilter(this);

            auto* row = new QHBoxLayout(frame);
        row->setSpacing(6);
        row->setContentsMargins(10, 4, 10, 4);

        const QString dotStyle = QStringLiteral(
            "QLabel { color: #9CA3AF; font-size: 8pt; font-weight: 600; background: transparent; }");
        const QString metaStyle = QStringLiteral(
            "QLabel { color: #374151; font-size: 8.5pt; font-weight: 600; background: transparent; }");
        const QString nameStyle = QStringLiteral(
            "QLabel { color: #111827; font-size: 10pt; font-weight: 700; background: transparent; }");

        auto* nameLab = new QLabel(QString::fromStdString(a.name), frame);
        nameLab->setStyleSheet(nameStyle);
        nameLab->setWordWrap(false);
        nameLab->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        nameLab->setMinimumWidth(48);
        row->addWidget(nameLab, 1);

        auto* dot1 = new QLabel(QStringLiteral("·"), frame);
        dot1->setStyleSheet(dotStyle);
        dot1->setFixedWidth(10);
        dot1->setAlignment(Qt::AlignCenter);
        row->addWidget(dot1);

        const QString sym = QString::fromStdString(a.symbol);
        auto* symLab = new QLabel(sym, frame);
        symLab->setStyleSheet(metaStyle);
        symLab->setWordWrap(false);
        symLab->setMaximumWidth(88);
        symLab->setToolTip(sym);
        row->addWidget(symLab);

        auto* dot2 = new QLabel(QStringLiteral("·"), frame);
        dot2->setStyleSheet(dotStyle);
        dot2->setFixedWidth(10);
        dot2->setAlignment(Qt::AlignCenter);
        row->addWidget(dot2);

        auto* typeLab = new QLabel(a.fungible ? tr("Fungible") : tr("NFT"), frame);
        typeLab->setStyleSheet(metaStyle);
        typeLab->setWordWrap(false);
        row->addWidget(typeLab);

        auto* dot3 = new QLabel(QStringLiteral("·"), frame);
        dot3->setStyleSheet(dotStyle);
        dot3->setFixedWidth(10);
        dot3->setAlignment(Qt::AlignCenter);
        row->addWidget(dot3);

        const QString idStr = a.fungible
            ? tr("T%1").arg(a.asset_type)
            : tr("T%1 #%2").arg(a.asset_type).arg(a.identifier);
        auto* idLab = new QLabel(idStr, frame);
        idLab->setStyleSheet(metaStyle);
        idLab->setWordWrap(false);
        row->addWidget(idLab);

        auto* dot4 = new QLabel(QStringLiteral("·"), frame);
        dot4->setStyleSheet(dotStyle);
        dot4->setFixedWidth(10);
        dot4->setAlignment(Qt::AlignCenter);
        row->addWidget(dot4);

        auto* supLab = new QLabel(
            tr("Sup %1").arg(QString::fromStdString(a.total_supply)), frame);
        supLab->setStyleSheet(metaStyle);
        supLab->setWordWrap(false);
        row->addWidget(supLab);

        auto* dot5 = new QLabel(QStringLiteral("·"), frame);
        dot5->setStyleSheet(dotStyle);
        dot5->setFixedWidth(10);
        dot5->setAlignment(Qt::AlignCenter);
        row->addWidget(dot5);

        auto* precLab = new QLabel(tr("Dec %1").arg(a.precision), frame);
        precLab->setStyleSheet(metaStyle);
        precLab->setWordWrap(false);
        row->addWidget(precLab);

        if (a.fungible) {
            auto* dot6 = new QLabel(QStringLiteral("·"), frame);
            dot6->setStyleSheet(dotStyle);
            dot6->setFixedWidth(10);
            dot6->setAlignment(Qt::AlignCenter);
            row->addWidget(dot6);

            auto* rsLab = new QLabel(
                a.resupplyable ? tr("+Mint") : tr("Fixed"), frame);
            rsLab->setStyleSheet(metaStyle);
            rsLab->setWordWrap(false);
            row->addWidget(rsLab);
        }

        auto* sparkBadge = new QLabel(frame);
        sparkBadge->setPixmap(GUIUtil::sparkAssetBadgePixmap(16));
        sparkBadge->setStyleSheet(QStringLiteral("background: transparent; border: none; padding: 0px; margin: 0px;"));
        sparkBadge->setAlignment(Qt::AlignVCenter);
        row->addWidget(sparkBadge, 0, Qt::AlignVCenter);

        const QString desc = QString::fromStdString(a.description).trimmed();
        QString tip = tr("%1\nSymbol: %2\n%3\n%4\nSupply: %5\nPrecision: %6")
                          .arg(QString::fromStdString(a.name))
                          .arg(sym)
                          .arg(a.fungible ? tr("Fungible") : tr("NFT"))
                          .arg(a.fungible
                                  ? tr("Asset type: %1").arg(a.asset_type)
                                  : tr("Type %1, ID %2").arg(a.asset_type).arg(a.identifier))
                          .arg(QString::fromStdString(a.total_supply))
                          .arg(a.precision);
        if (a.fungible)
            tip += QLatin1Char('\n')
                + (a.resupplyable ? tr("Resupplyable") : tr("Fixed supply"));
        if (!desc.isEmpty())
            tip += QLatin1String("\n\n") + desc;
        if (!QString::fromStdString(a.metadata).trimmed().isEmpty())
            tip += QLatin1String("\n\n") + tr("Metadata:\n%1").arg(QString::fromStdString(a.metadata));
        frame->setToolTip(tip);

            lay->addWidget(frame);
            my_own_assets_map_.emplace(uid, asset);
            ++cards_built;
            frame = nullptr;
        } catch (const std::exception& e) {
            qWarning() << "SparkAssetsPage::display_my_own_spats: skipped asset:" << e.what();
            if (frame)
                frame->deleteLater();
        }
    }
    lay->addStretch(1);

    ui->labelMyAssetsTitle->setText(
        tr("My Created Assets (%1)").arg(cards_built));

    if (saved_uid) {
        for (int i = 0; i < lay->count(); ++i) {
            QLayoutItem* item = lay->itemAt(i);
            if (!item)
                continue;
            auto* fr = qobject_cast<QFrame*>(item->widget());
            if (!fr || fr->objectName() != QLatin1String("myCreationAssetRow"))
                continue;
            bool ok1 = false;
            bool ok2 = false;
            const qulonglong t = fr->property("assetType").toULongLong(&ok1);
            const qulonglong id = fr->property("assetIdentifier").toULongLong(&ok2);
            if (!ok1 || !ok2)
                continue;
            if (spats::asset_type_t{t} == saved_uid->first
                && spats::identifier_t{id} == saved_uid->second) {
                onMyCreationCardClicked(fr);
                break;
            }
        }
    }

    updateButtonStates();
}

NewSparkAssetCreationContext SparkAssetsPage::make_new_asset_creation_context() const
{
    if (!wallet_model_)
        throw std::domain_error("Wallet not loaded.");

    const auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    const auto lowest_available_asset_type_for_new_fungible_asset =
        registry.get_lowest_available_asset_type_for_new_fungible_asset();
    if (!lowest_available_asset_type_for_new_fungible_asset) [[unlikely]]
        throw std::domain_error(
            "No available fungible asset type values left, all possible values are taken!");
    const auto lowest_available_asset_type_for_new_nft_line =
        registry.get_lowest_available_asset_type_for_new_nft_line();
    if (!lowest_available_asset_type_for_new_nft_line) [[unlikely]]
        throw std::domain_error(
            "No available NFT line asset type values left, all possible values are taken!");
    return NewSparkAssetCreationContext{
        wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin(),
        utils::to_underlying(*lowest_available_asset_type_for_new_fungible_asset),
        utils::to_underlying(*lowest_available_asset_type_for_new_nft_line)
    };
}

static spats::supply_amount_t convert_to_supply_amount(double value, unsigned precision)
{
    const double scaled_value =
        value * utils::math::integral_power(std::uintmax_t(10), precision);

    const spats::supply_amount_t a{
        boost::numeric_cast<std::uint64_t>(std::round(scaled_value)),
        precision
    };

    return a;
}

void SparkAssetsPage::onCreateButtonClicked()
{
    assert(wallet_model_);

    try
    {
        const bool fungible = ui->chkFungible->isChecked();

        const NewSparkAssetCreationContext creation_ctx = make_new_asset_creation_context();
        const uint64_t asset_type = fungible
            ? creation_ctx.lowest_available_asset_type_for_new_fungible_asset
            : creation_ctx.lowest_available_asset_type_for_new_nft_line;

        QString name        = ui->editName->text().trimmed();
        QString symbol      = ui->editSymbol->text().trimmed();
        QString description = ui->editDescription->toPlainText().trimmed();
        QString metadata    = ui->editMetadata->toPlainText().trimmed();
        QString supplyStr   = ui->editSupply->text().trimmed();
        QString idStr       = ui->editIdentifier->text().trimmed();

        if (name.isEmpty())
            throw std::runtime_error("Name cannot be empty.");

        if (symbol.isEmpty())
            throw std::runtime_error("Symbol cannot be empty.");

        uint64_t identifier = 0;
        if (!fungible)
        {
            if (idStr.isEmpty())
                throw std::runtime_error("Identifier cannot be empty for NFT.");

            identifier = idStr.toULongLong();
        }

        double total_supply = 0;
        unsigned precision = 0;
        bool resupplyable = false;

        if (fungible)
        {
            if (supplyStr.isEmpty())
                throw std::runtime_error("Total supply cannot be empty.");

            total_supply = supplyStr.toDouble();
            precision    = ui->comboPrecision->currentText().toUInt();
            resupplyable = (ui->comboResupply->currentText() == "Yes");
        }

        auto admin_addr =
            wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();

        spats::AssetNaming naming(
            spats::asset_name_t(name.toStdString()),
            spats::asset_symbol_t(symbol.toStdString()),
            description.toStdString()
        );

        std::optional<spats::SparkAsset> created;

        if (fungible)
        {
            const auto supply_amount =
                convert_to_supply_amount(total_supply, precision);

            spats::FungibleSparkAsset a(
                spats::asset_type_t(asset_type),
                naming,
                metadata.toStdString(),
                admin_addr,
                spats::supply_amount_t(supply_amount),
                resupplyable
            );

            created = a;
        }
        else
        {
            spats::NonfungibleSparkAsset a(
                spats::asset_type_t(asset_type),
                spats::identifier_t(identifier),
                naming,
                metadata.toStdString(),
                admin_addr
            );

            created = a;
        }

        if (!created.has_value())
            throw std::runtime_error("Internal error: asset creation failed.");

      
        wallet_model_->getWallet()->CreateNewSparkAsset(
            *created,
            admin_addr,
            MakeSpatsUserConfirmationCallback(*wallet_model_, this)
        );

        const spats::universal_asset_id_t pending_uid = spark_asset_uid(*created);
        pending_local_created_assets_.erase(
            std::remove_if(pending_local_created_assets_.begin(), pending_local_created_assets_.end(),
                [&](const spats::SparkAsset& x) { return spark_asset_uid(x) == pending_uid; }),
            pending_local_created_assets_.end());
        pending_local_created_assets_.push_back(*created);

        ui->editName->clear();
        ui->editSymbol->clear();
        ui->editDescription->clear();
        ui->editMetadata->clear();
        ui->editSupply->clear();
        ui->editIdentifier->clear();

        display_my_own_spats();
        ui->btnMyCreations->click();
        QTimer::singleShot(0, this, [this] {
            if (wallet_model_)
                display_my_own_spats();
        });

        QMessageBox::information(this, tr("Success"),
            tr("Spark Asset successfully created."));
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to create asset:\n%1").arg(e.what()));
    }
}

void SparkAssetsPage::onMintButtonClicked()
{
    assert(wallet_model_);
    if (const auto uid = getSelectedMyCreationUid()) {
        try {
            if (!selected_my_creation_card_
                || !selected_my_creation_card_->property("resupplyable").toBool())
                throw std::domain_error("Cannot mint for a non-resupplyable asset!");

            const spats::asset_type_t asset_type = uid->first;
            assert(is_fungible_asset_type(asset_type));
            const auto& asset = my_own_assets_map_.at(*uid);
            const auto& fungible_asset = std::get<spats::FungibleSparkAsset>(asset);
            assert(fungible_asset.resupplyable());

            SpatsMintDialog dialog(platform_style_, fungible_asset, this);
            if (dialog.exec() == QDialog::Accepted) {
                wallet_model_->getWallet()->MintSparkAssetSupply(
                    asset_type,
                    dialog.getNewSupply(),
                    dialog.getRecipient(),
                    nullptr,
                    MakeSpatsUserConfirmationCallback(*wallet_model_, this));
            }
        } catch (const std::exception& e) {
            QMessageBox::critical(this, tr("Error"),
                tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
            tr("Please select an asset to mint for."));
    }
}

void SparkAssetsPage::onModifyButtonClicked()
{
    assert(wallet_model_);
    if (const auto uid = getSelectedMyCreationUid()) {
        try {
            const auto& existing_asset = my_own_assets_map_.at(*uid);

            SparkAssetDialog dialog(platform_style_, existing_asset, this);
            if (dialog.exec() == QDialog::Accepted) {
                wallet_model_->getWallet()->ModifySparkAsset(
                    existing_asset,
                    *dialog.getResultAsset(),
                    MakeSpatsUserConfirmationCallback(*wallet_model_, this));
            }
        } catch (const std::exception& e) {
            QMessageBox::critical(this, tr("Error"),
                tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
            tr("Please select an asset to modify."));
    }
}

void SparkAssetsPage::onUnregisterButtonClicked()
{
    assert(wallet_model_);
    if (const auto uid = getSelectedMyCreationUid()) {
        try {
            const spats::asset_type_t asset_type = uid->first;
            std::optional<spats::identifier_t> identifier;

            if (!is_fungible_asset_type(asset_type)) {
                identifier = uid->second;

                if (any_other_nfts_within_same_line(asset_type, *identifier)) {
                    const QMessageBox::StandardButton reply =
                        QMessageBox::question(
                            this,
                            tr("Unregister NFT"),
                            tr("Would you like to unregister the whole NFT line or just this "
                               "specific NFT?"),
                            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel,
                            QMessageBox::Cancel);

                    switch (reply) {
                    case QMessageBox::Yes:
                        identifier.reset();
                        break;
                    case QMessageBox::No:
                        break;
                    case QMessageBox::Cancel:
                    default:
                        return;
                    }
                }
            }

            wallet_model_->getWallet()->UnregisterSparkAsset(
                asset_type,
                identifier,
                MakeSpatsUserConfirmationCallback(*wallet_model_, this));
        } catch (const std::exception &e) {
            QMessageBox::critical(this, tr("Error"),
                                  tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
                              tr("Please select an asset to unregister."));
    }
}

void SparkAssetsPage::onBurnButtonClicked()
{
    assert(wallet_model_);

    const auto uid = getSelectedMyCreationUid();
    if (!uid) {
        QMessageBox::warning(this, tr("Error"), tr("Please select an asset to burn."));
        return;
    }

    try {
        const spats::asset_type_t asset_type = uid->first;

        if (!is_fungible_asset_type(asset_type)) {
            throw std::domain_error("Burn is available only for fungible assets.");
        }

        const auto& asset_variant = my_own_assets_map_.at(*uid);

        const auto &asset = std::get<spats::FungibleSparkAsset>(asset_variant);

        const spats::supply_amount_t max_allowed = asset.total_supply();
        if (max_allowed == spats::supply_amount_t(0, asset.precision()))
            throw std::domain_error("Cannot burn: supply is zero.");

        SpatsBurnDialog dialog(
            platform_style_,
            asset_type,
            asset.naming().symbol.get(),
            max_allowed,
            this
        );

        if (dialog.exec() != QDialog::Accepted)
            return;

        const auto burn_amount = dialog.getBurnAmount();
        const spats::asset_symbol_t& symbol = asset.naming().symbol;

        wallet_model_->getWallet()->BurnSparkAssetSupply(
            asset_type,
            asset.naming().symbol,
            burn_amount,
            MakeSpatsUserConfirmationCallback(*wallet_model_, this)
        );

        QMessageBox::information(this, tr("Success"), tr("Burn transaction sent."));
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to burn supply:\n%1").arg(e.what()));
    }
}

void SparkAssetsPage::updateButtonStates()
{
    const bool row_selected =
        selected_my_creation_card_ != nullptr && selected_my_creation_uid_.has_value();

    ui->btnMetadata->setEnabled(row_selected);
    ui->btnResupply->setEnabled(row_selected);
    ui->btnRevoke->setEnabled(row_selected);
    ui->btnBurn->setEnabled(row_selected);

    bool can_mint = false;
    if (selected_my_creation_card_)
        can_mint = selected_my_creation_card_->property("resupplyable").toBool();
    ui->btnMint->setEnabled(can_mint);
}

bool SparkAssetsPage::any_other_nfts_within_same_line(spats::asset_type_t asset_type,
                                                      spats::identifier_t identifier) const
{
    assert(!is_fungible_asset_type(asset_type));
    assert(asset_type <= spats::max_allowed_asset_type_value);

    return std::ranges::any_of(
        my_own_assets_map_,
        [&](const auto &kv) {
            return kv.first.first == asset_type && kv.first.second != identifier;
        });
}

void SparkAssetsPage::process_spats_registry_changed(
    const admin_addresses_set_t & /*affected_asset_admin_addresses*/,
    const asset_ids_set_t & /*affected_asset_ids*/)
{
    if (!wallet_model_)
        return;
    QMetaObject::invokeMethod(
        this,
        &SparkAssetsPage::refreshMyCreationsDeferred,
        Qt::QueuedConnection);
}

void SparkAssetsPage::refreshMyCreationsDeferred()
{
    if (wallet_model_)
        display_my_own_spats();
}

void SparkAssetsPage::display_all_assets()
{
    if (!wallet_model_)
        return;

    const auto saved_uid = selected_portfolio_uid_;

    applyPortfolioCardChrome(selected_portfolio_card_, false);
    selected_portfolio_card_ = nullptr;
    selected_portfolio_uid_.reset();

    auto* lay = ui->layoutPortfolioAssetsList;
    QWidget* scrollHost = ui->scrollWidgetPortfolioAssets;
    if (!lay || !scrollHost)
        return;

    QLayoutItem* child;
    while ((child = lay->takeAt(0)) != nullptr) {
        if (QWidget* w = child->widget())
            w->deleteLater();
        delete child;
    }

    const auto& balances = wallet_model_->getSpatsBalances();
    auto& registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    std::vector<spats::SparkAssetDisplayAttributes> list;
    {
        std::shared_lock lock(registry.mutex_);
        for (const auto& p : registry.fungible_assets_)
            list.emplace_back(p.second);
        for (const auto& line : registry.nft_lines_) {
            for (const auto& kv : line.second)
                list.emplace_back(kv.second);
        }
    }

    const QColor cardShadowColor(100, 110, 120, 85);

    for (const auto& a : list) {
        const QString idText = a.fungible
            ? QStringLiteral("%1:0").arg(a.asset_type)
            : QStringLiteral("%1:%2").arg(a.asset_type).arg(a.identifier);

        const spats::identifier_t ident =
            a.fungible ? spats::identifier_t{} : spats::identifier_t{a.identifier};
        const spats::universal_asset_id_t uid{spats::asset_type_t(a.asset_type), ident};

        QString availableText = QStringLiteral("0");
        bool hasBal = false;
        const auto bit = balances.find(uid);
        if (bit != balances.end()) {
            availableText =
                QString::fromStdString(boost::lexical_cast<std::string>(bit->second.available));
            hasBal = (bit->second.available.raw() != 0);
        }

        const QString nameText = QString::fromStdString(a.name);

        auto* frame = new QFrame(scrollHost);
        frame->setObjectName(QStringLiteral("portfolioAssetRow"));
        frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        frame->setFixedHeight(80);
        frame->setCursor(Qt::PointingHandCursor);
        frame->setAttribute(Qt::WA_Hover, true);
        frame->setStyleSheet(portfolioCardFrameQss(false));
        frame->setProperty("assetType",
            QVariant::fromValue<qulonglong>(static_cast<qulonglong>(a.asset_type)));
        frame->setProperty("assetIdentifier",
            QVariant::fromValue<qulonglong>(
                a.fungible ? 0ull : static_cast<qulonglong>(a.identifier)));
        frame->setProperty("hasBalance", hasBal);
        frame->setProperty(
            "searchBlob",
            QString(idText + QLatin1Char(' ') + nameText + QLatin1Char(' ') + availableText)
                .toLower());

        auto* cardShadow = new QGraphicsDropShadowEffect(frame);
        cardShadow->setBlurRadius(18);
        cardShadow->setOffset(0, 5);
        cardShadow->setColor(cardShadowColor);
        frame->setGraphicsEffect(cardShadow);

        frame->installEventFilter(new PortfolioAssetCardHoverFilter(frame));
        frame->installEventFilter(this);

        auto* cardLayout = new QVBoxLayout(frame);
        cardLayout->setSpacing(0);
        cardLayout->setContentsMargins(0, 0, 0, 0);

        auto* glassHighlight = new QFrame(frame);
        glassHighlight->setObjectName(QStringLiteral("portfolioAssetGloss"));
        glassHighlight->setFixedHeight(10);
        glassHighlight->setStyleSheet(QStringLiteral(
            R"(
            QFrame#portfolioAssetGloss {
                border: none;
                border-top-left-radius: 18px;
                border-top-right-radius: 18px;
                border-bottom-left-radius: 14px;
                border-bottom-right-radius: 14px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 rgba(255, 255, 255, 52),
                                            stop:0.45 rgba(220, 228, 236, 18),
                                            stop:1 rgba(170, 180, 190, 6));
            }
        )"));
        cardLayout->addWidget(glassHighlight);

        auto* rowLayout = new QHBoxLayout();
        rowLayout->setSpacing(16);
        rowLayout->setContentsMargins(20, 1, 18, 7);

        auto makeCaptionLabel = [](const QString& text, QWidget* parent) {
            auto* label = new QLabel(text, parent);
            label->setStyleSheet(QStringLiteral(
                R"(QLabel { color: rgba(17, 24, 39, 160); font-size: 9pt; font-weight: 500; background: transparent; })"));
            return label;
        };
        auto makeValueLabel = [](const QString& text, QWidget* parent, bool wide) {
            auto* label = new QLabel(text, parent);
            label->setStyleSheet(QStringLiteral(
                R"(QLabel { color: #111827; font-size: 14pt; font-weight: 700; background: transparent; })"));
            if (wide)
                label->setMinimumWidth(180);
            return label;
        };

        auto* idColumn = new QVBoxLayout();
        idColumn->setSpacing(3);
        idColumn->addWidget(makeCaptionLabel(tr("Asset ID"), frame));
        idColumn->addWidget(makeValueLabel(idText, frame, false));

        auto* nameColumn = new QVBoxLayout();
        nameColumn->setSpacing(3);
        nameColumn->addWidget(makeCaptionLabel(tr("Name"), frame));
        nameColumn->addWidget(makeValueLabel(nameText, frame, true));

        auto* balanceColumn = new QVBoxLayout();
        balanceColumn->setSpacing(3);
        auto* availableCaption = makeCaptionLabel(tr("Available"), frame);
        availableCaption->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto* availableValue = makeValueLabel(availableText, frame, false);
        availableValue->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        balanceColumn->addWidget(availableCaption);
        balanceColumn->addWidget(availableValue);

        auto* leftColumnsLayout = new QHBoxLayout();
        leftColumnsLayout->setSpacing(18);
        leftColumnsLayout->addLayout(idColumn, 1);
        leftColumnsLayout->addLayout(nameColumn, 2);
        leftColumnsLayout->addLayout(balanceColumn, 2);

        auto* leftColumnsWidget = new QWidget(frame);
        leftColumnsWidget->setStyleSheet(QStringLiteral("background: transparent;"));
        leftColumnsWidget->setLayout(leftColumnsLayout);
        rowLayout->addWidget(leftColumnsWidget, 1);

        auto* portfolioSparkBadge = new QLabel(frame);
        portfolioSparkBadge->setPixmap(GUIUtil::sparkAssetBadgePixmap(15));
        portfolioSparkBadge->setStyleSheet(QStringLiteral("background: transparent; border: none; padding: 0px; margin: 0px;"));
        portfolioSparkBadge->setAlignment(Qt::AlignTop | Qt::AlignRight);
        rowLayout->addWidget(portfolioSparkBadge, 0, Qt::AlignTop);

        cardLayout->addLayout(rowLayout);

        lay->addWidget(frame);
    }
    lay->addStretch(1);

    ui->labelAssets->setText(tr("Assets (%1)").arg(list.size()));

    refreshPortfolioCardsVisibility();

    if (saved_uid) {
        for (int i = 0; i < lay->count(); ++i) {
            QLayoutItem* item = lay->itemAt(i);
            if (!item)
                continue;
            auto* frame = qobject_cast<QFrame*>(item->widget());
            if (!frame || frame->objectName() != QLatin1String("portfolioAssetRow"))
                continue;
            bool ok1 = false;
            bool ok2 = false;
            const qulonglong t = frame->property("assetType").toULongLong(&ok1);
            const qulonglong id = frame->property("assetIdentifier").toULongLong(&ok2);
            if (!ok1 || !ok2)
                continue;
            if (spats::asset_type_t{t} == saved_uid->first
                && spats::identifier_t{id} == saved_uid->second) {
                onPortfolioCardClicked(frame);
                break;
            }
        }
    }
}

void SparkAssetsPage::filterPortfolioTable(const QString& /*query*/)
{
    refreshPortfolioCardsVisibility();
}

void SparkAssetsPage::onRefreshButtonClicked()
{
    // Ensure action buttons appear next to each other in portfolio context
    if (ui->stackedAssets->currentWidget() == ui->pagePortfolio) {
        if (ui->btnSend) ui->btnSend->setVisible(true);
        if (ui->btnReceive) ui->btnReceive->setVisible(true);
        if (ui->btnAddWatch) ui->btnAddWatch->setVisible(true);
    }

    display_all_assets();
    filterPortfolioTable(ui->searchAssets->text());
    updateButtonStates();
}

void SparkAssetsPage::onClearCreateForm()
{
    ui->editName->clear();
    ui->editSymbol->clear();
    ui->editDescription->clear();
    ui->editMetadata->clear();
    ui->editSupply->clear();
    ui->editIdentifier->clear();

    ui->chkFungible->setChecked(true);
    ui->comboPrecision->setCurrentIndex(0);
    ui->comboResupply->setCurrentIndex(0);
    ui->editName->setFocus();
}

void SparkAssetsPage::onRemoveButtonClicked()
{
    if (!wallet_model_) {
        QMessageBox::warning(this, tr("Wallet"), tr("Wallet model not ready."));
        return;
    }

    auto uid = getSelectedPortfolioAssetUID();
    if (!uid) {
        QMessageBox::information(this, tr("Remove"), tr("Please select an asset first."));
        return;
    }

    const spats::asset_type_t asset_type = uid->first;
    std::optional<spats::identifier_t> identifier;
    if (!is_fungible_asset_type(asset_type)) {
        identifier = uid->second;
    }

    try {
        wallet_model_->getWallet()->UnregisterSparkAsset(
            asset_type,
            identifier,
            MakeSpatsUserConfirmationCallback(*wallet_model_, this));
        QMessageBox::information(this, tr("Remove"), tr("Asset removal requested."));
        onRefreshButtonClicked();
    } catch (const std::exception &e) {
        QMessageBox::critical(this, tr("Remove"), tr("Failed to remove asset: %1").arg(e.what()));
    }
}

}