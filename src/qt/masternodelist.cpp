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
#include <QCursor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLocale>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QSizePolicy>
#include <QStyle>
#include <QTextDocument>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QtGui/QClipboard>
#include <algorithm>
#include <map>
#include <set>

namespace {

QString formatBlockHeight(int height, bool none)
{
    if (none)
        return QStringLiteral("-");
    return QLocale(QLocale::English).toString(height);
}

QString elideMiddle(const QString& text, int keepLeft, int keepRight)
{
    if (text.size() <= keepLeft + keepRight + 2)
        return text;
    return text.left(keepLeft) + QStringLiteral("..") + text.right(keepRight);
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
    masternodeScroll(0),
    masternodeCardsHost(0),
    masternodeCardsLayout(0)
{
    ui->setupUi(this);

    ui->topLayout->setContentsMargins(24, 20, 24, 20);
    ui->topLayout->setSpacing(14);
    ui->verticalLayoutCard->removeItem(ui->horizontalLayout_4);
    ui->verticalLayoutCard->setContentsMargins(14, 10, 14, 14);
    ui->verticalLayoutCard->setSpacing(8);

    auto* filterCard = new QFrame(this);
    filterCard->setObjectName(QStringLiteral("masternodeFilterCard"));
    filterCard->setFixedHeight(64);
    auto* filterLayout = new QHBoxLayout(filterCard);
    filterLayout->setContentsMargins(14, 12, 14, 12);
    filterLayout->setSpacing(12);

    ui->label_filter_2->hide();
    filterLayout->addWidget(ui->filterLineEditDIP3, 1);
    filterLayout->addWidget(ui->checkBoxMyMasternodesOnly);

    auto* countPill = new QFrame(filterCard);
    countPill->setObjectName(QStringLiteral("nodeCountPill"));
    countPill->setFixedHeight(34);
    auto* countLayout = new QHBoxLayout(countPill);
    countLayout->setContentsMargins(12, 0, 12, 0);
    countLayout->setSpacing(4);
    countLayout->addWidget(ui->label_count_2);
    countLayout->addWidget(ui->countLabelDIP3);
    filterLayout->addWidget(countPill);

    ui->topLayout->insertWidget(0, filterCard);
    ui->masternodeContentCard->setMinimumHeight(420);
    ui->masternodeContentCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    ui->topLayout->setStretchFactor(ui->masternodeContentCard, 1);

    if (ui->masternodeContentCard) {
        ui->masternodeContentCard->setAttribute(Qt::WA_StyledBackground, true);
    }

    masternodeScroll = new QScrollArea(ui->masternodeContentCard);
    masternodeScroll->setObjectName(QStringLiteral("masternodeScroll"));
    masternodeScroll->setWidgetResizable(true);
    masternodeScroll->setFrameShape(QFrame::NoFrame);
    masternodeScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    masternodeCardsHost = new QWidget(masternodeScroll);
    masternodeCardsHost->setObjectName(QStringLiteral("masternodeCardsHost"));
    masternodeCardsLayout = new QVBoxLayout(masternodeCardsHost);
    masternodeCardsLayout->setContentsMargins(0, 0, 4, 0);
    masternodeCardsLayout->setSpacing(10);
    masternodeCardsLayout->setAlignment(Qt::AlignTop);
    masternodeScroll->setWidget(masternodeCardsHost);
    ui->verticalLayoutCard->addWidget(masternodeScroll, 1);
    masternodeScroll->viewport()->installEventFilter(this);

    emptyState = new QWidget(masternodeScroll->viewport());
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
    addCardShadow(ui->masternodeContentCard);

    QAction* copyProTxHashAction = new QAction(tr("Copy ProTx Hash"), this);
    QAction* copyCollateralOutpointAction = new QAction(tr("Copy Collateral Outpoint"), this);
    contextMenuDIP3 = new QMenu();
    contextMenuDIP3->addAction(copyProTxHashAction);
    contextMenuDIP3->addAction(copyCollateralOutpointAction);
    connect(copyProTxHashAction, &QAction::triggered, this, &MasternodeList::copyProTxHash_clicked);
    connect(copyCollateralOutpointAction, &QAction::triggered, this, &MasternodeList::copyCollateralOutpoint_clicked);
    //always start with "my znodes only" checked
    ui->checkBoxMyMasternodesOnly->setChecked(true);
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
  font-size: 11px;
  selection-background-color: $WINE;
}
QLineEdit#filterLineEditDIP3:focus {
  background: $PANEL;
  border-color: $WINE;
}
QCheckBox#checkBoxMyMasternodesOnly {
  color: $INK_SOFT;
  font-size: 10px;
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
QFrame#nodeCountPill {
  background: $PANEL_SOFT;
  border: 1px solid $BORDER;
  border-radius: 9px;
}
QFrame#nodeCountPill QLabel {
  color: $INK_SOFT;
  background: transparent;
  font-size: 10px;
  font-weight: 600;
}
QScrollArea#masternodeScroll,
QScrollArea#masternodeScroll > QWidget,
QWidget#masternodeCardsHost {
  background: transparent;
  border: none;
}
QFrame#masternodeCard {
  background: $PANEL;
  border: 1px solid $BORDER;
  border-radius: 16px;
}
QFrame#masternodeCard[selected="true"] {
  background: $PANEL_SOFT;
  border: 1px solid $WINE;
  border-radius: 16px;
}
QFrame#masternodeCard QLabel#cardTitle {
  color: $INK; font-size: 13px; font-weight: 700;
  background: transparent; border: none;
}
QFrame#masternodeCard QLabel#cardSubtitle {
  color: $INK_SOFT; font-size: 10px; font-weight: 500;
  background: transparent; border: none;
}
QFrame#masternodeCard QLabel#cardPoseLabel {
  color: $INK_SOFT; font-size: 10px; font-weight: 600;
  background: transparent; border: none;
}
QFrame#masternodeCard QFrame#cardPoseTrack {
  background: $BORDER; border: none; border-radius: 2px;
}
QFrame#masternodeCard QFrame#cardDivider {
  background: $BORDER; border: none;
}
QFrame#masternodeCard QLabel#cardMetricCaption {
  color: $INK_SOFT; font-size: 9px; font-weight: 700; letter-spacing: 0.4px;
  background: transparent; border: none;
}
QFrame#masternodeCard QLabel#cardMetricValue {
  color: $INK; font-size: 12px; font-weight: 700;
  background: transparent; border: none;
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
            "color: $INK_SOFT; font-size: 11px; font-weight: 700;")));
    }
    if (emptyDescription_) {
        emptyDescription_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "background: transparent; border: none;"
            "color: $INK_FAINT; font-size: 10px;")));
    }

    restyleMasternodeCards();
}

void MasternodeList::restyleMasternodeCards()
{
    if (!masternodeCardsLayout)
        return;
    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    for (int i = 0; i < masternodeCardsLayout->count(); ++i) {
        QLayoutItem* item = masternodeCardsLayout->itemAt(i);
        auto* card = item ? qobject_cast<QFrame*>(item->widget()) : nullptr;
        if (!card || card->objectName() != QLatin1String("masternodeCard"))
            continue;

        const bool selected = card->property("proTxHash").toString() == selectedProTxHash;
        card->setProperty("selected", selected);
        card->style()->unpolish(card);
        card->style()->polish(card);

        if (auto* icon = card->findChild<QLabel*>(QStringLiteral("cardIcon"))) {
            icon->setPixmap(masternodeGlyph());
        }

        const int statusKind = card->property("statusKind").toInt();
        QString badgeBg = tc.tealTint;
        QString badgeFg = tc.teal;
        if (statusKind == 1) {
            badgeBg = tc.goldTint;
            badgeFg = tc.gold;
        } else if (statusKind == 2) {
            badgeBg = tc.wineTint;
            badgeFg = tc.wine;
        }
        if (auto* statusLab = card->findChild<QLabel*>(QStringLiteral("cardStatusBadge"))) {
            statusLab->setStyleSheet(QStringLiteral(
                "QLabel { background: %1; color: %2; border: none; border-radius: 11px;"
                " padding: 2px 10px; font-size: 10px; font-weight: 700; }")
                                          .arg(badgeBg, badgeFg));
        }
        if (auto* poseFill = card->findChild<QFrame*>(QStringLiteral("cardPoseFill"))) {
            poseFill->setStyleSheet(QStringLiteral(
                "QFrame { background: %1; border: none; border-radius: 2px; }")
                                         .arg(statusKind == 2 ? tc.wine : tc.teal));
        }
    }
}

MasternodeList::~MasternodeList()
{
    delete ui;
}

void MasternodeList::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        // try to update list when masternode count changes
        connect(clientModel, &ClientModel::masternodeListChanged, this, &MasternodeList::handleMasternodeListChanged);
    }
}

void MasternodeList::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void MasternodeList::showContextMenuDIP3(const QPoint& globalPos)
{
    if (selectedProTxHash.isEmpty())
        return;
    contextMenuDIP3->exec(globalPos.isNull() ? QCursor::pos() : globalPos);
}

void MasternodeList::handleMasternodeListChanged()
{
    LOCK(cs_dip3list);
    mnListChanged = true;
}

void MasternodeList::updateDIP3ListScheduled()
{
    TRY_LOCK(cs_main, fMainAcquired);
    if (!fMainAcquired) return;

#ifdef ENABLE_WALLET
    if (!pwalletMain) return;
    TRY_LOCK(pwalletMain->cs_wallet, fWalletAcquired);
    if (!fWalletAcquired) return;
#endif

    TRY_LOCK(cs_dip3list, fLockAcquired);
    if (!fLockAcquired) return;

    if (!clientModel || ShutdownRequested()) {
        return;
    }

    // To prevent high cpu usage update only once in MASTERNODELIST_FILTER_COOLDOWN_SECONDS seconds
    // after filter was last changed unless we want to force the update.
    if (fFilterUpdatedDIP3) {
        int64_t nSecondsToWait = nTimeFilterUpdatedDIP3 - GetTime() + MASTERNODELIST_FILTER_COOLDOWN_SECONDS;
        if (nSecondsToWait <= 0) {
            updateDIP3List();
            fFilterUpdatedDIP3 = false;
        }
    } else if (mnListChanged) {
        int64_t nMnListUpdateSecods = masternodeSync.IsBlockchainSynced() ? MASTERNODELIST_UPDATE_SECONDS : MASTERNODELIST_UPDATE_SECONDS*10;
        int64_t nSecondsToWait = nTimeUpdatedDIP3 - GetTime() + nMnListUpdateSecods;

        if (nSecondsToWait <= 0) {
            updateDIP3List();
            mnListChanged = false;
        }
    }
}

void MasternodeList::updateDIP3List()
{
    if (!clientModel || ShutdownRequested()) {
        return;
    }

    auto mnList = clientModel->getMasternodeList();
    if(mnList.GetAllMNsCount()==0){
        clientModel->refreshMasternodeList();
        mnList = clientModel->getMasternodeList();    }
    std::map<uint256, CTxDestination> mapCollateralDests;
    std::map<uint256, CAmount> mapCollateralAmounts;

    {
        // Get all UTXOs for each MN collateral in one go so that we can reduce locking overhead for cs_main
        // We also do this outside of the below Qt list update loop to reduce cs_main locking time to a minimum
        TRY_LOCK(cs_main,lock_main);
        if (!lock_main)
            return;
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

    LOCK(cs_dip3list);

    clearLayout(masternodeCardsLayout);

    nTimeUpdatedDIP3 = GetTime();

    auto projectedPayees = mnList.GetProjectedMNPayees(mnList.GetValidMNsCount());
    std::map<uint256, int> nextPayments;
    for (size_t i = 0; i < projectedPayees.size(); ++i) {
        const auto& dmn = projectedPayees[i];
        nextPayments.emplace(dmn->proTxHash, mnList.GetHeight() + (int)i + 1);
    }

    std::set<COutPoint> setOutpts;
    if (walletModel && ui->checkBoxMyMasternodesOnly->isChecked()) {
        std::vector<COutPoint> vOutpts;
        walletModel->listProTxCoins(vOutpts);
        for (const auto& outpt : vOutpts) {
            setOutpts.emplace(outpt);
        }
    }

    const Consensus::Params& params = ::Params().GetConsensus();
    const int maxPose = std::max(100, mnList.CalcMaxPoSePenalty());
    QFrame* restoreSelection = nullptr;
    int shown = 0;
    int matched = 0;

    mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
        if (walletModel && ui->checkBoxMyMasternodesOnly->isChecked()) {
            bool fMyMasternode = setOutpts.count(dmn->collateralOutpoint) ||
                walletModel->IsSpendable(dmn->pdmnState->keyIDOwner) ||
                walletModel->IsSpendable(dmn->pdmnState->scriptPayout) ||
                walletModel->IsSpendable(dmn->pdmnState->scriptOperatorPayout);
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

        const QString operatorRewardShort =
            QString::number(dmn->nOperatorReward / 100.0, 'f', 2) + QLatin1Char('%');

        QString collateralAddr = QStringLiteral("-");
        auto collateralDestIt = mapCollateralDests.find(dmn->proTxHash);
        if (collateralDestIt != mapCollateralDests.end()) {
            collateralAddr = QString::fromStdString(CBitcoinAddress(collateralDestIt->second).ToString());
        }

        QString collateralAmount = QStringLiteral("-");
        auto collateralAmountIt = mapCollateralAmounts.find(dmn->proTxHash);
        if (collateralAmountIt != mapCollateralAmounts.end()) {
            collateralAmount = QStringLiteral("%1 FIRO").arg(
                QLocale(QLocale::English).toString(
                    static_cast<qlonglong>(collateralAmountIt->second / COIN)));
        }

        const QString ownerStr = QString::fromStdString(CBitcoinAddress(dmn->pdmnState->keyIDOwner).ToString());
        const QString proTxHash = QString::fromStdString(dmn->proTxHash.ToString());

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
                operatorRewardShort + QLatin1Char(' ') +
                collateralAddr + QLatin1Char(' ') +
                ownerStr + QLatin1Char(' ') +
                proTxHash;
            if (!strToFilter.contains(strCurrentFilterDIP3, Qt::CaseInsensitive))
                return;
        }

        ++matched;
        if (shown >= MASTERNODELIST_CARD_RENDER_LIMIT)
            return;

        QFrame* card = createMasternodeCard(
            address,
            status,
            statusKind,
            dmn->pdmnState->nPoSePenalty,
            maxPose,
            registered,
            lastPaid,
            nextPayment,
            payeeStr,
            operatorRewardShort,
            collateralAmount,
            collateralAddr,
            proTxHash);
        masternodeCardsLayout->addWidget(card);
        if (proTxHash == selectedProTxHash)
            restoreSelection = card;
        ++shown;
    });

    if (matched > shown) {
        auto* truncationNotice = new QLabel(
            tr("Showing the first %1 of %2 matching masternodes. Use the filter above to narrow the results.")
                .arg(shown).arg(matched),
            masternodeCardsHost);
        truncationNotice->setObjectName(QStringLiteral("masternodeTruncationNotice"));
        truncationNotice->setWordWrap(true);
        truncationNotice->setAlignment(Qt::AlignCenter);
        truncationNotice->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "color: $INK_SOFT; font-size: 10px; padding: 8px;")));
        masternodeCardsLayout->addWidget(truncationNotice);
    }

    masternodeCardsLayout->addStretch(1);
    ui->countLabelDIP3->setText(QString::number(matched));
    if (restoreSelection)
        selectMasternodeCard(restoreSelection);
    else
        selectedProTxHash.clear();
    updateEmptyState();
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

    auto mnList = clientModel->getMasternodeList();
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
    auto dmn = GetSelectedDIP3MN();
    if (!dmn) {
        return;
    }

    QApplication::clipboard()->setText(QString::fromStdString(dmn->proTxHash.ToString()));
}

void MasternodeList::copyCollateralOutpoint_clicked()
{
    auto dmn = GetSelectedDIP3MN();
    if (!dmn) {
        return;
    }

    QApplication::clipboard()->setText(QString::fromStdString(dmn->collateralOutpoint.ToStringShort()));
}

void MasternodeList::updateEmptyState()
{
    if (!emptyState || !masternodeScroll)
        return;

    emptyState->setGeometry(masternodeScroll->viewport()->rect());
    emptyState->setVisible(masternodeCardCount() == 0);
    if (emptyState->isVisible())
        emptyState->raise();
}

int MasternodeList::masternodeCardCount() const
{
    if (!masternodeCardsLayout)
        return 0;
    int count = 0;
    for (int i = 0; i < masternodeCardsLayout->count(); ++i) {
        QLayoutItem* item = masternodeCardsLayout->itemAt(i);
        if (item && qobject_cast<QFrame*>(item->widget()))
            ++count;
    }
    return count;
}

void MasternodeList::selectMasternodeCard(QFrame* frame)
{
    if (!frame || !masternodeCardsLayout)
        return;
    selectedProTxHash = frame->property("proTxHash").toString();
    for (int i = 0; i < masternodeCardsLayout->count(); ++i) {
        QLayoutItem* item = masternodeCardsLayout->itemAt(i);
        auto* card = item ? qobject_cast<QFrame*>(item->widget()) : nullptr;
        if (!card || card->objectName() != QLatin1String("masternodeCard"))
            continue;
        card->setProperty("selected", card == frame);
        card->style()->unpolish(card);
        card->style()->polish(card);
    }
}

QFrame* MasternodeList::createMasternodeCard(const QString& address,
                                            const QString& status,
                                            int statusKind,
                                            int poseScore,
                                            int maxPose,
                                            const QString& registered,
                                            const QString& lastPaid,
                                            const QString& nextPayment,
                                            const QString& payout,
                                            const QString& operatorReward,
                                            const QString& collateral,
                                            const QString& collateralId,
                                            const QString& proTxHash)
{
    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    auto* frame = new QFrame(masternodeCardsHost);
    frame->setObjectName(QStringLiteral("masternodeCard"));
    frame->setAttribute(Qt::WA_StyledBackground, true);
    frame->setCursor(Qt::PointingHandCursor);
    frame->setFocusPolicy(Qt::StrongFocus);
    frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    frame->setMinimumHeight(126);
    frame->setProperty("proTxHash", proTxHash);
    frame->setProperty("selected", false);
    frame->setProperty("statusKind", statusKind);

    auto* root = new QVBoxLayout(frame);
    root->setContentsMargins(16, 14, 16, 14);
    root->setSpacing(0);

    auto* header = new QHBoxLayout();
    header->setContentsMargins(0, 0, 0, 0);
    header->setSpacing(12);

    auto* icon = new QLabel(frame);
    icon->setObjectName(QStringLiteral("cardIcon"));
    icon->setFixedSize(36, 36);
    icon->setPixmap(masternodeGlyph());
    icon->setStyleSheet(QStringLiteral("background: transparent; border: none;"));
    header->addWidget(icon, 0, Qt::AlignVCenter);

    auto* titleCol = new QVBoxLayout();
    titleCol->setContentsMargins(0, 0, 0, 0);
    titleCol->setSpacing(2);
    auto* ipLab = new QLabel(address, frame);
    ipLab->setObjectName(QStringLiteral("cardTitle"));
    const QString subtitle = tr("Collateral · %1")
        .arg(elideMiddle(collateralId == QLatin1String("-") ? proTxHash : collateralId, 5, 7));
    auto* subLab = new QLabel(subtitle, frame);
    subLab->setObjectName(QStringLiteral("cardSubtitle"));
    titleCol->addWidget(ipLab);
    titleCol->addWidget(subLab);
    header->addLayout(titleCol, 1);

    QString badgeBg = tc.tealTint;
    QString badgeFg = tc.teal;
    if (statusKind == 1) {
        badgeBg = tc.goldTint;
        badgeFg = tc.gold;
    } else if (statusKind == 2) {
        badgeBg = tc.wineTint;
        badgeFg = tc.wine;
    }
    auto* statusLab = new QLabel(status, frame);
    statusLab->setObjectName(QStringLiteral("cardStatusBadge"));
    statusLab->setAlignment(Qt::AlignCenter);
    statusLab->setMinimumHeight(22);
    statusLab->setStyleSheet(QStringLiteral(
        "QLabel { background: %1; color: %2; border: none; border-radius: 11px;"
        " padding: 2px 10px; font-size: 10px; font-weight: 700; }")
                                 .arg(badgeBg, badgeFg));
    header->addWidget(statusLab, 0, Qt::AlignVCenter);

    auto* poseCol = new QVBoxLayout();
    poseCol->setContentsMargins(0, 0, 0, 0);
    poseCol->setSpacing(5);
    auto* poseLab = new QLabel(QStringLiteral("PoSe %1").arg(poseScore), frame);
    poseLab->setObjectName(QStringLiteral("cardPoseLabel"));
    poseLab->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    auto* poseTrack = new QFrame(frame);
    poseTrack->setObjectName(QStringLiteral("cardPoseTrack"));
    poseTrack->setAttribute(Qt::WA_StyledBackground, true);
    poseTrack->setFixedSize(64, 4);
    const int fillWidth = statusKind == 2
        ? std::max(18, std::min(64, maxPose > 0 ? 64 * poseScore / maxPose : 64))
        : (poseScore <= 0 ? 22 : std::max(10, std::min(64, maxPose > 0 ? 64 * poseScore / maxPose : 22)));
    auto* poseFill = new QFrame(poseTrack);
    poseFill->setObjectName(QStringLiteral("cardPoseFill"));
    poseFill->setGeometry(0, 0, fillWidth, 4);
    poseFill->setStyleSheet(QStringLiteral(
        "QFrame { background: %1; border: none; border-radius: 2px; }")
                                .arg(statusKind == 2 ? tc.wine : tc.teal));
    poseCol->addWidget(poseLab);
    poseCol->addWidget(poseTrack, 0, Qt::AlignRight);
    header->addLayout(poseCol, 0);

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
    grid->addWidget(metricColumn(tr("REGISTERED"), registered, frame), 1);
    grid->addWidget(metricColumn(tr("LAST PAID"), lastPaid, frame), 1);
    grid->addWidget(metricColumn(tr("NEXT PAYMENT"), nextPayment, frame), 1);
    grid->addWidget(metricColumn(tr("PAYOUT ADDRESS"), elideMiddle(payout, 18, 0), frame), 2);
    grid->addWidget(metricColumn(tr("OPERATOR REWARD"), operatorReward, frame), 1);
    grid->addWidget(metricColumn(tr("COLLATERAL"), collateral, frame), 1);
    root->addLayout(grid);

    frame->installEventFilter(this);
    for (auto* child : frame->findChildren<QWidget*>())
        child->installEventFilter(this);

    return frame;
}

bool MasternodeList::eventFilter(QObject* watched, QEvent* event)
{
    if (masternodeScroll && watched == masternodeScroll->viewport()
        && (event->type() == QEvent::Resize || event->type() == QEvent::Show)) {
        updateEmptyState();
        return QWidget::eventFilter(watched, event);
    }

    QWidget* widget = qobject_cast<QWidget*>(watched);
    QFrame* card = nullptr;
    while (widget) {
        card = qobject_cast<QFrame*>(widget);
        if (card && card->objectName() == QLatin1String("masternodeCard"))
            break;
        card = nullptr;
        widget = widget->parentWidget();
    }

    if (card) {
        if (event->type() == QEvent::MouseButtonPress) {
            auto* me = static_cast<QMouseEvent*>(event);
            selectMasternodeCard(card);
            if (me->button() == Qt::RightButton) {
                showContextMenuDIP3(me->globalPosition().toPoint());
                return true;
            }
        } else if (event->type() == QEvent::MouseButtonDblClick) {
            extraInfoDIP3_clicked();
            return true;
        } else if (event->type() == QEvent::FocusIn) {
            selectMasternodeCard(card);
        } else if (event->type() == QEvent::KeyPress) {
            auto* ke = static_cast<QKeyEvent*>(event);
            if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
                selectMasternodeCard(card);
                extraInfoDIP3_clicked();
                return true;
            }
            if (ke->key() == Qt::Key_Menu ||
                (ke->key() == Qt::Key_F10 && ke->modifiers() == Qt::ShiftModifier)) {
                selectMasternodeCard(card);
                showContextMenuDIP3(card->mapToGlobal(card->rect().center()));
                return true;
            }
        }
    }

    return QWidget::eventFilter(watched, event);
}

void MasternodeList::resizeEvent(QResizeEvent* event) 
{
    QWidget::resizeEvent(event);
    updateEmptyState();
}

void MasternodeList::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 70.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    ui->label_filter_2->setFont(font);
    ui->label_count_2->setFont(font);
    ui->countLabelDIP3->setFont(font);
    ui->checkBoxMyMasternodesOnly->setFont(font);
}