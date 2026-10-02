// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinamountfield.h"
#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guitheme.h"
#include "guiutil.h"
#include "spark/state.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"
#include "validation.h"
#include "chainparams.h"
#include "askpassphrasedialog.h"

#ifdef WIN32
#include <string.h>
#endif

#include "util.h"
#include "compat.h"

#include <algorithm>

#include <QAbstractItemDelegate>
#include <QAbstractItemView>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QStyleOptionViewItem>
#include <QVBoxLayout>

#define DECORATION_SIZE 54
#define NUM_ITEMS 8
#define ACTIVITY_ICON_SIZE 42
#define ACTIVITY_CARD_HEIGHT 44

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
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
        const bool selected = (option.state & QStyle::State_Selected);
        const QRect card = option.rect.adjusted(2, 3, -2, -3);
        if (card.width() <= 0 || card.height() <= 0) {
            painter->restore();
            return;
        }

        // Rows sit directly in the activity card, separated by hairlines.
        if (selected) {
            painter->setPen(Qt::NoPen);
            painter->setBrush(QColor(tc.wineTint));
            painter->drawRoundedRect(card, 10, 10);
        }
        if (index.row() + 1 < index.model()->rowCount(index.parent())) {
            painter->fillRect(QRect(card.left() + 8, option.rect.bottom(), card.width() - 16, 1), QColor(tc.border));
        }

        const int txType = index.data(TransactionTableModel::TypeRole).toInt();
        const qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        const bool incoming =
            txType == TransactionRecord::Generated ||
            txType == TransactionRecord::RecvWithAddress ||
            txType == TransactionRecord::RecvFromOther ||
            txType == TransactionRecord::RecvWithPcode ||
            txType == TransactionRecord::RecvSpark;
        const bool positive = incoming || amount > 0;

        const QRect iconRect(card.left() + 12, card.center().y() - 16, 32, 32);
        painter->setPen(Qt::NoPen);
        painter->setBrush(positive ? QColor(tc.tealTint) : QColor(tc.hover));
        painter->drawEllipse(iconRect);
        const QRect arrowRect = iconRect.adjusted(8, 8, -8, -8);
        painter->drawPixmap(arrowRect, GUIUtil::tintedIconPixmap(incoming ? receivedIcon : sentIcon, arrowRect.size(),
                                                                positive ? QColor(tc.teal) : QColor(tc.inkSoft)));
        QFont boldFont = option.font;
        boldFont.setBold(true);
        painter->setFont(boldFont);

        const QRect statusRect(iconRect.right() - 6, iconRect.bottom() - 12, 14, 14);
        const QVariant statusDec = index.sibling(index.row(), TransactionTableModel::Status)
                                       .data(TransactionTableModel::RawDecorationRole);
        if (statusDec.canConvert<QIcon>()) {
            const QIcon statusIcon = qvariant_cast<QIcon>(statusDec);
            if (!statusIcon.isNull()) {
                // A ring in the row's own surface, so the badge reads as cut out of the arrow circle.
                const QRectF ring = QRectF(statusRect).adjusted(-1.5, -1.5, 1.5, 1.5);
                painter->setPen(Qt::NoPen);
                painter->setBrush(QColor(tc.panel));
                painter->drawEllipse(ring);
                if (selected) {
                    painter->setBrush(QColor(tc.wineTint));
                    painter->drawEllipse(ring);
                }
                GUIUtil::paintThemedStatusIcon(painter, statusIcon, statusRect);
            }
        }

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();

        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if (!confirmed)
            amountText = QString("[") + amountText + QString("]");
        const int metadataLeft = iconRect.right() + 12;
        // Reserve the lock slot so dates and labels stay aligned across rows.
        const int textLeft = metadataLeft + 20;
        const int amountWidth = std::min(std::max(168, QFontMetrics(boldFont).horizontalAdvance(amountText)),
                                         std::max(0, card.right() - textLeft - 14));
        const int amountLeft = card.right() - amountWidth - 14;
        const int textWidth = std::max(0, amountLeft - textLeft - 12);
        const QString dateText = date.isValid() ? QLocale::system().toString(date, QLocale::ShortFormat)
                                               : GUIUtil::dateTimeStr(date);
        const int dateWidth = std::max(144, QFontMetrics(boldFont).horizontalAdvance(dateText));
        const bool inlineAddress = textWidth >= dateWidth + 12 + 96;
        const int lineHeight = option.fontMetrics.height();
        const QRect dateRect(textLeft, inlineAddress ? card.top() : card.center().y() - lineHeight,
                             inlineAddress ? dateWidth : textWidth, inlineAddress ? card.height() : lineHeight);
        const QRect addressRect = inlineAddress
            ? QRect(dateRect.right() + 13, card.top(), textWidth - dateWidth - 12, card.height())
            : QRect(textLeft, dateRect.bottom() + 1, card.right() - textLeft - 14, lineHeight);
        const QIcon instantSendIcon = qvariant_cast<QIcon>(index.data(TransactionTableModel::InstantSendDecorationRole));
        if (!instantSendIcon.isNull() && amountLeft - metadataLeft >= 20)
            GUIUtil::paintThemedStatusIcon(painter, instantSendIcon,
                                         QRect(metadataLeft, inlineAddress ? card.center().y() - 8 : dateRect.top(), 16, 16));
        painter->setFont(boldFont);
        painter->setPen(QColor(tc.ink));
        painter->drawText(dateRect, Qt::AlignLeft | Qt::AlignVCenter,
                          QFontMetrics(boldFont).elidedText(dateText, Qt::ElideRight, dateRect.width()));

        QFont addrFont = boldFont;
        addrFont.setBold(false);
        painter->setFont(addrFont);
        painter->setPen(QColor(tc.inkFaint));
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter,
                          QFontMetrics(addrFont).elidedText(address, Qt::ElideMiddle, addressRect.width()));

        // Received is teal; sent stays in ink with its minus sign, since red means an error.
        painter->setFont(boldFont);
        const QRect amountRect(amountLeft, inlineAddress ? card.top() : dateRect.top(),
                               amountWidth, inlineAddress ? card.height() : lineHeight);
        GUIUtil::paintAmountRuns(painter, amountRect, amountText, amount < 0 ? QColor(tc.ink) : QColor(tc.teal),
                                 Qt::AlignRight | Qt::AlignVCenter);

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        return QSize(ACTIVITY_ICON_SIZE, std::max(ACTIVITY_CARD_HEIGHT, 2 * option.fontMetrics.height() + 12));
    }

    int unit;
    const PlatformStyle *platformStyle;
    // The sidebar's Send and Receive icons mark the direction.
    const QIcon sentIcon{QStringLiteral(":/icons/sidebar_send")};
    const QIcon receivedIcon{QStringLiteral(":/icons/sidebar_receive")};

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
    currentPrivateBalance(-1),
    currentUnconfirmedPrivateBalance(-1),
    currentAnonymizableBalance(-1),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);

    ui->topLayout->removeItem(ui->mainGrid);
    ui->mainGrid->setParent(nullptr);

    auto* overviewScrollContents = new QWidget(this);
    overviewScrollContents->setObjectName(QStringLiteral("overviewScrollContents"));
    auto* overviewScrollLayout = new QVBoxLayout(overviewScrollContents);
    overviewScrollLayout->setContentsMargins(0, 0, 0, 0);
    overviewScrollLayout->addLayout(ui->mainGrid);

    auto* overviewScroll = new QScrollArea(this);
    overviewScroll->setObjectName(QStringLiteral("overviewScroll"));
    overviewScroll->setWidgetResizable(true);
    overviewScroll->setFrameShape(QFrame::NoFrame);
    overviewScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    overviewScroll->setFocusPolicy(Qt::NoFocus);
    overviewScroll->setWidget(overviewScrollContents);
    overviewScroll->setStyleSheet(QStringLiteral(
        "QScrollArea#overviewScroll, QWidget#overviewScrollContents { background: transparent; border: none; }"));
    ui->topLayout->addWidget(overviewScroll, 1);

    ui->labelTransactionsStatus->hide();
    ui->labelWalletStatus->hide();

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(ACTIVITY_ICON_SIZE, ACTIVITY_ICON_SIZE));
    ui->listTransactions->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);
    ui->listTransactions->setAccessibleName(tr("Recent transactions"));

    connect(ui->listTransactions, &QListView::clicked, this, &OverviewPage::handleTransactionClicked);
    connect(ui->listTransactions, &QListView::activated, this, &OverviewPage::handleTransactionClicked);

    applyOverviewRedesign();

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
}

void OverviewPage::applyOverviewRedesign()
{
    setAttribute(Qt::WA_StyledBackground, true);

    ui->topLayout->setContentsMargins(24, 18, 24, 18);
    ui->topLayout->setSpacing(16);
    ui->mainGrid->setHorizontalSpacing(16);
    ui->mainGrid->setVerticalSpacing(16);
    ui->mainGrid->setColumnStretch(0, 1);
    ui->mainGrid->setColumnStretch(1, 1);

    ui->balancesCardLayout->setContentsMargins(24, 18, 24, 18);
    ui->balancesCardLayout->setSpacing(8);
    ui->detailsCardLayout->setContentsMargins(18, 16, 18, 16);
    ui->detailsCardLayout->setSpacing(8);
    ui->activityCardLayout->setContentsMargins(18, 16, 18, 16);
    ui->activityCardLayout->setSpacing(8);

    ui->detailsCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    ui->activityCard->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    ui->mainGrid->setRowStretch(1, 1);

    networkBadge_ = new QLabel(ui->balancesCard);
    networkBadge_->setObjectName(QStringLiteral("networkBadge"));
    const QString networkId = QString::fromStdString(Params().NetworkIDString());
    QString networkLabel;
    if (networkId == QLatin1String("main"))
        networkLabel = tr("Mainnet");
    else if (networkId == QLatin1String("test"))
        networkLabel = tr("Testnet");
    else if (networkId == QLatin1String("dev"))
        networkLabel = tr("Devnet");
    else if (networkId == QLatin1String("regtest"))
        networkLabel = tr("Regtest");
    else
        networkLabel = networkId;
    networkBadge_->setText(networkLabel);
    networkBadge_->setAlignment(Qt::AlignCenter);
    ui->balanceHeaderRow->insertWidget(1, networkBadge_, 0, Qt::AlignVCenter);

    ui->labelTotalText->hide();

    ui->privateTransparentBarLayout->setSpacing(10);
    ui->privateTransparentBarFrame->setAttribute(Qt::WA_StyledBackground, true);
    ui->privateTransparentBarFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ui->privateTransparentBarFrame->setFixedHeight(8);
    if (!privateSplitProgress) {
        privateSplitProgress = new QProgressBar(ui->privateTransparentBarFrame);
        privateSplitProgress->setObjectName(QStringLiteral("privateSplitProgress"));
        privateSplitProgress->setRange(0, 100);
        privateSplitProgress->setValue(0);
        privateSplitProgress->setTextVisible(false);
        privateSplitProgress->setInvertedAppearance(true);
        privateSplitProgress->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        privateSplitProgress->setFixedHeight(8);
        ui->privateTransparentBarSegmentsLayout->addWidget(privateSplitProgress);
    }
    updatePrivateTransparentSplitBar();

    ui->privateTransparentSplitRow->setSpacing(0);
    ui->labelPrivateSplit->setTextFormat(Qt::RichText);
    ui->labelTransparentSplit->setTextFormat(Qt::RichText);

    // Drawn arrows replace the arrow characters that used to lead the labels.
    ui->sendButton->setText(tr("Send"));
    ui->receiveButton->setText(tr("Receive"));
    for (QPushButton* button : {ui->sendButton, ui->receiveButton, ui->anonymizeButton})
        button->setIconSize(QSize(18, 18));

    ui->anonymizeButton->setText(tr("Make Private"));

    connect(ui->sendButton, &QPushButton::clicked, this, &OverviewPage::gotoSendCoinsPage);
    connect(ui->receiveButton, &QPushButton::clicked, this, &OverviewPage::gotoReceiveCoinsPage);

    ui->gridLayout->setHorizontalSpacing(12);
    ui->gridLayout->setVerticalSpacing(8);

    activityEmptyState_ = new QWidget(ui->activityCard);
    activityEmptyState_->setObjectName(QStringLiteral("activityEmptyState"));
    auto* emptyLayout = new QVBoxLayout(activityEmptyState_);
    emptyLayout->setContentsMargins(0, 24, 0, 24);
    emptyLayout->setSpacing(7);
    emptyIcon_ = new QLabel(activityEmptyState_);
    emptyIcon_->setFixedSize(48, 48);
    emptyIcon_->setAlignment(Qt::AlignCenter);
    emptyTitle_ = new QLabel(tr("No transactions yet"), activityEmptyState_);
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyHint_ = new QLabel(
        tr("Your history will appear here after the first transfer"), activityEmptyState_);
    emptyHint_->setAlignment(Qt::AlignCenter);
    emptyHint_->setWordWrap(true);
    emptyLayout->addStretch();
    emptyLayout->addWidget(emptyIcon_, 0, Qt::AlignHCenter);
    emptyLayout->addWidget(emptyTitle_);
    emptyLayout->addWidget(emptyHint_);
    emptyLayout->addStretch();
    ui->activityCardLayout->insertWidget(2, activityEmptyState_, 1);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &OverviewPage::applyOverviewTheme);
    applyOverviewTheme();

    updateActivityEmptyState();
}

void OverviewPage::applyOverviewTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QWidget#OverviewPage { background: $BG; }")));

    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();

    // The balance card carries the brand gradient; the other cards stay quiet.
    ui->balancesCard->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QFrame#balancesCard {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 $HERO_START, stop:1 $HERO_END);
            border: none;
            border-radius: 20px;
        }
    )")));
    const QString cardStyle = GUIUtil::themed(QStringLiteral(R"(
        QFrame#detailsCard, QFrame#activityCard {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 14px;
        }
    )"));
    ui->detailsCard->setStyleSheet(cardStyle);
    ui->activityCard->setStyleSheet(cardStyle);

    ui->warningFrame->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QFrame#warningFrame { background: $GOLD_TINT; border: 1px solid $GOLD; border-radius: 10px; }"
        "QFrame#warningFrame QLabel { background: transparent; color: $INK; }")));
    ui->labelAlerts->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel#labelAlerts { background: $GOLD_TINT; color: $INK;"
        " border: 1px solid $GOLD; border-radius: 10px; padding: 8px 12px; }")));

    const QString syncWarningStyle = QStringLiteral(
        "QPushButton { background: transparent; border: none; padding: 0px; }");
    ui->labelWalletStatus->setStyleSheet(syncWarningStyle);
    ui->labelTransactionsStatus->setStyleSheet(syncWarningStyle);

    // Text on the gradient: white for values, 78% white for captions.
    if (networkBadge_) {
        networkBadge_->setStyleSheet(QStringLiteral(
            "QLabel#networkBadge {"
            " color: #FFFFFF; background: #29FFFFFF; border: none;"
            " border-radius: 10px; padding: 2px 9px; font-weight: 700;"
            "}"));
    }

    ui->labelPrimaryText->setStyleSheet(QStringLiteral(
        "QLabel { background: transparent; color: #C7FFFFFF; font-weight: 700; }"));

    ui->labelTotal->setTextFormat(Qt::RichText);
    ui->labelTotal->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: #FFFFFF;"
        " font: $FONT_H1; }")));

    ui->privateTransparentBarFrame->setStyleSheet(QStringLiteral(
        "QFrame#privateTransparentBarFrame {"
        " background: #2EFFFFFF;"
        " border: none;"
        " border-radius: 4px;"
        "}"
        "QFrame#privateTransparentBarFrame QProgressBar {"
        " background: transparent;"
        " border: none;"
        " border-radius: 4px;"
        " min-height: 8px; max-height: 8px;"
        "}"
        "QFrame#privateTransparentBarFrame QProgressBar::chunk {"
        " background: #6FE3CC;"
        " border: none;"
        " border-radius: 4px;"
        "}"));

    const QString splitLabelStyle = QStringLiteral(
        "QLabel { background: transparent; color: #C7FFFFFF; }");
    ui->labelPrivateSplit->setStyleSheet(splitLabelStyle);
    ui->labelTransparentSplit->setStyleSheet(splitLabelStyle);

    // One filled action on the card: Send is the inverse primary; Make Private keeps its
    // emphasis through the privacy teal instead of a second filled wine button.
    const QString actionStyle = QStringLiteral(
        "QPushButton { border-radius: 10px; min-width: 0; min-height: 20px; padding: 8px 18px; font-weight: 700; }");
    ui->sendButton->setStyleSheet(actionStyle + GUIUtil::themed(QStringLiteral(
        "QPushButton { color: $HERO_START; background: #FFFFFF; border: 1px solid transparent; }"
        "QPushButton:hover, QPushButton:pressed { background: #E6FFFFFF; }"
        "QPushButton:focus { border-color: #6FE3CC; }")));
    ui->receiveButton->setStyleSheet(actionStyle + QStringLiteral(
        "QPushButton { color: #FFFFFF; background: #1FFFFFFF; border: 1px solid #47FFFFFF; }"
        "QPushButton:hover, QPushButton:pressed { background: #33FFFFFF; }"
        "QPushButton:focus { border-color: #FFFFFF; }"));
    ui->anonymizeButton->setStyleSheet(actionStyle + QStringLiteral(
        "QPushButton { color: #FFFFFF; background: #296FE3CC; border: 1px solid #996FE3CC; }"
        "QPushButton:hover, QPushButton:pressed { background: #406FE3CC; }"
        "QPushButton:focus { border-color: #6FE3CC; }"
        "QPushButton:disabled { color: #8CFFFFFF; background: #1FFFFFFF; border-color: #2EFFFFFF; }"));
    // The sidebar icons, recolored for the gradient; Make Private uses the Spark mark.
    const QSize actionIconSize(18, 18);
    ui->sendButton->setIcon(GUIUtil::tintedIconPixmap(QIcon(QStringLiteral(":/icons/sidebar_send")), actionIconSize,
                                                      QColor(tc.heroStart)));
    ui->receiveButton->setIcon(GUIUtil::tintedIconPixmap(QIcon(QStringLiteral(":/icons/sidebar_receive")), actionIconSize,
                                                         QColor(Qt::white)));
    ui->anonymizeButton->setIcon(GUIUtil::tintedIconPixmap(QIcon(QStringLiteral(":/icons/spark")), actionIconSize,
                                                           QColor(QStringLiteral("#6FE3CC"))));

    // The out-of-sync warning sits on the gradient too; its glyph is solid black, so draw it in white.
    ui->labelWalletStatus->setIcon(GUIUtil::tintedIconPixmap(QIcon(QStringLiteral(":/icons/warning")),
                                                             ui->labelWalletStatus->iconSize(), QColor(Qt::white)));

    const QString sectionTitleStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font: $FONT_H3; }"));
    ui->label_5->setStyleSheet(sectionTitleStyle);
    ui->label->setStyleSheet(sectionTitleStyle);
    ui->label_4->setStyleSheet(sectionTitleStyle);
    ui->labelWatchonly->setStyleSheet(sectionTitleStyle);

    // Captions recede to regular weight so the amounts carry the card.
    const QString captionStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; }"));
    for (QLabel* caption : {ui->labelPrivateText, ui->labelUnconfirmedPrivateText,
                            ui->labelAnonymizableText, ui->labelBalanceText,
                            ui->labelPendingText, ui->labelImmatureText,
                            ui->labelWatchAvailableText, ui->labelWatchPendingText,
                            ui->labelWatchImmatureText, ui->labelWatchTotalText}) {
        caption->setStyleSheet(captionStyle);
    }

    const QString amountStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-weight: 700; }"));
    for (QLabel* amount : {ui->labelPrivate, ui->labelUnconfirmedPrivate, ui->labelAnonymizable,
                           ui->labelBalance, ui->labelUnconfirmed, ui->labelImmature,
                           ui->labelWatchAvailable, ui->labelWatchPending,
                           ui->labelWatchImmature, ui->labelWatchTotal}) {
        amount->setTextFormat(Qt::RichText);
        amount->setStyleSheet(amountStyle);
    }

    ui->listTransactions->setStyleSheet(QStringLiteral(
        "QListView, QListView::viewport { background: transparent; border: none; }"
        "QListView::item { border: none; padding: 0px; }"
        "QListView::item:selected { background: transparent; }"));
    QStyleOptionViewItem activityOption;
    activityOption.initFrom(ui->listTransactions);
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * txdelegate->sizeHint(activityOption, QModelIndex()).height());
    if (ui->listTransactions->viewport())
        ui->listTransactions->viewport()->update();

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: $WINE_TINT; border-radius: 24px; }")));
        emptyIcon_->setPixmap(GUIUtil::tintedIconPixmap(QIcon(QStringLiteral(":/icons/sidebar_transactions")),
                                                        QSize(24, 24), QColor(tc.wineText)));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK; font-weight: 700; }")));
    }
    if (emptyHint_) {
        emptyHint_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK_SOFT; }")));
    }

    // The amount runs embed the theme's faded color, so render them again.
    if (currentBalance != -1) {
        updateBalanceLabels();
    }
    updateBalanceSplitLabels();
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
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
    auto wallet = walletModel ? walletModel->getWallet() : nullptr;
    if (!walletModel || !walletModel->getOptionsModel() || !wallet || !wallet->sparkWallet ||
        !spark::IsSparkAllowed() || currentAnonymizableBalance <= 0) {
        return;
    }

    const int unit = walletModel->getOptionsModel()->getDisplayUnit();
    const CAmount available = currentAnonymizableBalance;
    QDialog amountDialog(this);
    amountDialog.setWindowTitle(tr("Make Funds Private"));
    amountDialog.setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog { background: $BG; }
        QLabel { background: transparent; color: $INK; }
        QLabel#amountDialogAvailable { color: $INK_SOFT; font-weight: 700; }
    )")));

    auto layout = new QVBoxLayout(&amountDialog);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(16);
    layout->setSizeConstraint(QLayout::SetFixedSize);

    auto description = new QLabel(
        tr("Move FIRO from your transparent balance into Spark, Firo's private balance."),
        &amountDialog);
    description->setWordWrap(true);
    layout->addWidget(description);

    auto form = new QFormLayout();
    form->setSpacing(12);
    form->addRow(tr("From"), new QLabel(tr("Transparent balance"), &amountDialog));
    form->addRow(tr("To"), new QLabel(tr("Private balance (Spark)"), &amountDialog));

    auto amountLayout = new QHBoxLayout();
    amountLayout->setSpacing(10);
    auto amountField = new BitcoinAmountField(&amountDialog);
    amountField->setDisplayUnit(unit);
    amountField->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QAbstractSpinBox, QComboBox {
            background: $PANEL_SOFT;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            padding: 5px 10px;
            color: $INK;
        }
        QAbstractSpinBox:focus, QComboBox:focus { border: 1px solid $WINE; }
        QAbstractSpinBox[invalidInput="true"] { border-color: $ERROR; }
        QAbstractSpinBox QLineEdit { %1 }
    )")).arg(GUIUtil::spinBoxInnerLineEditReset()));
    auto maxButton = new QPushButton(tr("Max"), &amountDialog);
    maxButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    amountLayout->addWidget(amountField);
    amountLayout->addWidget(maxButton);
    form->addRow(tr("Amount"), amountLayout);
    auto feeNoteLabel = new QLabel(
        tr("The network fee will be deducted from this amount."), &amountDialog);
    feeNoteLabel->setWordWrap(true);
    feeNoteLabel->setVisible(false);
    form->addRow(QString(), feeNoteLabel);
    auto availableLabel = new QLabel(BitcoinUnits::formatWithUnit(unit, available), &amountDialog);
    availableLabel->setObjectName(QStringLiteral("amountDialogAvailable"));
    form->addRow(tr("Available"), availableLabel);
    layout->addLayout(form);

    auto buttons = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok, &amountDialog);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Review"));
    buttons->button(QDialogButtonBox::Ok)->setStyleSheet(GUIUtil::primaryButtonStyle());
    buttons->button(QDialogButtonBox::Cancel)->setStyleSheet(GUIUtil::secondaryButtonStyle());
    layout->addWidget(buttons);

    connect(maxButton, &QPushButton::clicked, [amountField, available] {
        amountField->setValue(available);
    });
    connect(amountField, &BitcoinAmountField::valueChanged, [amountField, feeNoteLabel, available] {
        bool valid = false;
        const CAmount amount = amountField->value(&valid);
        feeNoteLabel->setVisible(valid && amount == available);
    });
    connect(buttons, &QDialogButtonBox::rejected, &amountDialog, &QDialog::reject);
    connect(buttons->button(QDialogButtonBox::Ok), &QPushButton::clicked, [&, available] {
        bool valid = false;
        const CAmount amount = amountField->value(&valid);
        if (!valid || amount <= 0 || amount > available) {
            amountField->setValid(false);
            return;
        }
        amountDialog.accept();
    });

    auto errorDetails = [unit](const WalletModel::SendCoinsReturn& result) {
        switch (result.status) {
        case WalletModel::AmountExceedsBalance:
            return tr("The amount exceeds your available transparent balance.");
        case WalletModel::AmountWithFeeExceedsBalance:
            return tr("The amount and transaction fee exceed your available transparent balance.");
        case WalletModel::AbsurdFee:
            return tr("The transaction fee is higher than the configured maximum of %1.")
                .arg(BitcoinUnits::formatWithUnit(unit, maxTxFee));
        case WalletModel::TransactionCreationFailed:
            return result.reasonCommitFailed;
        case WalletModel::TransactionCommitFailed:
            return tr("The transaction was rejected: %1").arg(result.reasonCommitFailed);
        default:
            return tr("Unable to create the Spark transaction.");
        }
    };

    QString sparkAddress;
    amountField->setFocus();
    while (amountDialog.exec() == QDialog::Accepted) {
        WalletModel::UnlockContext unlockContext(walletModel->requestUnlock(tr("Make funds private")));
        if (!unlockContext.isValid()) {
            return;
        }
        if (sparkAddress.isEmpty()) {
            sparkAddress = walletModel->generateSparkAddress();
        }

        const CAmount amount = amountField->value();
        SendCoinsRecipient recipient;
        recipient.address = sparkAddress;
        recipient.amount = amount;
        recipient.fSubtractFeeFromAmount = amount == available;

        QList<SendCoinsRecipient> recipients;
        recipients.append(recipient);
        std::vector<WalletModelTransaction> transactions;
        std::vector<std::pair<CWalletTx, CAmount>> transactionsAndFees;
        std::list<CReserveKey> reserveKeys;

        WalletModel::SendCoinsReturn prepareResult;
        GUIUtil::runWalletOperation([&] {
            prepareResult = walletModel->prepareMintSparkTransaction(
                transactions, recipients, transactionsAndFees, reserveKeys, nullptr);
        });
        if (prepareResult.status != WalletModel::OK) {
            const bool amountTooHigh =
                prepareResult.status == WalletModel::AmountExceedsBalance ||
                prepareResult.status == WalletModel::AmountWithFeeExceedsBalance;
            QMessageBox error(
                QMessageBox::Warning,
                tr("Unable to Make Funds Private"),
                tr("Firo could not create a Spark transaction for this amount."),
                QMessageBox::Cancel,
                this);
            error.setInformativeText(amountTooHigh
                ? tr("Use Maximum fills in the highest amount that can be made private, with the network fee deducted from it. No funds were moved.")
                : tr("Change the amount and try again. No funds were moved."));
            const QString details = errorDetails(prepareResult);
            if (!details.isEmpty()) {
                error.setDetailedText(details);
            }
            QPushButton* useMaxButton = nullptr;
            if (amountTooHigh) {
                useMaxButton = error.addButton(tr("Use Maximum"), QMessageBox::AcceptRole);
            }
            auto changeAmountButton = error.addButton(tr("Change Amount"), QMessageBox::AcceptRole);
            error.setDefaultButton(QMessageBox::Cancel);
            error.exec();
            if (useMaxButton && error.clickedButton() == useMaxButton) {
                amountField->setValue(available);
            } else if (error.clickedButton() != changeAmountButton) {
                return;
            }
            amountField->setFocus();
            continue;
        }

        CAmount privateAmount = 0;
        CAmount fee = 0;
        for (auto& transaction : transactions) {
            privateAmount += transaction.getTotalTransactionAmount();
            fee += transaction.getTransactionFee();
        }

        QMessageBox confirmation(
            QMessageBox::Question,
            tr("Review Private Transfer"),
            tr("Amount to make private: <b>%1</b><br>"
               "Network fee: %2<br>"
               "Total from transparent balance: %3")
                .arg(BitcoinUnits::formatWithUnit(unit, privateAmount),
                     BitcoinUnits::formatWithUnit(unit, fee),
                     BitcoinUnits::formatWithUnit(unit, privateAmount + fee)),
            QMessageBox::Cancel,
            this);
        auto confirmButton = confirmation.addButton(tr("Make Private"), QMessageBox::AcceptRole);
        confirmation.setDefaultButton(QMessageBox::Cancel);
        confirmation.exec();
        if (confirmation.clickedButton() != confirmButton) {
            return;
        }

        WalletModel::SendCoinsReturn sendResult;
        GUIUtil::runWalletOperation([&] {
            sendResult = walletModel->mintSparkCoins(transactions, transactionsAndFees, reserveKeys);
        });
        if (sendResult.status != WalletModel::OK) {
            // The wallet may have split the request into several transactions
            // (e.g. with the Split option) and committed some before failing,
            // so the message must not claim that nothing was sent.
            QMessageBox error(
                QMessageBox::Critical,
                tr("Unable to Make Funds Private"),
                sendResult.partiallyCommitted
                    ? tr("The transfer could not be fully completed. Part of it may already have been sent; check the Transactions tab before trying again.")
                    : tr("The transfer could not be completed. No funds were moved."),
                QMessageBox::Ok,
                this);
            const QString details = errorDetails(sendResult);
            if (!details.isEmpty()) {
                error.setDetailedText(details);
            }
            error.exec();
            return;
        }

        QMessageBox::information(
            this,
            tr("Funds Moving to Spark"),
            tr("%1 is moving to your private Spark balance. It will become available after confirmation.")
                .arg(BitcoinUnits::formatWithUnit(unit, privateAmount)));
        return;
    }
}

void OverviewPage::setBalance(
    const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
    const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance,
    const CAmount& privateBalance, const CAmount& unconfirmedPrivateBalance, const CAmount& anonymizableBalance)
{
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    currentPrivateBalance = privateBalance;
    currentUnconfirmedPrivateBalance = unconfirmedPrivateBalance;
    currentAnonymizableBalance = anonymizableBalance;
    updateBalanceLabels();

    auto wallet = walletModel->getWallet();
    updateSparkAnonymizeRowVisibility();
    ui->anonymizeButton->setEnabled(wallet && wallet->sparkWallet && spark::IsSparkAllowed() && anonymizableBalance > 0);

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmatureText->setVisible(showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature);

    updateBalanceSplitLabels();
    updatePrivateTransparentSplitBar();
    updateActivityEmptyState();
}

void OverviewPage::updateBalanceLabels()
{
    if (!walletModel || !walletModel->getOptionsModel()) {
        return;
    }
    const int unit = walletModel->getOptionsModel()->getDisplayUnit();
    const QString faded = GUIUtil::themeColors().inkFaint;
    const auto runs = [unit, &faded](const CAmount& amount) {
        return GUIUtil::amountRunsHtml(BitcoinUnits::formatWithUnit(unit, amount, false, BitcoinUnits::separatorAlways), faded);
    };
    ui->labelBalance->setText(runs(currentBalance));
    ui->labelUnconfirmed->setText(runs(currentUnconfirmedBalance));
    ui->labelImmature->setText(runs(currentImmatureBalance));
    // The total sits on the gradient: decimals at 60% white, unit in the light display weight.
    ui->labelTotal->setText(GUIUtil::amountRunsHtml(
        BitcoinUnits::formatWithUnit(unit, currentBalance + currentUnconfirmedBalance + currentImmatureBalance + currentPrivateBalance + currentUnconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways),
        QStringLiteral("#99FFFFFF"), QStringLiteral("font-size:24px; font-weight:300")));
    ui->labelWatchAvailable->setText(runs(currentWatchOnlyBalance));
    ui->labelWatchPending->setText(runs(currentWatchUnconfBalance));
    ui->labelWatchImmature->setText(runs(currentWatchImmatureBalance));
    ui->labelWatchTotal->setText(runs(currentWatchOnlyBalance + currentWatchUnconfBalance + currentWatchImmatureBalance));
    ui->labelPrivate->setText(runs(currentPrivateBalance));
    ui->labelUnconfirmedPrivate->setText(runs(currentUnconfirmedPrivateBalance));
    ui->labelAnonymizable->setText(runs(currentAnonymizableBalance));
}

void OverviewPage::updateBalanceSplitLabels()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;
    const int unit = walletModel->getOptionsModel()->getDisplayUnit();

    const CAmount privateTotal = currentPrivateBalance + currentUnconfirmedPrivateBalance;
    const CAmount transparentTotal = currentBalance + currentUnconfirmedBalance + currentImmatureBalance;
    const CAmount splitTotal = privateTotal + transparentTotal;
    int privatePercent = 0;
    if (splitTotal > 0) {
        privatePercent = static_cast<int>((privateTotal * 100 + splitTotal / 2) / splitTotal);
        privatePercent = std::min(100, std::max(0, privatePercent));
    }
    privateBarSplitPercent_ = privatePercent;

    // Legend on the balance gradient: dot, caption at 78% white, amount in white.
    ui->labelTransparentSplit->setText(
        QStringLiteral("<span style=\"color:#8CFFFFFF\">●</span>&nbsp; "
                       "<span style=\"color:#C7FFFFFF\">%3</span> "
                       "<span style=\"color:#FFFFFF; font-weight:700\">%1 (%2%)</span>")
            .arg(BitcoinUnits::formatWithUnit(unit, transparentTotal, false, BitcoinUnits::separatorAlways).toHtmlEscaped())
            .arg(100 - privatePercent)
            .arg(tr("Transparent")));
    ui->labelPrivateSplit->setText(
        QStringLiteral("<span style=\"color:#6FE3CC\">●</span>&nbsp; "
                       "<span style=\"color:#C7FFFFFF\">%3</span> "
                       "<span style=\"color:#FFFFFF; font-weight:700\">%1 (%2%)</span>")
            .arg(BitcoinUnits::formatWithUnit(unit, privateTotal, false, BitcoinUnits::separatorAlways).toHtmlEscaped())
            .arg(privatePercent)
            .arg(tr("Private (Spark):")));
}

void OverviewPage::updatePrivateTransparentSplitBar()
{
    if (!privateSplitProgress)
        return;
    privateSplitProgress->setValue(privateBarSplitPercent_);
    privateSplitProgress->setToolTip(
        tr("Private (Spark) %1%  ·  Transparent %2%")
            .arg(privateBarSplitPercent_)
            .arg(100 - privateBarSplitPercent_));
}

void OverviewPage::updateActivityEmptyState()
{
    const bool hasTransactions = filter && filter->rowCount() > 0;
    if (activityEmptyState_) {
        activityEmptyState_->setVisible(!hasTransactions);
        ui->listTransactions->setVisible(hasTransactions);
    }
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelWatchonly->setVisible(showWatchOnly);
    ui->lineWatchBalance->setVisible(showWatchOnly);
    ui->labelWatchAvailableText->setVisible(showWatchOnly);
    ui->labelWatchAvailable->setVisible(showWatchOnly);
    ui->labelWatchPendingText->setVisible(showWatchOnly);
    ui->labelWatchPending->setVisible(showWatchOnly);
    ui->labelWatchTotalText->setVisible(showWatchOnly);
    ui->labelWatchTotal->setVisible(showWatchOnly);

    if (!showWatchOnly) {
        ui->labelWatchImmatureText->hide();
        ui->labelWatchImmature->hide();
    }
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        connect(model, &ClientModel::numBlocksChanged, this, [this]() { ui->warningFrame->hide(); });
        // Show warning if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    ui->warningFrame->hide();
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        connect(model->getTransactionTableModel(), &TransactionTableModel::confirmationsChanged,
                filter.get(), &TransactionFilterProxy::refreshConfirmations);
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        // The row delegate paints status metadata in the address column.
        connect(filter.get(), &QAbstractItemModel::dataChanged, this, [this] {
            ui->listTransactions->viewport()->update();
        });

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        connect(filter.get(), &QAbstractItemModel::rowsInserted, this, [this] { updateActivityEmptyState(); });
        connect(filter.get(), &QAbstractItemModel::rowsRemoved, this, [this] { updateActivityEmptyState(); });
        connect(filter.get(), &QAbstractItemModel::modelReset, this, [this] { updateActivityEmptyState(); });
        updateActivityEmptyState();

        auto privateBalance = walletModel->getSparkBalance();

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
        connect(model->getOptionsModel(), &OptionsModel::sparkPageChanged, this, &OverviewPage::updateSparkAnonymizeRowVisibility);

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, &WalletModel::notifyWatchonlyChanged, this, &OverviewPage::updateWatchOnlyLabels);
        updateSparkAnonymizeRowVisibility();
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
    emptyTitle_->setText(fShow ? tr("Wallet is still syncing") : tr("No transactions yet"));
    emptyHint_->setText(fShow
        ? tr("Transactions will appear here as synchronization completes")
        : tr("Your history will appear here after the first transfer"));
    updateActivityEmptyState();
}

void OverviewPage::updateSparkAnonymizeRowVisibility()
{
    if (!walletModel || !walletModel->getOptionsModel()) {
        return;
    }
    const bool show = spark::IsSparkAllowed() && walletModel->getOptionsModel()->getSparkPage();
    ui->labelAnonymizableText->setVisible(show);
    ui->labelAnonymizable->setVisible(show);
    // Watch-only funds cannot be spent, so wallets with nothing eligible
    // (e.g. watch-only wallets) get no dead Make Private control.
    ui->anonymizeButton->setVisible(show && currentAnonymizableBalance > 0);
}
