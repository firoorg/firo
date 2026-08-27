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
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

#define DECORATION_SIZE 54
#define NUM_ITEMS 5
#define ACTIVITY_ICON_SIZE 42
#define ACTIVITY_CARD_HEIGHT 72

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
        const QRect card = option.rect.adjusted(2, 4, -2, -4);
        if (card.width() <= 0 || card.height() <= 0) {
            painter->restore();
            return;
        }

        painter->setPen(QPen(selected ? QColor(tc.wine) : QColor(tc.border), 1));
        painter->setBrush(selected ? QColor(tc.panelSoft) : QColor(tc.panel));
        painter->drawRoundedRect(card, 14, 14);

        const int txType = index.data(TransactionTableModel::TypeRole).toInt();
        const qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        const bool mined = txType == TransactionRecord::Generated;
        const bool incoming =
            mined ||
            txType == TransactionRecord::RecvWithAddress ||
            txType == TransactionRecord::RecvFromOther ||
            txType == TransactionRecord::RecvWithPcode ||
            txType == TransactionRecord::RecvSpark;
        const bool positive = incoming || amount > 0;

        const QRect iconRect(card.left() + 12, card.center().y() - 16, 32, 32);
        painter->setPen(Qt::NoPen);
        painter->setBrush(positive ? QColor(tc.tealTint) : QColor(tc.wineTint));
        painter->drawRoundedRect(iconRect, 10, 10);
        QFont iconFont = painter->font();
        iconFont.setPixelSize(14);
        iconFont.setBold(true);
        painter->setFont(iconFont);
        painter->setPen(positive ? QColor(tc.teal) : QColor(tc.wine));
        painter->drawText(iconRect, Qt::AlignCenter,
                          mined ? QStringLiteral("↗")
                                : incoming ? QStringLiteral("↙")
                                           : QStringLiteral("↗"));

        const QRect statusRect(iconRect.right() - 6, iconRect.bottom() - 12, 14, 14);
        const QVariant statusDec = index.sibling(index.row(), TransactionTableModel::Status)
                                       .data(TransactionTableModel::RawDecorationRole);
        if (statusDec.canConvert<QIcon>()) {
            const QIcon statusIcon = qvariant_cast<QIcon>(statusDec);
            if (!statusIcon.isNull())
                GUIUtil::paintThemedStatusIcon(painter, statusIcon, statusRect);
        }

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();

        const int textLeft = iconRect.right() + 12;
        const int amountWidth = 168;
        QFont dateFont = iconFont;
        dateFont.setPixelSize(12);
        dateFont.setWeight(QFont::DemiBold);
        painter->setFont(dateFont);
        painter->setPen(QColor(tc.ink));
        const QRect dateRect(textLeft, card.top() + 12, card.width() - textLeft - amountWidth - 16, 16);
        painter->drawText(dateRect, Qt::AlignLeft | Qt::AlignVCenter,
                          date.isValid() ? QLocale::system().toString(date, QLocale::ShortFormat)
                                         : GUIUtil::dateTimeStr(date));

        QFont addrFont = dateFont;
        addrFont.setPixelSize(12);
        addrFont.setBold(false);
        painter->setFont(addrFont);
        painter->setPen(QColor(tc.inkFaint));
        const QRect addressRect(textLeft, dateRect.bottom() + 1, dateRect.width(), 16);
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter,
                          QFontMetrics(addrFont).elidedText(address, Qt::ElideMiddle, addressRect.width()));

        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if (!confirmed)
            amountText = QString("[") + amountText + QString("]");
        QFont amountFont = dateFont;
        amountFont.setPixelSize(14);
        amountFont.setBold(true);
        painter->setFont(amountFont);
        painter->setPen(amount < 0 ? QColor(tc.wine) : QColor(tc.teal));
        const QRect amountRect(card.right() - amountWidth - 14, card.top(), amountWidth, card.height());
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText);

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override
    {
        return QSize(ACTIVITY_ICON_SIZE, ACTIVITY_CARD_HEIGHT);
    }

    int unit;
    const PlatformStyle *platformStyle;

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
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (ACTIVITY_CARD_HEIGHT + 10));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &QListView::clicked, this, &OverviewPage::handleTransactionClicked);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);

    applyOverviewRedesign();
}

void OverviewPage::addShadow(QWidget *w, int blurRadius, int yOffset, int alpha)
{
    auto *shadow = new QGraphicsDropShadowEffect(w);
    shadow->setBlurRadius(blurRadius);
    shadow->setOffset(0, yOffset);
    shadow->setColor(QColor(32, 28, 46, alpha));
    w->setGraphicsEffect(shadow);
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
    addShadow(ui->balancesCard);
    addShadow(ui->detailsCard);
    addShadow(ui->activityCard);

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
    if (!privateSplitProgress) {
        privateSplitProgress = new QProgressBar(ui->privateTransparentBarFrame);
        privateSplitProgress->setObjectName(QStringLiteral("privateSplitProgress"));
        privateSplitProgress->setRange(0, 100);
        privateSplitProgress->setValue(0);
        privateSplitProgress->setTextVisible(false);
        privateSplitProgress->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        privateSplitProgress->setFixedHeight(14);
        ui->privateTransparentBarSegmentsLayout->addWidget(privateSplitProgress);
    }
    updatePrivateTransparentSplitBar();

    ui->privateTransparentSplitRow->setSpacing(0);
    ui->labelPrivateSplit->setTextFormat(Qt::RichText);
    ui->labelTransparentSplit->setTextFormat(Qt::RichText);

    ui->sendButton->setText(tr("↗  Send"));
    auto *sendShadow = new QGraphicsDropShadowEffect(ui->sendButton);
    sendShadow->setBlurRadius(20);
    sendShadow->setOffset(0, 6);
    sendShadow->setColor(QColor(139, 26, 58, 70));
    ui->sendButton->setGraphicsEffect(sendShadow);

    ui->receiveButton->setText(tr("↙  Receive"));

    ui->anonymizeButton->setText(tr("Make Private"));
    GUIUtil::applyPrimaryButtonShadow(ui->anonymizeButton);

    connect(ui->sendButton, &QPushButton::clicked, this, &OverviewPage::gotoSendCoinsPage);
    connect(ui->receiveButton, &QPushButton::clicked, this, &OverviewPage::gotoReceiveCoinsPage);

    ui->gridLayout->setHorizontalSpacing(12);
    ui->gridLayout->setVerticalSpacing(8);

    activityEmptyState_ = new QWidget(ui->activityCard);
    activityEmptyState_->setObjectName(QStringLiteral("activityEmptyState"));
    auto* emptyLayout = new QVBoxLayout(activityEmptyState_);
    emptyLayout->setContentsMargins(0, 24, 0, 24);
    emptyLayout->setSpacing(7);
    emptyIcon_ = new QLabel(QStringLiteral("≡"), activityEmptyState_);
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

    const QString cardStyle = GUIUtil::themed(QStringLiteral(R"(
        QFrame#balancesCard, QFrame#detailsCard, QFrame#activityCard {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 18px;
        }
    )"));
    ui->balancesCard->setStyleSheet(cardStyle);
    ui->detailsCard->setStyleSheet(cardStyle);
    ui->activityCard->setStyleSheet(cardStyle);

    ui->warningFrame->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QFrame#warningFrame { background: $GOLD_TINT; border: 1px solid $GOLD; border-radius: 10px; }"
        "QFrame#warningFrame QLabel { background: transparent; color: $INK; font-size: 14px; }")));
    ui->labelAlerts->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel#labelAlerts { background: $GOLD_TINT; color: $INK;"
        " border: 1px solid $GOLD; border-radius: 10px; padding: 8px 12px; }")));

    const QString syncWarningStyle = QStringLiteral(
        "QPushButton { background: transparent; border: none; padding: 0px; }");
    ui->labelWalletStatus->setStyleSheet(syncWarningStyle);
    ui->labelTransactionsStatus->setStyleSheet(syncWarningStyle);

    if (networkBadge_) {
        networkBadge_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel#networkBadge {"
            " color: $INK; background: $WINE_TINT; border: none;"
            " border-radius: 9px; padding: 2px 8px; font-size: 12px; font-weight: 700;"
            "}")));
    }

    ui->labelPrimaryText->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT;"
        " font-size: 14px; font-weight: 700; }")));

    ui->labelTotal->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK;"
        " font-size: 31px; font-weight: 700; }")));

    ui->privateTransparentBarFrame->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QFrame#privateTransparentBarFrame {"
        " background: $PANEL_SOFT;"
        " border: 1px solid $INK_FAINT;"
        " border-radius: 7px;"
        "}"
        "QFrame#privateTransparentBarFrame QProgressBar {"
        " background: $PANEL_SOFT;"
        " border: none;"
        " border-radius: 7px;"
        " min-height: 14px; max-height: 14px;"
        "}"
        "QFrame#privateTransparentBarFrame QProgressBar::chunk {"
        " background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
        "                             stop:0 $TEAL, stop:1 $TEAL);"
        " border: none;"
        " border-radius: 7px;"
        "}")));

    const QString splitLabelStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 13px; font-weight: 600; }"));
    ui->labelPrivateSplit->setStyleSheet(splitLabelStyle);
    ui->labelTransparentSplit->setStyleSheet(splitLabelStyle);

    ui->sendButton->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QPushButton {
            color: #FFFFFF;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
            border: none;
            border-radius: 12px;
            padding: 10px 20px;
            font-size: 13px;
            font-weight: 700;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
        }
        QPushButton:pressed { background: $WINE_DEEP; }
    )")));

    ui->receiveButton->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QPushButton {
            color: $INK;
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 12px;
            padding: 10px 20px;
            font-size: 13px;
            font-weight: 700;
        }
        QPushButton:hover { background: $PANEL_SOFT; border-color: $BORDER; }
        QPushButton:pressed { background: $PANEL_SOFT; }
    )")));

    ui->anonymizeButton->setStyleSheet(
        GUIUtil::primaryButtonStyle(QStringLiteral("10px 20px")));

    const QString sectionTitleStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-size: 18px; font-weight: 700; }"));
    ui->label_5->setStyleSheet(sectionTitleStyle);
    ui->label->setStyleSheet(sectionTitleStyle);
    ui->label_4->setStyleSheet(sectionTitleStyle);
    ui->labelWatchonly->setStyleSheet(sectionTitleStyle);

    const QString captionStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 13px; font-weight: 600; }"));
    for (QLabel* caption : {ui->labelPrivateText, ui->labelUnconfirmedPrivateText,
                            ui->labelAnonymizableText, ui->labelBalanceText,
                            ui->labelPendingText, ui->labelImmatureText,
                            ui->labelWatchAvailableText, ui->labelWatchPendingText,
                            ui->labelWatchImmatureText, ui->labelWatchTotalText}) {
        caption->setStyleSheet(captionStyle);
    }

    const QString amountStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-size: 14px; font-weight: 700; }"));
    for (QLabel* amount : {ui->labelPrivate, ui->labelUnconfirmedPrivate, ui->labelAnonymizable,
                           ui->labelBalance, ui->labelUnconfirmed, ui->labelImmature,
                           ui->labelWatchAvailable, ui->labelWatchPending,
                           ui->labelWatchImmature, ui->labelWatchTotal}) {
        amount->setStyleSheet(amountStyle);
    }

    ui->listTransactions->setStyleSheet(QStringLiteral(
        "QListView, QListView::viewport { background: transparent; border: none; }"
        "QListView::item { border: none; padding: 0px; }"
        "QListView::item:selected { background: transparent; }"));
    if (ui->listTransactions->viewport())
        ui->listTransactions->viewport()->update();

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { color: $WINE; background: $WINE_TINT; border-radius: 14px;"
            " font-size: 22px; font-weight: 700; }")));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK; font-size: 14px; font-weight: 700; }")));
    }
    if (emptyHint_) {
        emptyHint_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK_SOFT; font-size: 12px; }")));
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

void OverviewPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);

    adjustTextSize(event->size().width(), event->size().height());
    updatePrivateTransparentSplitBar();
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
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 5px 10px;
            color: $INK;
        }
        QAbstractSpinBox:focus, QComboBox:focus { border: 1px solid $WINE; }
        QAbstractSpinBox[invalidInput="true"] { border-color: $ERROR; }
    )")));
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
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    currentPrivateBalance = privateBalance;
    currentUnconfirmedPrivateBalance = unconfirmedPrivateBalance;
    currentAnonymizableBalance = anonymizableBalance;
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, balance + unconfirmedBalance + immatureBalance + currentPrivateBalance + currentUnconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance + watchUnconfBalance + watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelPrivate->setText(BitcoinUnits::formatWithUnit(unit, privateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmedPrivate->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways));
    ui->labelAnonymizable->setText(BitcoinUnits::formatWithUnit(unit, anonymizableBalance, false, BitcoinUnits::separatorAlways));

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

    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    ui->labelTransparentSplit->setText(
        QStringLiteral("<span style=\"color:%3\">●</span>&nbsp; "
                       "<span style=\"color:%4\">%6</span> "
                       "<span style=\"color:%5; font-weight:700\">%1 (%2%)</span>")
            .arg(BitcoinUnits::formatWithUnit(unit, transparentTotal, false, BitcoinUnits::separatorAlways).toHtmlEscaped())
            .arg(100 - privatePercent)
            .arg(tc.inkFaint, tc.inkSoft, tc.ink)
            .arg(tr("Transparent")));
    ui->labelPrivateSplit->setText(
        QStringLiteral("<span style=\"color:%3\">●</span>&nbsp; "
                       "<span style=\"color:%4\">%6</span> "
                       "<span style=\"color:%5; font-weight:700\">%1 (%2%)</span>")
            .arg(BitcoinUnits::formatWithUnit(unit, privateTotal, false, BitcoinUnits::separatorAlways).toHtmlEscaped())
            .arg(privatePercent)
            .arg(tc.teal, tc.inkSoft, tc.ink)
            .arg(tr("Private")));
}

void OverviewPage::updatePrivateTransparentSplitBar()
{
    if (!privateSplitProgress)
        return;
    privateSplitProgress->setValue(privateBarSplitPercent_);
    privateSplitProgress->setToolTip(
        tr("Private %1%  ·  Transparent %2%")
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
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

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
    updateActivityEmptyState();
}

void OverviewPage::adjustTextSize(int width, int)
{
    const double fontSizeScalingFactor = 133.0;
    int baseFontSize = width / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));

    QFont textFont = ui->textWarning1->font();
    textFont.setPointSize(fontSize);
    textFont.setBold(false);

    QFont labelFont = textFont;
    labelFont.setBold(true);

    ui->textWarning1->setFont(textFont);
    ui->textWarning2->setFont(textFont);
    ui->labelAlerts->setFont(labelFont);
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
