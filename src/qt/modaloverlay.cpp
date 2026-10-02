// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "modaloverlay.h"
#include "ui_modaloverlay.h"

#include "guiconstants.h"
#include "guitheme.h"
#include "guiutil.h"

#include "primitives/block.h"

#include <cmath>
#include <limits>

#include <QResizeEvent>
#include <QFrame>
#include <QFormLayout>
#include <QIcon>
#include <QLabel>
#include <QPropertyAnimation>
#include <QSizePolicy>
#include <QScrollArea>
#include <QStyle>
#include <QVBoxLayout>

namespace {

int targetBlockSpacing(int height, const QDateTime& date)
{
    CBlockHeader header;
    header.nHeight = height;
    header.nTime = static_cast<uint32_t>(date.toSecsSinceEpoch());
    return qMax(1, header.GetTargetBlocksSpacing());
}

}

ModalOverlay::ModalOverlay(QWidget *parent) :
QWidget(parent),
ui(new Ui::ModalOverlay),
bestHeaderHeight(0),
bestHeaderDate(QDateTime()),
layerIsVisible(false),
userClosed(false)
{
    ui->setupUi(this);
    ui->contentWidget->setAttribute(Qt::WA_StyledBackground, true);
    ui->verticalLayoutMain->removeWidget(ui->contentWidget);
    ui->contentWidget->setMinimumSize(QSize(0, 0));
    ui->contentWidget->setMaximumHeight(QWIDGETSIZE_MAX);
    ui->contentWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    ui->verticalLayoutSub->setSizeConstraint(QLayout::SetMinimumSize);

    auto* scrollArea = new QScrollArea(ui->bgWidget);
    scrollArea->setObjectName(QStringLiteral("syncScrollArea"));
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setAlignment(Qt::AlignCenter);
    scrollArea->setWidget(ui->contentWidget);
    ui->verticalLayoutMain->addWidget(scrollArea, 1);

    ui->verticalLayoutSub->removeItem(ui->formLayout);
    auto* statsCard = new QFrame(ui->contentWidget);
    statsCard->setObjectName(QStringLiteral("syncStatsCard"));
    statsCard->setMinimumHeight(245);
    auto* statsLayout = new QVBoxLayout(statsCard);
    statsLayout->setContentsMargins(28, 14, 28, 14);
    statsLayout->addLayout(ui->formLayout);
    ui->verticalLayoutSub->insertWidget(2, statsCard);

    ui->formLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    ui->formLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);
    ui->formLayout->setHorizontalSpacing(24);
    ui->formLayout->setVerticalSpacing(15);

    for (QLabel* value : {
             ui->numberOfBlocksLeft,
             ui->newestBlockDate,
             ui->percentageProgress,
             ui->progressIncreasePerH,
             ui->expectedTimeLeft}) {
        value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        value->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }

    ui->warningIcon->setEnabled(true);
    ui->warningIcon->setIcon(QIcon());
    ui->warningIcon->setText(QStringLiteral("⚠"));
    ui->warningIcon->setFocusPolicy(Qt::NoFocus);
    ui->warningIcon->setAttribute(Qt::WA_TransparentForMouseEvents);

    GUIUtil::applyPrimaryButtonShadow(ui->closeButton);

    connect(ui->closeButton, &QPushButton::clicked, this, &ModalOverlay::closeClicked);
    if (parent) {
        parent->installEventFilter(this);
        raise();
    }

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &ModalOverlay::applyTheme);
    applyTheme();

    blockProcessTime.clear();
    setVisible(false);
}

void ModalOverlay::applyTheme()
{
    ui->bgWidget->setStyleSheet(QStringLiteral(
        "#bgWidget { background-color: rgba(17, 12, 18, 148); }"));

    if (QScrollArea* scrollArea = findChild<QScrollArea*>(QStringLiteral("syncScrollArea"))) {
        scrollArea->setStyleSheet(QStringLiteral(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background: transparent; }"));
    }

    ui->contentWidget->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
#contentWidget {
    background: $PANEL;
    border: 1px solid $BORDER;
    border-radius: 22px;
}
#contentWidget QLabel {
    background: transparent;
    border: none;
    color: $INK_SOFT;
}
#contentWidget QLabel#titleLabel {
    color: $INK;
    font: $FONT_H2;
}
#contentWidget QLabel#infoText {
    color: $INK_SOFT;
}
#contentWidget QFrame#syncStatsCard {
    background: $PANEL_SOFT;
    border: 1px solid $BORDER;
    border-radius: 18px;
}
#contentWidget QLabel#labelNumberOfBlocksLeft,
#contentWidget QLabel#labelLastBlockTime,
#contentWidget QLabel#labelSyncDone,
#contentWidget QLabel#labelProgressIncrease,
#contentWidget QLabel#labelEstimatedTimeLeft {
    color: $INK_SOFT;
    font-weight: 700;
}
#contentWidget QLabel#numberOfBlocksLeft,
#contentWidget QLabel#newestBlockDate,
#contentWidget QLabel#percentageProgress,
#contentWidget QLabel#progressIncreasePerH,
#contentWidget QLabel#expectedTimeLeft {
    color: $INK;
    font-weight: 700;
}
#contentWidget QProgressBar {
    min-height: 10px;
    max-height: 10px;
    border: none;
    border-radius: 5px;
    background: $BORDER;
}
#contentWidget QProgressBar::chunk {
    border-radius: 5px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 $GOLD, stop:1 $GOLD);
}
#contentWidget QProgressBar[synced="true"]::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 $TEAL, stop:1 $TEAL);
}
#contentWidget QPushButton#closeButton {
    min-width: 112px;
    min-height: 46px;
    color: #FFFFFF;
    font-weight: 700;
    border: none;
    border-radius: 12px;
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 $WINE, stop:1 $WINE_DEEP);
}
#contentWidget QPushButton#closeButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 $WINE, stop:1 $WINE_DEEP);
}
#contentWidget QPushButton#closeButton:pressed {
    background: $WINE_DEEP;
}
#contentWidget QPushButton#warningIcon {
    min-width: 64px;
    max-width: 64px;
    min-height: 64px;
    max-height: 64px;
    background: $GOLD_TINT;
    color: $GOLD;
    font-size: 30px;
    border: none;
    border-radius: 14px;
    padding: 8px;
}
    )")));
}

ModalOverlay::~ModalOverlay()
{
    delete ui;
}

void ModalOverlay::setSyncComplete(bool complete)
{
    if (complete && ui->progressBar->property("synced").toBool()) {
        blockProcessTime.clear();
        return;
    }
    if (ui->progressBar->property("synced").toBool() != complete) {
        ui->progressBar->setProperty("synced", complete);
        ui->progressBar->style()->unpolish(ui->progressBar);
        ui->progressBar->style()->polish(ui->progressBar);
        ui->warningIcon->setVisible(!complete);
        ui->titleLabel->setText(complete
            ? tr("Wallet is synchronized")
            : tr("Wallet is still syncing"));
        ui->infoText->setText(complete
            ? tr("The wallet is up to date with the Firo network.")
            : tr("Recent transactions may not yet be visible, and your balance might be incorrect until the wallet finishes synchronizing with the Firo network."));
        if (!complete) {
            ui->progressIncreasePerH->setText(QStringLiteral("—"));
            ui->expectedTimeLeft->setText(tr("Unknown..."));
            blockProcessTime.clear();
        }
    }
    if (complete) {
        ui->percentageProgress->setText(QStringLiteral("100.00%"));
        ui->progressBar->setValue(100);
        ui->numberOfBlocksLeft->setText(QStringLiteral("0"));
        ui->progressIncreasePerH->setText(QStringLiteral("—"));
        ui->expectedTimeLeft->setText(tr("Complete"));
        blockProcessTime.clear();
    } else {
        updateProgressDisplay();
    }
}

bool ModalOverlay::eventFilter(QObject * obj, QEvent * ev) {
    if (obj == parent()) {
        if (ev->type() == QEvent::Resize) {
            QResizeEvent * rev = static_cast<QResizeEvent*>(ev);
            resize(rev->size());
            if (!layerIsVisible)
                setGeometry(0, height(), width(), height());

        }
        else if (ev->type() == QEvent::ChildAdded) {
            raise();
        }
    }
    return QWidget::eventFilter(obj, ev);
}

//! Tracks parent widget changes
bool ModalOverlay::event(QEvent* ev) {
    if (ev->type() == QEvent::ParentAboutToChange) {
        if (parent()) parent()->removeEventFilter(this);
    }
    else if (ev->type() == QEvent::ParentChange) {
        if (parent()) {
            parent()->installEventFilter(this);
            raise();
        }
    }
    return QWidget::event(ev);
}

void ModalOverlay::setKnownBestHeight(int count, const QDateTime& blockDate)
{
    if (count < bestHeaderHeight || !blockDate.isValid() ||
        (count == bestHeaderHeight && blockDate == bestHeaderDate)) {
        return;
    }
    bestHeaderHeight = count;
    bestHeaderDate = blockDate;
    updateProgressDisplay();
}

bool ModalOverlay::isHeaderSyncPending() const
{
    return bestHeaderHeight > blockHeight && bestHeaderDate.isValid() &&
        bestHeaderDate.secsTo(QDateTime::currentDateTime()) >= MAX_SYNCED_TIP_AGE_SECS;
}

double ModalOverlay::headerSyncProgress() const
{
    if (bestHeaderHeight <= 0 || !bestHeaderDate.isValid())
        return 0.0;

    const QDateTime currentDate = QDateTime::currentDateTime();
    const qint64 secondsBehind = qMax<qint64>(0, bestHeaderDate.secsTo(currentDate));
    const double estimatedHeadersLeft = static_cast<double>(secondsBehind) /
                                        targetBlockSpacing(bestHeaderHeight, currentDate);
    return qBound(0.0, bestHeaderHeight / (bestHeaderHeight + estimatedHeadersLeft), 1.0);
}

void ModalOverlay::tipUpdate(int count, const QDateTime& blockDate, double nVerificationProgress)
{
    if (!blockDate.isValid() || !std::isfinite(nVerificationProgress)) {
        return;
    }

    blockHeight = count;
    lastBlockDate = blockDate;
    verificationProgress = qBound(0.0, nVerificationProgress, 1.0);
    blockProcessTime.push_front(qMakePair(QDateTime::currentMSecsSinceEpoch(), verificationProgress));
    static const int MAX_SAMPLES = 5000;
    if (blockProcessTime.count() > MAX_SAMPLES)
        blockProcessTime.remove(MAX_SAMPLES, blockProcessTime.count()-MAX_SAMPLES);
    updateProgressDisplay();
}

void ModalOverlay::updateProgressDisplay()
{
    ui->newestBlockDate->setText(lastBlockDate.isValid() ? lastBlockDate.toString() : tr("Unknown..."));
    if (ui->progressBar->property("synced").toBool()) {
        return;
    }

    ui->progressIncreasePerH->setText(QStringLiteral("0.00%"));
    ui->expectedTimeLeft->setText(tr("Unknown..."));

    // show progress speed if we have more then one sample
    if (blockProcessTime.size() >= 2)
    {
        double progressStart = blockProcessTime[0].second;
        double progressDelta = 0;
        double progressPerHour = 0;
        qint64 timeDelta = 0;
        double remainingProgress = 1.0 - verificationProgress;
        for (int i = 1; i < blockProcessTime.size(); i++)
        {
            QPair<qint64, double> sample = blockProcessTime[i];

            // take first sample after 500 seconds or last available one
            if (sample.first < (blockProcessTime[0].first - 500LL * 1000) || i == blockProcessTime.size() - 1) {
                progressDelta = progressStart-sample.second;
                timeDelta = blockProcessTime[0].first - sample.first;
                break;
            }
        }
        if (progressDelta > 0 && timeDelta > 0) {
            progressPerHour = progressDelta / static_cast<double>(timeDelta) * 1000 * 3600;
            ui->progressIncreasePerH->setText(QString::number(progressPerHour*100, 'f', 2)+"%");
            const double remainingSeconds = remainingProgress / progressDelta * static_cast<double>(timeDelta) / 1000;
            if (std::isfinite(remainingSeconds) && remainingSeconds < static_cast<double>(std::numeric_limits<qint64>::max()) / 1000.0) {
                ui->expectedTimeLeft->setText(GUIUtil::formatNiceTimeOffset(static_cast<qint64>(remainingSeconds)));
            }
        }
    }

    // show the percentage done according to nVerificationProgress
    ui->percentageProgress->setText(QString::number(verificationProgress*100, 'f', 2)+"%");
    ui->progressBar->setValue(static_cast<int>(verificationProgress*100));

    if (isHeaderSyncPending()) {
        ui->numberOfBlocksLeft->setText(tr("Unknown. Syncing Headers (%1)...").arg(bestHeaderHeight));
        ui->expectedTimeLeft->setText(tr("Unknown..."));
    } else if (bestHeaderDate.isValid() && blockHeight >= 0 && bestHeaderHeight >= blockHeight &&
               bestHeaderDate.secsTo(QDateTime::currentDateTime()) < MAX_SYNCED_TIP_AGE_SECS) {
        ui->numberOfBlocksLeft->setText(QString::number(bestHeaderHeight - blockHeight));
    } else {
        ui->numberOfBlocksLeft->setText(tr("Unknown..."));
    }
}

void ModalOverlay::toggleVisibility()
{
    showHide(layerIsVisible, true);
    if (!layerIsVisible)
        userClosed = true;
}

void ModalOverlay::showHide(bool hide, bool userRequested)
{
    if ( (layerIsVisible && !hide) || (!layerIsVisible && hide) || (!hide && userClosed && !userRequested))
        return;

    if (!isVisible() && !hide)
        setVisible(true);

    // The initial sync state is set before the main window is shown. Place the
    // overlay directly instead of animating inside a window that is still hidden.
    if (!hide && !window()->isVisible()) {
        setGeometry(0, 0, width(), height());
        layerIsVisible = true;
        return;
    }

    setGeometry(0, hide ? 0 : height(), width(), height());

    QPropertyAnimation* animation = new QPropertyAnimation(this, "pos");
    animation->setDuration(300);
    animation->setStartValue(QPoint(0, hide ? 0 : this->height()));
    animation->setEndValue(QPoint(0, hide ? this->height() : 0));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    layerIsVisible = !hide;
}

void ModalOverlay::closeClicked()
{
    showHide(true);
    userClosed = true;
}
