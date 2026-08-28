// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "modaloverlay.h"
#include "ui_modaloverlay.h"

#include "guitheme.h"
#include "guiutil.h"

#include "primitives/block.h"

#include <QResizeEvent>
#include <QFrame>
#include <QFormLayout>
#include <QGraphicsDropShadowEffect>
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
userClosed(false),
foreverHidden(false)
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

    auto* buttonShadow = new QGraphicsDropShadowEffect(ui->closeButton);
    buttonShadow->setBlurRadius(20);
    buttonShadow->setOffset(0, 6);
    buttonShadow->setColor(QColor(139, 26, 58, 70));
    ui->closeButton->setGraphicsEffect(buttonShadow);

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
    font-family: 'Saira SemiCondensed';
    font-size: 24px;
    font-weight: 700;
}
#contentWidget QLabel#infoText {
    color: $INK_SOFT;
    font-size: 14px;
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
    font-size: 13px;
}
#contentWidget QLabel#numberOfBlocksLeft,
#contentWidget QLabel#newestBlockDate,
#contentWidget QLabel#percentageProgress,
#contentWidget QLabel#progressIncreasePerH,
#contentWidget QLabel#expectedTimeLeft {
    color: $INK;
    font-size: 13px;
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
    font-size: 14px;
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
    if (ui->progressBar->property("synced").toBool() == complete)
        return;

    ui->progressBar->setProperty("synced", complete);
    ui->progressBar->style()->unpolish(ui->progressBar);
    ui->progressBar->style()->polish(ui->progressBar);
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
    if (count > bestHeaderHeight) {
        bestHeaderHeight = count;
        bestHeaderDate = blockDate;
        const QDateTime currentDate = QDateTime::currentDateTime();
        const qint64 estimatedHeadersLeft = qMax<qint64>(0, blockDate.secsTo(currentDate)) /
                                            targetBlockSpacing(count, currentDate);
        headerSyncPending = estimatedHeadersLeft >= HEADER_HEIGHT_DELTA_SYNC;
    }
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
    QDateTime currentDate = QDateTime::currentDateTime();

    // keep a vector of samples of verification progress at height
    blockProcessTime.push_front(qMakePair(currentDate.toMSecsSinceEpoch(), nVerificationProgress));

    // show progress speed if we have more then one sample
    if (blockProcessTime.size() >= 2)
    {
        double progressStart = blockProcessTime[0].second;
        double progressDelta = 0;
        double progressPerHour = 0;
        qint64 timeDelta = 0;
        qint64 remainingMSecs = 0;
        double remainingProgress = 1.0 - nVerificationProgress;
        for (int i = 1; i < blockProcessTime.size(); i++)
        {
            QPair<qint64, double> sample = blockProcessTime[i];

            // take first sample after 500 seconds or last available one
            if (sample.first < (currentDate.toMSecsSinceEpoch() - 500 * 1000) || i == blockProcessTime.size() - 1) {
                progressDelta = progressStart-sample.second;
                timeDelta = blockProcessTime[0].first - sample.first;
                progressPerHour = progressDelta/(double)timeDelta*1000*3600;
                remainingMSecs = remainingProgress / progressDelta * timeDelta;
                break;
            }
        }
        // show progress increase per hour
        ui->progressIncreasePerH->setText(QString::number(progressPerHour*100, 'f', 2)+"%");

        // show expected remaining time
        ui->expectedTimeLeft->setText(GUIUtil::formatNiceTimeOffset(remainingMSecs/1000.0));

        static const int MAX_SAMPLES = 5000;
        if (blockProcessTime.count() > MAX_SAMPLES)
            blockProcessTime.remove(MAX_SAMPLES, blockProcessTime.count()-MAX_SAMPLES);
    }

    // show the last block date
    ui->newestBlockDate->setText(blockDate.toString());

    // show the percentage done according to nVerificationProgress
    ui->percentageProgress->setText(QString::number(nVerificationProgress*100, 'f', 2)+"%");
    ui->progressBar->setValue(nVerificationProgress*100);

    if (!bestHeaderDate.isValid())
        // not syncing
        return;

    // estimate the number of headers left based on the active target spacing
    // and check if the gui is not aware of the the best header (happens rarely)
    int estimateNumHeadersLeft = bestHeaderDate.secsTo(currentDate) /
                                 targetBlockSpacing(bestHeaderHeight, currentDate);
    bool hasBestHeader = bestHeaderHeight >= count;

    // show remaining number of blocks
    headerSyncPending = !(estimateNumHeadersLeft < HEADER_HEIGHT_DELTA_SYNC && hasBestHeader);
    if (!headerSyncPending) {
        ui->numberOfBlocksLeft->setText(QString::number(bestHeaderHeight - count));
    } else {
        ui->numberOfBlocksLeft->setText(tr("Unknown. Syncing Headers (%1)...").arg(bestHeaderHeight));
        ui->expectedTimeLeft->setText(tr("Unknown..."));
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

    if (!hide && foreverHidden && !userRequested)
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

void ModalOverlay::hideForever()
{
    foreverHidden = true;
}
