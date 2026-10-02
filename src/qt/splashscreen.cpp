// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "splashscreen.h"

#include "guitheme.h"
#include "networkstyle.h"

#include "clientversion.h"
#include "init.h"
#include "ui_interface.h"
#include "util.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <QCloseEvent>
#include <QEasingCurve>
#include <QFont>
#include <QFontMetrics>
#include <QIcon>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QStyle>
#include <QTextLayout>
#include <QThread>
#include <QTimer>
#include <QToolButton>
#include <QVariantAnimation>
#include <QWindow>

namespace
{
// Layout in device-independent pixels, for left-to-right layouts; asymmetric
// rects are mirrored with QStyle::visualRect() for right-to-left ones.
constexpr int SPLASH_WIDTH = 600;
constexpr int SPLASH_HEIGHT = 400;
constexpr int NETWORK_STRIPE_HEIGHT = 4;
constexpr QRect BACKDROP(200, -80, 600, 600); //!< The mark, oversized and cropped by the window edges
constexpr QRectF MARK_BOUNDS(8, 8, 496, 496); //!< Extent of MarkPath()
constexpr QRect LOCKUP(16, 8, 123, 64); //!< Lockup asset including its padding; the mark ends up 32px with its left edge at 32
constexpr QPoint BADGE_TOP_LEFT(138, 30);
constexpr int BADGE_HEIGHT = 20;
constexpr QRect VERSION_LINE(SPLASH_WIDTH - 62 - 200, 24, 200, 32);
constexpr QRect CLOSE_BUTTON(SPLASH_WIDTH - 22 - 28, 26, 28, 28);

// Startup progress is anchored to the bottom so the step never moves while
// tasks come and go: the step wraps upward, and the slot above it holds the
// task's percentage or, while there is none, the steps that led here.
constexpr int TEXT_LEFT = 36;
constexpr int TEXT_WIDTH = 480;
constexpr int TEXT_BOTTOM = 364;
constexpr int STEP_LINE_HEIGHT = 28;
constexpr int STEP_MAX_LINES = 2;
constexpr int SLOT_GAP = 2; //!< Between the slot and the step
constexpr int PERCENT_HEIGHT = 84;
constexpr int PERCENT_INDENT = 4; //!< Pulls the large digits back to the text edge past their side bearing
constexpr int TRAIL_LENGTH = 3;
constexpr qreal TRAIL_OPACITY[TRAIL_LENGTH] = {0.62, 0.42, 0.26}; //!< Newest first
constexpr int TRAIL_LINE_HEIGHT = 22;
constexpr int TRAIL_GAP = 10; //!< Between the trail and the step
constexpr QRect PROGRESS_TRACK(0, SPLASH_HEIGHT - 4, SPLASH_WIDTH, 4);

constexpr int ANIMATION_INTERVAL_MS = 30;
constexpr int SWEEP_DURATION_MS = 1400;
constexpr qreal SWEEP_LENGTH = 0.3; //!< Share of the track covered by the indeterminate segment
constexpr int STEP_RISE_MS = 280;
constexpr int STEP_RISE_DISTANCE = 10;

QFont SplashFont(int pixelSize, bool bold = false)
{
    QFont splashFont(QStringLiteral("Source Sans Pro"));
    splashFont.setPixelSize(pixelSize);
    splashFont.setBold(bold);
    return splashFont;
}

/** The brand display face, which has digits but no Cyrillic, Greek or CJK: only the percentage uses it */
QFont PercentFont()
{
    QFont percentFont = GUIUtil::brandFont(GUIUtil::TextStyle::Heading1);
    percentFont.setPixelSize(88);
    percentFont.setFeature("tnum", 1); // Tabular figures, so the number doesn't shift as it counts
    return percentFont;
}

/** The two shapes of the Firo mark that leave the f between them, as in res/icons/firo.svg */
QPainterPath MarkPath()
{
    QPainterPath path;
    path.moveTo(153.9, 364.3);
    path.cubicTo(159.7, 364.3, 164.9, 361.2, 167.6, 356.1);
    path.lineTo(204.1, 287.0);
    path.lineTo(147.9, 287.0);
    path.cubicTo(139.4, 287.0, 132.4, 280.1, 132.4, 271.5);
    path.lineTo(132.4, 240.6);
    path.cubicTo(132.4, 232.1, 139.3, 225.1, 147.9, 225.1);
    path.lineTo(236.8, 225.1);
    path.lineTo(305.9, 94.1);
    path.cubicTo(308.5, 89.0, 313.8, 85.9, 319.6, 85.9);
    path.lineTo(435.8, 85.9);
    path.cubicTo(390.5, 38.2, 326.7, 8.5, 256.0, 8.5);
    path.cubicTo(119.3, 8.5, 8.5, 119.3, 8.5, 256.0);
    path.cubicTo(8.5, 294.8, 17.5, 331.6, 33.4, 364.3);
    path.closeSubpath();

    path.moveTo(358.1, 147.7);
    path.cubicTo(352.3, 147.7, 347.1, 150.8, 344.4, 155.9);
    path.lineTo(307.9, 225.0);
    path.lineTo(364.1, 225.0);
    path.cubicTo(372.6, 225.0, 379.6, 231.9, 379.6, 240.5);
    path.lineTo(379.6, 271.4);
    path.cubicTo(379.6, 279.9, 372.7, 286.9, 364.1, 286.9);
    path.lineTo(275.2, 286.9);
    path.lineTo(206.1, 417.9);
    path.cubicTo(203.5, 423.0, 198.2, 426.1, 192.4, 426.1);
    path.lineTo(76.4, 426.1);
    path.cubicTo(121.5, 473.8, 185.3, 503.6, 256.0, 503.6);
    path.cubicTo(392.7, 503.6, 503.5, 392.8, 503.5, 256.1);
    path.cubicTo(503.5, 217.3, 494.5, 180.5, 478.6, 147.8);
    path.closeSubpath();
    return path;
}

/** Break text into at most maxLines lines of the given width, eliding the last one if the rest doesn't fit */
QStringList WrapLines(const QString& text, const QFont& font, int width, int maxLines)
{
    QTextOption option;
    option.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    QTextLayout layout(text, font);
    layout.setTextOption(option);

    QStringList lines;
    layout.beginLayout();
    for (QTextLine line = layout.createLine(); line.isValid(); line = layout.createLine()) {
        line.setLineWidth(width);
        if (lines.size() == maxLines - 1) {
            lines.append(QFontMetrics(font).elidedText(text.mid(line.textStart()), Qt::ElideRight, width));
            break;
        }
        lines.append(text.mid(line.textStart(), line.textLength()).trimmed());
    }
    layout.endLayout();
    return lines;
}
} // namespace

SplashScreen::SplashScreen(const NetworkStyle* networkStyle) :
    animationTimer(new QTimer(this)),
    stepAnimation(new QVariantAnimation(this)),
    closeButton(new QToolButton(this))
{
    setWindowTitle(QStringLiteral("%1 %2").arg(tr(PACKAGE_NAME), networkStyle->getTitleAddText()).trimmed());
    setPixmap(renderArtwork(networkStyle));
    setFocusPolicy(Qt::StrongFocus);
    setFocus();

    closeButton->setGeometry(QStyle::visualRect(layoutDirection(), rect(), CLOSE_BUTTON));
    closeButton->setIcon(QIcon(GUIUtil::themedStatusIconPixmap(style()->standardIcon(QStyle::SP_TitleBarCloseButton), closeButton->iconSize())));
    closeButton->setAutoRaise(true);
    closeButton->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QToolButton { border: 1px solid transparent; border-radius: 14px; background: transparent; }"
        "QToolButton:hover, QToolButton:pressed { background: $PANEL_SOFT; }"
        "QToolButton:focus { border-color: $INK_SOFT; }")));
    closeButton->setCursor(Qt::PointingHandCursor);
    closeButton->setToolTip(tr("Quit application"));
    closeButton->setAccessibleName(closeButton->toolTip());
    closeButton->setFocusPolicy(Qt::StrongFocus);
    connect(closeButton, &QToolButton::clicked, this, &SplashScreen::requestShutdown);

    // The sweep runs on the timer for as long as progress is unknown; a new
    // step's short rise into place runs as an animation.
    animationTimer->setInterval(ANIMATION_INTERVAL_MS);
    connect(animationTimer, &QTimer::timeout, this, [this] { update(PROGRESS_TRACK.adjusted(-1, -1, 1, 1)); });
    animationClock.start();

    stepAnimation->setDuration(STEP_RISE_MS);
    stepAnimation->setStartValue(0.0);
    stepAnimation->setEndValue(1.0);
    stepAnimation->setEasingCurve(QEasingCurve::OutCubic);
    connect(stepAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        stepReveal = value.toReal();
        update();
    });

    showStatus(tr("Starting Firo..."));
    subscribeToCoreSignals();
}

QPixmap SplashScreen::renderArtwork(const NetworkStyle* networkStyle) const
{
    const GUIUtil::ThemeColors& colors = GUIUtil::themeColors();
    const bool dark = GUIUtil::isDarkMode();
    const Qt::LayoutDirection direction = layoutDirection();
    const qreal dpr = devicePixelRatio();
    const QRect canvas(0, 0, SPLASH_WIDTH, SPLASH_HEIGHT);

    QPixmap artwork(canvas.size() * dpr);
    artwork.setDevicePixelRatio(dpr);
    artwork.fill(QColor(colors.panel));

    QPainter painter(&artwork);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.setLayoutDirection(direction);

    // The mark, oversized in the theme's wine tint behind the progress
    const QRect backdrop = QStyle::visualRect(direction, canvas, BACKDROP);
    painter.save();
    painter.translate(backdrop.topLeft());
    painter.scale(backdrop.width() / MARK_BOUNDS.width(), backdrop.height() / MARK_BOUNDS.height());
    painter.translate(-MARK_BOUNDS.topLeft());
    painter.fillPath(MarkPath(), QColor(colors.wineTint));
    painter.restore();

    // Hairline edge, so the frameless window doesn't melt into a desktop of the same color
    painter.setPen(QPen(QColor(colors.border), 1));
    painter.setBrush(Qt::NoBrush);
    painter.drawRect(QRectF(canvas).adjusted(0.5, 0.5, -0.5, -0.5));

    // The same lockup as the sidebar, small in the header and recolored like the app icon on test networks
    const QIcon lockup(dark ? QStringLiteral(":/images/firo_logo_toolbar_dark") : QStringLiteral(":/images/firo_logo_toolbar"));
    const QRect lockupRect = QStyle::visualRect(direction, canvas, LOCKUP);
    painter.drawPixmap(lockupRect.topLeft(), networkStyle->tintPixmap(lockup.pixmap(LOCKUP.size(), dpr)));

    // Test networks get a caution stripe, and a badge after the lockup, in the theme's gold
    const QString badgeText = networkStyle->getBadgeText().toUpper();
    if (!badgeText.isEmpty()) {
        const QColor gold(colors.gold);
        painter.fillRect(QRect(0, 0, SPLASH_WIDTH, NETWORK_STRIPE_HEIGHT), gold);

        QFont badgeFont = SplashFont(11, true);
        badgeFont.setLetterSpacing(QFont::PercentageSpacing, 108);
        painter.setFont(badgeFont);
        const QSize badgeSize(painter.fontMetrics().horizontalAdvance(badgeText) + 18, BADGE_HEIGHT);
        const QRect badge = QStyle::visualRect(direction, canvas, QRect(BADGE_TOP_LEFT, badgeSize));
        painter.setPen(Qt::NoPen);
        painter.setBrush(gold);
        painter.drawRoundedRect(badge, BADGE_HEIGHT / 2.0, BADGE_HEIGHT / 2.0);
        painter.setPen(QColor(dark ? colors.bg : colors.panel));
        painter.drawText(badge, Qt::AlignCenter, badgeText);
    }

    painter.setFont(SplashFont(12));
    painter.setPen(QColor(colors.inkFaint));
    painter.drawText(QStyle::visualRect(direction, canvas, VERSION_LINE), Qt::AlignRight | Qt::AlignVCenter, QString::fromStdString(FormatFullVersion()));

    return artwork;
}

void SplashScreen::drawContents(QPainter* painter)
{
    const GUIUtil::ThemeColors& colors = GUIUtil::themeColors();
    const Qt::LayoutDirection direction = layoutDirection();
    const QColor ink(colors.ink);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing);
    painter->setLayoutDirection(direction);

    // The step, wrapping upward from the bottom and rising into place when it changes
    const QFont stepFont = SplashFont(22);
    const QStringList stepLines = WrapLines(statusText, stepFont, TEXT_WIDTH, STEP_MAX_LINES);
    const int stepTop = TEXT_BOTTOM - stepLines.size() * STEP_LINE_HEIGHT;
    painter->save();
    painter->setOpacity(stepReveal);
    painter->translate(0, (1 - stepReveal) * STEP_RISE_DISTANCE);
    painter->setFont(stepFont);
    painter->setPen(ink);
    for (int i = 0; i < stepLines.size(); ++i) {
        const QRect line(TEXT_LEFT, stepTop + i * STEP_LINE_HEIGHT, TEXT_WIDTH, STEP_LINE_HEIGHT);
        painter->drawText(QStyle::visualRect(direction, rect(), line), Qt::AlignLeft | Qt::AlignVCenter, stepLines[i]);
    }
    painter->restore();

    // Above it, how far the task is, or the steps that led here while that is unknown
    const int slotBottom = stepTop - SLOT_GAP;
    if (progress > 0) {
        const QRect percent(TEXT_LEFT - PERCENT_INDENT, slotBottom - PERCENT_HEIGHT, TEXT_WIDTH, PERCENT_HEIGHT);
        painter->setFont(PercentFont());
        painter->setPen(QColor(colors.wine));
        painter->drawText(QStyle::visualRect(direction, rect(), percent), Qt::AlignLeft | Qt::AlignVCenter, tr("%1%").arg(progress));
    } else {
        painter->setFont(SplashFont(15));
        for (int i = 0; i < recentSteps.size(); ++i) {
            QColor faded(ink);
            faded.setAlphaF(TRAIL_OPACITY[i]);
            painter->setPen(faded);
            const QRect line(TEXT_LEFT, slotBottom - TRAIL_GAP - (i + 1) * TRAIL_LINE_HEIGHT, TEXT_WIDTH, TRAIL_LINE_HEIGHT);
            painter->drawText(QStyle::visualRect(direction, rect(), line), Qt::AlignLeft | Qt::AlignVCenter,
                              painter->fontMetrics().elidedText(recentSteps[i], Qt::ElideRight, TEXT_WIDTH));
        }
    }

    // Progress runs along the bottom edge: filled to the percentage, or a sweeping segment while it is unknown
    const qreal radius = PROGRESS_TRACK.height() / 2.0;
    painter->fillRect(PROGRESS_TRACK, QColor(colors.border));

    QRectF filled(PROGRESS_TRACK);
    if (progress > 0) {
        // Square at the window edge, rounded where it ends
        filled.setLeft(PROGRESS_TRACK.left() - radius);
        filled.setRight(PROGRESS_TRACK.left() + PROGRESS_TRACK.width() * progress / 100.0);
    } else {
        static const QEasingCurve sweep(QEasingCurve::InOutSine);
        const qreal phase = sweep.valueForProgress(qreal(animationClock.elapsed() % SWEEP_DURATION_MS) / SWEEP_DURATION_MS);
        filled.setWidth(PROGRESS_TRACK.width() * SWEEP_LENGTH);
        filled.moveLeft(PROGRESS_TRACK.left() - filled.width() + phase * (PROGRESS_TRACK.width() + filled.width()));
    }
    if (direction == Qt::RightToLeft) {
        filled.moveLeft(width() - filled.right());
    }
    QPainterPath fill;
    fill.addRoundedRect(filled, radius, radius);
    painter->setClipRect(PROGRESS_TRACK);
    painter->fillPath(fill, QColor(colors.wine));
    painter->setClipping(false);

    painter->restore();
}

void SplashScreen::showStatus(const QString& text, bool animate)
{
    if (updateShutdownState()) {
        return;
    }
    setStep(text, animate);
    progress = -1;
    update();
    updateAnimation();
}

void SplashScreen::showProgress(const QString& title, int percent)
{
    if (updateShutdownState()) {
        return;
    }
    if (!title.isEmpty()) {
        setStep(title, true);
    }
    // 0 starts progress reporting; 100 closes it, including on failure or interruption.
    progress = (percent > 0 && percent < 100) ? percent : -1;
    update();
    updateAnimation();
}

void SplashScreen::setStep(const QString& text, bool animate)
{
    if (text == statusText) {
        return;
    }
    if (!statusText.isEmpty()) {
        recentSteps.prepend(statusText);
        if (recentSteps.size() > TRAIL_LENGTH) {
            recentSteps.removeLast();
        }
    }
    statusText = text;
    setAccessibleDescription(statusText);

    stepAnimation->stop();
    stepReveal = 1;
    if (animate && isVisible()) {
        stepReveal = 0;
        stepAnimation->start();
    }
}

bool SplashScreen::updateShutdownState()
{
    if (shutdownRequested && !ShutdownRequested()) {
        // Core can cancel shutdown when the user accepts a block database rebuild.
        shutdownRequested = false;
        setFocus();
        closeButton->show();
    }
    return shutdownRequested;
}

void SplashScreen::updateAnimation()
{
    if (progress < 0 && isVisible()) {
        if (!animationTimer->isActive()) {
            animationTimer->start();
        }
    } else {
        animationTimer->stop();
    }
}

void SplashScreen::requestShutdown()
{
    StartShutdown();
    if (shutdownRequested) {
        return;
    }
    shutdownRequested = true;
    setStep(tr("Shutting down..."), true);
    progress = -1;
    closeButton->hide();
    update();
    updateAnimation();
}

void SplashScreen::slotFinish(QWidget *mainWin)
{
    Q_UNUSED(mainWin);

    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    unsubscribeFromCoreSignals();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    const QString text = QString::fromStdString(message);
    if (QThread::currentThread() == splash->thread()) {
        // Paint GUI startup stages immediately without processing queued events,
        // so without a transition that only the event loop could finish.
        splash->showStatus(text, false);
        splash->QWidget::repaint();
    } else {
        QMetaObject::invokeMethod(splash, "showStatus", Qt::QueuedConnection, Q_ARG(QString, text));
    }
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress)
{
    QMetaObject::invokeMethod(splash, "showProgress",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(title)),
        Q_ARG(int, nProgress));
}

#ifdef ENABLE_WALLET
void SplashScreen::ConnectWallet(CWallet* wallet)
{
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    connectedWallets.push_back(wallet);
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.InitMessage.connect(boost::bind(InitMessage, this, _1));
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
#ifdef ENABLE_WALLET
    uiInterface.LoadWallet.connect(boost::bind(&SplashScreen::ConnectWallet, this, _1));
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.InitMessage.disconnect(boost::bind(InitMessage, this, _1));
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
#ifdef ENABLE_WALLET
    uiInterface.LoadWallet.disconnect(boost::bind(&SplashScreen::ConnectWallet, this, _1));
    for (CWallet* const & pwallet : connectedWallets) {
        pwallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    }
#endif
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    requestShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}

void SplashScreen::mousePressEvent(QMouseEvent* event)
{
    // Unlike QSplashScreen, don't hide on click; drag the frameless window.
    if (event->button() == Qt::LeftButton && windowHandle()) {
        windowHandle()->startSystemMove();
    }
}

void SplashScreen::showEvent(QShowEvent* event)
{
    QSplashScreen::showEvent(event);
    updateAnimation();
}

void SplashScreen::hideEvent(QHideEvent* event)
{
    animationTimer->stop();
    stepAnimation->stop();
    stepReveal = 1;
    QSplashScreen::hideEvent(event);
}
