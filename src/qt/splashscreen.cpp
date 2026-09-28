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
#include <QRadialGradient>
#include <QStyle>
#include <QThread>
#include <QTimer>
#include <QToolButton>
#include <QWindow>

namespace
{
// Layout in device-independent pixels, for left-to-right layouts; asymmetric
// rects are mirrored with QStyle::visualRect() for right-to-left ones.
constexpr int SPLASH_WIDTH = 600;
constexpr int SPLASH_HEIGHT = 400;
constexpr int MARGIN = 32;
constexpr int FOOTER_TOP = 296;
constexpr int NETWORK_STRIPE_HEIGHT = 4;
constexpr QPoint LOGO_CENTER(SPLASH_WIDTH / 2, 148);
constexpr QSize LOGO_SIZE(292, 153); //!< Lockup asset including its padding; the mark ends up ~76px tall
constexpr QPoint BADGE_TOP_LEFT(20, 19);
constexpr int BADGE_HEIGHT = 22;
constexpr QRect CLOSE_BUTTON(SPLASH_WIDTH - 16 - 28, 16, 28, 28);
constexpr QRect STATUS_LINE(MARGIN, 316, SPLASH_WIDTH - 2 * MARGIN, 22);
constexpr QRect PROGRESS_TRACK(MARGIN, 348, SPLASH_WIDTH - 2 * MARGIN, 4);
constexpr QRect VERSION_LINE(MARGIN, 364, SPLASH_WIDTH - 2 * MARGIN, 18);

constexpr int ANIMATION_INTERVAL_MS = 30;
constexpr int SWEEP_DURATION_MS = 1400;
constexpr qreal SWEEP_LENGTH = 0.3; //!< Share of the track covered by the indeterminate segment

QFont SplashFont(int pixelSize, bool bold = false)
{
    QFont splashFont(QStringLiteral("Source Sans Pro"));
    splashFont.setPixelSize(pixelSize);
    splashFont.setBold(bold);
    return splashFont;
}
} // namespace

SplashScreen::SplashScreen(const NetworkStyle *networkStyle) :
    animationTimer(new QTimer(this)),
    closeButton(new QToolButton(this))
{
    setWindowTitle(QStringLiteral("%1 %2").arg(tr(PACKAGE_NAME), networkStyle->getTitleAddText()).trimmed());
    setPixmap(renderArtwork(networkStyle));

    closeButton->setGeometry(QStyle::visualRect(layoutDirection(), rect(), CLOSE_BUTTON));
    closeButton->setIcon(QIcon(GUIUtil::themedStatusIconPixmap(style()->standardIcon(QStyle::SP_TitleBarCloseButton), closeButton->iconSize())));
    closeButton->setAutoRaise(true);
    closeButton->setCursor(Qt::PointingHandCursor);
    closeButton->setToolTip(tr("Quit application"));
    closeButton->setAccessibleName(closeButton->toolTip());
    closeButton->setFocusPolicy(Qt::StrongFocus);
    connect(closeButton, &QToolButton::clicked, this, &SplashScreen::requestShutdown);

    animationTimer->setInterval(ANIMATION_INTERVAL_MS);
    connect(animationTimer, &QTimer::timeout, this, [this] { update(PROGRESS_TRACK.adjusted(-1, -1, 1, 1)); });
    animationClock.start();

    showStatus(tr("Starting Firo..."));
    subscribeToCoreSignals();
}

QPixmap SplashScreen::renderArtwork(const NetworkStyle *networkStyle) const
{
    const GUIUtil::ThemeColors &colors = GUIUtil::themeColors();
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

    // A faint glow of the brand color behind the logo
    QColor glow(colors.wine);
    glow.setAlpha(dark ? 40 : 10);
    QRadialGradient halo(LOGO_CENTER, SPLASH_WIDTH / 2);
    halo.setColorAt(0, glow);
    glow.setAlpha(0);
    halo.setColorAt(1, glow);
    painter.fillRect(QRect(0, 0, SPLASH_WIDTH, FOOTER_TOP), halo);

    // Footer band for the live status
    painter.fillRect(QRect(0, FOOTER_TOP, SPLASH_WIDTH, SPLASH_HEIGHT - FOOTER_TOP), QColor(colors.bg));
    painter.fillRect(QRect(0, FOOTER_TOP, SPLASH_WIDTH, 1), QColor(colors.border));

    // Hairline edge, so the frameless window doesn't melt into a desktop of the same color
    painter.setPen(QPen(QColor(colors.border), 1));
    painter.setBrush(Qt::NoBrush);
    painter.drawRect(QRectF(canvas).adjusted(0.5, 0.5, -0.5, -0.5));

    // The same lockup as the sidebar, recolored like the app icon on test networks
    const QIcon lockup(dark ? QStringLiteral(":/images/firo_logo_toolbar_dark") : QStringLiteral(":/images/firo_logo_toolbar"));
    const QPixmap logo = networkStyle->tintPixmap(lockup.pixmap(LOGO_SIZE, dpr));
    const QSizeF logoSize = logo.deviceIndependentSize();
    painter.drawPixmap(QPointF(LOGO_CENTER.x() - logoSize.width() / 2, LOGO_CENTER.y() - logoSize.height() / 2), logo);

    // Test networks get a caution stripe and badge in the theme's gold
    const QString badgeText = networkStyle->getBadgeText().toUpper();
    if (!badgeText.isEmpty()) {
        const QColor gold(colors.gold);
        painter.fillRect(QRect(0, 0, SPLASH_WIDTH, NETWORK_STRIPE_HEIGHT), gold);

        QFont badgeFont = SplashFont(12, true);
        badgeFont.setLetterSpacing(QFont::PercentageSpacing, 108);
        painter.setFont(badgeFont);
        const QSize badgeSize(painter.fontMetrics().horizontalAdvance(badgeText) + 20, BADGE_HEIGHT);
        const QRect badge = QStyle::visualRect(direction, canvas, QRect(BADGE_TOP_LEFT, badgeSize));
        painter.setPen(Qt::NoPen);
        painter.setBrush(gold);
        painter.drawRoundedRect(badge, BADGE_HEIGHT / 2.0, BADGE_HEIGHT / 2.0);
        painter.setPen(QColor(dark ? colors.bg : colors.panel));
        painter.drawText(badge, Qt::AlignCenter, badgeText);
    }

    painter.setFont(SplashFont(12));
    painter.setPen(QColor(colors.inkFaint));
    painter.drawText(VERSION_LINE, Qt::AlignLeft | Qt::AlignVCenter, QString::fromStdString(FormatFullVersion()));

    return artwork;
}

void SplashScreen::drawContents(QPainter *painter)
{
    const GUIUtil::ThemeColors &colors = GUIUtil::themeColors();
    const Qt::LayoutDirection direction = layoutDirection();

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing);
    painter->setLayoutDirection(direction);

    // Status line: the step on the leading side, the percentage on the trailing side
    QRect messageLine = STATUS_LINE;
    painter->setPen(QColor(colors.ink));
    if (progress >= 0) {
        const QString percentText = tr("%1%").arg(progress);
        painter->setFont(SplashFont(15, true));
        painter->drawText(STATUS_LINE, Qt::AlignRight | Qt::AlignVCenter, percentText);
        messageLine.setRight(STATUS_LINE.right() - painter->fontMetrics().horizontalAdvance(percentText) - 16);
    }
    painter->setFont(SplashFont(15));
    painter->drawText(QStyle::visualRect(direction, rect(), messageLine), Qt::AlignLeft | Qt::AlignVCenter,
                      painter->fontMetrics().elidedText(statusText, Qt::ElideRight, messageLine.width()));

    // Progress track: filled to the percentage, or a sweeping segment while it is unknown
    const qreal radius = PROGRESS_TRACK.height() / 2.0;
    QPainterPath track;
    track.addRoundedRect(QRectF(PROGRESS_TRACK), radius, radius);
    painter->fillPath(track, QColor(colors.border));

    QRectF filled(PROGRESS_TRACK);
    if (progress >= 0) {
        filled.setWidth(PROGRESS_TRACK.width() * progress / 100.0);
    } else {
        static const QEasingCurve sweep(QEasingCurve::InOutSine);
        const qreal phase = sweep.valueForProgress(qreal(animationClock.elapsed() % SWEEP_DURATION_MS) / SWEEP_DURATION_MS);
        filled.setWidth(PROGRESS_TRACK.width() * SWEEP_LENGTH);
        filled.moveLeft(PROGRESS_TRACK.left() - filled.width() + phase * (PROGRESS_TRACK.width() + filled.width()));
    }
    if (direction == Qt::RightToLeft)
        filled.moveLeft(width() - filled.right());
    QPainterPath fill;
    fill.addRoundedRect(filled, radius, radius);
    painter->setClipPath(track);
    painter->fillPath(fill, QColor(colors.wine));
    painter->setClipping(false);

    painter->restore();
}

void SplashScreen::showStatus(const QString &text)
{
    if (shutdownRequested)
        return;
    statusText = text;
    progress = -1;
    update();
    updateAnimation();
}

void SplashScreen::showProgress(const QString &title, int percent)
{
    if (shutdownRequested)
        return;
    // A finished task is reported as ShowProgress("", 100): keep its title, drop the percentage
    if (!title.isEmpty())
        statusText = title;
    progress = (percent >= 0 && percent < 100) ? percent : -1;
    update();
    updateAnimation();
}

void SplashScreen::updateAnimation()
{
    if (progress < 0 && isVisible()) {
        if (!animationTimer->isActive())
            animationTimer->start();
    } else {
        animationTimer->stop();
    }
}

void SplashScreen::requestShutdown()
{
    StartShutdown();
    if (shutdownRequested)
        return;
    shutdownRequested = true;
    statusText = tr("Shutting down...");
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
    const bool guiThread = QThread::currentThread() == splash->thread();
    QMetaObject::invokeMethod(splash, "showStatus",
        Qt::AutoConnection,
        Q_ARG(QString, QString::fromStdString(message)));
    if (guiThread) {
        // Paint GUI startup stages immediately without processing queued events.
        splash->QWidget::repaint();
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

void SplashScreen::mousePressEvent(QMouseEvent *event)
{
    // Unlike QSplashScreen, don't hide on click; drag the frameless window.
    if (event->button() == Qt::LeftButton && windowHandle())
        windowHandle()->startSystemMove();
}

void SplashScreen::showEvent(QShowEvent *event)
{
    QSplashScreen::showEvent(event);
    updateAnimation();
}

void SplashScreen::hideEvent(QHideEvent *event)
{
    animationTimer->stop();
    QSplashScreen::hideEvent(event);
}
