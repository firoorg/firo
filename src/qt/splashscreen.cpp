// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "splashscreen.h"

#include "networkstyle.h"

#include "clientversion.h"
#include "init.h"
#include "util.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <QCloseEvent>
#include <QFont>
#include <QFontMetrics>
#include <QLinearGradient>
#include <QPainter>
#include <QThread>
#include <QTimer>
#include <QtMath>

SplashScreen::SplashScreen(const NetworkStyle *networkStyle, Qt::WindowFlags f)
    : QSplashScreen([] {
          QPixmap background(600, 400);
          background.fill(QColor("#191A1E"));
          return background;
      }(), f),
      logo(":/icons/bitcoin"),
      networkLabel(networkStyle->getTitleAddText().toUpper()),
      curMessage(tr("Starting Firo...")),
      curColor(Qt::white),
      curAlignment(Qt::AlignLeft),
      rotation(0)
{
    networkLabel.remove('[').remove(']');

    setFixedSize(600, 400);
    setWindowTitle(QStringLiteral("Firo") + (networkLabel.isEmpty() ? QString() : QStringLiteral(" [%1]").arg(networkLabel)));

    QTimer *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, [this] {
        rotation = (rotation + 30) % 360;
        update(QRect(30, 319, 32, 36));
    });
    timer->start(80);

    subscribeToCoreSignals();
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
    QMetaObject::invokeMethod(splash, "showMessage",
        Qt::AutoConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignLeft),
        Q_ARG(QColor, QColor(Qt::white)));
    if (guiThread) {
        // Paint GUI startup stages immediately without processing queued events.
        splash->QWidget::repaint();
    }
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress)
{
    InitMessage(splash, title + strprintf("%d", nProgress) + "%");
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

void SplashScreen::showMessage(const QString &message, int alignment, const QColor &color)
{
    curMessage = message;
    curAlignment = alignment;
    curColor = color;
    update();
}

void SplashScreen::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);

    QLinearGradient background(0, 0, width(), height());
    background.setColorAt(0, QColor("#191A1E"));
    background.setColorAt(1, QColor("#3B1923"));
    painter.fillRect(rect(), background);

    painter.drawPixmap(QRect(258, 70, 84, 84), logo, logo.rect());

    QFont titleFont("Saira SemiCondensed");
    titleFont.setPixelSize(46);
    titleFont.setBold(true);
    painter.setFont(titleFont);
    painter.setPen(Qt::white);
    painter.drawText(QRect(0, 160, width(), 60), Qt::AlignHCenter | Qt::AlignVCenter, QStringLiteral("firo"));

    painter.fillRect(QRect(281, 228, 38, 3), QColor("#C6475C"));

    if (!networkLabel.isEmpty()) {
        QFont badgeFont("Source Sans Pro");
        badgeFont.setPixelSize(13);
        badgeFont.setBold(true);
        painter.setFont(badgeFont);
        const int badgeWidth = painter.fontMetrics().horizontalAdvance(networkLabel) + 24;
        const QRect badge(width() - 32 - badgeWidth, 28, badgeWidth, 26);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor("#9B1C2E"));
        painter.drawRoundedRect(badge, 13, 13);
        painter.setPen(Qt::white);
        painter.drawText(badge, Qt::AlignCenter, networkLabel);
    }

    painter.fillRect(QRect(32, 296, width() - 64, 1), QColor("#63444D"));

    painter.setPen(Qt::NoPen);
    for (int i = 0; i < 8; ++i) {
        painter.setBrush(QColor(255, 255, 255, 255 - i * 27));
        const qreal angle = qDegreesToRadians(qreal(rotation + i * 45));
        painter.drawEllipse(QPointF(46 + qCos(angle) * 10, 337 + qSin(angle) * 10), 2.5, 2.5);
    }

    QFont statusFont("Source Sans Pro");
    statusFont.setPixelSize(16);
    painter.setFont(statusFont);
    painter.setPen(curColor);
    painter.drawText(QRect(72, 318, width() - 104, 38), curAlignment | Qt::AlignVCenter,
                     painter.fontMetrics().elidedText(curMessage, Qt::ElideRight, width() - 112));

    QFont versionFont("Source Sans Pro");
    versionFont.setPixelSize(12);
    painter.setFont(versionFont);
    painter.setPen(QColor("#B6AEB1"));
    painter.drawText(QRect(32, 366, width() - 64, 18), Qt::AlignRight | Qt::AlignVCenter,
                     QString::fromStdString(FormatFullVersion()));
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}

void SplashScreen::mousePressEvent(QMouseEvent* event)
{
    event->ignore();
}
