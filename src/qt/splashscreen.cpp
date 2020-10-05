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
#include "ui_interface.h"
#include "version.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include "elysium/version.h"
#include "elysium/utilsbitcoin.h"

#include <QApplication>
#include <QCloseEvent>
#include <QDesktopWidget>
#include <QPainter>
#include <QRadialGradient>

SplashScreen::SplashScreen(const QPixmap &pixmap, Qt::WindowFlags f) : QSplashScreen(pixmap, f)
{
    // set reference point, paddings
    int paddingLeftCol2         = 232;
    int paddingTopCol2          = 200;
    int line1 = 0;
    int line2 = 13;
    int line3 = 26;
    int line4 = 39;

    float fontFactor            = 1.0;

    // define text to place
    QString titleText       = QString(QApplication::applicationName()).replace(QString("-testnet"), QString(""), Qt::CaseSensitive); // cut of testnet, place it as single object further down
    //QString versionText     = QString("Version %1 ").arg(QString::fromStdString(FormatFullVersion()));
    //QString copyrightText1   = QChar(0xA9)+QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Bitcoin developers"));
    //QString copyrightText2   = QChar(0xA9)+QString(" 2011-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Litecoin developers"));
    //QString copyrightText3   = QChar(0xA9)+QString(" 2014 ") + QString(tr("The Zcoin developers"));

    QString font            = "Arial";

    // load the bitmap for writing some text over it
    QPixmap newPixmap;
//    if(GetBoolArg("-testnet")) {
//        newPixmap     = QPixmap(":/images/splash_testnet");
//    }
//    else {
    newPixmap     = QPixmap(":/images/splash");
//    }

    QPainter pixPaint(&newPixmap);
    pixPaint.setPen(QColor(70,70,70));

    pixPaint.setFont(QFont(font, 9*fontFactor));
    //pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line4,versionText);

    // draw copyright stuff
    pixPaint.setFont(QFont(font, 9*fontFactor));
    //pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line1,copyrightText1);
    //pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line2,copyrightText2);
    //pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line3,copyrightText3);

    pixPaint.end();

    this->setPixmap(newPixmap);
}


//SplashScreen::SplashScreen(Qt::WindowFlags f, const NetworkStyle *networkStyle) : QWidget(0, f), curAlignment(0)
//{
//    // set reference point, paddings
//    int paddingRight            = 50;
//    int paddingTop              = 50;
//    int titleVersionVSpace      = 17;
//    int titleCopyrightVSpace    = 40;
//
//    float fontFactor            = 1.0;
//    float devicePixelRatio      = 1.0;
//#if QT_VERSION > 0x050100
//    devicePixelRatio = ((QGuiApplication*)QCoreApplication::instance())->devicePixelRatio();
//#endif
//
//    // define text to place
//    QString titleText       = tr(PACKAGE_NAME);
//    QString versionText     = QString("Version %1").arg(QString::fromStdString(FormatFullVersion()));
//    QString copyrightText   = QString::fromUtf8(CopyrightHolders(strprintf("\xc2\xA9 %u-%u ", 2009, COPYRIGHT_YEAR)).c_str());
//    QString titleAddText    = networkStyle->getTitleAddText();
//
//    QString font            = QApplication::font().toString();
//
//    // create a bitmap according to device pixelratio
//    QSize splashSize(480*devicePixelRatio,320*devicePixelRatio);
//    pixmap = QPixmap(splashSize);
//
//#if QT_VERSION > 0x050100
//    // change to HiDPI if it makes sense
//    pixmap.setDevicePixelRatio(devicePixelRatio);
//#endif
//
//    QPainter pixPaint(&pixmap);
//    pixPaint.setPen(QColor(100,100,100));
//
//    // draw a slightly radial gradient
//    QRadialGradient gradient(QPoint(0,0), splashSize.width()/devicePixelRatio);
//    gradient.setColorAt(0, Qt::white);
//    gradient.setColorAt(1, QColor(247,247,247));
//    QRect rGradient(QPoint(0,0), splashSize);
//    pixPaint.fillRect(rGradient, gradient);
//
//    // draw the Zcoin icon, expected size of PNG: 1024x1024
//    QRect rectIcon(QPoint(-150,-122), QSize(430,430));
//
//    const QSize requiredSize(1024,1024);
//    QPixmap icon(networkStyle->getAppIcon().pixmap(requiredSize));
//
//    pixPaint.drawPixmap(rectIcon, icon);
//
//    // check font size and drawing with
//    pixPaint.setFont(QFont(font, 33*fontFactor));
//    QFontMetrics fm = pixPaint.fontMetrics();
//    int titleTextWidth = fm.width(titleText);
//    if (titleTextWidth > 176) {
//        fontFactor = fontFactor * 176 / titleTextWidth;
//    }
//
//    pixPaint.setFont(QFont(font, 33*fontFactor));
//    fm = pixPaint.fontMetrics();
//    titleTextWidth  = fm.width(titleText);
//    pixPaint.drawText(pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight,paddingTop,titleText);
//
//    pixPaint.setFont(QFont(font, 15*fontFactor));
//
//    // if the version string is to long, reduce size
//    fm = pixPaint.fontMetrics();
//    int versionTextWidth  = fm.width(versionText);
//    if(versionTextWidth > titleTextWidth+paddingRight-10) {
//        pixPaint.setFont(QFont(font, 10*fontFactor));
//        titleVersionVSpace -= 5;
//    }
//    pixPaint.drawText(pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight+2,paddingTop+titleVersionVSpace,versionText);
//
//    // draw copyright stuff
//    {
//        pixPaint.setFont(QFont(font, 10*fontFactor));
//        const int x = pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight;
//        const int y = paddingTop+titleCopyrightVSpace;
//        QRect copyrightRect(x, y, pixmap.width() - x - paddingRight, pixmap.height() - y);
//        pixPaint.drawText(copyrightRect, Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, copyrightText);
//    }
//
//    // draw additional text if special network
//    if(!titleAddText.isEmpty()) {
//        QFont boldFont = QFont(font, 10*fontFactor);
//        boldFont.setWeight(QFont::Bold);
//        pixPaint.setFont(boldFont);
//        fm = pixPaint.fontMetrics();
//        int titleAddTextWidth  = fm.width(titleAddText);
//        pixPaint.drawText(pixmap.width()/devicePixelRatio-titleAddTextWidth-10,15,titleAddText);
//    }
//
//    pixPaint.end();
//
//    // Set window title
//    setWindowTitle(titleText + " " + titleAddText);
//
//    // Resize window and move to center of desktop, disallow resizing
//    QRect r(QPoint(), QSize(pixmap.size().width()/devicePixelRatio,pixmap.size().height()/devicePixelRatio));
//    resize(r.size());
//    setFixedSize(r.size());
//    move(QApplication::desktop()->screenGeometry().center() - r.center());
//
//    subscribeToCoreSignals();
//}
//
//SplashScreen::~SplashScreen()
//{
//    unsubscribeFromCoreSignals();
//}

void SplashScreen::slotFinish(QWidget *mainWin)
{
    Q_UNUSED(mainWin);

    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    QMetaObject::invokeMethod(splash, "showMessage",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignBottom|Qt::AlignHCenter),
        Q_ARG(QColor, QColor(55,55,55)));
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress)
{
    InitMessage(splash, title + strprintf("%d", nProgress) + "%");
}

#ifdef ENABLE_WALLET
void SplashScreen::ConnectWallet(CWallet* wallet)
{
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
    connectedWallets.push_back(wallet);
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.InitMessage.connect(boost::bind(InitMessage, this, boost::placeholders::_1));
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
#ifdef ENABLE_WALLET
    uiInterface.LoadWallet.connect(boost::bind(&SplashScreen::ConnectWallet, this, boost::placeholders::_1));
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.InitMessage.disconnect(boost::bind(InitMessage, this, boost::placeholders::_1));
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
#ifdef ENABLE_WALLET
    Q_FOREACH(CWallet* const & pwallet, connectedWallets) {
        pwallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
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
    QPainter painter(this);
    painter.drawPixmap(0, 0, pixmap);
    QRect r = rect().adjusted(5, 5, -5, -5);
    painter.setPen(curColor);
    painter.drawText(r, curAlignment, curMessage);
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}
