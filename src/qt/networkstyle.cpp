// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "networkstyle.h"

#include "guiconstants.h"

#include <QApplication>

static const struct {
    const char *networkId;
    const char *appName;
    const int iconColorHueShift;
    const int iconColorSaturationReduction;
    const char *titleAddText;
    const char *badgeText;
} network_styles[] = {
    {"main", QAPP_APP_NAME_DEFAULT, 0, 0, "", ""},
    {"test", QAPP_APP_NAME_TESTNET, 70, 30, QT_TRANSLATE_NOOP("SplashScreen", "[testnet]"), QT_TRANSLATE_NOOP("SplashScreen", "Testnet")},
    {"dev", QAPP_APP_NAME_TESTNET, 70, 30, QT_TRANSLATE_NOOP("SplashScreen", "[devnet]"), QT_TRANSLATE_NOOP("SplashScreen", "Devnet")},
    {"regtest", QAPP_APP_NAME_TESTNET, 160, 30, QT_TRANSLATE_NOOP("SplashScreen", "[regtest]"), QT_TRANSLATE_NOOP("SplashScreen", "Regtest")}
};
static const unsigned network_styles_count = sizeof(network_styles)/sizeof(*network_styles);

// titleAddText and badgeText need to be const char* for tr()
NetworkStyle::NetworkStyle(const QString& _appName, const int _iconColorHueShift, const int _iconColorSaturationReduction, const char* _titleAddText, const char* _badgeText):
    appName(_appName),
    iconColorHueShift(_iconColorHueShift),
    iconColorSaturationReduction(_iconColorSaturationReduction),
    titleAddText(qApp->translate("SplashScreen", _titleAddText)),
    badgeText(qApp->translate("SplashScreen", _badgeText))
{
    const QPixmap pixmap = tintPixmap(QPixmap(":/icons/bitcoin"));

    appIcon             = QIcon(pixmap);
    trayAndWindowIcon   = QIcon(pixmap.scaled(QSize(256,256)));
}

QPixmap NetworkStyle::tintPixmap(const QPixmap& pixmap) const
{
    if (iconColorHueShift == 0 || iconColorSaturationReduction == 0) {
        return pixmap;
    }

    // generate QImage from QPixmap; work on straight (not premultiplied) alpha
    QImage img = pixmap.toImage().convertToFormat(QImage::Format_ARGB32);

    int h,s,l,a;

    // traverse though lines
    for(int y=0;y<img.height();y++)
    {
        QRgb *scL = reinterpret_cast< QRgb *>( img.scanLine( y ) );

        // loop through pixels
        for(int x=0;x<img.width();x++)
        {
            // preserve alpha because QColor::getHsl doesen't return the alpha value
            a = qAlpha(scL[x]);
            QColor col(scL[x]);

            // get hue value
            col.getHsl(&h,&s,&l);

            // rotate color on RGB color circle
            // 70° should end up with the typical "testnet" green
            h+=iconColorHueShift;

            // change saturation value
            if(s>iconColorSaturationReduction)
            {
                s -= iconColorSaturationReduction;
            }
            col.setHsl(h,s,l,a);

            // set the pixel
            scL[x] = col.rgba();
        }
    }

    //convert back to QPixmap
    QPixmap tinted = QPixmap::fromImage(img);
    tinted.setDevicePixelRatio(pixmap.devicePixelRatio());
    return tinted;
}

const NetworkStyle *NetworkStyle::instantiate(const QString &networkId)
{
    for (unsigned x=0; x<network_styles_count; ++x)
    {
        if (networkId == network_styles[x].networkId)
        {
            return new NetworkStyle(
                    network_styles[x].appName,
                    network_styles[x].iconColorHueShift,
                    network_styles[x].iconColorSaturationReduction,
                    network_styles[x].titleAddText,
                    network_styles[x].badgeText);
        }
    }
    return 0;
}
