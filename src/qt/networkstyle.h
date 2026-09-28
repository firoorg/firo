// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_NETWORKSTYLE_H
#define BITCOIN_QT_NETWORKSTYLE_H

#include <QIcon>
#include <QPixmap>
#include <QString>

/* Coin network-specific GUI style information */
class NetworkStyle
{
public:
    /** Get style associated with provided BIP70 network id, or 0 if not known */
    static const NetworkStyle *instantiate(const QString &networkId);

    const QString &getAppName() const { return appName; }
    const QIcon &getAppIcon() const { return appIcon; }
    const QIcon &getTrayAndWindowIcon() const { return trayAndWindowIcon; }
    const QString &getTitleAddText() const { return titleAddText; }
    /** Short network name for badges, e.g. "Testnet"; empty on mainnet */
    const QString &getBadgeText() const { return badgeText; }

    /** Recolor a pixmap the way the app icon is recolored for this network; returned unchanged on mainnet */
    QPixmap tintPixmap(const QPixmap &pixmap) const;

private:
    NetworkStyle(const QString &appName, const int iconColorHueShift, const int iconColorSaturationReduction, const char *titleAddText, const char *badgeText);

    QString appName;
    int iconColorHueShift;
    int iconColorSaturationReduction;
    QIcon appIcon;
    QIcon trayAndWindowIcon;
    QString titleAddText;
    QString badgeText;
};

#endif // BITCOIN_QT_NETWORKSTYLE_H
