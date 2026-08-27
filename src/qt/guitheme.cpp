// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "guitheme.h"
#include "guiutil.h"

#include <QApplication>
#include <QColor>
#include <QGraphicsDropShadowEffect>
#include <QHash>
#include <QIcon>
#include <QPainter>
#include <QPair>
#include <QPixmap>
#include <QSettings>
#include <QSize>
#include <QWidget>
#include <QWidgetList>

namespace GUIUtil
{

ThemeNotifier& ThemeNotifier::instance()
{
    static ThemeNotifier notifier;
    return notifier;
}

static const ThemeColors LIGHT_COLORS{
    QStringLiteral("#F7F5F8"),
    QStringLiteral("#FFFFFF"),
    QStringLiteral("#FBFAFD"),
    QStringLiteral("#ECE8F2"),
    QStringLiteral("#201C2E"),
    QStringLiteral("#6E6A80"),
    QStringLiteral("#726E7B"),
    QStringLiteral("#9B1C2E"),
    QStringLiteral("#7A1830"),
    QStringLiteral("#FCE9EE"),
    QStringLiteral("#237A6E"),
    QStringLiteral("#E6F5F2"),
    QStringLiteral("#9B1C2E"),
    QStringLiteral("#A66314"),
    QStringLiteral("#FBF1E3"),
};

static const ThemeColors DARK_COLORS{
    QStringLiteral("#110C12"),
    QStringLiteral("#1C151B"),
    QStringLiteral("#241B22"),
    QStringLiteral("#362A34"),
    QStringLiteral("#F5EFF3"),
    QStringLiteral("#B4A8B2"),
    QStringLiteral("#8D818B"),
    QStringLiteral("#DE3358"),
    QStringLiteral("#A3223F"),
    QStringLiteral("rgba(222,51,88,0.16)"),
    QStringLiteral("#4FBBA8"),
    QStringLiteral("rgba(79,187,168,0.14)"),
    QStringLiteral("#FF708A"),
    QStringLiteral("#E7B678"),
    QStringLiteral("rgba(231,182,120,0.14)"),
};

static bool g_darkMode = false;
static bool g_loaded = false;

static void loadThemeModeFromSettings()
{
    if (g_loaded)
        return;
    QSettings settings;
    g_darkMode = settings.value("fDarkMode", false).toBool();
    g_loaded = true;
}

ThemeMode currentThemeMode()
{
    loadThemeModeFromSettings();
    return g_darkMode ? ThemeMode::Dark : ThemeMode::Light;
}

bool isDarkMode()
{
    return currentThemeMode() == ThemeMode::Dark;
}

void setThemeMode(ThemeMode mode)
{
    loadThemeModeFromSettings();
    const bool dark = (mode == ThemeMode::Dark);
    if (dark == g_darkMode)
        return;
    g_darkMode = dark;

    QSettings settings;
    settings.setValue("fDarkMode", g_darkMode);

    const QWidgetList topLevels = QApplication::topLevelWidgets();
    for (QWidget* w : topLevels)
        w->setUpdatesEnabled(false);

    loadTheme();
    Q_EMIT ThemeNotifier::instance().themeChanged();

    for (QWidget* w : topLevels)
        w->setUpdatesEnabled(true);
}

const ThemeColors& themeColors()
{
    return isDarkMode() ? DARK_COLORS : LIGHT_COLORS;
}

QString themed(const QString& cssTemplate)
{
    return themed(cssTemplate, currentThemeMode());
}

QString themed(const QString& cssTemplate, ThemeMode mode)
{
    const ThemeColors& c = mode == ThemeMode::Dark ? DARK_COLORS : LIGHT_COLORS;
    QString result = cssTemplate;
    result.replace(QLatin1String("$ASSET_THEME"), mode == ThemeMode::Dark
                                                     ? QLatin1String("dark")
                                                     : QLatin1String("light"));
    result.replace(QLatin1String("$BG"), c.bg);
    result.replace(QLatin1String("$PANEL_SOFT"), c.panelSoft);
    result.replace(QLatin1String("$PANEL"), c.panel);
    result.replace(QLatin1String("$BORDER"), c.border);
    result.replace(QLatin1String("$INK_SOFT"), c.inkSoft);
    result.replace(QLatin1String("$INK_FAINT"), c.inkFaint);
    result.replace(QLatin1String("$INK"), c.ink);
    result.replace(QLatin1String("$WINE_DEEP"), c.wineDeep);
    result.replace(QLatin1String("$WINE_TINT"), c.wineTint);
    result.replace(QLatin1String("$WINE"), c.wine);
    result.replace(QLatin1String("$TEAL_TINT"), c.tealTint);
    result.replace(QLatin1String("$TEAL"), c.teal);
    result.replace(QLatin1String("$ERROR"), c.error);
    result.replace(QLatin1String("$GOLD_TINT"), c.goldTint);
    result.replace(QLatin1String("$GOLD"), c.gold);
    return result;
}

QString primaryButtonStyle(const QString& padding)
{
    return themed(QStringLiteral(R"(
        QPushButton {
            color: #FFFFFF;
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
            border: none;
            border-radius: 12px;
            font-weight: 700;
            padding: %1;
        }
        QPushButton:hover:enabled {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
        }
        QPushButton:pressed { background: $WINE_DEEP; }
        QPushButton:disabled { background: $BORDER; color: $INK_FAINT; }
    )")).arg(padding);
}

QString secondaryButtonStyle(const QString& padding)
{
    return themed(QStringLiteral(R"(
        QPushButton {
            color: $INK;
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 12px;
            font-weight: 700;
            padding: %1;
        }
        QPushButton:hover:enabled { background: $PANEL_SOFT; border-color: $BORDER; }
        QPushButton:pressed { background: $PANEL_SOFT; }
        QPushButton:disabled { color: $INK_FAINT; background: $PANEL; }
    )")).arg(padding);
}

QString spinBoxInnerLineEditReset()
{
    return QStringLiteral("background: transparent; border: none; border-radius: 0; padding: 0; min-height: 0;");
}

void applyPrimaryButtonShadow(QWidget* button)
{
    if (!button) return;
    auto* shadow = new QGraphicsDropShadowEffect(button);
    shadow->setBlurRadius(20);
    shadow->setOffset(0, 6);
    shadow->setColor(QColor(139, 26, 58, 70));
    button->setGraphicsEffect(shadow);
}

QPixmap themedStatusIconPixmap(const QIcon& icon, const QSize& size)
{
    const QPixmap source = icon.pixmap(size);
    if (!isDarkMode() || source.isNull())
        return source;

    QImage img = source.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
    const QColor tint(themeColors().inkSoft);
    for (int y = 0; y < img.height(); ++y) {
        QRgb* line = reinterpret_cast<QRgb*>(img.scanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            const int a = qAlpha(line[x]);
            line[x] = qRgba(tint.red() * a / 255, tint.green() * a / 255, tint.blue() * a / 255, a);
        }
    }

    QPixmap result = QPixmap::fromImage(img);
    result.setDevicePixelRatio(source.devicePixelRatio());
    return result;
}

void paintThemedStatusIcon(QPainter* painter, const QIcon& icon, const QRect& rect)
{
    if (!isDarkMode()) {
        icon.paint(painter, rect, Qt::AlignCenter);
        return;
    }

    const QSize size = rect.size().isEmpty() ? QSize(16, 16) : rect.size();
    const QPixmap tinted = themedStatusIconPixmap(icon, size);
    if (tinted.isNull()) {
        icon.paint(painter, rect, Qt::AlignCenter);
        return;
    }

    const QRect target(
        rect.left() + (rect.width() - size.width()) / 2,
        rect.top() + (rect.height() - size.height()) / 2,
        size.width(), size.height());
    painter->drawPixmap(target, tinted);
}

} // namespace GUIUtil
