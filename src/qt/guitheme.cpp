// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "guitheme.h"
#include "guiutil.h"

#include <QApplication>
#include <QColor>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QPixmapCache>
#include <QPointer>
#include <QSettings>
#include <QSize>
#include <QStyleOptionViewItem>
#include <QWidget>

namespace GUIUtil
{

QFont brandFont(TextStyle style)
{
    QFont font(QStringLiteral("Source Sans Pro"));
    font.setPixelSize(16);
    font.setWeight(QFont::Normal);
    if (style == TextStyle::Heading1 || style == TextStyle::Heading2) {
        font.setFamily(QStringLiteral("Saira SemiCondensed"));
        font.setPixelSize(style == TextStyle::Heading1 ? 40 : 24);
        font.setWeight(style == TextStyle::Heading1 ? QFont::Bold : QFont::Light);
    } else if (style == TextStyle::Heading3) {
        font.setPixelSize(18);
        font.setBold(true);
    }
    return font;
}

void loadBrandFonts()
{
    QFontDatabase::addApplicationFont(":/fonts/Saira_SemiCondensed-Bold");
    QFontDatabase::addApplicationFont(":/fonts/Saira_SemiCondensed-Light");
    QFontDatabase::addApplicationFont(":/fonts/SourceSansPro-Bold");
    QFontDatabase::addApplicationFont(":/fonts/SourceSansPro-Regular");
    QApplication::setFont(brandFont());
}

ThemeNotifier& ThemeNotifier::instance()
{
    static ThemeNotifier notifier;
    return notifier;
}

// One warm neutral ramp tinted toward the brand wine, with semantic colors kept distinct:
// teal marks private funds, red marks errors only, gold marks pending or expiring states.
static const ThemeColors LIGHT_COLORS{
    QStringLiteral("#F5F3F4"), // bg
    QStringLiteral("#FFFFFF"), // panel
    QStringLiteral("#F8F6F7"), // panelSoft
    QStringLiteral("#E8E3E6"), // border
    QStringLiteral("#1A1216"), // ink
    QStringLiteral("#554B51"), // inkSoft
    QStringLiteral("#776C73"), // inkFaint
    QStringLiteral("#9B1C2E"), // wine
    QStringLiteral("#7E1726"), // wineDeep
    QStringLiteral("#FBEEF0"), // wineTint
    QStringLiteral("#1E7D6F"), // teal
    QStringLiteral("#E5F4F0"), // tealTint
    QStringLiteral("#CC2F26"), // error
    QStringLiteral("#96560C"), // gold
    QStringLiteral("#FCF1E1"), // goldTint
    QStringLiteral("#F0ECEE"), // hover
    QStringLiteral("#CFC6CB"), // fieldBorder
    QStringLiteral("#9B1C2E"), // wineText
    QStringLiteral("#176A5E"), // tealText
    QStringLiteral("#FDECEA"), // errorTint
    QStringLiteral("#9B1C2E"), // heroStart
    QStringLiteral("#5E0F1D"), // heroEnd
    QStringLiteral("#FFFFFF"), // heroInk
    QStringLiteral("#C7FFFFFF"), // heroInkSoft
    QStringLiteral("#99FFFFFF"), // heroInkFaint
    QStringLiteral("#29FFFFFF"), // heroFill
    QStringLiteral("#3DFFFFFF"), // heroFillHover
    QStringLiteral("#47FFFFFF"), // heroLine
    QStringLiteral("#6FE3CC"), // heroAccent
};

static const ThemeColors DARK_COLORS{
    QStringLiteral("#0F0C10"),
    QStringLiteral("#18141A"),
    QStringLiteral("#211B23"),
    QStringLiteral("#2E2730"),
    QStringLiteral("#F5F0F3"),
    QStringLiteral("#C2B8BF"),
    QStringLiteral("#958A92"),
    QStringLiteral("#C8304F"),
    QStringLiteral("#A62742"),
    QStringLiteral("#24E84868"),
    QStringLiteral("#4CC2AD"),
    QStringLiteral("#244CC2AD"),
    QStringLiteral("#FF7B6E"),
    QStringLiteral("#EBB15E"),
    QStringLiteral("#24EBB15E"),
    QStringLiteral("#2A232C"),
    QStringLiteral("#463C48"),
    QStringLiteral("#F27A93"),
    QStringLiteral("#4CC2AD"),
    QStringLiteral("#24FF7B6E"),
    QStringLiteral("#86182A"),
    QStringLiteral("#3F0A15"),
    QStringLiteral("#FFFFFF"),
    QStringLiteral("#C7FFFFFF"),
    QStringLiteral("#99FFFFFF"),
    QStringLiteral("#29FFFFFF"),
    QStringLiteral("#3DFFFFFF"),
    QStringLiteral("#47FFFFFF"),
    QStringLiteral("#6FE3CC"),
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

    QList<QPointer<QWidget>> pausedWidgets;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->updatesEnabled()) {
            pausedWidgets.append(widget);
            widget->setUpdatesEnabled(false);
        }
    }

    loadTheme();
    Q_EMIT ThemeNotifier::instance().themeChanged();

    // Theme callbacks may destroy windows. Restore only widgets we paused.
    for (const auto& widget : pausedWidgets) {
        if (widget)
            widget->setUpdatesEnabled(true);
    }
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
    for (const auto style : {TextStyle::Body, TextStyle::Heading1, TextStyle::Heading2, TextStyle::Heading3}) {
        const QFont font = brandFont(style);
        const QString token = style == TextStyle::Body ? QStringLiteral("$FONT_BODY")
            : QStringLiteral("$FONT_H%1").arg(static_cast<int>(style));
        result.replace(token, QStringLiteral("%1 %2px '%3'")
                                  .arg(font.weight()).arg(font.pixelSize()).arg(font.family()));
    }
    result.replace(QLatin1String("$ASSET_THEME"), mode == ThemeMode::Dark
                                                     ? QLatin1String("dark")
                                                     : QLatin1String("light"));
    result.replace(QLatin1String("$FRAME_BG"), mode == ThemeMode::Dark ? QStringLiteral("transparent") : c.bg);
    // Longer tokens first, so $WINE_TEXT is not consumed by $WINE.
    result.replace(QLatin1String("$BG"), c.bg);
    result.replace(QLatin1String("$HOVER"), c.hover);
    result.replace(QLatin1String("$HERO_START"), c.heroStart);
    result.replace(QLatin1String("$HERO_END"), c.heroEnd);
    result.replace(QLatin1String("$HERO_INK_SOFT"), c.heroInkSoft);
    result.replace(QLatin1String("$HERO_INK_FAINT"), c.heroInkFaint);
    result.replace(QLatin1String("$HERO_INK"), c.heroInk);
    result.replace(QLatin1String("$HERO_FILL_HOVER"), c.heroFillHover);
    result.replace(QLatin1String("$HERO_FILL"), c.heroFill);
    result.replace(QLatin1String("$HERO_LINE"), c.heroLine);
    result.replace(QLatin1String("$HERO_ACCENT"), c.heroAccent);
    result.replace(QLatin1String("$PANEL_SOFT"), c.panelSoft);
    result.replace(QLatin1String("$PANEL"), c.panel);
    result.replace(QLatin1String("$FIELD_BORDER"), c.fieldBorder);
    result.replace(QLatin1String("$BORDER"), c.border);
    result.replace(QLatin1String("$INK_SOFT"), c.inkSoft);
    result.replace(QLatin1String("$INK_FAINT"), c.inkFaint);
    result.replace(QLatin1String("$INK"), c.ink);
    result.replace(QLatin1String("$WINE_DEEP"), c.wineDeep);
    result.replace(QLatin1String("$WINE_TINT"), c.wineTint);
    result.replace(QLatin1String("$WINE_TEXT"), c.wineText);
    result.replace(QLatin1String("$WINE"), c.wine);
    result.replace(QLatin1String("$TEAL_TINT"), c.tealTint);
    result.replace(QLatin1String("$TEAL_TEXT"), c.tealText);
    result.replace(QLatin1String("$TEAL"), c.teal);
    result.replace(QLatin1String("$ERROR_TINT"), c.errorTint);
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
            background: $WINE;
            border: 1px solid transparent;
            border-radius: 10px;
            min-width: 0;
            font-weight: 700;
            padding: %1;
        }
        QPushButton:hover:enabled { background: $WINE_DEEP; }
        QPushButton:focus { border: 1px solid $WINE_DEEP; }
        QPushButton:pressed { background: $WINE_DEEP; }
        QPushButton:disabled { background: $HOVER; color: $INK_FAINT; }
    )")).arg(padding);
}

QString secondaryButtonStyle(const QString& padding)
{
    return themed(QStringLiteral(R"(
        QPushButton {
            color: $INK;
            background: $PANEL;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            min-width: 0;
            font-weight: 700;
            padding: %1;
        }
        QPushButton:hover:enabled { background: $HOVER; }
        QPushButton:focus { border-color: $INK_FAINT; }
        QPushButton:pressed { background: $HOVER; }
        QPushButton:disabled { color: $INK_FAINT; background: $PANEL; border-color: $BORDER; }
    )")).arg(padding);
}

QString spinBoxInnerLineEditReset()
{
    return QStringLiteral("background: transparent; border: none; border-radius: 0; padding: 0; min-height: 0;");
}

void paintAddressTypeBadge(QPainter* painter, const QStyleOptionViewItem& option,
                          const QString& text, bool isPrivate)
{
    if (option.rect.width() <= 16)
        return;
    const auto& colors = themeColors();
    QFont font = option.font;
    font.setBold(true);
    painter->setFont(font);
    // Private funds are teal everywhere, matching the Overview split bar.
    const int dot = 6;
    const int textWidth = QFontMetrics(font).horizontalAdvance(text);
    const int width = qMin(option.rect.width() - 16, textWidth + dot + 26);
    const int height = QFontMetrics(font).height() + 6;
    const QRect badge(option.rect.left() + 8, option.rect.center().y() - height / 2, width, height);
    painter->setPen(Qt::NoPen);
    painter->setBrush(QColor(isPrivate ? colors.tealTint : colors.hover));
    painter->drawRoundedRect(badge, height / 2.0, height / 2.0);
    painter->setBrush(QColor(isPrivate ? colors.teal : colors.inkFaint));
    painter->drawEllipse(QRectF(badge.left() + 10, badge.center().y() - dot / 2.0 + 0.5, dot, dot));
    painter->setPen(QColor(isPrivate ? colors.tealText : colors.inkSoft));
    painter->drawText(badge.adjusted(10 + dot + 6, 0, -8, 0), Qt::AlignLeft | Qt::AlignVCenter,
                      QFontMetrics(font).elidedText(text, Qt::ElideRight, qMax(0, badge.width() - dot - 24)));
}

void paintRowBackground(QPainter* painter, const QRect& rect, bool selected)
{
    const auto& colors = themeColors();
    painter->fillRect(rect, QColor(colors.panel));
    if (selected) {
        painter->fillRect(rect, QColor(colors.wineTint));
    }
    painter->fillRect(QRect(rect.left(), rect.bottom(), rect.width(), 1), QColor(colors.border));
}

QString amountRunsHtml(const QString& formatted, const QString& fadedColor, const QString& unitStyle)
{
    const int split = formatted.indexOf(QLatin1Char('.'));
    if (split < 0) {
        return formatted.toHtmlEscaped();
    }
    const int unitStart = formatted.lastIndexOf(QLatin1Char(' '));
    const QString whole = formatted.left(split);
    const QString decimals = unitStart > split ? formatted.mid(split, unitStart - split) : formatted.mid(split);
    const QString unit = unitStart > split ? formatted.mid(unitStart) : QString();
    // white-space:pre keeps the thin-space thousands separators; Qt's HTML parser
    // would otherwise turn them into full-width spaces.
    QString html = QStringLiteral("<span style=\"white-space:pre\">") + whole.toHtmlEscaped() +
        QStringLiteral("<span style=\"color:%1\">%2</span>").arg(fadedColor, decimals.toHtmlEscaped());
    if (!unit.isEmpty()) {
        html += QStringLiteral("<span style=\"color:%1;%2\">%3</span>")
                    .arg(fadedColor, unitStyle, unit.toHtmlEscaped());
    }
    return html + QStringLiteral("</span>");
}

void paintAmountRuns(QPainter* painter, const QRect& rect, const QString& text, const QColor& color, Qt::Alignment align,
                     Qt::TextElideMode elide)
{
    const QFontMetrics metrics(painter->font());
    const int split = text.indexOf(QLatin1Char('.'));
    const int width = metrics.horizontalAdvance(text);
    painter->save();
    painter->setPen(color);
    if (split < 0 || width > rect.width()) {
        painter->drawText(rect, align, metrics.elidedText(text, elide, rect.width()));
        painter->restore();
        return;
    }
    const QString whole = text.left(split);
    const int x = (align & Qt::AlignRight) ? rect.right() + 1 - width : rect.left();
    const QRect wholeRect(x, rect.top(), metrics.horizontalAdvance(whole), rect.height());
    painter->drawText(wholeRect, (align & ~Qt::AlignHorizontal_Mask) | Qt::AlignLeft, whole);
    QColor faded = color;
    faded.setAlphaF(color.alphaF() * 0.55);
    painter->setPen(faded);
    painter->drawText(QRect(wholeRect.right() + 1, rect.top(), width - wholeRect.width() + 1, rect.height()),
                      (align & ~Qt::AlignHorizontal_Mask) | Qt::AlignLeft, text.mid(split));
    painter->restore();
}

QPixmap themedStatusIconPixmap(const QIcon& icon, const QSize& size)
{
    if (!isDarkMode())
        return icon.pixmap(size);
    return tintedIconPixmap(icon, size, QColor(themeColors().inkSoft));
}

QPixmap tintedIconPixmap(const QIcon& icon, const QSize& size, const QColor& tint)
{
    const QPixmap source = icon.pixmap(size);
    if (source.isNull())
        return source;

    const QString cacheKey = QStringLiteral("firo-tinted-icon:%1:%2x%3:%4:%5")
                                 .arg(source.cacheKey())
                                 .arg(source.width())
                                 .arg(source.height())
                                 .arg(source.devicePixelRatio())
                                 .arg(tint.name());
    QPixmap cached;
    if (QPixmapCache::find(cacheKey, &cached))
        return cached;

    QImage img = source.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
    for (int y = 0; y < img.height(); ++y) {
        QRgb* line = reinterpret_cast<QRgb*>(img.scanLine(y));
        for (int x = 0; x < img.width(); ++x) {
            const int a = qAlpha(line[x]);
            line[x] = qRgba(tint.red() * a / 255, tint.green() * a / 255, tint.blue() * a / 255, a);
        }
    }

    QPixmap result = QPixmap::fromImage(img);
    result.setDevicePixelRatio(source.devicePixelRatio());
    QPixmapCache::insert(cacheKey, result);
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
