// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUITHEME_H
#define BITCOIN_QT_GUITHEME_H

#include <QColor>
#include <QFont>
#include <QObject>
#include <QString>

QT_BEGIN_NAMESPACE
class QAction;
class QColor;
class QIcon;
class QPainter;
class QPixmap;
class QRect;
class QRectF;
class QSize;
class QStyleOptionViewItem;
class QWidget;
QT_END_NAMESPACE

namespace GUIUtil
{
    //! Caption is the small bold label over a value or field; QSS cannot carry its letter spacing.
    enum class TextStyle { Body, Heading1, Heading2, Heading3, Caption };

    // Brand sizes are logical pixels; Qt scales fonts and widget geometry together.
    QFont brandFont(TextStyle style = TextStyle::Body);
    void loadBrandFonts();

    enum class ThemeMode {
        Light,
        Dark
    };

    struct ThemeColors {
        QString bg;
        QString panel;
        QString panelSoft;
        QString border;
        QString ink;
        QString inkSoft;
        QString inkFaint;
        QString wine;
        QString wineDeep;
        QString wineTint;
        QString teal;
        QString tealTint;
        QString error;
        QString gold;
        QString goldTint;
        QString hover;       //!< Hover and pressed fill for quiet controls
        QString fieldBorder; //!< Edge of inputs and secondary buttons; $BORDER is the card hairline
        QString wineText;    //!< Wine for text and icons, readable on both surfaces
        QString tealText;    //!< Teal for text on teal tints
        QString errorTint;
        QString heroStart;   //!< Overview balance card gradient
        QString heroEnd;
        // On the balance gradient, identical in both themes
        QString heroInk;       //!< Values and filled-button surface
        QString heroInkSoft;   //!< Captions and legend text
        QString heroInkFaint;  //!< Decimals, units and the transparent dot
        QString heroFill;      //!< Badge, track and quiet button surface
        QString heroFillHover; //!< Quiet button hover
        QString heroLine;      //!< Quiet button edge
        QString heroAccent;    //!< Private funds: a light teal that holds up on wine
        QString heroAccentFill;      //!< Make Private surface
        QString heroAccentFillHover; //!< Make Private hover
        QString heroAccentLine;      //!< Make Private edge
    };

    class ThemeNotifier : public QObject
    {
        Q_OBJECT
    public:
        static ThemeNotifier& instance();
    Q_SIGNALS:
        void themeChanged();
    private:
        explicit ThemeNotifier(QObject* parent = nullptr) : QObject(parent) {}
    };

    ThemeMode currentThemeMode();
    void setThemeMode(ThemeMode mode);
    bool isDarkMode();
    const ThemeColors& themeColors();

    QString themed(const QString& cssTemplate);
    QString themed(const QString& cssTemplate, ThemeMode mode);

    QString primaryButtonStyle(const QString& padding = QStringLiteral("8px 16px"));
    QString secondaryButtonStyle(const QString& padding = QStringLiteral("8px 16px"));
    //! A borderless action that recedes next to the primary and secondary buttons.
    QString ghostButtonStyle(const QString& padding = QStringLiteral("8px 16px"));

    QString spinBoxInnerLineEditReset();

    /** Meaning of a pill: teal for private or healthy, gold for pending, red for failed. */
    enum class PillTone { Neutral, Positive, Warning, Danger };

    struct PillColors {
        QString background;
        QString dot;
        QString text;
    };

    /** @return The colors of a pill with tone in the active theme. */
    PillColors pillColors(PillTone tone);

    /** @return The width a pill needs to show text in metrics' font, with its dot and padding. */
    int pillWidth(const QFontMetrics& metrics, const QString& text);

    /**
     * Paint a rounded pill with a leading dot, eliding text to fit.
     * @param[in] painter  Painter whose current font is used for text.
     * @param[in] pill     Bounds of the pill.
     * @param[in] text     Label.
     * @param[in] tone     Meaning, which sets the colors.
     */
    void paintPill(QPainter* painter, const QRect& pill, const QString& text, PillTone tone);

    void paintAddressTypeBadge(QPainter* painter, const QStyleOptionViewItem& option,
                              const QString& text, bool isPrivate);

    /**
     * Fill a list cell as part of a flat row: panel surface, wine tint when selected,
     * and a hairline along the bottom edge. Cells of one row together form the row.
     */
    void paintRowBackground(QPainter* painter, const QRect& rect, bool selected);

    /**
     * Rich text for a formatted amount with the decimals and unit faded, so the whole
     * number reads first. The digits are the same as in formatted; a minus sign is shown
     * as the typographic minus.
     * @param[in] formatted  Output of BitcoinUnits::formatWithUnit().
     * @param[in] fadedColor CSS color for the decimals and unit.
     * @param[in] unitStyle  Extra CSS for the unit run, e.g. a smaller size.
     */
    QString amountRunsHtml(const QString& formatted, const QString& fadedColor, const QString& unitStyle = QString());

    /**
     * Paint a formatted amount with the decimals and unit at reduced opacity, and a minus
     * sign as the typographic minus. Falls back to a single run, elided with elide, when the text has no decimal point
     * (e.g. a placeholder) or does not fit rect.
     */
    void paintAmountRuns(QPainter* painter, const QRect& rect, const QString& text, const QColor& color, Qt::Alignment align,
                         Qt::TextElideMode elide = Qt::ElideRight);

    /**
     * Paint a single-color status icon in the muted ink, or in tint when one is given
     * (e.g. teal once a transaction is confirmed).
     */
    void paintThemedStatusIcon(QPainter* painter, const QIcon& icon, const QRect& rect, const QColor& tint = QColor());

    //! A single-color status icon in the muted ink of the current theme.
    QPixmap themedStatusIconPixmap(const QIcon& icon, const QSize& size);

    /**
     * Recolor a single-color icon, keeping its shape and anti-aliasing. Results are cached.
     * @param[in] icon   Icon whose alpha channel gives the shape, e.g. a sidebar icon.
     * @param[in] size   Logical size of the pixmap.
     * @param[in] tint   Opaque color to fill the shape with.
     */
    QPixmap tintedIconPixmap(const QIcon& icon, const QSize& size, const QColor& tint);

    /**
     * Give a menu action an outline icon in the muted ink, re-tinted whenever the theme changes.
     * @param[in] action    Action shown in a menu; owns the theme connection.
     * @param[in] resource  Single-color icon resource, e.g. ":/icons/editcopy".
     */
    void setThemedIcon(QAction* action, const QString& resource);
} // namespace GUIUtil

#endif // BITCOIN_QT_GUITHEME_H
