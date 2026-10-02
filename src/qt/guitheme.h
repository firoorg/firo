// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUITHEME_H
#define BITCOIN_QT_GUITHEME_H

#include <QFont>
#include <QObject>
#include <QString>

QT_BEGIN_NAMESPACE
class QIcon;
class QPainter;
class QPixmap;
class QRect;
class QSize;
class QStyleOptionViewItem;
class QWidget;
QT_END_NAMESPACE

namespace GUIUtil
{
    enum class TextStyle { Body, Heading1, Heading2, Heading3 };

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

    QString spinBoxInnerLineEditReset();

    void paintAddressTypeBadge(QPainter* painter, const QStyleOptionViewItem& option,
                              const QString& text, bool isPrivate);

    void paintThemedStatusIcon(QPainter* painter, const QIcon& icon, const QRect& rect);

    QPixmap themedStatusIconPixmap(const QIcon& icon, const QSize& size);
} // namespace GUIUtil

#endif // BITCOIN_QT_GUITHEME_H
