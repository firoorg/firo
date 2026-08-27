// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_GUITHEME_H
#define BITCOIN_QT_GUITHEME_H

#include <QObject>
#include <QString>

QT_BEGIN_NAMESPACE
class QIcon;
class QPainter;
class QPixmap;
class QRect;
class QSize;
class QWidget;
QT_END_NAMESPACE

namespace GUIUtil
{
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
        QString gold;
        QString goldTint;
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

    void applyPrimaryButtonShadow(QWidget* button);

    void paintThemedStatusIcon(QPainter* painter, const QIcon& icon, const QRect& rect);

    QPixmap themedStatusIconPixmap(const QIcon& icon, const QSize& size);
} // namespace GUIUtil

#endif // BITCOIN_QT_GUITHEME_H
