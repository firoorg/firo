// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SPLASHSCREEN_H
#define BITCOIN_QT_SPLASHSCREEN_H

#include <QElapsedTimer>
#include <QList>
#include <QSplashScreen>

class CWallet;
class NetworkStyle;

QT_BEGIN_NAMESPACE
class QTimer;
class QToolButton;
QT_END_NAMESPACE

/** Splash screen with startup status from the running client.
 *
 * Everything that stays the same while it is shown (themed background, logo,
 * network badge, version) is rendered once into the QSplashScreen pixmap;
 * drawContents() only paints the status line and progress track.
 */
class SplashScreen : public QSplashScreen
{
    Q_OBJECT

public:
    explicit SplashScreen(const NetworkStyle* networkStyle);

protected:
    void drawContents(QPainter* painter) override;
    void closeEvent(QCloseEvent *event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

public Q_SLOTS:
    /** Slot to call finish() method as it's not defined as slot */
    void slotFinish(QWidget *mainWin);

    /** Show a startup step; clears the percentage of a previous task */
    void showStatus(const QString& text);

    /** Show a long-running task and how far along it is (0-100) */
    void showProgress(const QString& title, int percent);

private:
    /** Connect core signals to splash screen */
    void subscribeToCoreSignals();
    /** Disconnect core signals to splash screen */
    void unsubscribeFromCoreSignals();
    /** Connect wallet signals to splash screen */
    void ConnectWallet(CWallet*);

    /** Paint everything that doesn't change while the splash is shown */
    QPixmap renderArtwork(const NetworkStyle* networkStyle) const;
    /** Restore startup controls if core canceled shutdown; return whether shutdown is still pending. */
    bool updateShutdownState();
    /** Run the indeterminate progress animation only while it can be seen */
    void updateAnimation();
    /** Start shutdown and say so on the splash */
    void requestShutdown();

    QTimer* animationTimer;
    QToolButton* closeButton;
    QElapsedTimer animationClock;
    /** Kept here instead of QSplashScreen::showMessage(), which repaints synchronously and spins the event loop */
    QString statusText;
    int progress = -1; //!< Percentage of the running task, -1 while unknown
    bool shutdownRequested = false;

    QList<CWallet*> connectedWallets;
};

#endif // BITCOIN_QT_SPLASHSCREEN_H
