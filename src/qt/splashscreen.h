// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SPLASHSCREEN_H
#define BITCOIN_QT_SPLASHSCREEN_H

#include <QElapsedTimer>
#include <QList>
#include <QSplashScreen>
#include <QStringList>

class CWallet;
class NetworkStyle;

QT_BEGIN_NAMESPACE
class QTimer;
class QToolButton;
class QVariantAnimation;
QT_END_NAMESPACE

/** Splash screen with startup status from the running client.
 *
 * Everything that stays the same while it is shown (themed background,
 * oversized mark, lockup, network badge, version) is rendered once into the
 * QSplashScreen pixmap; drawContents() only paints the startup progress: the
 * current step, the percentage or recent steps above it, and the progress bar.
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

    /** Show a startup step; clears the percentage of a previous task.
     * @param[in] animate  Let the step rise into place; pass false when the event loop can't run the transition
     */
    void showStatus(const QString& text, bool animate = true);

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
    /** Make text the current step, moving the previous one onto the trail of recent steps */
    void setStep(const QString& text, bool animate);
    /** Restore startup controls if core canceled shutdown; return whether shutdown is still pending. */
    bool updateShutdownState();
    /** Run the indeterminate progress animation only while it can be seen */
    void updateAnimation();
    /** Start shutdown and say so on the splash */
    void requestShutdown();

    QTimer* animationTimer;
    QVariantAnimation* stepAnimation;
    QToolButton* closeButton;
    QElapsedTimer animationClock;
    /** Kept here instead of QSplashScreen::showMessage(), which repaints synchronously and spins the event loop */
    QString statusText;
    QStringList recentSteps; //!< Steps before the current one, newest first
    int progress = -1; //!< Percentage of the running task, -1 while unknown
    qreal stepReveal = 1; //!< How far the current step has risen into place, from 0 to 1
    bool shutdownRequested = false;

    QList<CWallet*> connectedWallets;
};

#endif // BITCOIN_QT_SPLASHSCREEN_H
