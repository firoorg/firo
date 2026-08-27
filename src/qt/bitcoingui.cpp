// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "bitcoingui.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guitheme.h"
#include "guiutil.h"
#include "modaloverlay.h"
#include "networkstyle.h"
#include "notificator.h"
#include "openuridialog.h"
#include "optionsdialog.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "rpcconsole.h"
#include "utilitydialog.h"

#ifdef ENABLE_WALLET
#include "walletframe.h"
#include "walletmodel.h"
#endif // ENABLE_WALLET

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include "chainparams.h"
#include "init.h"
#include "util.h"
#include "validation.h"

#include "evo/deterministicmns.h"
#include "masternode-sync.h"
#include "masternodelist.h"
#include "spark/state.h"
#include <iostream>

#include <QAbstractButton>
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QDragEnterEvent>
#include <QEasingCurve>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QIcon>
#include <QLabel>
#include <QLinearGradient>
#include <QListWidget>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QMimeData>
#include <QMouseEvent>
#include <QParallelAnimationGroup>
#include <QPainter>
#include <QPixmap>
#include <QProgressDialog>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QScreen>
#include <QSettings>
#include <QShortcut>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>
#include <QVBoxLayout>

#if QT_VERSION < 0x050000
#include <QTextDocument>
#include <QUrl>
#else
#include <QUrlQuery>
#endif

const std::string BitcoinGUI::DEFAULT_UIPLATFORM =
#if defined(Q_OS_MAC)
        "macosx"
#elif defined(Q_OS_WIN)
        "windows"
#else
        "other"
#endif
        ;

/** Display name for default wallet name. Uses tilde to avoid name
 * collisions in the future with additional wallets */
const QString BitcoinGUI::DEFAULT_WALLET = "~Default";

BitcoinGUI::BitcoinGUI(const PlatformStyle *_platformStyle, const NetworkStyle *networkStyle, QWidget *parent) :
    QMainWindow(parent),
    enableWallet(false),
    clientModel(0),
    walletFrame(0),
    unitDisplayControl(0),
    labelWalletEncryptionIcon(0),
    labelWalletHDStatusIcon(0),
    connectionsControl(0),
    torStatusBadge(0),
    labelBlocksIcon(0),
    progressBarLabel(0),
    progressBar(0),
    progressDialog(0),
    appMenuBar(0),
    overviewAction(0),
    historyAction(0),
    quitAction(0),
    sendCoinsAction(0),
    sendCoinsMenuAction(0),
    usedSendingAddressesAction(0),
    usedReceivingAddressesAction(0),
    signMessageAction(0),
    verifyMessageAction(0),
    aboutAction(0),
    receiveCoinsAction(0),
    receiveCoinsMenuAction(0),
    sparkNamesAction(0),
    optionsAction(0),
    toggleHideAction(0),
    encryptWalletAction(0),
    backupWalletAction(0),
    exportViewKeyAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    openRPCConsoleAction(0),
    consoleAction(0),
    openAction(0),
    showHelpMessageAction(0),
    masternodeAction(0),
    logoAction(0),
    trayIcon(0),
    trayIconMenu(0),
    notificator(0),
    rpcConsole(0),
    helpMessageDialog(0),
    modalOverlay(0),
    prevBlocks(0),
    spinnerFrame(0),
#ifdef ENABLE_WALLET
    sparkAddressbookUpdated(false),
#endif
    platformStyle(_platformStyle)
{
    // load stylesheet
    GUIUtil::loadTheme();

    QSettings settings;
    if (!restoreGeometry(settings.value("nWindow").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QGuiApplication::primaryScreen()->availableGeometry().center() - frameGeometry().center());
    }

    QString windowTitle = tr(PACKAGE_NAME) + " - ";
#ifdef ENABLE_WALLET
    enableWallet = WalletModel::isWalletEnabled();
#endif // ENABLE_WALLET
    if(enableWallet)
    {
        windowTitle += tr("Wallet");
    } else {
        windowTitle += tr("Node");
    }
    windowTitle += " " + networkStyle->getTitleAddText();
#ifndef Q_OS_MAC
    QApplication::setWindowIcon(networkStyle->getTrayAndWindowIcon());
    setWindowIcon(networkStyle->getTrayAndWindowIcon());
#else
    MacDockIconHandler::instance()->setIcon(networkStyle->getAppIcon());
#endif
    setWindowTitle(windowTitle);

#if defined(Q_OS_MAC) && QT_VERSION < 0x050000
    // This property is not implemented in Qt 5. Setting it has no effect.
    // A replacement API (QtMacUnifiedToolBar) is available in QtMacExtras.
    setUnifiedTitleAndToolBarOnMac(true);
#endif

    rpcConsole = new RPCConsole(_platformStyle, 0);
    helpMessageDialog = new HelpMessageDialog(this, false);
#ifdef ENABLE_WALLET
    if(enableWallet)
    {
        auto* walletContainer = new QWidget(this);
        walletContainer->setObjectName(QStringLiteral("walletContainer"));
        walletFrame = new WalletFrame(_platformStyle, this);
        walletFrame->setParent(walletContainer);
        setCentralWidget(walletContainer);
    } else
#endif // ENABLE_WALLET
    {
        /* When compiled without wallet or -disablewallet is provided,
         * the central widget is the rpc console.
         */
        setCentralWidget(rpcConsole);
    }

    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    // Needs walletFrame to be initialized
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create system tray icon and notification
    createTrayIcon(networkStyle);

    // Create status bar
    statusBar();

    // Disable size grip because it looks ugly and nobody needs it
    statusBar()->setSizeGripEnabled(false);

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    unitDisplayControl = new UnitDisplayStatusBarControl(platformStyle);
    labelWalletEncryptionIcon = new QLabel();
    labelWalletHDStatusIcon = new QLabel();
    connectionsControl = new GUIUtil::ClickableLabel();
    torStatusBadge = new QLabel(tr("Tor"));
    torStatusBadge->setObjectName(QStringLiteral("torStatusBadge"));
    torStatusBadge->setVisible(GetBoolArg("-torsetup", DEFAULT_TOR_SETUP));
    torStatusBadge->setToolTip(tr("Tor quickstart is enabled for this session. This confirms configuration, not Tor bootstrap or routing health. Manual proxy settings may override affected routes."));
    labelBlocksIcon = new GUIUtil::ClickableLabel();
    if(enableWallet)
    {
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(unitDisplayControl);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelWalletEncryptionIcon);
        frameBlocksLayout->addWidget(labelWalletHDStatusIcon);
    }
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(torStatusBadge);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(connectionsControl);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    // Notification for pending transactions
    QFrame *framePending = new QFrame();
    framePending->setContentsMargins(0,0,0,0);
    framePending->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *framePendingLayout = new QHBoxLayout(framePending);
    framePendingLayout->setContentsMargins(3,0,3,0);
    framePendingLayout->setSpacing(3);
    framePendingLayout->addStretch();

    // Progress bar and label for blocks download
    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new GUIUtil::ProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);

    // Override style sheet for progress bar for styles that have a segmented progress bar,
    // as they make the text unreadable (workaround for issue #1071)
    // See https://qt-project.org/doc/qt-4.8/gallery.html
    QString curStyle = QApplication::style()->metaObject()->className();
    if(curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
    {
        progressBar->setStyleSheet("QProgressBar { background-color: #e8e8e8; border: 1px solid grey; border-radius: 7px; padding: 1px; text-align: center; } QProgressBar::chunk { background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF8000, stop: 1 orange); border-radius: 7px; margin: 0px; }");
    }

    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);
    statusBar()->addWidget(framePending);

    // Install event filter to be able to catch status tip events (QEvent::StatusTip)
    this->installEventFilter(this);
#ifdef ENABLE_WALLET
    // Initially wallet actions should be disabled
    setWalletActionsEnabled(false);
#endif // ENABLE_WALLET

    // Subscribe to notifications from core
    subscribeToCoreSignals();

    connect(connectionsControl, &GUIUtil::ClickableLabel::clicked, this, &BitcoinGUI::toggleNetworkActive);

    modalOverlay = new ModalOverlay(this->centralWidget());
#ifdef ENABLE_WALLET
    if(enableWallet) {
        connect(walletFrame, &WalletFrame::requestedSyncWarningInfo, this, &BitcoinGUI::showModalOverlay);
        connect(labelBlocksIcon, &GUIUtil::ClickableLabel::clicked, this, &BitcoinGUI::showModalOverlay);
        connect(progressBar, &GUIUtil::ClickableProgressBar::clicked, this, &BitcoinGUI::showModalOverlay);
    }
#endif
}

BitcoinGUI::~BitcoinGUI()
{
    // Unsubscribe from notifications from core
    unsubscribeFromCoreSignals();

    QSettings settings;
    settings.setValue("nWindow", saveGeometry());
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
    MacDockIconHandler::cleanup();
#endif

    delete rpcConsole;
}

void BitcoinGUI::createActions()
{
    size_t key = Qt::Key_1;
	QActionGroup *tabGroup = new QActionGroup(this);

	overviewAction = new QAction(tr("&Overview"), this);
	overviewAction->setStatusTip(tr("Show general overview of wallet"));
	overviewAction->setToolTip(overviewAction->statusTip());
	overviewAction->setCheckable(true);
	overviewAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
	tabGroup->addAction(overviewAction);

	sendCoinsAction = new QAction(tr("&Send"), this);
	sendCoinsAction->setStatusTip(tr("Send coins to a Firo address"));
	sendCoinsAction->setToolTip(sendCoinsAction->statusTip());
	sendCoinsAction->setCheckable(true);
	sendCoinsAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
	tabGroup->addAction(sendCoinsAction);

	sendCoinsMenuAction = new QAction(sendCoinsAction->text(), this);
	sendCoinsMenuAction->setStatusTip(sendCoinsAction->statusTip());
	sendCoinsMenuAction->setToolTip(sendCoinsMenuAction->statusTip());

	receiveCoinsAction = new QAction(tr("&Receive"), this);
	receiveCoinsAction->setStatusTip(tr("Request payments (generates QR codes and firo: URIs)"));
	receiveCoinsAction->setToolTip(receiveCoinsAction->statusTip());
	receiveCoinsAction->setCheckable(true);
	receiveCoinsAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
	tabGroup->addAction(receiveCoinsAction);

	receiveCoinsMenuAction = new QAction(receiveCoinsAction->text(), this);
	receiveCoinsMenuAction->setStatusTip(receiveCoinsAction->statusTip());
	receiveCoinsMenuAction->setToolTip(receiveCoinsMenuAction->statusTip());

	historyAction = new QAction(tr("&Transactions"), this);
	historyAction->setStatusTip(tr("Browse transaction history"));
	historyAction->setToolTip(historyAction->statusTip());
	historyAction->setCheckable(true);
	historyAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
	tabGroup->addAction(historyAction);

	sparkNamesAction = new QAction(tr("&Spark Names"), this);
	sparkNamesAction->setStatusTip(tr("Manage your registered Spark Names"));
	sparkNamesAction->setToolTip(sparkNamesAction->statusTip());
	sparkNamesAction->setCheckable(true);
	sparkNamesAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
	tabGroup->addAction(sparkNamesAction);

#ifdef ENABLE_WALLET
    // These showNormalIfMinimized are needed because Send Coins and Receive Coins
    // can be triggered from the tray menu, and need to show the GUI to be useful.
    masternodeAction = new QAction(tr("&Masternodes"), this);
    masternodeAction->setStatusTip(tr("Browse masternodes"));
    masternodeAction->setToolTip(masternodeAction->statusTip());
    masternodeAction->setCheckable(true);
#ifdef Q_OS_MAC
    masternodeAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
#else
    masternodeAction->setShortcut(QKeySequence(QString("Alt+%1").arg(key++)));
#endif
    tabGroup->addAction(masternodeAction);
#endif

#ifdef ENABLE_WALLET
    connect(masternodeAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
    connect(masternodeAction, &QAction::triggered, this, &BitcoinGUI::gotoMasternodePage);
	connect(overviewAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
    connect(overviewAction, &QAction::triggered, this, &BitcoinGUI::gotoOverviewPage);
	connect(sendCoinsAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
	connect(sendCoinsAction, &QAction::triggered, [this]{ gotoSendCoinsPage(); });
	connect(sendCoinsMenuAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
	connect(sendCoinsMenuAction, &QAction::triggered, [this]{ gotoSendCoinsPage(); });
	connect(receiveCoinsAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
	connect(receiveCoinsAction, &QAction::triggered, this, &BitcoinGUI::gotoReceiveCoinsPage);
	connect(receiveCoinsMenuAction, &QAction::triggered, [this]{ showNormalIfMinimized(); });
	connect(receiveCoinsMenuAction, &QAction::triggered, this, &BitcoinGUI::gotoReceiveCoinsPage);
	connect(historyAction, &QAction::triggered, this, [this]{ showNormalIfMinimized(); });
	connect(historyAction, &QAction::triggered, this, &BitcoinGUI::gotoHistoryPage);
	connect(sparkNamesAction, &QAction::triggered, this, [this]{ showNormalIfMinimized(); });
	connect(sparkNamesAction, &QAction::triggered, this, &BitcoinGUI::gotoSparkNamesPage);

#endif // ENABLE_WALLET

    quitAction = new QAction(tr("E&xit"), this);
    quitAction->setStatusTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(tr("&About %1").arg(tr(PACKAGE_NAME)), this);
    aboutAction->setStatusTip(tr("Show information about %1").arg(tr(PACKAGE_NAME)));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutAction->setEnabled(false);
    aboutQtAction = new QAction(tr("About &Qt"), this);
    aboutQtAction->setStatusTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    optionsAction = new QAction(tr("&Options..."), this);
    optionsAction->setStatusTip(tr("Modify configuration options for %1").arg(tr(PACKAGE_NAME)));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    optionsAction->setEnabled(false);
    toggleHideAction = new QAction(tr("&Show / Hide"), this);
    toggleHideAction->setStatusTip(tr("Show or hide the main Window"));
#ifdef ENABLE_WALLET
    encryptWalletAction = new QAction(tr("&Encrypt Wallet..."), this);
    encryptWalletAction->setStatusTip(tr("Encrypt the private keys that belong to your wallet"));
    encryptWalletAction->setCheckable(true);
#endif // ENABLE_WALLET
    backupWalletAction = new QAction(tr("&Backup Wallet..."), this);
    backupWalletAction->setStatusTip(tr("Backup wallet to another location"));
    exportViewKeyAction = new QAction(tr("&Export View Key..."), this);
    exportViewKeyAction->setStatusTip(tr("Export Spark view key"));
    changePassphraseAction = new QAction(tr("&Change Passphrase..."), this);
    changePassphraseAction->setStatusTip(tr("Change the passphrase used for wallet encryption"));
    signMessageAction = new QAction(tr("Sign &message..."), this);
    signMessageAction->setStatusTip(tr("Sign messages with your Firo addresses to prove you own them"));
    verifyMessageAction = new QAction(tr("&Verify message..."), this);
    verifyMessageAction->setStatusTip(tr("Verify messages to ensure they were signed with specified Firo addresses"));

    openRPCConsoleAction = new QAction(tr("&Debug window"), this);
    openRPCConsoleAction->setStatusTip(tr("Open debugging and diagnostic console"));
    // initially disable the debug window menu item
    openRPCConsoleAction->setEnabled(false);

    consoleAction = new QAction(tr("&Console"), this);
    consoleAction->setStatusTip(tr("Open the console in the debug window"));
    consoleAction->setEnabled(false);

    usedSendingAddressesAction = new QAction(tr("&Sending addresses..."), this);
    usedSendingAddressesAction->setStatusTip(tr("Show the list of used sending addresses and labels"));
    usedReceivingAddressesAction = new QAction( tr("&Receiving addresses..."), this);
    usedReceivingAddressesAction->setStatusTip(tr("Show the list of used receiving addresses and labels"));

    openAction = new QAction(tr("Open &URI..."), this);
    openAction->setStatusTip(tr("Open a firo: URI"));

    showHelpMessageAction = new QAction(tr("&Command-line options"), this);
    showHelpMessageAction->setMenuRole(QAction::NoRole);
    showHelpMessageAction->setStatusTip(tr("Show the %1 help message to get a list with possible Firo command-line options").arg(tr(PACKAGE_NAME)));

    connect(quitAction, &QAction::triggered, qApp, QApplication::quit);
    connect(aboutAction, &QAction::triggered, this, &BitcoinGUI::aboutClicked);
    connect(aboutQtAction, &QAction::triggered, qApp, QApplication::aboutQt);
    connect(optionsAction, &QAction::triggered, this, &BitcoinGUI::optionsClicked);
    connect(toggleHideAction, &QAction::triggered, this, &BitcoinGUI::toggleHidden);
    connect(showHelpMessageAction, &QAction::triggered, this, &BitcoinGUI::showHelpMessageClicked);
    connect(openRPCConsoleAction, &QAction::triggered, this, &BitcoinGUI::showDebugWindow);
    connect(consoleAction, &QAction::triggered,
            this, &BitcoinGUI::showDebugWindowActivateConsole);
    // prevents an open debug window from becoming stuck/unusable on client shutdown
    connect(quitAction, &QAction::triggered, rpcConsole, &QWidget::hide);

#ifdef ENABLE_WALLET
    if(walletFrame)
    {
        connect(encryptWalletAction, &QAction::triggered, walletFrame, &WalletFrame::encryptWallet);
        connect(backupWalletAction, &QAction::triggered, walletFrame, &WalletFrame::backupWallet);
        connect(exportViewKeyAction, &QAction::triggered, walletFrame, &WalletFrame::exportViewKey);
        connect(changePassphraseAction, &QAction::triggered, walletFrame, &WalletFrame::changePassphrase);
        connect(signMessageAction, &QAction::triggered, [this]{ gotoSignMessageTab(); });
        connect(verifyMessageAction, &QAction::triggered, [this]{ gotoVerifyMessageTab(); });
        connect(usedSendingAddressesAction, &QAction::triggered, walletFrame, &WalletFrame::usedSendingAddresses);
        connect(usedReceivingAddressesAction, &QAction::triggered, walletFrame, &WalletFrame::usedReceivingAddresses);
        connect(openAction, &QAction::triggered, this, &BitcoinGUI::openClicked);
    }
#endif // ENABLE_WALLET

    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C), this), &QShortcut::activated, this, &BitcoinGUI::showDebugWindowActivateConsole);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_D), this), &QShortcut::activated, this, &BitcoinGUI::showDebugWindow);
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
    appMenuBar->setStyleSheet(GUIUtil::themed(QStringLiteral("QMenuBar::item { color: $INK; }")));
#endif

    // Configure the menus
    QMenu *file = appMenuBar->addMenu(tr("&File"));
    if(walletFrame)
    {
        file->addAction(openAction);
        file->addAction(backupWalletAction);
        file->addAction(signMessageAction);
        file->addAction(verifyMessageAction);
        file->addAction(exportViewKeyAction);
        file->addSeparator();
        file->addAction(usedSendingAddressesAction);
        file->addAction(usedReceivingAddressesAction);
        file->addSeparator();
    }
    file->addAction(quitAction);

    QMenu *settings = appMenuBar->addMenu(tr("&Settings"));
    if(walletFrame)
    {
        settings->addAction(encryptWalletAction);
        settings->addAction(changePassphraseAction);
        settings->addSeparator();
    }
    settings->addAction(optionsAction);

    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    if(walletFrame)
    {
        help->addAction(openRPCConsoleAction);
    }
    help->addAction(showHelpMessageAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
}

static QPixmap ColorizeNavigationIcon(const QPixmap& centeredSource, const QColor& color)
{
    QPixmap result(centeredSource.size());
    result.fill(Qt::transparent);

    QPainter painter(&result);
    painter.drawPixmap(0, 0, centeredSource);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(result.rect(), color);
    return result;
}

static QIcon NavigationIcon(const QString& resource)
{
    constexpr int iconSize = 22;
    const QPixmap source(resource);
    if (source.isNull())
        return QIcon();

    const QPixmap scaled =
        source.scaled(iconSize, iconSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    QPixmap centered(iconSize, iconSize);
    centered.fill(Qt::transparent);
    QPainter centerPainter(&centered);
    centerPainter.drawPixmap((iconSize - scaled.width()) / 2, (iconSize - scaled.height()) / 2, scaled);
    centerPainter.end();

    const GUIUtil::ThemeColors& c = GUIUtil::themeColors();
    QIcon icon;
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(c.inkSoft)),
                   QIcon::Normal, QIcon::Off);
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(QStringLiteral("#FFFFFF"))),
                   QIcon::Normal, QIcon::On);
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(c.ink)),
                   QIcon::Active, QIcon::Off);
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(QStringLiteral("#FFFFFF"))),
                   QIcon::Active, QIcon::On);
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(QStringLiteral("#FFFFFF"))),
                   QIcon::Selected, QIcon::On);
    icon.addPixmap(ColorizeNavigationIcon(centered, QColor(c.inkFaint)),
                   QIcon::Disabled, QIcon::Off);
    return icon;
}

namespace {
class ThemeToggleSwitch : public QAbstractButton
{
    Q_OBJECT
    Q_PROPERTY(qreal thumbPos READ thumbPos WRITE setThumbPos)

public:
    explicit ThemeToggleSwitch(QWidget* parent = nullptr) : QAbstractButton(parent)
    {
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setFixedSize(40, 22);
        setToolTip(QCoreApplication::translate("BitcoinGUI", "Toggle light / dark theme"));

        animation_ = new QPropertyAnimation(this, "thumbPos", this);
        animation_->setDuration(180);
        animation_->setEasingCurve(QEasingCurve::InOutCubic);

        connect(this, &QAbstractButton::toggled, this, [this](bool checked) {
            animation_->stop();
            animation_->setStartValue(thumbPos_);
            animation_->setEndValue(checked ? 1.0 : 0.0);
            animation_->start();
            QTimer::singleShot(0, this, [checked]() {
                GUIUtil::setThemeMode(checked ? GUIUtil::ThemeMode::Dark : GUIUtil::ThemeMode::Light);
            });
        });
    }

    qreal thumbPos() const { return thumbPos_; }
    void setThumbPos(qreal pos)
    {
        thumbPos_ = pos;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const GUIUtil::ThemeColors& c = GUIUtil::themeColors();
        const QRectF track = rect().adjusted(0, 0, -1, -1);
        p.setPen(Qt::NoPen);

        QColor trackColor;
        if (thumbPos_ <= 0.0) {
            trackColor = QColor(c.border);
        } else if (thumbPos_ >= 1.0) {
            trackColor = QColor(c.wineDeep);
        } else {
            QColor off(c.border);
            QColor on(c.wineDeep);
            trackColor = QColor(
                off.red()   + (on.red()   - off.red())   * thumbPos_,
                off.green() + (on.green() - off.green()) * thumbPos_,
                off.blue()  + (on.blue()  - off.blue())  * thumbPos_);
        }
        p.setBrush(trackColor);
        p.drawRoundedRect(track, track.height() / 2, track.height() / 2);

        const qreal d = track.height() - 6;
        const qreal xOff = track.left() + 3;
        const qreal xOn = track.right() - d - 3;
        const qreal x = xOff + (xOn - xOff) * thumbPos_;
        p.setBrush(QColor("#FFFFFF"));
        p.drawEllipse(QRectF(x, track.top() + 3, d, d));
    }

private:
    qreal thumbPos_ = 0.0;
    QPropertyAnimation* animation_ = nullptr;
};

class NavigationSelectionHighlight : public QWidget
{
    Q_OBJECT

public:
    explicit NavigationSelectionHighlight(QWidget* parent = nullptr) : QWidget(parent)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const GUIUtil::ThemeColors& c = GUIUtil::themeColors();
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(Qt::NoPen);
        QLinearGradient grad(rect().topLeft(), rect().topRight());
        grad.setColorAt(0, QColor(c.wine));
        grad.setColorAt(1, QColor(c.wineDeep));
        p.setBrush(grad);
        p.drawRoundedRect(rect(), 12, 12);
    }
};
}

#include "bitcoingui.moc"

static constexpr int MAX_SYNCED_TIP_AGE_SECS = 45 * 60;

static constexpr int NAVIGATION_SIDEBAR_WIDTH = 220;
static constexpr int NAVIGATION_ACTION_WIDTH = 190;
static constexpr int NAVIGATION_TOGGLE_WIDTH = 30;

void BitcoinGUI::createToolBars()
{
    if(walletFrame)
    {
        toolbar = new QToolBar(tr("Wallet navigation"), centralWidget());
        toolbar->setObjectName(QStringLiteral("navigationSidebar"));
        toolbar->setContextMenuPolicy(Qt::PreventContextMenu);
        toolbar->setOrientation(Qt::Vertical);
        toolbar->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
        toolbar->setMovable(false);
        toolbar->setFloatable(false);
        toolbar->setIconSize(QSize(22, 22));
        toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

        logoLabel = new QLabel(toolbar);
        logoLabel->setObjectName(QStringLiteral("navigationLogo"));
        logoLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        logoLabel->setFixedHeight(88);
        toolbar->addWidget(logoLabel);

        overviewAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_overview")));
        sendCoinsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_send")));
        receiveCoinsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_receive")));
        historyAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_transactions")));
        sparkNamesAction->setIcon(NavigationIcon(QStringLiteral(":/icons/spark")));
        masternodeAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_masternodes")));
        consoleAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_console")));
        optionsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_options")));
        consoleAction->setIconText(tr("Console"));
        optionsAction->setIconText(tr("Options"));

        toolbar->addAction(overviewAction);
        toolbar->addAction(sendCoinsAction);
        toolbar->addAction(receiveCoinsAction);
        toolbar->addAction(historyAction);
        toolbar->addAction(sparkNamesAction);
        toolbar->addAction(masternodeAction);

        auto* navigationSpacer = new QWidget(toolbar);
        navigationSpacer->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
        toolbar->addWidget(navigationSpacer);

        navigationThemeRow = new QFrame(toolbar);
        navigationThemeRow->setObjectName(QStringLiteral("navigationThemeRow"));
        navigationThemeRow->setFixedWidth(NAVIGATION_ACTION_WIDTH);
        auto* themeRowLayout = new QHBoxLayout(navigationThemeRow);
        themeRowLayout->setContentsMargins(12, 8, 12, 8);
        themeRowLayout->setSpacing(6);
        navigationThemeLightLabel = new QLabel(tr("Light"), navigationThemeRow);
        navigationThemeSwitch = new ThemeToggleSwitch(navigationThemeRow);
        navigationThemeDarkLabel = new QLabel(tr("Dark"), navigationThemeRow);
        themeRowLayout->addWidget(navigationThemeLightLabel);
        themeRowLayout->addWidget(navigationThemeSwitch);
        themeRowLayout->addStretch();
        themeRowLayout->addWidget(navigationThemeDarkLabel);
        navigationThemeSwitch->setChecked(GUIUtil::isDarkMode());
        toolbar->addWidget(navigationThemeRow);

        navigationSyncCard = new QFrame(toolbar);
        navigationSyncCard->setObjectName(QStringLiteral("navigationSyncCard"));
        navigationSyncCard->setFixedWidth(NAVIGATION_ACTION_WIDTH);
        navigationSyncCard->setMinimumHeight(76);
        navigationSyncCard->setCursor(Qt::PointingHandCursor);
        navigationSyncCard->setToolTip(tr("Show synchronization details"));
        navigationSyncCard->installEventFilter(this);
        auto* syncLayout = new QVBoxLayout(navigationSyncCard);
        syncLayout->setContentsMargins(10, 11, 14, 11);
        syncLayout->setSpacing(8);
        auto* syncHeader = new QHBoxLayout();
        syncHeader->setContentsMargins(0, 0, 0, 0);
        syncHeader->setSpacing(6);
        navigationSyncLabel = new QLabel(tr("Syncing..."), navigationSyncCard);
        navigationSyncPercent = new QLabel(QStringLiteral("0%"), navigationSyncCard);
        navigationSyncLabel->setObjectName(QStringLiteral("navigationSyncLabel"));
        navigationSyncLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
        navigationSyncPercent->setAttribute(Qt::WA_TransparentForMouseEvents);
        navigationSyncPercent->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        navigationSyncPercent->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
        syncHeader->addWidget(navigationSyncLabel, 1);
        syncHeader->addWidget(navigationSyncPercent, 0);
        syncLayout->addLayout(syncHeader);
        navigationSyncProgress = new QProgressBar(navigationSyncCard);
        navigationSyncProgress->setRange(0, 100);
        navigationSyncProgress->setValue(0);
        navigationSyncProgress->setTextVisible(false);
        navigationSyncProgress->setAttribute(Qt::WA_TransparentForMouseEvents);
        syncLayout->addWidget(navigationSyncProgress);
        navigationSyncCardAction = toolbar->addWidget(navigationSyncCard);
        navigationSyncCardAction->setVisible(false);

        toolbar->addAction(consoleAction);
        toolbar->addAction(optionsAction);

        navigationSelectionHighlight = new NavigationSelectionHighlight(toolbar);
        navigationSelectionHighlight->lower();
        auto* highlightShadow = new QGraphicsDropShadowEffect(navigationSelectionHighlight);
        highlightShadow->setBlurRadius(20);
        highlightShadow->setOffset(0, 6);
        highlightShadow->setColor(QColor(130, 24, 51, 65));
        navigationSelectionHighlight->setGraphicsEffect(highlightShadow);

        overviewAction->setChecked(true);

        const QList<QAction*> navigationActions = {
            overviewAction,
            sendCoinsAction,
            receiveCoinsAction,
            historyAction,
            sparkNamesAction,
            masternodeAction
        };
        for (QAction* action : navigationActions) {
            connect(action, &QAction::toggled, this,
                    [this](bool) { updateNavigationSelectionHighlight(); });
        }
        updateNavigationSelectionHighlight();

        updateToolbarTabWidths();

        navigationToggleButton = new QToolButton(centralWidget());
        navigationToggleButton->setObjectName(QStringLiteral("navigationDrawerToggle"));
        navigationToggleButton->setArrowType(Qt::LeftArrow);
        navigationToggleButton->setCursor(Qt::PointingHandCursor);
        navigationToggleButton->setFixedSize(NAVIGATION_TOGGLE_WIDTH, 46);
        navigationToggleButton->setToolTip(tr("Hide navigation"));
        connect(navigationToggleButton, &QToolButton::clicked,
                this, &BitcoinGUI::toggleNavigationSidebar);

        connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
                this, &BitcoinGUI::applyNavigationTheme);
        applyNavigationTheme();

        updateNavigationSidebarGeometry();
        toolbar->show();
        toolbar->raise();
        navigationToggleButton->show();
        navigationToggleButton->raise();
    }
}

void BitcoinGUI::applyNavigationTheme()
{
    if (!toolbar)
        return;

    if (navigationThemeSwitch) {
        QSignalBlocker blocker(navigationThemeSwitch);
        navigationThemeSwitch->setChecked(GUIUtil::isDarkMode());
        navigationThemeSwitch->update();
    }

    if (logoLabel) {
        const QString logoResource = GUIUtil::isDarkMode()
            ? QStringLiteral(":/images/firo_logo_toolbar_dark")
            : QStringLiteral(":/images/firo_logo_toolbar");
        logoLabel->setPixmap(QPixmap(logoResource).scaledToWidth(145, Qt::SmoothTransformation));
    }

    overviewAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_overview")));
    sendCoinsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_send")));
    receiveCoinsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_receive")));
    historyAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_transactions")));
    sparkNamesAction->setIcon(NavigationIcon(QStringLiteral(":/icons/spark")));
    masternodeAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_masternodes")));
    consoleAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_console")));
    optionsAction->setIcon(NavigationIcon(QStringLiteral(":/icons/sidebar_options")));

    if (labelWalletHDStatusIcon)
        setHDStatus(labelWalletHDStatusIcon->isEnabled());
    if (cachedEncryptionStatus >= 0)
        setEncryptionStatus(cachedEncryptionStatus);
    if (clientModel && connectionsControl)
        updateNetworkState();
    if (labelBlocksIcon && masternodeSync.IsSynced())
        labelBlocksIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(":/icons/synced"), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
    if (torStatusBadge) {
        torStatusBadge->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel#torStatusBadge {"
            " color: $INK; background: $WINE_TINT; border: none;"
            " border-radius: 8px; padding: 2px 7px; font-size: 12px; font-weight: 700;"
            "}")));
    }

    if (navigationThemeRow) {
        navigationThemeRow->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QFrame#navigationThemeRow {"
            " background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 14px;"
            "}"
            "QFrame#navigationThemeRow QLabel {"
            " background: transparent; border: none; color: $INK_SOFT;"
            " font-size: 12px; font-weight: 700;"
            "}")));
    }

    if (navigationSyncCard) {
        navigationSyncCard->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QFrame#navigationSyncCard {
                background: $PANEL_SOFT;
                border: 1px solid $BORDER;
                border-radius: 14px;
            }
            QLabel {
                background: transparent;
                border: none;
                color: $INK_SOFT;
                font-size: 12px;
                font-weight: 700;
            }
            QLabel#navigationSyncLabel {
                font-size: 12px;
            }
            QProgressBar {
                background: $BORDER;
                border: 1px solid transparent;
                border-radius: 5px;
                min-height: 10px;
                max-height: 10px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 $GOLD,
                                            stop:1 $GOLD);
                border: 1px solid transparent;
                border-radius: 5px;
            }
            QProgressBar[synced="true"]::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 $TEAL,
                                            stop:1 $TEAL);
                border: 1px solid transparent;
                border-radius: 5px;
            }
        )")));
    }

    toolbar->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QToolBar#navigationSidebar {
            background: $PANEL;
            border: none;
            border-right: 1px solid $BORDER;
            spacing: 6px;
            padding: 14px 12px;
            min-height: 0;
            font: 11pt 'Source Sans Pro';
        }

        QToolBar#navigationSidebar QLabel#navigationLogo {
            background: transparent;
            border: none;
            padding-left: 10px;
        }

        QToolBar#navigationSidebar QToolButton {
            background: transparent;
            color: $INK_SOFT;
            border: none;
            border-radius: 12px;
            min-height: 32px;
            max-height: 32px;
            min-width: %1px;
            max-width: %1px;
            font-size: 11pt;
            font-weight: 700;
            padding: 3px 14px;
            margin: 0;
            text-align: left;
        }

        QToolBar#navigationSidebar QToolButton:hover {
            background: $PANEL_SOFT;
            color: $INK;
        }

        QToolBar#navigationSidebar QToolButton:checked {
            background: transparent;
            color: #FFFFFF;
            border: none;
            border-radius: 12px;
            min-height: 32px;
            max-height: 32px;
            min-width: %1px;
            max-width: %1px;
            padding: 3px 14px;
            font-weight: 700;
        }

        QToolBar#navigationSidebar QToolButton:checked:hover {
            background: transparent;
            color: #FFFFFF;
            border: none;
            border-radius: 12px;
            min-height: 32px;
            max-height: 32px;
            min-width: %1px;
            max-width: %1px;
            padding: 3px 14px;
        }

        QToolBar#navigationSidebar QToolButton:disabled {
            color: $INK_FAINT;
            background: transparent;
        }

        QToolBar#navigationSidebar[compact="true"] {
            spacing: 2px;
            padding: 6px 12px;
        }

        QToolBar#navigationSidebar[compact="true"] QToolButton,
        QToolBar#navigationSidebar[compact="true"] QToolButton:checked,
        QToolBar#navigationSidebar[compact="true"] QToolButton:checked:hover {
            min-height: 26px;
            max-height: 26px;
            padding: 1px 14px;
        }

        QToolBar#navigationSidebar[ultraCompact="true"] {
            spacing: 0;
            padding: 4px 12px;
        }
        )")).arg(NAVIGATION_ACTION_WIDTH));

    toolbar->style()->unpolish(toolbar);
    toolbar->style()->polish(toolbar);
    if (QLayout* toolbarLayout = toolbar->layout()) {
        toolbarLayout->invalidate();
        toolbarLayout->activate();
    }
    QTimer::singleShot(0, this, [this] {
        if (!toolbar)
            return;
        if (QLayout* toolbarLayout = toolbar->layout()) {
            toolbarLayout->invalidate();
            toolbarLayout->activate();
        }
    });

    if (navigationToggleButton) {
        navigationToggleButton->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QToolButton#navigationDrawerToggle {
                background: $PANEL;
                border: 1px solid $BORDER;
                border-radius: 14px;
                color: $INK_SOFT;
            }
            QToolButton#navigationDrawerToggle:hover {
                background: $PANEL_SOFT;
                border-color: $INK_FAINT;
            }
            QToolButton#navigationDrawerToggle:pressed {
                background: $BORDER;
            }
        )")));
    }

    updateNavigationSelectionHighlight();
    QTimer::singleShot(0, this, [this] { updateNavigationSelectionHighlight(); });
}

void BitcoinGUI::updateNavigationSelectionHighlight()
{
    if (!toolbar || !navigationSelectionHighlight)
        return;

    const QList<QAction*> navigationActions = {
        overviewAction,
        sendCoinsAction,
        receiveCoinsAction,
        historyAction,
        sparkNamesAction,
        masternodeAction
    };

    QWidget* checkedWidget = nullptr;
    for (QAction* action : navigationActions) {
        if (action->isChecked()) {
            checkedWidget = toolbar->widgetForAction(action);
            break;
        }
    }

    if (!checkedWidget) {
        navigationSelectionHighlight->hide();
        return;
    }

    QRect geometry = checkedWidget->geometry();
    if (geometry.width() > NAVIGATION_ACTION_WIDTH)
        geometry.setWidth(NAVIGATION_ACTION_WIDTH);
    navigationSelectionHighlight->setGeometry(geometry);
    navigationSelectionHighlight->lower();
    navigationSelectionHighlight->show();
    navigationSelectionHighlight->update();
}

bool BitcoinGUI::syncInProgress() const
{
    if (!clientModel)
        return false;

    if (!masternodeSync.IsSynced())
        return true;

    if (clientModel->inInitialBlockDownload())
        return true;

    if (clientModel->getLastBlockDate().secsTo(QDateTime::currentDateTime()) >= MAX_SYNCED_TIP_AGE_SECS)
        return true;

    return false;
}

void BitcoinGUI::updateNavigationSyncCard(
    const QString& status, double progress)
{
    if (!navigationSyncCard || !navigationSyncLabel ||
        !navigationSyncPercent || !navigationSyncProgress)
        return;

    QString fullStatus = status;
    const bool networkActive = clientModel && clientModel->getNetworkActive();
    const bool hasPeers = clientModel && clientModel->getNumConnections() > 0;
    const bool fullySynced = networkActive && hasPeers && !syncInProgress();
    if (clientModel && !networkActive) {
        fullStatus = tr("Network activity disabled");
    } else if (clientModel && !hasPeers) {
        fullStatus = tr("Connecting to peers...");
    } else if (fullySynced) {
        fullStatus = tr("Synced");
        progress = 1.0;
    }

    if (navigationSyncProgress->property("synced").toBool() != fullySynced) {
        navigationSyncProgress->setProperty("synced", fullySynced);
        navigationSyncProgress->style()->unpolish(navigationSyncProgress);
        navigationSyncProgress->style()->polish(navigationSyncProgress);
    }
    if (modalOverlay)
        modalOverlay->setSyncComplete(fullySynced);

    const double clampedProgress = qBound(0.0, progress, 1.0);
    if (fullStatus.isEmpty())
        fullStatus = tr("Syncing...");
    const QString percentText = QString::number(clampedProgress * 100.0, 'f', 2) + "%";
    navigationSyncPercent->setText(percentText);

    const int percentWidth = QFontMetrics(navigationSyncPercent->font()).horizontalAdvance(percentText);
    const int availableWidth = navigationSyncCard->width() - 10 - 14 - 6 - percentWidth;
    const QFontMetrics labelMetrics(navigationSyncLabel->font());
    navigationSyncLabel->setText(labelMetrics.elidedText(fullStatus, Qt::ElideRight, availableWidth));
    navigationSyncLabel->setToolTip(fullStatus);

    navigationSyncProgress->setValue(qRound(clampedProgress * 100.0));
    if (navigationSyncCardAction)
        navigationSyncCardAction->setVisible(clientModel != nullptr);
    navigationSyncCard->setVisible(clientModel != nullptr);
}

void BitcoinGUI::updateToolbarTabWidths()
{
    if (!toolbar)
        return;

    toolbar->setMinimumWidth(NAVIGATION_SIDEBAR_WIDTH);
    toolbar->setMaximumWidth(NAVIGATION_SIDEBAR_WIDTH);

    QWidget* overviewWidget = overviewAction ? toolbar->widgetForAction(overviewAction) : nullptr;
    QWidget* receiveWidget = receiveCoinsAction ? toolbar->widgetForAction(receiveCoinsAction) : nullptr;
    QWidget* historyWidget = historyAction ? toolbar->widgetForAction(historyAction) : nullptr;
    QWidget* sparkNamesWidget = sparkNamesAction ? toolbar->widgetForAction(sparkNamesAction) : nullptr;
    QWidget* sendCoinsWidget = sendCoinsAction ? toolbar->widgetForAction(sendCoinsAction) : nullptr;
    QWidget* masternodeWidget = masternodeAction ? toolbar->widgetForAction(masternodeAction) : nullptr;
    QWidget* consoleWidget = consoleAction ? toolbar->widgetForAction(consoleAction) : nullptr;
    QWidget* optionsWidget = optionsAction ? toolbar->widgetForAction(optionsAction) : nullptr;

    const auto setActionWidth = [](QWidget* widget) {
        if (!widget)
            return;
        widget->setMinimumWidth(NAVIGATION_ACTION_WIDTH);
        widget->setMaximumWidth(NAVIGATION_ACTION_WIDTH);
    };
    setActionWidth(overviewWidget);
    setActionWidth(receiveWidget);
    setActionWidth(historyWidget);
    setActionWidth(sparkNamesWidget);
    setActionWidth(sendCoinsWidget);
    setActionWidth(masternodeWidget);
    setActionWidth(consoleWidget);
    setActionWidth(optionsWidget);
}

void BitcoinGUI::updateNavigationSidebarGeometry()
{
    if (!toolbar || !navigationToggleButton || !centralWidget() || !walletFrame)
        return;

    const bool compact = centralWidget()->height() < 600;
    const bool ultraCompact = centralWidget()->height() < 450;
    bool densityChanged = false;
    if (toolbar->property("compact").toBool() != compact) {
        toolbar->setProperty("compact", compact);
        densityChanged = true;
    }
    if (toolbar->property("ultraCompact").toBool() != ultraCompact) {
        toolbar->setProperty("ultraCompact", ultraCompact);
        densityChanged = true;
    }
    if (densityChanged) {
        toolbar->style()->unpolish(toolbar);
        toolbar->style()->polish(toolbar);
    }
    if (logoLabel) {
        logoLabel->setVisible(!ultraCompact);
        logoLabel->setFixedHeight(compact ? 54 : 88);
    }
    if (navigationThemeRow) {
        navigationThemeRow->setMinimumHeight(compact ? 34 : 0);
        navigationThemeRow->setMaximumHeight(compact ? 34 : QWIDGETSIZE_MAX);
        if (QLayout* layout = navigationThemeRow->layout())
            layout->setContentsMargins(12, compact ? 4 : 8, 12, compact ? 4 : 8);
    }
    if (navigationSyncCard) {
        navigationSyncCard->setMinimumHeight(compact ? 58 : 76);
        navigationSyncCard->setMaximumHeight(compact ? 58 : QWIDGETSIZE_MAX);
        if (QLayout* layout = navigationSyncCard->layout()) {
            layout->setContentsMargins(10, compact ? 6 : 11, 14, compact ? 6 : 11);
            layout->setSpacing(compact ? 4 : 8);
        }
    }

    const int drawerX = navigationSidebarExpanded ? 0 : -NAVIGATION_SIDEBAR_WIDTH;
    toolbar->setGeometry(
        drawerX, 0, NAVIGATION_SIDEBAR_WIDTH, centralWidget()->height());

    const int contentX = navigationSidebarExpanded ? NAVIGATION_SIDEBAR_WIDTH : 0;
    walletFrame->setGeometry(
        contentX,
        0,
        qMax(0, centralWidget()->width() - contentX),
        centralWidget()->height());

    const int toggleX = navigationSidebarExpanded
        ? NAVIGATION_SIDEBAR_WIDTH - NAVIGATION_TOGGLE_WIDTH / 2
        : 8;
    navigationToggleButton->move(toggleX, 20);
    if (QLayout* layout = toolbar->layout()) {
        layout->invalidate();
        layout->activate();
    }
    updateNavigationSelectionHighlight();
    toolbar->raise();
    navigationToggleButton->raise();
}

void BitcoinGUI::toggleNavigationSidebar()
{
    if (!toolbar || !navigationToggleButton || !centralWidget() || !walletFrame)
        return;

    navigationSidebarExpanded = !navigationSidebarExpanded;
    navigationToggleButton->setArrowType(
        navigationSidebarExpanded ? Qt::LeftArrow : Qt::RightArrow);
    navigationToggleButton->setToolTip(
        navigationSidebarExpanded ? tr("Hide navigation") : tr("Show navigation"));

    const QRect drawerEnd(
        navigationSidebarExpanded ? 0 : -NAVIGATION_SIDEBAR_WIDTH,
        0,
        NAVIGATION_SIDEBAR_WIDTH,
        centralWidget()->height());
    const QPoint toggleEnd(
        navigationSidebarExpanded
            ? NAVIGATION_SIDEBAR_WIDTH - NAVIGATION_TOGGLE_WIDTH / 2
            : 8,
        20);
    const int contentX = navigationSidebarExpanded ? NAVIGATION_SIDEBAR_WIDTH : 0;
    const QRect walletEnd(
        contentX,
        0,
        qMax(0, centralWidget()->width() - contentX),
        centralWidget()->height());

    auto* animations = new QParallelAnimationGroup(this);
    auto* drawerAnimation = new QPropertyAnimation(toolbar, "geometry", animations);
    drawerAnimation->setDuration(220);
    drawerAnimation->setStartValue(toolbar->geometry());
    drawerAnimation->setEndValue(drawerEnd);
    drawerAnimation->setEasingCurve(QEasingCurve::InOutCubic);

    auto* toggleAnimation = new QPropertyAnimation(navigationToggleButton, "pos", animations);
    toggleAnimation->setDuration(220);
    toggleAnimation->setStartValue(navigationToggleButton->pos());
    toggleAnimation->setEndValue(toggleEnd);
    toggleAnimation->setEasingCurve(QEasingCurve::InOutCubic);

    auto* walletAnimation = new QPropertyAnimation(walletFrame, "geometry", animations);
    walletAnimation->setDuration(220);
    walletAnimation->setStartValue(walletFrame->geometry());
    walletAnimation->setEndValue(walletEnd);
    walletAnimation->setEasingCurve(QEasingCurve::InOutCubic);

    toolbar->raise();
    navigationToggleButton->raise();
    animations->start(QAbstractAnimation::DeleteWhenStopped);
}

void BitcoinGUI::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
    if(_clientModel)
    {
        // Create system tray menu (or setup the dock menu) that late to prevent users from calling actions,
        // while the client has not yet fully loaded
        createTrayIconMenu();

        // Keep up to date with client
        updateNetworkState();
        connect(_clientModel, &ClientModel::numConnectionsChanged, this, &BitcoinGUI::setNumConnections);
        connect(_clientModel, &ClientModel::networkActiveChanged, this, &BitcoinGUI::setNetworkActive);

        modalOverlay->setKnownBestHeight(_clientModel->getHeaderTipHeight(), QDateTime::fromSecsSinceEpoch(_clientModel->getHeaderTipTime()));
        setNumBlocks(_clientModel->getNumBlocks(), _clientModel->getLastBlockDate(), _clientModel->getVerificationProgress(NULL), false);
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &BitcoinGUI::setNumBlocks);

        connect(clientModel, &ClientModel::additionalDataSyncProgressChanged, this, &BitcoinGUI::setAdditionalDataSyncProgress);

        // Receive and report messages from client model
        connect(_clientModel, &ClientModel::message, [this](const QString &title, const QString &message, unsigned int style){
            this->message(title, message, style);
        });

        // Show progress dialog
        connect(_clientModel, &ClientModel::showProgress, this, &BitcoinGUI::showProgress);

        // Update progress bar label textw
        connect(_clientModel, &ClientModel::updateProgressBarLabel, this, &BitcoinGUI::updateProgressBarLabel);

        rpcConsole->setClientModel(_clientModel);

#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->setClientModel(_clientModel);
        }
#endif // ENABLE_WALLET
        unitDisplayControl->setOptionsModel(_clientModel->getOptionsModel());

        OptionsModel* optionsModel = _clientModel->getOptionsModel();
        if(optionsModel)
        {
            // be aware of the tray icon disable state change reported by the OptionsModel object.
            connect(optionsModel, &OptionsModel::hideTrayIconChanged, this, &BitcoinGUI::setTrayIconVisible);

            // initialize the disable state of the tray icon with the current value in the model.
            setTrayIconVisible(optionsModel->getHideTrayIcon());
        }
        {
#ifdef ENABLE_WALLET
            auto blocks = clientModel->getNumBlocks();
            checkZnodeVisibility(blocks);
            checkSparkNamesVisibility(blocks);
#endif // ENABLE_WALLET
        }
    } else {
        // Disable possibility to show main window via action
        toggleHideAction->setEnabled(false);
        if(trayIconMenu)
        {
            // Disable context menu on tray icon
            trayIconMenu->clear();
        }
        // Propagate cleared model to child objects
        rpcConsole->setClientModel(nullptr);
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setClientModel(nullptr);
        }
#endif // ENABLE_WALLET
        unitDisplayControl->setOptionsModel(nullptr);
    }
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::addWallet(const QString& name, WalletModel *walletModel)
{
    if(!walletFrame)
        return false;
    setWalletActionsEnabled(true);
    const bool walletAdded = walletFrame->addWallet(name, walletModel);
    if (walletAdded && clientModel && !sparkAddressbookUpdated) {
        sparkAddressbookUpdated = walletFrame->updateAddressbook();
    }
    return walletAdded;
}

bool BitcoinGUI::setCurrentWallet(const QString& name)
{
    if(!walletFrame)
        return false;
    const bool walletSelected = walletFrame->setCurrentWallet(name);
    if (walletSelected && clientModel && !sparkAddressbookUpdated) {
        sparkAddressbookUpdated = walletFrame->updateAddressbook();
    }
    return walletSelected;
}

void BitcoinGUI::removeAllWallets()
{
    if(!walletFrame)
        return;
    setWalletActionsEnabled(false);
    walletFrame->removeAllWallets();
}
#endif // ENABLE_WALLET

void BitcoinGUI::setWalletActionsEnabled(bool enabled)
{
    overviewAction->setEnabled(enabled);
    sendCoinsAction->setEnabled(enabled);
    sendCoinsMenuAction->setEnabled(enabled);
    receiveCoinsAction->setEnabled(enabled);
    receiveCoinsMenuAction->setEnabled(enabled);
    historyAction->setEnabled(enabled);
    sparkNamesAction->setEnabled(enabled);
    masternodeAction->setEnabled(enabled);
    encryptWalletAction->setEnabled(enabled);
    backupWalletAction->setEnabled(enabled);
    changePassphraseAction->setEnabled(enabled);
    exportViewKeyAction->setEnabled(enabled);
    signMessageAction->setEnabled(enabled);
    verifyMessageAction->setEnabled(enabled);
    usedSendingAddressesAction->setEnabled(enabled);
    usedReceivingAddressesAction->setEnabled(enabled);
    openAction->setEnabled(enabled);
}

void BitcoinGUI::createTrayIcon(const NetworkStyle *networkStyle)
{
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    QString toolTip = tr("%1 client").arg(tr(PACKAGE_NAME)) + " " + networkStyle->getTitleAddText();
    trayIcon->setToolTip(toolTip);
    trayIcon->setIcon(networkStyle->getTrayAndWindowIcon());
    trayIcon->hide();
#endif

    notificator = new Notificator(QApplication::applicationName(), trayIcon, this);
}

void BitcoinGUI::createTrayIconMenu()
{
#ifndef Q_OS_MAC
    // return if trayIcon is unset (only on non-Mac OSes)
    if (!trayIcon)
        return;

    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);

    connect(trayIcon, &QSystemTrayIcon::activated, this, &BitcoinGUI::trayIconActivated);
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    dockIconHandler->setMainWindow((QMainWindow *)this);
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsMenuAction);
    trayIconMenu->addAction(receiveCoinsMenuAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(signMessageAction);
    trayIconMenu->addAction(verifyMessageAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addAction(openRPCConsoleAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHidden();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;

    OptionsDialog dlg(this, enableWallet);
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    if(!clientModel)
        return;

    HelpMessageDialog dlg(this, true);
    dlg.exec();
}

void BitcoinGUI::showDebugWindow()
{
    rpcConsole->showNormal();
    rpcConsole->show();
    rpcConsole->raise();
    rpcConsole->activateWindow();
}

void BitcoinGUI::showDebugWindowActivateConsole()
{
    rpcConsole->setTabFocus(RPCConsole::TAB_CONSOLE);
    showDebugWindow();
}

void BitcoinGUI::showHelpMessageClicked()
{
    helpMessageDialog->show();
}

#ifdef ENABLE_WALLET
void BitcoinGUI::openClicked()
{
    OpenURIDialog dlg(this);
    if(dlg.exec())
    {
        Q_EMIT receivedURI(dlg.getURI());
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    if (walletFrame) walletFrame->gotoOverviewPage();
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    if (walletFrame) walletFrame->gotoHistoryPage();
}

void BitcoinGUI::gotoBitcoinHistoryTab()
{
    historyAction->setChecked(true);
    if (walletFrame) walletFrame->gotoBitcoinHistoryTab();
}

void BitcoinGUI::gotoMasternodePage()
{
    QSettings settings;
    masternodeAction->setChecked(true);
    if (walletFrame) walletFrame->gotoMasternodePage();
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoReceiveCoinsPage();
}

void BitcoinGUI::gotoSparkNamesPage()
{
    sparkNamesAction->setChecked(true);
    if (walletFrame) walletFrame->gotoSparkNamesPage();
}

void BitcoinGUI::gotoSendCoinsPage(QString addr)
{
    sendCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoSendCoinsPage(addr);
}

void BitcoinGUI::gotoSignMessageTab(QString addr)
{
    if (walletFrame) walletFrame->gotoSignMessageTab(addr);
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    if (walletFrame) walletFrame->gotoVerifyMessageTab(addr);
}
#endif // ENABLE_WALLET

void BitcoinGUI::updateNetworkState()
{
    int count = clientModel->getNumConnections();
    QString icon;
    switch(count)
    {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }

    QString tooltip;

    if (clientModel->getNetworkActive()) {
        tooltip = tr("%n active connection(s) to Firo network", "", count) + QString(".<br>") + tr("Click to disable network activity.");
    } else {
        tooltip = tr("Network activity disabled.") + QString("<br>") + tr("Click to enable network activity again.");
        icon = ":/icons/network_disabled";
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");
    connectionsControl->setToolTip(tooltip);

    connectionsControl->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(icon), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
}

void BitcoinGUI::setNumConnections(int count)
{
    updateNetworkState();

    if (!navigationSyncProgress || !navigationSyncLabel)
        return;

    const double progress = navigationSyncProgress->value() / 100.0;
    const QString status = count == 0 && syncInProgress()
        ? tr("Connecting to peers...")
        : QString();
    updateNavigationSyncCard(status, progress);
}

void BitcoinGUI::setNetworkActive(bool networkActive)
{
    updateNetworkState();

    if (!networkActive) {
        const double progress = navigationSyncProgress
            ? navigationSyncProgress->value() / 100.0
            : 0.0;
        updateNavigationSyncCard(tr("Network activity disabled"), progress);
    } else if (clientModel) {
        setNumConnections(clientModel->getNumConnections());
    }
}

void BitcoinGUI::updateHeadersSyncProgressLabel()
{
    if (modalOverlay->isHeaderSyncPending())
        progressBarLabel->setText(tr("Syncing Headers..."));
    updateNavigationSyncCard(progressBarLabel->text(), modalOverlay->headerSyncProgress());
}

void BitcoinGUI::setNumBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if (modalOverlay)
    {
        if (header)
            modalOverlay->setKnownBestHeight(count, blockDate);
        else
            modalOverlay->tipUpdate(count, blockDate, nVerificationProgress);
    }
    if (!clientModel)
        return;

    // Prevent orphan statusbar messages (e.g. hover Quit in main menu, wait until chain-sync starts -> garbled text)
    statusBar()->clearMessage();

    // Acquire current block source
    enum BlockSource blockSource = clientModel->getBlockSource();
    switch (blockSource) {
        case BLOCK_SOURCE_NETWORK:
            if (header) {
                updateHeadersSyncProgressLabel();
                return;
            }
            progressBarLabel->setText(tr("Synchronizing with network..."));
            updateHeadersSyncProgressLabel();
            break;
        case BLOCK_SOURCE_DISK:
            if (header) {
                progressBarLabel->setText(tr("Indexing blocks on disk..."));
            } else {
                progressBarLabel->setText(tr("Processing blocks on disk..."));
            }
            break;
        case BLOCK_SOURCE_REINDEX:
            progressBarLabel->setText(tr("Reindexing blocks on disk..."));
            break;
        case BLOCK_SOURCE_NONE:
            if (header) {
                return;
            }
            progressBarLabel->setText(tr("Connecting to peers..."));
            break;
    }

    QString tooltip;

    QDateTime currentDate = QDateTime::currentDateTime();
    qint64 secs = blockDate.secsTo(currentDate);

    tooltip = tr("Processed %n block(s) of transaction history.", "", count);

#ifdef ENABLE_WALLET
    if(walletFrame)
    {
        if (secs < MAX_SYNCED_TIP_AGE_SECS) {
            modalOverlay->showHide(true, true);
            // TODO instead of hiding it forever, we should add meaningful information about MN sync to the overlay
            modalOverlay->hideForever();
        }
        else
        {
            modalOverlay->showHide();
        }
    }
#endif // ENABLE_WALLET

    if (!masternodeSync.IsBlockchainSynced())
    {
        QString timeBehindText = GUIUtil::formatNiceTimeOffset(secs);

        progressBarLabel->setVisible(false);
        progressBar->setFormat(tr("%1 behind").arg(timeBehindText));
        progressBar->setMaximum(1000000000);
        progressBar->setValue(nVerificationProgress * 1000000000.0 + 0.5);
        progressBar->setVisible(false);
        if (blockSource != BLOCK_SOURCE_NETWORK && blockSource != BLOCK_SOURCE_NONE)
            updateNavigationSyncCard(progressBarLabel->text(), nVerificationProgress);
        else if (blockSource == BLOCK_SOURCE_NONE)
            updateNavigationSyncCard(progressBarLabel->text(), 0.0);

        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        if(count != prevBlocks)
        {
            labelBlocksIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(QString(
                ":/movies/spinner-%1").arg(spinnerFrame, 3, 10, QChar('0'))),
                QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;
        }
        prevBlocks = count;

#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->showOutOfSyncWarning(true);
            modalOverlay->showHide();
        }
#endif // ENABLE_WALLET

        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1 ago.").arg(timeBehindText);
        tooltip += QString("<br>");
        tooltip += tr("Transactions after this will not yet be visible.");
    } else if (fLiteMode) {
        setAdditionalDataSyncProgress(1);
    } else if (masternodeSync.IsSynced()) {
        updateNavigationSyncCard(QString(), 1.0);
#ifdef ENABLE_WALLET
        if (walletFrame)
            walletFrame->showOutOfSyncWarning(false);
#endif // ENABLE_WALLET
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);

#ifdef ENABLE_WALLET
    checkZnodeVisibility(count);
    if (!header)
        checkSparkNamesVisibility(count);
    if (!header && walletFrame && !sparkAddressbookUpdated && count >= ::Params().GetConsensus().nSparkStartBlock) {
        sparkAddressbookUpdated = walletFrame->updateAddressbook();
    }
#endif // ENABLE_WALLET
}


void BitcoinGUI::setAdditionalDataSyncProgress(double nSyncProgress)
{
    if(!clientModel)
        return;

    // No additional data sync should be happening while blockchain is not synced, nothing to update
    if(!masternodeSync.IsBlockchainSynced())
        return;

    // Prevent orphan statusbar messages (e.g. hover Quit in main menu, wait until chain-sync starts -> garbelled text)
    statusBar()->clearMessage();

    QString tooltip;

    QString strSyncStatus;
    // Set icon state: spinning if catching up, tick otherwise
    tooltip = tr("Up to date") + QString(".<br>") + tooltip;

#ifdef ENABLE_WALLET
    if(walletFrame)
        walletFrame->showOutOfSyncWarning(false);
#endif // ENABLE_WALLET

    if(masternodeSync.IsSynced()) {
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);
        updateNavigationSyncCard(QString(), 1.0);
        labelBlocksIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(":/icons/synced"), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
    } else {

        labelBlocksIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(QString(
                        ":/movies/spinner-%1").arg(spinnerFrame, 3, 10, QChar('0'))),
                                            QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
        spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;

        progressBar->setFormat(tr("Synchronizing additional data: %p%"));
        progressBar->setMaximum(1000000000);
        progressBar->setValue(nSyncProgress * 1000000000.0 + 0.5);
    }

    strSyncStatus = QString(masternodeSync.GetSyncStatus().c_str());
    progressBarLabel->setText(strSyncStatus);
    if (!masternodeSync.IsSynced())
        updateNavigationSyncCard(strSyncStatus, nSyncProgress);
    tooltip = strSyncStatus + QString("<br>") + tooltip;

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}


void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style, bool *ret)
{
    QString strTitle = tr("Firo"); // default title
    // Default to information icon
    int nMBoxIcon = QMessageBox::Information;
    int nNotifyIcon = Notificator::Information;

    QString msgType;

    // Prefer supplied title over style based title
    if (!title.isEmpty()) {
        msgType = title;
    }
    else {
        switch (style) {
        case CClientUIInterface::MSG_ERROR:
            msgType = tr("Error");
            break;
        case CClientUIInterface::MSG_WARNING:
            msgType = tr("Warning");
            break;
        case CClientUIInterface::MSG_INFORMATION:
            msgType = tr("Information");
            break;
        default:
            break;
        }
    }
    // Append title to "Firo - "
    if (!msgType.isEmpty())
        strTitle += " - " + msgType;

    // Check for error/warning icon
    if (style & CClientUIInterface::ICON_ERROR) {
        nMBoxIcon = QMessageBox::Critical;
        nNotifyIcon = Notificator::Critical;
    }
    else if (style & CClientUIInterface::ICON_WARNING) {
        nMBoxIcon = QMessageBox::Warning;
        nNotifyIcon = Notificator::Warning;
    }

    // Display message
    if (style & CClientUIInterface::MODAL) {
        // Check for buttons, use OK as default, if none was supplied
        QMessageBox::StandardButton buttons;
        if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
            buttons = QMessageBox::Ok;

        showNormalIfMinimized();
        QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons, this);
        int r = mBox.exec();
        if (ret != NULL)
            *ret = r == QMessageBox::Ok;
    }
    else
        notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel() && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, &BitcoinGUI::hide);
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
#ifndef Q_OS_MAC // Ignored on Mac
    if(clientModel && clientModel->getOptionsModel())
    {
        if(!clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            // close rpcConsole in case it was open to make some space for the shutdown window
            rpcConsole->close();

            QApplication::quit();
        }
        else
        {
            QMainWindow::showMinimized();
            event->ignore();
        }
    }
#else
    QMainWindow::closeEvent(event);
#endif
}

void BitcoinGUI::showEvent(QShowEvent *event)
{
    // enable the debug window when the main window shows up
    openRPCConsoleAction->setEnabled(true);
    consoleAction->setEnabled(true);
    aboutAction->setEnabled(true);
    optionsAction->setEnabled(true);

    updateNavigationSidebarGeometry();
    applyNavigationTheme();
}

#ifdef ENABLE_WALLET
void BitcoinGUI::incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString& label)
{
    // On new transaction, make an info balloon
    QString msg = tr("Date: %1\n").arg(date) +
                  tr("Amount: %1\n").arg(BitcoinUnits::formatWithUnit(unit, amount, true)) +
                  tr("Type: %1\n").arg(type);
    if (!label.isEmpty())
        msg += tr("Label: %1\n").arg(label);
    else if (!address.isEmpty())
        msg += tr("Address: %1\n").arg(address);

    // Declare before lambda to ensure they're in scope
    QString title = (amount < 0) ? tr("Sent transaction") : tr("Incoming transaction");
    QString finalMsg = msg;

    // skip tx notifications in case it is not fully sync
    if (masternodeSync.IsBlockchainSynced()) {
        QMetaObject::invokeMethod(this, [this, title, finalMsg]() {
            message(title, finalMsg, CClientUIInterface::MSG_INFORMATION);
        }, Qt::QueuedConnection);
    }

}
#endif // ENABLE_WALLET

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        for (const QUrl &uri : event->mimeData()->urls())
        {
            Q_EMIT receivedURI(uri.toString());
        }
    }
    event->acceptProposedAction();
}

bool BitcoinGUI::eventFilter(QObject *object, QEvent *event)
{
    if (object == navigationSyncCard && event->type() == QEvent::MouseButtonRelease)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            showModalOverlay();
            return true;
        }
    }

    // Catch status tip events
    if (event->type() == QEvent::StatusTip)
    {
        // Prevent adding text from setStatusTip(), if we currently use the status bar for displaying other stuff
        if ((navigationSyncCard && navigationSyncCard->isVisible()) ||
            progressBarLabel->isVisible() || progressBar->isVisible())
            return true;
    }
    return QMainWindow::eventFilter(object, event);
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    // URI has to be valid
    if (walletFrame && walletFrame->handlePaymentRequest(recipient))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
        return true;
    }
    return false;
}

void BitcoinGUI::setHDStatus(int hdEnabled)
{
    labelWalletHDStatusIcon->setPixmap(GUIUtil::themedStatusIconPixmap(
        QIcon(hdEnabled ? ":/icons/hd_enabled" : ":/icons/hd_disabled"), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
    labelWalletHDStatusIcon->setToolTip(hdEnabled ? tr("HD key generation is <b>enabled</b>") : tr("HD key generation is <b>disabled</b>"));

    // eventually disable the QLabel to set its opacity to 50%
    labelWalletHDStatusIcon->setEnabled(hdEnabled);
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    cachedEncryptionStatus = status;
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelWalletEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        changePassphraseAction->setEnabled(false);
        encryptWalletAction->setEnabled(true);
        break;
    case WalletModel::Unlocked:
        labelWalletEncryptionIcon->show();
        labelWalletEncryptionIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(":/icons/lock_open"), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
        labelWalletEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    case WalletModel::Locked:
        labelWalletEncryptionIcon->show();
        labelWalletEncryptionIcon->setPixmap(GUIUtil::themedStatusIconPixmap(QIcon(":/icons/lock_closed"), QSize(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE)));
        labelWalletEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    }
}
#endif // ENABLE_WALLET

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    if(!clientModel)
        return;

    if (!isHidden() && !isMinimized() && !GUIUtil::isObscured(this) && fToggleHidden) {
        hide();
    } else {
        // activateWindow() (sometimes) helps with keyboard focus on Windows
        if (isMinimized()) {
            showNormal();
        } else {
            show();
        }
        raise();
        activateWindow();
    }
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::detectShutdown()
{
    if (ShutdownRequested())
    {
        if(rpcConsole)
            rpcConsole->hide();
        qApp->quit();
    }
}

void BitcoinGUI::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}

void BitcoinGUI::updateProgressBarLabel(const QString& text)
{
    if (!progressBarLabel)
        return;

    progressBarLabel->setVisible(!text.isEmpty());
    progressBarLabel->setText(text);
}

void BitcoinGUI::setTrayIconVisible(bool fHideTrayIcon)
{
    if (trayIcon)
    {
        trayIcon->setVisible(!fHideTrayIcon);
    }
}

void BitcoinGUI::showModalOverlay()
{
    if (modalOverlay)
        modalOverlay->toggleVisibility();
}

static bool ThreadSafeMessageBox(BitcoinGUI *gui, const std::string& message, const std::string& caption, unsigned int style)
{
    bool modal = (style & CClientUIInterface::MODAL);
    // The SECURE flag has no effect in the Qt GUI.
    // bool secure = (style & CClientUIInterface::SECURE);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;
    // In case of modal message, use blocking connection to wait for user to click a button
    QMetaObject::invokeMethod(gui, "message",
                               modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                               Q_ARG(QString, QString::fromStdString(caption)),
                               Q_ARG(QString, QString::fromStdString(message)),
                               Q_ARG(unsigned int, style),
                               Q_ARG(bool*, &ret));
    return ret;
}

void BitcoinGUI::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ThreadSafeMessageBox.connect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.connect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

void BitcoinGUI::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ThreadSafeMessageBox.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

void BitcoinGUI::checkZnodeVisibility(int numBlocks) {

    const Consensus::Params& params = ::Params().GetConsensus();
    // Before legacy window
    if(numBlocks < params.DIP0003Height){
        masternodeAction->setVisible(false);
    } else {
        masternodeAction->setVisible(true);
    }
    updateToolbarTabWidths();
}

void BitcoinGUI::checkSparkNamesVisibility(int numBlocks) {
    if (!sparkNamesAction)
        return;

    const Consensus::Params& params = ::Params().GetConsensus();
    const int nextBlockHeight = numBlocks + 1;
    const bool visible = spark::IsSparkAllowed(nextBlockHeight) &&
        nextBlockHeight >= params.nSparkNamesStartBlock;
    sparkNamesAction->setVisible(visible);
    updateToolbarTabWidths();
}

void BitcoinGUI::toggleNetworkActive()
{
    if (clientModel) {
        clientModel->setNetworkActive(!clientModel->getNetworkActive());
    }
}

UnitDisplayStatusBarControl::UnitDisplayStatusBarControl(const PlatformStyle *platformStyle) :
    optionsModel(0),
    menu(0)
{
    createContextMenu();
    setToolTip(tr("Unit to show amounts in. Click to select another unit."));
    QList<BitcoinUnits::Unit> units = BitcoinUnits::availableUnits();
    int max_width = 0;
    const QFontMetrics fm(font());
    for (const BitcoinUnits::Unit unit : units)
    {
        max_width = qMax(max_width, GUIUtil::TextWidth(fm, BitcoinUnits::name(unit)));
    }
    setMinimumSize(max_width, 0);
    setAlignment(Qt::AlignRight | Qt::AlignVCenter);
}

/** So that it responds to button clicks */
void UnitDisplayStatusBarControl::mousePressEvent(QMouseEvent *event)
{
    onDisplayUnitsClicked(event->pos());
}

/** Creates context menu, its actions, and wires up all the relevant signals for mouse events. */
void UnitDisplayStatusBarControl::createContextMenu()
{
    menu = new QMenu(this);
    for (BitcoinUnits::Unit u : BitcoinUnits::availableUnits())
    {
        QAction *menuAction = new QAction(QString(BitcoinUnits::name(u)), this);
        menuAction->setData(QVariant(u));
        menu->addAction(menuAction);
    }
    connect(menu, &QMenu::triggered, this, &UnitDisplayStatusBarControl::onMenuSelection);
}

/** Lets the control know about the Options Model (and its signals) */
void UnitDisplayStatusBarControl::setOptionsModel(OptionsModel *_optionsModel)
{
    if (_optionsModel)
    {
        this->optionsModel = _optionsModel;

        // be aware of a display unit change reported by the OptionsModel object.
        connect(_optionsModel, &OptionsModel::displayUnitChanged, this, &UnitDisplayStatusBarControl::updateDisplayUnit);

        // initialize the display units label with the current value in the model.
        updateDisplayUnit(_optionsModel->getDisplayUnit());
    }
}

/** When Display Units are changed on OptionsModel it will refresh the display text of the control on the status bar */
void UnitDisplayStatusBarControl::updateDisplayUnit(int newUnits)
{
    setText(BitcoinUnits::name(newUnits));
}

/** Shows context menu with Display Unit options by the mouse coordinates */
void UnitDisplayStatusBarControl::onDisplayUnitsClicked(const QPoint& point)
{
    QPoint globalPos = mapToGlobal(point);
    menu->exec(globalPos);
}

/** Tells underlying optionsModel to update its current display unit. */
void UnitDisplayStatusBarControl::onMenuSelection(QAction* action)
{
    if (action)
    {
        optionsModel->setDisplayUnit(action->data());
    }
}

// Handles resize events for the BitcoinGUI widget by adjusting internal component sizes.
void BitcoinGUI::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    updateToolbarTabWidths();
    updateNavigationSidebarGeometry();
}
