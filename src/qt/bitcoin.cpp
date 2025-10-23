// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "bitcoingui.h"

#include "chainparams.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "intro.h"
#include "recover.h"
#include "notifymnemonic.h"
#include "networkstyle.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "splashscreen.h"
#include "utilitydialog.h"
#include "winshutdownmonitor.h"
#include "askpassphrasedialog.h"
#ifdef ENABLE_WALLET
#include "paymentserver.h"
#include "walletmodel.h"
#endif

#include "init.h"
#include "rpc/server.h"
#include "scheduler.h"
#include "stacktraces.h"
#include "util.h"
#include "warnings.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <stdint.h>

#include <boost/filesystem/operations.hpp>
#include <boost/thread.hpp>
#include <fstream>

#include <QApplication>
#include <QDebug>
#include <QLibraryInfo>
#include <QLocale>
#include <QMessageBox>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <QTranslator>
#include <QSslConfiguration>
#include <QCheckBox>

#if defined(QT_STATICPLUGIN)
#include <QtPlugin>
#if QT_VERSION < 0x050000
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
Q_IMPORT_PLUGIN(qtaccessiblewidgets)
#else
#if QT_VERSION < 0x050400
Q_IMPORT_PLUGIN(AccessibleFactory)
#endif
#if defined(QT_QPA_PLATFORM_XCB)
Q_IMPORT_PLUGIN(QXcbIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_WINDOWS)
Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin);
#elif defined(QT_QPA_PLATFORM_COCOA)
Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin);
#endif
#endif
#endif

#if QT_VERSION < 0x050000
#include <QTextCodec>
#endif

#include <QFontDatabase>

static bool newWallet = false;

// Declare meta types used for QMetaObject::invokeMethod
Q_DECLARE_METATYPE(bool*)
Q_DECLARE_METATYPE(CAmount)

static void InitMessage(const std::string &message)
{
    LogPrintf("init message: %s\n", message);
}

/*
   Translate string to current locale using Qt.
 */
static std::string Translate(const char* psz)
{
    return QCoreApplication::translate("firo-core", psz).toStdString();
}

static QString GetLangTerritory()
{
    QSettings settings;
    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = QLocale::system().name();
    // 2) Language from QSettings
    QString lang_territory_qsettings = settings.value("language", "").toString();
    if(!lang_territory_qsettings.isEmpty())
        lang_territory = lang_territory_qsettings;
    // 3) -lang command line argument
    lang_territory = QString::fromStdString(GetArg("-lang", lang_territory.toStdString()));
    return lang_territory;
}

/** Set up translations */
static void initTranslations(QTranslator &qtTranslatorBase, QTranslator &qtTranslator, QTranslator &translatorBase, QTranslator &translator)
{
    // Remove old translators
    QApplication::removeTranslator(&qtTranslatorBase);
    QApplication::removeTranslator(&qtTranslator);
    QApplication::removeTranslator(&translatorBase);
    QApplication::removeTranslator(&translator);

    // Get desired locale (e.g. "de_DE")
    // 1) System default language
    QString lang_territory = GetLangTerritory();

    // Convert to "de" only by truncating "_DE"
    QString lang = lang_territory;
    lang.truncate(lang_territory.lastIndexOf('_'));

    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator

    // Load e.g. qt_de.qm
    if (qtTranslatorBase.load("qt_" + lang, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslatorBase);

    // Load e.g. qt_de_DE.qm
    if (qtTranslator.load("qt_" + lang_territory, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        QApplication::installTranslator(&qtTranslator);

    // Load e.g. bitcoin_de.qm (shortcut "de" needs to be defined in bitcoin.qrc)
    if (translatorBase.load(lang, ":/translations/"))
        QApplication::installTranslator(&translatorBase);

    // Load e.g. bitcoin_de_DE.qm (shortcut "de_DE" needs to be defined in bitcoin.qrc)
    if (translator.load(lang_territory, ":/translations/"))
        QApplication::installTranslator(&translator);
}

/* qDebug() message handler --> debug.log */
#if QT_VERSION < 0x050000
void DebugMessageHandler(QtMsgType type, const char *msg)
{
    const char *category = (type == QtDebugMsg) ? "qt" : NULL;
    LogPrint(category, "GUI: %s\n", msg);
}
#else
void DebugMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString &msg)
{
    Q_UNUSED(context);
    const char *category = (type == QtDebugMsg) ? "qt" : NULL;
    LogPrint(category, "GUI: %s\n", msg.toStdString());
}
#endif

/** Class encapsulating Bitcoin Core startup and shutdown.
 * Allows running startup and shutdown in a different thread from the UI thread.
 */
class BitcoinCore: public QObject
{
    Q_OBJECT
public:
    explicit BitcoinCore();

public Q_SLOTS:
    void initialize();
    void shutdown();

Q_SIGNALS:
    void initializeResult(int retval);
    void shutdownResult(int retval);
    void runawayException(const QString &message);

private:
    boost::thread_group threadGroup;
    CScheduler scheduler;

    /// Pass fatal exception message to UI thread
    void handleRunawayException(const std::exception_ptr e);
};

/** Main Bitcoin application object */
class BitcoinApplication: public QApplication
{
    Q_OBJECT
public:
    explicit BitcoinApplication(int &argc, char **argv);
    ~BitcoinApplication();

#ifdef ENABLE_WALLET
    /// Create payment server
    void createPaymentServer();
#endif
    /// parameter interaction/setup based on rules
    void parameterSetup();
    /// Create options model
    void createOptionsModel(bool resetSettings);
    /// Create main window
    void createWindow(const NetworkStyle *networkStyle);
    /// Create splash screen
    void createSplashScreen(const NetworkStyle *networkStyle);
    // migrate settings to firo. Returns true if there was migration
    bool migrateSettings(const QString &oldOrganizationName, const QString &newOrganizationName, const QString &oldApplicationName, const QString &newApplicationName);
    // set data directory in settings file
    void setDataDirInSettings(const QString &organization, const QString &application, const QString &dataDir);
    // migrate directories to firo if needed
    void migrateToFiro();

    /// Request core initialization
    void requestInitialize();
    /// Request core shutdown
    void requestShutdown();

    void showCloseWindow();

    /// Get process return value
    int getReturnValue() { return returnValue; }

    /// Get window identifier of QMainWindow (BitcoinGUI)
    WId getMainWinId() const;

public Q_SLOTS:
#ifdef ENABLE_WALLET
    void unlockWallet_(void * wallet);
#endif
    void initializeResult(int retval);
    void shutdownResult(int retval);
    /// Handle runaway exceptions. Shows a message box with the problem and quits the program.
    void handleRunawayException(const QString &message);

Q_SIGNALS:
    void requestedInitialize();
    void requestedShutdown();
    void stopThread();
    void splashFinished(QWidget *window);

private:
    QThread *coreThread;
    OptionsModel *optionsModel;
    ClientModel *clientModel;
    BitcoinGUI *window;
    QTimer *pollShutdownTimer;
#ifdef ENABLE_WALLET
    PaymentServer* paymentServer;
    WalletModel *walletModel;
#endif
    int returnValue;
    const PlatformStyle *platformStyle;
    std::unique_ptr<QWidget> shutdownWindow;

    void startThread();
};

#include "bitcoin.moc"

BitcoinCore::BitcoinCore():
    QObject()
{
}

void BitcoinCore::handleRunawayException(const std::exception_ptr e)
{
    PrintExceptionContinue(e, "Runaway exception");
    Q_EMIT runawayException(QString::fromStdString(GetWarnings("gui")));
}

void BitcoinCore::initialize()
{
    try
    {
        qDebug() << __func__ << ": Running AppInit2 in thread";
        if (!AppInitBasicSetup())
        {
            Q_EMIT initializeResult(false);
            return;
        }
        if (!AppInitParameterInteraction())
        {
            Q_EMIT initializeResult(false);
            return;
        }
        if (!AppInitSanityChecks())
        {
            Q_EMIT initializeResult(false);
            return;
        }
        int rv = AppInitMain(threadGroup, scheduler);
        Q_EMIT initializeResult(rv);
    }
    catch (...) {
        handleRunawayException(std::current_exception());
    }
}

void BitcoinCore::shutdown()
{
    try
    {
        qDebug() << __func__ << ": Running Shutdown in thread";
        Interrupt(threadGroup);
        threadGroup.join_all();
        Shutdown();
        qDebug() << __func__ << ": Shutdown finished";
        Q_EMIT shutdownResult(1);
    }
    catch (...) {
        handleRunawayException(std::current_exception());
    }
}

#ifdef ENABLE_WALLET
static void unlockWallet(BitcoinApplication* application, CWallet* wallet)
{
    Q_UNUSED(wallet);
    QMetaObject::invokeMethod(application, "unlockWallet_", Qt::QueuedConnection,
                              Q_ARG(void *, wallet));
}
#endif

BitcoinApplication::BitcoinApplication(int &argc, char **argv):
    QApplication(argc, argv),
    coreThread(0),
    optionsModel(0),
    clientModel(0),
    window(0),
    pollShutdownTimer(0),
#ifdef ENABLE_WALLET
    paymentServer(0),
    walletModel(0),
#endif
    returnValue(0)
{
    setQuitOnLastWindowClosed(false);

    // UI per-platform customization
    // This must be done inside the BitcoinApplication constructor, or after it, because
    // PlatformStyle::instantiate requires a QApplication
    std::string platformName;
    platformName = GetArg("-uiplatform", BitcoinGUI::DEFAULT_UIPLATFORM);
    platformStyle = PlatformStyle::instantiate(QString::fromStdString(platformName));
    if (!platformStyle) // Fall back to "other" if specified name not found
        platformStyle = PlatformStyle::instantiate("other");
    assert(platformStyle);

#ifdef ENABLE_WALLET
    UnlockWallet.connect(boost::bind(unlockWallet, this, _1));
#endif
}

BitcoinApplication::~BitcoinApplication()
{
    if(coreThread)
    {
        qDebug() << __func__ << ": Stopping thread";
        Q_EMIT stopThread();
        coreThread->wait();
        qDebug() << __func__ << ": Stopped thread";
    }

    delete window;
    window = 0;
#ifdef ENABLE_WALLET
    delete paymentServer;
    paymentServer = 0;
    UnlockWallet.disconnect(boost::bind(unlockWallet, this, _1));

#endif
    delete optionsModel;
    optionsModel = 0;
    delete platformStyle;
    platformStyle = 0;
}

#ifdef ENABLE_WALLET
void BitcoinApplication::createPaymentServer()
{
    paymentServer = new PaymentServer(this);
}

void BitcoinApplication::unlockWallet_(void * wallet)
{
    CWallet * wallet_ = reinterpret_cast<CWallet *>(wallet);

    QString info = tr("You need to unlock to allow Spark wallet be created.");

    walletModel = new WalletModel(platformStyle, wallet_, optionsModel);

    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this->window, info);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}
#endif

void BitcoinApplication::createOptionsModel(bool resetSettings)
{
    optionsModel = new OptionsModel(NULL, resetSettings);
}

void BitcoinApplication::createWindow(const NetworkStyle *networkStyle)
{
    window = new BitcoinGUI(platformStyle, networkStyle, 0);

    pollShutdownTimer = new QTimer(window);
    connect(pollShutdownTimer, &QTimer::timeout, window, &BitcoinGUI::detectShutdown);
    pollShutdownTimer->start(200);
}

void BitcoinApplication::createSplashScreen(const NetworkStyle *networkStyle)
{
    SplashScreen *splash = new SplashScreen(QPixmap(), Qt::WindowFlags());
    // We don't hold a direct pointer to the splash screen after creation, but the splash
    // screen will take care of deleting itself when slotFinish happens.
    splash->show();
    connect(this, &BitcoinApplication::splashFinished, splash, &SplashScreen::slotFinish);
    connect(this, &BitcoinApplication::requestedShutdown, splash, &QWidget::close);
}

void BitcoinApplication::startThread()
{
    if(coreThread)
        return;
    coreThread = new QThread(this);
    BitcoinCore *executor = new BitcoinCore();
    executor->moveToThread(coreThread);

    /*  communication to and from thread */
    connect(executor, &BitcoinCore::initializeResult, this, &BitcoinApplication::initializeResult);
    connect(executor, &BitcoinCore::shutdownResult, this, &BitcoinApplication::shutdownResult);
    connect(executor, &BitcoinCore::runawayException, this, &BitcoinApplication::handleRunawayException);
    connect(this, &BitcoinApplication::requestedInitialize, executor, &BitcoinCore::initialize);
    connect(this, &BitcoinApplication::requestedShutdown, executor, &BitcoinCore::shutdown);
    /*  make sure executor object is deleted in its own thread */
    connect(this, &BitcoinApplication::stopThread, executor, &QObject::deleteLater);
    connect(this, &BitcoinApplication::stopThread, coreThread, &QThread::quit);

    coreThread->start();
}

void BitcoinApplication::parameterSetup()
{
    InitLogging();
    InitParameterInteraction();
}

void BitcoinApplication::requestInitialize()
{
    qDebug() << __func__ << ": Requesting initialize";
    startThread();
    Q_EMIT requestedInitialize();
}

void BitcoinApplication::requestShutdown()
{
    // Show a simple window indicating shutdown status
    // Do this first as some of the steps may take some time below,
    // for example the RPC console may still be executing a command.
    shutdownWindow.reset(ShutdownWindow::showShutdownWindow(window));

    qDebug() << __func__ << ": Requesting shutdown";
    startThread();
    window->hide();
    window->setClientModel(0);
    pollShutdownTimer->stop();
    showCloseWindow();
#ifdef ENABLE_WALLET
    window->removeAllWallets();
    delete walletModel;
    walletModel = 0;
#endif
    delete clientModel;
    clientModel = 0;

    StartShutdown();
    // Delay shutdown signal by 500 milliseconds
    QTimer::singleShot(1000, this, [this]() {
        // Request shutdown from core thread after delay
        Q_EMIT requestedShutdown();
    });
}

void BitcoinApplication::showCloseWindow(){
    shutdownWindow->show();
}

void BitcoinApplication::initializeResult(int retval)
{
    qDebug() << __func__ << ": Initialization result: " << retval;
    // Set exit result: 0 if successful, 1 if failure
    returnValue = retval ? 0 : 1;
    if(retval)
    {
        // Log this only after AppInit2 finishes, as then logging setup is guaranteed complete
        qWarning() << "Platform customization:" << platformStyle->getName();
        clientModel = new ClientModel(optionsModel);
        window->setClientModel(clientModel);

#ifdef ENABLE_WALLET
        if(pwalletMain)
        {
            walletModel = new WalletModel(platformStyle, pwalletMain, optionsModel);

            window->addWallet(BitcoinGUI::DEFAULT_WALLET, walletModel);
            window->setCurrentWallet(BitcoinGUI::DEFAULT_WALLET);
        }
#endif

        // If -min option passed, start window minimized.
        if(GetBoolArg("-min", false))
        {
            window->showMinimized();
        }
        else
        {
            window->show();
        }
        Q_EMIT splashFinished(window);

#ifdef ENABLE_WALLET

        if (pwalletMain)
            if(newWallet)
                NotifyMnemonic::notify();

        // Now that initialization/startup is done, process any command-line
        // firo: URIs or payment requests:
        connect(paymentServer, &PaymentServer::receivedPaymentRequest, window, &BitcoinGUI::handlePaymentRequest);
        connect(window, &BitcoinGUI::receivedURI, paymentServer, &PaymentServer::handleURIOrFile);
        connect(paymentServer, &PaymentServer::message, [this](const QString& title, const QString& message, unsigned int style) {
            window->message(title, message, style);
        });
        QTimer::singleShot(100, paymentServer, &PaymentServer::uiReady);
#endif
    } else {
        quit(); // Exit main loop
    }
}

void BitcoinApplication::shutdownResult(int retval)
{
    qDebug() << __func__ << ": Shutdown result: " << retval;
    if (shutdownWindow) {
        shutdownWindow->close();
        shutdownWindow.reset();
    }
    quit(); // Exit main loop after shutdown finished
}

void BitcoinApplication::handleRunawayException(const QString &message)
{
    QMessageBox::critical(0, "Runaway exception", BitcoinGUI::tr("A fatal error occurred. Firo can no longer continue safely and will quit.") + QString("\n\n") + message);
    ::exit(EXIT_FAILURE);
}

WId BitcoinApplication::getMainWinId() const
{
    if (!window)
        return 0;

    return window->winId();
}

bool BitcoinApplication::migrateSettings(const QString &oldOrganizationName, const QString &newOrganizationName,
                                            const QString &oldApplicationName, const QString &newApplicationName)
{
    QSettings newSettings(newOrganizationName, newApplicationName);
    if (!newSettings.allKeys().empty())
        // no migration is needed
        return false;

    QSettings oldSettings(oldOrganizationName, oldApplicationName);
    QList<QString> keys = oldSettings.allKeys();
    if (!keys.empty()) {
        for (const QString &key : keys) {
            newSettings.setValue(key, oldSettings.value(key));
        }
        newSettings.sync();

        return true;
    }

    return false;
}

void BitcoinApplication::setDataDirInSettings(const QString &organization, const QString &application, const QString &dataDir)
{
    QSettings settings(organization, application);
    if (!settings.value("strDataDir").isNull()) {
        boost::filesystem::path zcoinDataDir = GetDefaultDataDirForCoinName("zcoin");
        boost::filesystem::path settingsDataDir = GUIUtil::qstringToBoostPath(settings.value("strDataDir", GUIUtil::boostPathToQString(zcoinDataDir)).toString());

        if (settingsDataDir == zcoinDataDir) {
            settings.setValue("strDataDir", dataDir);
            settings.sync();
        }
    }
}

void BitcoinApplication::migrateToFiro()
{
    migrateSettings("Zcoin", "Firo", "Zcoin-Qt", "Firo-Qt");
    migrateSettings("Zcoin", "Firo", "Zcoin-Qt-testnet", "Firo-Qt-testnet");

    QSettings settings;
    if (IsArgSet("-datadir"))
        return;

    boost::filesystem::path dataDir = GetDefaultDataDir();
    dataDir = GUIUtil::qstringToBoostPath(settings.value("strDataDir", GUIUtil::boostPathToQString(GetDefaultDataDir())).toString());
    boost::filesystem::path zcoinDefaultDataDir = GetDefaultDataDirForCoinName("zcoin");
    boost::filesystem::path firoDefaultDataDir = GetDefaultDataDirForCoinName("firo");

    if (dataDir != zcoinDefaultDataDir)
        return;

    boost::filesystem::path dontMigrateFilePath = dataDir / ".dontmigratetofiro";
    if (boost::filesystem::exists(dontMigrateFilePath) && !GetBoolArg("-migratetofiro", false))
        return;

    QCheckBox *doNotAskMeAgainCheckbox = new QCheckBox("Do not ask me again");
    QMessageBox messageBox;
    QString messageText;
    QTextStream(&messageText) <<
        "Migrate directory structure from zcoin to firo? "
        "Directory " << GUIUtil::boostPathToQString(zcoinDefaultDataDir) <<
          " will be renamed to " << GUIUtil::boostPathToQString(firoDefaultDataDir) <<
          " and file zcoin.conf in it will be renamed to firo.conf";
    messageBox.setText(messageText);

    messageBox.setIcon(QMessageBox::Icon::Question);
    messageBox.addButton(QMessageBox::Yes);
    messageBox.addButton(QMessageBox::No);
    messageBox.setDefaultButton(QMessageBox::Yes);
    messageBox.setCheckBox(doNotAskMeAgainCheckbox);

    bool doNotShowAgain = false;

    QObject::connect(doNotAskMeAgainCheckbox, &QCheckBox::stateChanged, [&doNotShowAgain] (int state) {
        doNotShowAgain = static_cast<Qt::CheckState>(state) == Qt::CheckState::Checked;
    });

    if (messageBox.exec() == QMessageBox::Yes) {
        if (RenameDirectoriesFromZcoinToFiro()) {
            // Update path in settings if not set to non-default value
            setDataDirInSettings("Firo", "Firo-Qt", GUIUtil::boostPathToQString(firoDefaultDataDir));
            setDataDirInSettings("Firo", "Firo-Qt-testnet", GUIUtil::boostPathToQString(firoDefaultDataDir));
        }
    }
    else if (doNotShowAgain) {
        // create file to block migration in the future
        std::ofstream(dontMigrateFilePath.string()).flush();
    }
}

#ifndef BITCOIN_QT_TEST
int main(int argc, char *argv[])
{
#ifdef ENABLE_CRASH_HOOKS
    RegisterPrettyTerminateHander();
    RegisterPrettySignalHandlers();
#endif    
    SetupEnvironment();

    /// 1. Parse command-line options. These take precedence over anything else.
    // Command-line options take precedence:
    ParseParameters(argc, argv);

    // Do not refer to data directory yet, this can be overridden by Intro::pickDataDirectory

    /// 2. Basic Qt initialization (not dependent on parameters or configuration)
#if QT_VERSION < 0x050000
    // Internal string conversion is all UTF-8
    QTextCodec::setCodecForTr(QTextCodec::codecForName("UTF-8"));
    QTextCodec::setCodecForCStrings(QTextCodec::codecForTr());
#endif

    Q_INIT_RESOURCE(bitcoin);
    Q_INIT_RESOURCE(bitcoin_locale);

#if QT_VERSION > 0x050100
    // Generate high-dpi pixmaps
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#endif
#if QT_VERSION >= 0x050600
    QGuiApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
#ifdef Q_OS_MAC
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif

    BitcoinApplication app(argc, argv);

    // Register meta types used for QMetaObject::invokeMethod
    qRegisterMetaType< bool* >();
    //   Need to pass name here as CAmount is a typedef (see http://qt-project.org/doc/qt-5/qmetatype.html#qRegisterMetaType)
    //   IMPORTANT if it is no longer a typedef use the normal variant above
    qRegisterMetaType< CAmount >("CAmount");
    qRegisterMetaType< uint256 >("uint256");

    /// 3. Application identification
    // must be set before OptionsModel is initialized or translations are loaded,
    // as it is used to locate QSettings
    QApplication::setOrganizationName(QAPP_ORG_NAME);
    QApplication::setOrganizationDomain(QAPP_ORG_DOMAIN);
    QApplication::setApplicationName(QAPP_APP_NAME_DEFAULT);

    // GUIUtil::SubstituteFonts(GetLangTerritory()); // use inlcuded fonts below
    // load included fonts
    QFontDatabase::addApplicationFont(":/fonts/Saira_SemiCondensed-Bold");
    QFontDatabase::addApplicationFont(":/fonts/SourceSansPro-Bold");
    QFontDatabase::addApplicationFont(":/fonts/SourceSansPro-Regular");

    /// 4. Initialization of translations, so that intro dialog is in user's language
    // Now that QSettings are accessible, initialize translations
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;
    initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator);
    translationInterface.Translate.connect(Translate);

#ifdef ENABLE_CRASH_HOOKS
    if (IsArgSet("-printcrashinfo")) {
        auto crashInfo = GetCrashInfoStrFromSerializedStr(GetArg("-printcrashinfo", ""));
        std::cout << crashInfo << std::endl;
        QMessageBox::critical(0, QObject::tr(PACKAGE_NAME), QString::fromStdString(crashInfo));
        return EXIT_SUCCESS;
    }
#endif

    // Show help message immediately after parsing command-line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (IsArgSet("-?") || IsArgSet("-h") || IsArgSet("-help") || IsArgSet("-version"))
    {
        HelpMessageDialog help(NULL, IsArgSet("-version"));
        help.showOrPrint();
        return EXIT_SUCCESS;
    }

    /// 5. Now that settings and translations are available, ask user for data directory
    // User language is set up: pick a data directory
    if (!Intro::pickDataDirectory())
        return EXIT_SUCCESS;

    app.migrateToFiro();

    /// 6. Determine availability of data directory and parse firo.conf
    /// - Do not call GetDataDir(true) before this step finishes
    if (!boost::filesystem::is_directory(GetDataDir(false)))
    {
        QMessageBox::critical(0, QObject::tr(PACKAGE_NAME),
                              QObject::tr("Error: Specified data directory \"%1\" does not exist.").arg(QString::fromStdString(GetArg("-datadir", ""))));
        return EXIT_FAILURE;
    }
    try {
        ReadConfigFile(GetArg("-conf", BITCOIN_CONF_FILENAME));
    } catch (const std::exception& e) {
        QMessageBox::critical(0, QObject::tr(PACKAGE_NAME),
                              QObject::tr("Error: Cannot parse configuration file: %1. Only use key=value syntax.").arg(e.what()));
        return EXIT_FAILURE;
    }

    /// 7. Determine network (and switch to network specific options)
    // - Do not call Params() before this step
    // - Do this after parsing the configuration file, as the network can be switched there
    // - QSettings() will use the new application name after this, resulting in network-specific settings
    // - Needs to be done before createOptionsModel

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    try {
        SelectParams(ChainNameFromCommandLine());
    } catch(std::exception &e) {
        QMessageBox::critical(0, QObject::tr(PACKAGE_NAME), QObject::tr("Error: %1").arg(e.what()));
        return EXIT_FAILURE;
    }
#ifdef ENABLE_WALLET
    // Parse URIs on command line -- this can affect Params()
    PaymentServer::ipcParseCommandLine(argc, argv);
#endif

    QScopedPointer<const NetworkStyle> networkStyle(NetworkStyle::instantiate(QString::fromStdString(Params().NetworkIDString())));
    assert(!networkStyle.isNull());
    // Allow for separate UI settings for testnets
    QApplication::setApplicationName(networkStyle->getAppName());
    // Re-initialize translations after changing application name (language in network-specific settings can be different)
    initTranslations(qtTranslatorBase, qtTranslator, translatorBase, translator);

#ifdef ENABLE_WALLET
    // Determine if user wants to create new wallet or recover existing one.
    // Only show if:
    // - Using mnemonic (-usemnemonic on (default)) and
    // - mnemonic not set (default, not setting mnemonic from conf file instead) and
    // - hdseed not set (default, not setting hd seed from conf file instead)
    if(GetBoolArg("-usehd", DEFAULT_USE_HD_WALLET) &&
       GetBoolArg("-usemnemonic", DEFAULT_USE_MNEMONIC) &&
       !GetBoolArg("-disablewallet", false) &&
       GetArg("-mnemonic", "").empty() &&
       GetArg("-hdseed", "not hex")=="not hex"){
        if(!Recover::askRecover(newWallet))
            return EXIT_SUCCESS;
    }
    /// 8. URI IPC sending
    // - Do this early as we don't want to bother initializing if we are just calling IPC
    // - Do this *after* setting up the data directory, as the data directory hash is used in the name
    // of the server.
    // - Do this after creating app and setting up translations, so errors are
    // translated properly.
    if (PaymentServer::ipcSendCommandLine())
        exit(EXIT_SUCCESS);

    // Start up the payment server early, too, so impatient users that click on
    // firo: links repeatedly have their payment requests routed to this process:
    app.createPaymentServer();
#endif
    /// 9. Main GUI initialization
    // Install global event filter that makes sure that long tooltips can be word-wrapped
    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));
#if QT_VERSION < 0x050000
    // Install qDebug() message handler to route to debug.log
    qInstallMsgHandler(DebugMessageHandler);
#else
#if defined(Q_OS_WIN)
    // Install global event filter for processing Windows session related Windows messages (WM_QUERYENDSESSION and WM_ENDSESSION)
    qApp->installNativeEventFilter(new WinShutdownMonitor());
#endif
    // Install qDebug() message handler to route to debug.log
    qInstallMessageHandler(DebugMessageHandler);
#endif
    // Allow parameter interaction before we create the options model
    app.parameterSetup();
    // Load GUI settings from QSettings
    app.createOptionsModel(IsArgSet("-resetguisettings"));

    // Subscribe to global signals from core
    uiInterface.InitMessage.connect(InitMessage);

    if (GetBoolArg("-splash", DEFAULT_SPLASHSCREEN) && !GetBoolArg("-min", false))
        app.createSplashScreen(networkStyle.data());

    try
    {
        app.createWindow(networkStyle.data());
        app.requestInitialize();
#if defined(Q_OS_WIN) && QT_VERSION >= 0x050000
        WinShutdownMonitor::registerShutdownBlockReason(QObject::tr("%1 didn't yet exit safely...").arg(QObject::tr(PACKAGE_NAME)), (HWND)app.getMainWinId());
#endif
        app.exec();
        app.requestShutdown();
        app.exec();
    } catch (...) {
        PrintExceptionContinue(std::current_exception(), "Runaway exception");
        app.handleRunawayException(QString::fromStdString(GetWarnings("gui")));
    }
    return app.getReturnValue();
}
#endif // BITCOIN_QT_TEST
