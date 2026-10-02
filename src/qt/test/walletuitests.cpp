// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletuitests.h"

#include "addresstablemodel.h"
#include "bitcoingui.h"
#include "bip47/defs.h"
#include "chainparams.h"
#include "clientmodel.h"
#include "createsparknamepage.h"
#include "guitheme.h"
#include "guiutil.h"
#include "init.h"
#include "masternode-sync.h"
#include "modaloverlay.h"
#include "networkstyle.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "receiverequestdialog.h"
#include "sendcoinsdialog.h"
#include "sparkname.h"
#include "sparknamespage.h"
#include "splashscreen.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "transactionview.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "validation.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "walletview.h"

#include <QAbstractItemDelegate>
#include <QAbstractSpinBox>
#include <QAction>
#include <QColor>
#include <QComboBox>
#include <QElapsedTimer>
#include <QFrame>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QListView>
#include <QLocale>
#include <QPainter>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QScopeGuard>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSignalSpy>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QStyleOptionViewItem>
#include <QTableView>
#include <QTest>
#include <QTextEdit>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>
#include <QToolTip>
#include <QVariant>

#include <memory>
#include <atomic>
#include <chrono>
#include <future>
#include <thread>

namespace {
class TransactionHistory : public QAbstractTableModel
{
public:
    static constexpr int ROWS = 10000;
    mutable int reads = 0;
    int conflictedRow = -1;
    int lockedRow = -1;
    int newestStatusRow = -1;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override { return parent.isValid() ? 0 : ROWS; }
    int columnCount(const QModelIndex& parent = QModelIndex()) const override { return parent.isValid() ? 0 : 7; }
    QVariant data(const QModelIndex& index, int role) const override
    {
        ++reads;
        if (role == TransactionTableModel::StatusRole)
            return index.row() == conflictedRow ? TransactionStatus::Conflicted : TransactionStatus::Confirmed;
        if (role == TransactionTableModel::InstantSendRole ||
            (role == Qt::EditRole && index.column() == TransactionTableModel::InstantSend))
            return index.row() == lockedRow;
        if (role == Qt::EditRole)
            return index.column() == TransactionTableModel::Status && index.row() == newestStatusRow ? ROWS : index.row();
        return QVariant();
    }
};
}

void WalletUiTests::confirmationRefresh()
{
    TransactionHistory history;
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&history);
    proxy.setLimit(5);
    proxy.setShowInactive(false);
    proxy.setDynamicSortFilter(true);
    proxy.setSortRole(Qt::EditRole);
    proxy.sort(TransactionTableModel::Date, Qt::DescendingOrder);
    QCOMPARE(proxy.rowCount(), 5);
    QCOMPARE(proxy.mapToSource(proxy.index(0, 0)).row(), TransactionHistory::ROWS - 1);
    QSignalSpy repaint(&proxy, &QAbstractItemModel::dataChanged);

    history.reads = 0;
    proxy.refreshConfirmations();
    QCOMPARE(repaint.count(), 1);
    QCOMPARE(history.reads, 0);

    // A targeted update still removes and restores a conflicted recent transaction.
    const auto latest = history.index(TransactionHistory::ROWS - 1, 0);
    history.conflictedRow = latest.row();
    Q_EMIT history.dataChanged(latest, latest);
    QCOMPARE(proxy.mapToSource(proxy.index(0, 0)).row(), TransactionHistory::ROWS - 2);
    history.conflictedRow = -1;
    Q_EMIT history.dataChanged(latest, latest);
    QCOMPARE(proxy.mapToSource(proxy.index(0, 0)).row(), TransactionHistory::ROWS - 1);
    QVERIFY(history.reads < 100);

    // Lock expiry may have no individual transaction notification.
    proxy.setInstantSendFilter(TransactionFilterProxy::InstantSendFilter_Yes);
    QCOMPARE(proxy.rowCount(), 0);
    history.lockedRow = latest.row();
    proxy.refreshConfirmations();
    QCOMPARE(proxy.rowCount(), 1);
    history.lockedRow = -1;
    proxy.refreshConfirmations();
    QCOMPARE(proxy.rowCount(), 0);

    proxy.setInstantSendFilter(TransactionFilterProxy::InstantSendFilter_All);
    proxy.sort(TransactionTableModel::InstantSend, Qt::DescendingOrder);
    history.lockedRow = 42;
    proxy.refreshConfirmations();
    QCOMPARE(proxy.mapToSource(proxy.index(0, 0)).row(), 42);

    proxy.sort(TransactionTableModel::Status, Qt::DescendingOrder);
    history.newestStatusRow = 17;
    proxy.refreshConfirmations();
    QCOMPARE(proxy.mapToSource(proxy.index(0, 0)).row(), 17);
}

void WalletUiTests::themeTintColors()
{
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    const QIcon instantSendIcon(":/icons/instantsend");
    QVERIFY(!instantSendIcon.isNull());
    QVERIFY(!style->TextColorIcon(instantSendIcon).isNull());

    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        const auto& colors = GUIUtil::themeColors();
        for (const auto& tint : {colors.wineTint, colors.tealTint, colors.goldTint}) {
            const QColor color(tint);
            QVERIFY2(color.isValid(), qPrintable(tint));
            QVERIFY(color.alpha() > 0);
            QCOMPARE(color.alpha() < 255, mode == GUIUtil::ThemeMode::Dark);
            QWidget swatch;
            swatch.setStyleSheet(QStringLiteral("background-color: %1;").arg(tint));
            swatch.ensurePolished();
            QCOMPARE(swatch.palette().color(QPalette::Window), color);
        }
    }
}

void WalletUiTests::paymentCodeIndexesWithoutAddressCache()
{
    CWallet wallet;
    wallet.mapCustomKeyValues.emplace(bip47::PcodeLabel() + "test-payment-code", "Test label");
    const auto addedSlots = uiInterface.NotifySparkNameAdded.num_slots();
    const auto removedSlots = uiInterface.NotifySparkNameRemoved.num_slots();
    PcodeAddressTableModel model(&wallet);
    QCOMPARE(uiInterface.NotifySparkNameAdded.num_slots(), addedSlots);
    QCOMPARE(uiInterface.NotifySparkNameRemoved.num_slots(), removedSlots);
    QCOMPARE(model.columnCount(QModelIndex()), 2);
    const auto index = model.index(0, 1);
    QVERIFY(index.isValid());
    QCOMPARE(model.data(index, Qt::DisplayRole).toString(), QString("test-payment-code"));
    QVERIFY(!model.index(0, 2).isValid());
    QVERIFY(!model.index(1, 0).isValid());
    QVERIFY(!model.index(0, 0, index).isValid());

    auto addressBook = std::make_unique<AddressTableModel>(&wallet);
    {
        PcodeAddressTableModel temporaryModel(&wallet);
    }
    QCOMPARE(uiInterface.NotifySparkNameAdded.num_slots(), addedSlots + 1);
    QCOMPARE(uiInterface.NotifySparkNameRemoved.num_slots(), removedSlots + 1);
    const int addressRows = addressBook->rowCount(QModelIndex());
    const CSparkNameBlockIndexData name("test-name", "test-spark-address", 100, "");
    uiInterface.NotifySparkNameAdded(name);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
    QCOMPARE(addressBook->rowCount(QModelIndex()), addressRows + 1);
    QCOMPARE(model.rowCount(QModelIndex()), 1);
    uiInterface.NotifySparkNameRemoved(name);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
    QCOMPARE(addressBook->rowCount(QModelIndex()), addressRows);
    QCOMPARE(model.rowCount(QModelIndex()), 1);
    addressBook.reset();
    QCOMPARE(uiInterface.NotifySparkNameAdded.num_slots(), addedSlots);
    QCOMPARE(uiInterface.NotifySparkNameRemoved.num_slots(), removedSlots);
}

void WalletUiTests::splashMessageDoesNotProcessEvents()
{
    class TestSplashScreen : public SplashScreen
    {
    public:
        using SplashScreen::SplashScreen;
        int paints = 0;
        void paintEvent(QPaintEvent* event) override
        {
            ++paints;
            SplashScreen::paintEvent(event);
        }
    };
    const auto loadWalletSlots = uiInterface.LoadWallet.num_slots();
    const std::unique_ptr<const NetworkStyle> networkStyle(NetworkStyle::instantiate("regtest"));
    auto* splash = new TestSplashScreen(networkStyle.get());
    const auto cleanup = qScopeGuard([splash, loadWalletSlots] {
        splash->slotFinish(nullptr);
        QCoreApplication::sendPostedEvents(splash, QEvent::DeferredDelete);
        QCOMPARE(uiInterface.LoadWallet.num_slots(), loadWalletSlots);
    });
    splash->setAttribute(Qt::WA_DontShowOnScreen);
    splash->show();
    QCoreApplication::processEvents();
    const int paintsBeforeMessage = splash->paints;
    bool callbackRan = false;
    QObject receiver;
    QMetaObject::invokeMethod(&receiver, [&callbackRan] { callbackRan = true; }, Qt::QueuedConnection);

    uiInterface.InitMessage("Loading wallet...");
    QVERIFY(splash->paints > paintsBeforeMessage);
    QVERIFY(!callbackRan);
    QCoreApplication::processEvents();
    QVERIFY(callbackRan);

    const int paintsBeforeProgress = splash->paints;
    std::thread core([] {
        uiInterface.ShowProgress("Verifying blocks...", 1);
        uiInterface.ShowProgress("Verifying blocks...", 2);
        uiInterface.InitMessage("Loading wallet...");
    });
    core.join();
    QCoreApplication::sendPostedEvents(splash, QEvent::MetaCall);
    QCOMPARE(splash->paints, paintsBeforeProgress);
    QCoreApplication::processEvents();
    QVERIFY(splash->paints > paintsBeforeProgress);

    auto* timer = splash->findChild<QTimer*>();
    QVERIFY(timer);
    QVERIFY(timer->isActive());
    splash->showProgress("Verifying blocks...", 50);
    QVERIFY(!timer->isActive());
    splash->showProgress("", 100);
    QVERIFY(timer->isActive());
    splash->hide();
    QVERIFY(!timer->isActive());

    auto* closeButton = splash->findChild<QToolButton*>();
    QVERIFY(closeButton);
    QVERIFY(!closeButton->accessibleName().isEmpty());
    QCOMPARE(closeButton->focusPolicy(), Qt::StrongFocus);
}

void WalletUiTests::splashShutdownControls()
{
    extern std::atomic<bool> fRequestShutdown;
    const bool wasShuttingDown = fRequestShutdown.exchange(false);
    const auto restoreShutdown = qScopeGuard([wasShuttingDown] { fRequestShutdown = wasShuttingDown; });
    const std::unique_ptr<const NetworkStyle> networkStyle(NetworkStyle::instantiate("regtest"));
    auto* splash = new SplashScreen(networkStyle.get());
    const auto cleanup = qScopeGuard([splash] {
        splash->slotFinish(nullptr);
        QCoreApplication::sendPostedEvents(splash, QEvent::DeferredDelete);
    });
    splash->setAttribute(Qt::WA_DontShowOnScreen);
    splash->show();
    splash->activateWindow();
    QCoreApplication::processEvents();
    auto* closeButton = splash->findChild<QToolButton*>();
    auto* timer = splash->findChild<QTimer*>();
    QVERIFY(closeButton);
    QVERIFY(timer);
    QVERIFY(splash->focusWidget());

    QTest::keyClick(splash->focusWidget(), Qt::Key_Space);
    QVERIFY(!ShutdownRequested());
    QTest::keyClick(splash, Qt::Key_Tab);
    QCOMPARE(splash->focusWidget(), closeButton);
    QTest::keyClick(closeButton, Qt::Key_Space);
    QVERIFY(ShutdownRequested());
    QVERIFY(closeButton->isHidden());

    // Late updates must not replace shutdown until core accepts a database rebuild.
    splash->showStatus("Loading block index...");
    splash->showProgress("Verifying blocks...", 50);
    QVERIFY(closeButton->isHidden());
    QVERIFY(timer->isActive());
    fRequestShutdown = false;
    splash->showStatus("Loading block index...");
    QVERIFY(!closeButton->isHidden());
    QCOMPARE(splash->focusWidget(), splash);
    QTest::keyClick(splash->focusWidget(), Qt::Key_Space);
    QVERIFY(!ShutdownRequested());
    splash->showProgress("Verifying blocks...", 50);
    QVERIFY(!timer->isActive());

    // Progress can also be the first update after a canceled shutdown.
    closeButton->click();
    QVERIFY(ShutdownRequested());
    fRequestShutdown = false;
    splash->showProgress("Verifying blocks...", 50);
    QVERIFY(!closeButton->isHidden());
    QVERIFY(!timer->isActive());
}

void WalletUiTests::deferredTransactionsKeepOrder()
{
    CWallet wallet;
    OptionsModel options;
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    WalletModel model(style.get(), &wallet, &options);
    auto* table = model.getTransactionTableModel();
    QSignalSpy inserted(table, &QAbstractItemModel::rowsInserted);
    QSignalSpy removed(table, &QAbstractItemModel::rowsRemoved);

    // A metadata-only wallet entry is sufficient; this test never reads status roles.
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    tx.vout.emplace_back(COIN, CScript());
    const auto transaction = MakeTransactionRef(tx);
    wallet.mapWallet.emplace(transaction->GetHash(), CWalletTx(&wallet, transaction));
    const QString hash = QString::fromStdString(transaction->GetHash().GetHex());

    std::promise<void> locked, release;
    auto ready = locked.get_future();
    auto done = release.get_future();
    std::thread validation([&] {
        LOCK(cs_main);
        locked.set_value();
        done.wait_for(std::chrono::seconds(2));
    });
    ready.wait();
    QElapsedTimer timer;
    timer.start();
    table->updateTransaction(hash, CT_NEW, true);
    table->updateTransaction(hash, CT_DELETED, false);
    const auto elapsed = timer.elapsed();
    release.set_value();
    validation.join();
    QVERIFY(elapsed < 1000);
    QTRY_COMPARE(inserted.count(), 1);
    QCOMPARE(removed.count(), 1);
    QCOMPARE(table->rowCount(QModelIndex()), 0);

    // A synchronous view callback may enqueue another update while insertion finishes.
    inserted.clear();
    removed.clear();
    connect(table, &QAbstractItemModel::rowsInserted, &model, [&] {
        table->updateTransaction(hash, CT_DELETED, false);
    });
    table->updateTransaction(hash, CT_NEW, true);
    QCOMPARE(inserted.count(), 1);
    QCOMPARE(removed.count(), 1);
    QCOMPARE(table->rowCount(QModelIndex()), 0);
}

void WalletUiTests::failedAbandonKeepsTransactionVisible()
{
    CWallet wallet;
    OptionsModel options;
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    WalletModel model(style.get(), &wallet, &options);
    auto* table = model.getTransactionTableModel();

    // A non-final record can display its status without initializing LLMQ services.
    CMutableTransaction tx;
    tx.nLockTime = 100;
    tx.vin.emplace_back(COutPoint(uint256S("01"), 0), CScript(), 0);
    tx.vout.emplace_back(COIN, CScript());
    const auto transaction = MakeTransactionRef(tx);
    const auto hash = transaction->GetHash();
    wallet.mapWallet.emplace(hash, CWalletTx(&wallet, transaction));
    table->updateTransaction(QString::fromStdString(hash.GetHex()), CT_NEW, true);

    // Model a transaction entering the mempool after the context menu was opened.
    const auto removeTransaction = qScopeGuard([&] { mempool.removeRecursive(*transaction); });
    QVERIFY(mempool.addUnchecked(hash, CTxMemPoolEntry(transaction, 0, 0, 0, 0, false, 0, LockPoints()), false));
    QVERIFY(!model.abandonTransaction(hash));
    TransactionView view(style.get());
    view.setModel(&model);
    auto* tableCard = view.findChild<QFrame*>(QStringLiteral("tableCard"));
    QVERIFY(tableCard);
    auto* list = tableCard->findChild<QTableView*>();
    QVERIFY(list);
    QCOMPARE(list->model()->rowCount(), 1);
    list->selectRow(0);
    QVERIFY(!list->selectionModel()->selectedRows().isEmpty());
    QSignalSpy removed(table, &QAbstractItemModel::rowsRemoved);

    QVERIFY(QMetaObject::invokeMethod(&view, "abandonTx", Qt::DirectConnection));
    QCOMPARE(removed.count(), 0);
    QCOMPARE(table->rowCount(QModelIndex()), 1);
    QCOMPARE(list->model()->rowCount(), 1);
}

void WalletUiTests::themeChangePreservesWidgetState()
{
    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    QWidget enabled, disabled;
    disabled.setUpdatesEnabled(false);
    QPointer<QWidget> destroyed = new QWidget;
    QObject receiver;
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged, &receiver, [&] {
        delete destroyed.data();
    });
    GUIUtil::setThemeMode(previousTheme == GUIUtil::ThemeMode::Light ? GUIUtil::ThemeMode::Dark : GUIUtil::ThemeMode::Light);
    QVERIFY(enabled.updatesEnabled());
    QVERIFY(!disabled.updatesEnabled());
    QVERIFY(destroyed.isNull());
}

void WalletUiTests::sparkNamesRefreshAfterModelDestruction()
{
    CWallet wallet;
    OptionsModel options;
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    auto model = std::make_unique<WalletModel>(style.get(), &wallet, &options);
    auto client = std::make_unique<ClientModel>(&options);
    SparkNamesPage page(style.get());
    page.setModel(model.get());
    page.setClientModel(client.get());

    Q_EMIT model->getAddressTableModel()->dataChanged(QModelIndex(), QModelIndex());
    QVERIFY(page.refreshScheduled);
    client.reset();
    QVERIFY(!page.clientModel);
    QTRY_VERIFY(!page.refreshScheduled);

    // Shutdown removes wallet tabs before destroying their models, leaving a
    // pending page callback alive after the address-table sender is destroyed.
    Q_EMIT model->getAddressTableModel()->dataChanged(QModelIndex(), QModelIndex());
    QVERIFY(page.refreshScheduled);
    model.reset();
    QVERIFY(!page.model);
    QVERIFY(!page.addressModel);
    QTRY_VERIFY(!page.refreshScheduled);
}

void WalletUiTests::sparkNameRegistrationDetails()
{
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    CreateSparkNamePage dialog(style.get());
    auto* name = dialog.findChild<QLineEdit*>("sparkNameEdit");
    auto* years = dialog.findChild<QSpinBox*>("numberOfYearsEdit");
    auto* fee = dialog.findChild<QLabel*>("feeTextLabel");
    auto* detailsButton = dialog.findChild<QToolButton*>("detailsButton");
    auto* details = dialog.findChild<QWidget*>("detailsWidget");
    auto* additionalInfo = dialog.findChild<QTextEdit*>("additionalInfoEdit");
    QVERIFY(name && years && fee && detailsButton && details && additionalInfo);

    struct FeeTier { int length; int annualFee; };
    for (const auto tier : {FeeTier{1, 1000}, {2, 100}, {3, 10}, {5, 10}, {6, 1}, {20, 1}}) {
        name->setText(QString(tier.length, QLatin1Char('a')));
        for (const int period : {1, 3}) {
            years->setValue(period);
            QString displayedFee = fee->text();
            QVERIFY(displayedFee.endsWith(QStringLiteral(" FIRO")));
            displayedFee.chop(5);
            bool parsed = false;
            QCOMPARE(QLocale().toInt(displayedFee, &parsed), tier.annualFee * period);
            QVERIFY(parsed);
        }
    }
    for (const auto& invalidName : {QString(), QStringLiteral("bad name"), QStringLiteral("@sparky")}) {
        name->setText(invalidName);
        QVERIFY(!fee->text().contains(QStringLiteral("FIRO")));
    }

    const QString metadata = QStringLiteral("Public details to retain");
    QVERIFY(details->isHidden());
    detailsButton->click();
    QVERIFY(!details->isHidden());
    additionalInfo->setPlainText(metadata);
    detailsButton->click();
    QVERIFY(details->isHidden());
    detailsButton->click();
    QCOMPARE(additionalInfo->toPlainText(), metadata);

    // Extensions can reveal existing details before the first show. Fit the
    // editor unless the available screen height requires scrolling.
    dialog.setAttribute(Qt::WA_DontShowOnScreen);
    dialog.show();
    QCoreApplication::processEvents();
    auto* scroll = dialog.findChild<QScrollArea*>("scrollArea");
    QVERIFY(scroll);
    const int maximumHeight = qMax(dialog.minimumHeight(), GUIUtil::availableScreenSize(&dialog).height() - 40
        - (dialog.frameGeometry().height() - dialog.height()));
    QVERIFY(scroll->verticalScrollBar()->maximum() == 0 || dialog.height() == maximumHeight);
    detailsButton->click();
    dialog.resize(dialog.width(), qMin(460, dialog.height()));
    detailsButton->click();
    QCoreApplication::processEvents();
    QVERIFY(scroll->verticalScrollBar()->maximum() == 0 || dialog.height() == maximumHeight);
    const int expandedHeight = dialog.height();
    detailsButton->click();
    detailsButton->click();
    QCOMPARE(dialog.height(), expandedHeight);

    const auto hideTooltip = qScopeGuard([] { QToolTip::hideText(); });
    for (const char* objectName : {"nameHelpButton", "feeHelpButton"}) {
        auto* help = dialog.findChild<QToolButton*>(objectName);
        QVERIFY(help);
        QVERIFY(!help->toolTip().isEmpty());
        QVERIFY(help->focusPolicy() & Qt::TabFocus);
        QTest::keyClick(help, Qt::Key_Space);
        QCOMPARE(QToolTip::text(), help->toolTip());
    }
}

void WalletUiTests::initialSyncQueryDoesNotBlock()
{
    ClientModel model(nullptr);
    std::promise<void> locked, release;
    auto ready = locked.get_future();
    auto done = release.get_future();
    std::thread validation([&] {
        LOCK(cs_main);
        locked.set_value();
        done.wait_for(std::chrono::seconds(2));
    });
    ready.wait();
    QElapsedTimer timer;
    timer.start();
    const bool initialSync = model.inInitialBlockDownload();
    model.cachedVerificationProgress = 0.625;
    const auto progress = model.getVerificationProgress(nullptr);
    const auto date = model.getLastBlockDate();
    const auto elapsed = timer.elapsed();
    release.set_value();
    validation.join();
    QVERIFY(initialSync);
    QVERIFY(elapsed < 1000);
    QCOMPARE(progress, 0.625);
    QVERIFY(date.isValid());

    CBlockIndex header;
    header.nHeight = 100;
    header.nTime = GetTime();
    model.cachedNumBlocks = 5;
    uiInterface.NotifyHeaderTip(false, &header);
    QVERIFY(!model.inInitialBlockDownload());
    QCOMPARE(model.cachedNumBlocks.load(), 5);
    uiInterface.NotifyBlockTip(true, &header);
    QVERIFY(!model.inInitialBlockDownload());
    QCOMPARE(model.cachedNumBlocks.load(), 100);
    QSignalSpy tips(&model, &ClientModel::numBlocksChanged);
    header.nHeight = 101;
    uiInterface.NotifyBlockTip(true, &header);
    model.updateTimer();
    QCOMPARE(tips.count(), 2);
    QCOMPARE(tips.last().at(0).toInt(), 101);
    QCOMPARE(tips.last().at(3).toBool(), false);
    model.updateTimer();
    QCOMPARE(tips.count(), 2);
}

void WalletUiTests::synchronizationProgress()
{
    const auto oldDisableWallet = GetArg("-disablewallet", "0");
    const auto oldNetwork = Params().NetworkIDString();
    const auto oldMasternodeSync = masternodeSync;
    auto oldConnections = std::move(g_connman);
    const bool oldReindex = fReindex;
    const auto restoreNode = qScopeGuard([&] {
        ForceSetArg("-disablewallet", oldDisableWallet);
        SelectParams(oldNetwork);
        masternodeSync = oldMasternodeSync;
        fReindex = oldReindex;
        g_connman = std::move(oldConnections);
    });
    SelectParams(CBaseChainParams::TESTNET);
    fReindex = false;
    g_connman = std::make_unique<CConnman>(0, 0);
    masternodeSync.Reset();
    masternodeSync.SwitchToNextAsset(*g_connman);
    masternodeSync.SwitchToNextAsset(*g_connman);
    QVERIFY(masternodeSync.IsSynced());
    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    const std::unique_ptr<const NetworkStyle> networkStyle(NetworkStyle::instantiate("test"));
    QVERIFY(platformStyle);
    QVERIFY(networkStyle);
    ClientModel model(nullptr);
    const auto now = QDateTime::currentDateTime();
    model.cachedNumBlocks = 10;
    model.cachedLastBlockDate = now.addDays(-1);
    model.cachedInitialBlockDownload = true;
    model.cachedVerificationProgress = 0.6251;

    // Validation may be busy throughout these updates. All GUI reads use real cached values.
    std::promise<void> locked, release;
    auto ready = locked.get_future();
    auto done = release.get_future();
    std::thread validation([&] {
        LOCK(cs_main);
        locked.set_value();
        done.wait_for(std::chrono::seconds(30));
    });
    const auto releaseValidation = qScopeGuard([&] {
        release.set_value();
        validation.join();
    });
    ready.wait();
    ForceSetArg("-disablewallet", "0");
    BitcoinGUI gui(platformStyle.get(), networkStyle.get());
    gui.clientModel = &model;
    gui.setNumConnections(1);
    gui.setNumBlocks(10, now.addDays(-1), 0.6251, false);
    gui.setNumBlocks(100, now.addDays(-10), 0.99, true);
    QVERIFY(gui.progressBarLabel->text().startsWith("Syncing Headers"));
    QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("62.51%"));
    const int stalledFrame = gui.spinnerFrame;
    gui.updateSyncStatus();
    QCOMPARE(gui.spinnerFrame, stalledFrame);
    gui.setNumBlocks(11, now.addDays(-1), 0.65, false);
    QVERIFY(gui.spinnerFrame != stalledFrame);
    QVERIFY(gui.progressBarLabel->text().startsWith("Syncing Headers"));
    QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("65.00%"));

    // Header completion must update the phase even without another block.
    gui.setNumBlocks(101, now, 0.99, true);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Synchronizing with network..."));
    QCOMPARE(gui.navigationSyncFraction, 0.65);
    gui.setNumConnections(0);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Connecting to peers..."));
    QCOMPARE(gui.navigationSyncFraction, 0.65);
    gui.setNumConnections(1);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Synchronizing with network..."));
    QCOMPARE(gui.navigationSyncFraction, 0.65);

    // A lull in a caught-up chain is not evidence of an active header download.
    model.cachedInitialBlockDownload = false;
    model.cachedNumBlocks = 101;
    model.cachedBestHeaderHeight = 101;
    model.cachedLastBlockDate = now.addSecs(-2LL * 60 * 60);
    gui.setNumBlocks(101, model.cachedLastBlockDate, 0.99, false);
    gui.setNumBlocks(101, model.cachedLastBlockDate, 0.99, true);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Catching up..."));
    QVERIFY(!gui.modalOverlay->isHeaderSyncPending());
    QVERIFY(!gui.modalOverlay->isLayerVisible());

    // A fresh block tip does not finish pending headers after the IBD latch clears.
    model.cachedLastBlockDate = now;
    gui.setNumBlocks(101, now, 0.99, false);
    QVERIFY(!model.inInitialBlockDownload());
    QVERIFY(!gui.blockchainSyncInProgress());
    gui.setNumBlocks(102, now.addDays(-5), 0.99, true);
    QVERIFY(gui.modalOverlay->isHeaderSyncPending());
    QVERIFY(gui.blockchainSyncInProgress());
    QVERIFY(!gui.navigationSyncCard->isHidden());
    QVERIFY(gui.progressBarLabel->text().startsWith("Syncing Headers"));
    gui.setNumBlocks(102, now, 0.99, true);

    model.cachedLastBlockDate = now;
    masternodeSync.Reset();
    masternodeSync.SwitchToNextAsset(*g_connman);
    gui.setNumBlocks(101, now, 1.0, false);
    gui.setAdditionalDataSyncProgress(-0.25);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Finishing sync..."));
    QCOMPARE(gui.navigationSyncFraction, 1.0);
    gui.showModalOverlay();
    QVERIFY(gui.modalOverlay->isLayerVisible());
    auto* refreshTimer = gui.findChild<QTimer*>("syncStateTimer");
    QVERIFY(refreshTimer);
    QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
    QVERIFY(gui.modalOverlay->isLayerVisible());
    const int waitingFrame = gui.spinnerFrame;
    QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
    QCOMPARE(gui.spinnerFrame, waitingFrame);

    // Observe queued balloons without invoking the platform notification service.
    struct NotificationCalls : QObject {
        int count{0};
        bool eventFilter(QObject*, QEvent* event) override
        {
            if (event->type() != QEvent::MetaCall) {
                return false;
            }
            ++count;
            return true;
        }
    } notifications;
    gui.installEventFilter(&notifications);
    QCoreApplication::sendPostedEvents(&gui, QEvent::MetaCall);
    notifications.count = 0;
    gui.incomingTransaction("today", 0, COIN, "Received", "", "");
    QCoreApplication::sendPostedEvents(&gui, QEvent::MetaCall);
    QCOMPARE(notifications.count, 0);

    masternodeSync.SwitchToNextAsset(*g_connman);
    gui.setAdditionalDataSyncProgress(1.0);
    gui.incomingTransaction("today", 0, COIN, "Received", "", "");
    QCoreApplication::sendPostedEvents(&gui, QEvent::MetaCall);
    QCOMPARE(notifications.count, 1);
    QVERIFY(gui.navigationSyncCard->isHidden());
    QVERIFY(gui.labelBlocksIcon->toolTip().contains("Up to date"));
    const auto syncedIcon = gui.labelBlocksIcon->pixmap().toImage();
    gui.updateProgressBarLabel("Batch verifying Spark Proofs...");
    QCOMPARE(gui.navigationSyncLabel->toolTip(), QStringLiteral("Synced"));
    QVERIFY(gui.progressBarLabel->isHidden());
    QVERIFY(gui.navigationSyncCard->isHidden());
    QVERIFY(gui.navigationSyncProgress->property("synced").toBool());
    QVERIFY(gui.modalOverlay->findChild<QProgressBar*>("progressBar")->property("synced").toBool());
    QCOMPARE(gui.labelBlocksIcon->pixmap().toImage(), syncedIcon);
    gui.updateProgressBarLabel(QString());
    QVERIFY(gui.navigationSyncCard->isHidden());

    gui.setNumConnections(0);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Connecting to peers..."));
    QVERIFY(!gui.navigationSyncProgress->property("synced").toBool());
    QVERIFY(!gui.modalOverlay->findChild<QProgressBar*>("progressBar")->property("synced").toBool());
    QVERIFY(gui.labelBlocksIcon->pixmap().toImage() != syncedIcon);
    QVERIFY(gui.labelBlocksIcon->toolTip().contains("Connecting to peers..."));
    QVERIFY(!gui.labelBlocksIcon->toolTip().contains("Up to date"));
    gui.setNumConnections(1);
    g_connman->SetNetworkActive(false);
    gui.setNetworkActive(false);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Network activity disabled"));
    QVERIFY(!gui.modalOverlay->findChild<QProgressBar*>("progressBar")->property("synced").toBool());
    QVERIFY(gui.labelBlocksIcon->pixmap().toImage() != syncedIcon);
    QVERIFY(gui.labelBlocksIcon->toolTip().contains("Network activity disabled"));
    QVERIFY(!gui.labelBlocksIcon->toolTip().contains("Up to date"));
    g_connman->SetNetworkActive(true);
    gui.setNetworkActive(true);

    gui.modalOverlay->showHide(true);
    model.cachedLastBlockDate = now.addDays(-1);
    model.cachedBestHeaderHeight = 102;
    model.cachedBestHeaderTime = now.toSecsSinceEpoch();
    model.cachedVerificationProgress = 0.987;
    QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Catching up..."));
    QCOMPARE(gui.navigationSyncFraction, 0.987);
    QCOMPARE(gui.modalOverlay->findChild<QLabel*>("percentageProgress")->text(), QStringLiteral("98.70%"));
    QVERIFY(gui.modalOverlay->isLayerVisible());
    gui.incomingTransaction("today", 0, COIN, "Received", "", "");
    QCoreApplication::sendPostedEvents(&gui, QEvent::MetaCall);
    QCOMPARE(notifications.count, 1);
    model.cachedLastBlockDate = now;
    gui.setNumBlocks(102, now, 1.0, false);
    QCOMPARE(gui.labelBlocksIcon->pixmap().toImage(), syncedIcon);
    QVERIFY(gui.labelBlocksIcon->toolTip().contains("Up to date"));

    fReindex = true;
    gui.setNumBlocks(102, now, 0.25, false);
    gui.setNumBlocks(103, now.addDays(-5), 0.99, true);
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Reindexing blocks on disk..."));
    QCOMPARE(gui.navigationSyncFraction, 0.25);
    fReindex = false;
    SelectParams(CBaseChainParams::REGTEST);
    model.cachedLastBlockDate = now.addDays(-1);
    gui.setNumBlocks(102, model.cachedLastBlockDate, 1.0, false);
    QVERIFY(gui.modalOverlay->isHeaderSyncPending());
    QVERIFY(!gui.blockchainSyncInProgress());
    QVERIFY(!gui.modalOverlay->isLayerVisible());
    QCOMPARE(gui.progressBarLabel->text(), QStringLiteral("Synced"));
    QVERIFY(!gui.isActivelySyncing());
    fReindex = true;
    QVERIFY(gui.isActivelySyncing());
    fReindex = false;
    SelectParams(CBaseChainParams::TESTNET);
    model.cachedLastBlockDate = now;

    ForceSetArg("-disablewallet", "1");
    BitcoinGUI node(platformStyle.get(), networkStyle.get());
    node.clientModel = &model;
    node.setNumConnections(1);
    model.cachedInitialBlockDownload = true;
    node.setNumBlocks(10, now.addDays(-1), 0.25, false);
    node.setNumBlocks(100, now.addDays(-10), 0.99, true);
    QVERIFY(!node.progressBarLabel->isHidden());
    QVERIFY(!node.progressBar->isHidden());
    QCOMPARE(node.progressBar->value(), 250000000);
    node.setNumBlocks(101, now, 0.99, true);
    QCOMPARE(node.progressBarLabel->text(), QStringLiteral("Synchronizing with network..."));
    model.cachedInitialBlockDownload = false;
    node.setNumBlocks(101, now, 1.0, false);
    QVERIFY(node.progressBarLabel->isHidden());
    QVERIFY(node.progressBar->isHidden());
}

void WalletUiTests::synchronizationEstimates()
{
    QWidget parent;
    ModalOverlay overlay(&parent);
    const auto now = QDateTime::currentDateTime();
    auto* rate = overlay.findChild<QLabel*>("progressIncreasePerH");
    auto* remaining = overlay.findChild<QLabel*>("expectedTimeLeft");
    auto* blocks = overlay.findChild<QLabel*>("numberOfBlocksLeft");
    auto* percentage = overlay.findChild<QLabel*>("percentageProgress");
    QVERIFY(rate);
    QVERIFY(remaining);
    QVERIFY(blocks);
    QVERIFY(percentage);
    QVERIFY(!overlay.isHeaderSyncPending());
    overlay.tipUpdate(10, QDateTime(), 0.0);
    QVERIFY(overlay.blockProcessTime.isEmpty());
    overlay.tipUpdate(10, now.addDays(-1), 0.5);
    overlay.setKnownBestHeight(100, now.addDays(-10));
    QVERIFY(blocks->text().contains("Syncing Headers"));
    overlay.setKnownBestHeight(101, now);
    QCOMPARE(blocks->text(), QStringLiteral("91"));

    const qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
    for (const auto& sample : {qMakePair(timestamp, 0.4),
                              qMakePair(timestamp - 1000, 0.5),
                              qMakePair(timestamp - 1000, 0.6)}) {
        overlay.blockProcessTime = {{timestamp, 0.5}, sample};
        overlay.updateProgressDisplay();
        QCOMPARE(rate->text(), QStringLiteral("0.00%"));
        QCOMPARE(remaining->text(), QStringLiteral("Unknown..."));
    }
    overlay.blockProcessTime = {{timestamp, 0.5}, {timestamp - 1000, 0.4}};
    overlay.updateProgressDisplay();
    QVERIFY(rate->text() != QStringLiteral("0.00%"));
    QVERIFY(remaining->text() != QStringLiteral("Unknown..."));
    overlay.setSyncComplete(true);
    QCOMPARE(percentage->text(), QStringLiteral("100.00%"));
    overlay.setSyncComplete(false);
    QCOMPARE(percentage->text(), QStringLiteral("50.00%"));
    QCOMPARE(remaining->text(), QStringLiteral("Unknown..."));
    overlay.tipUpdate(101, now.addSecs(-5LL * 60 * 60), 0.99);
    overlay.setKnownBestHeight(101, now.addSecs(-5LL * 60 * 60));
    QVERIFY(!overlay.isHeaderSyncPending());
    QCOMPARE(blocks->text(), QStringLiteral("Unknown..."));
    overlay.setKnownBestHeight(101, now);
    QCOMPARE(blocks->text(), QStringLiteral("0"));
    overlay.closeClicked();
    overlay.showHide();
    QVERIFY(!overlay.isLayerVisible());
    overlay.showHide(false, true);
    QVERIFY(overlay.isLayerVisible());
}

void WalletUiTests::synchronizationWarnings()
{
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    WalletView view(style.get(), nullptr);
    auto* sendWarning = view.findChild<QPushButton*>("balanceSyncWarning");
    auto* masternodeWarning = view.findChild<QLabel*>("masternodeSyncWarning");
    QVERIFY(sendWarning);
    QVERIFY(masternodeWarning);
    view.showOutOfSyncWarning(false);
    QVERIFY(sendWarning->isHidden());
    QVERIFY(masternodeWarning->isHidden());
    view.showOutOfSyncWarning(true);
    QVERIFY(!sendWarning->isHidden());
    QVERIFY(!masternodeWarning->isHidden());
    QSignalSpy details(&view, &WalletView::outOfSyncWarningClicked);
    sendWarning->click();
    QCOMPARE(details.count(), 1);
}

void WalletUiTests::collapsedNavigationRemainsUsable()
{
    const auto oldDisableWallet = GetArg("-disablewallet", "0");
    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restore = qScopeGuard([&] {
        ForceSetArg("-disablewallet", oldDisableWallet);
        GUIUtil::setThemeMode(previousTheme);
    });
    ForceSetArg("-disablewallet", "0");
    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    const std::unique_ptr<const NetworkStyle> networkStyle(NetworkStyle::instantiate("regtest"));
    QVERIFY(platformStyle);
    QVERIFY(networkStyle);
    BitcoinGUI gui(platformStyle.get(), networkStyle.get());
    gui.setAttribute(Qt::WA_DontShowOnScreen);
    gui.setWalletActionsEnabled(true);
    gui.resize(900, 700);
    gui.show();
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        const int expandedWidth = gui.toolbar->width();
        QTest::mouseClick(gui.navigationToggleButton, Qt::LeftButton);
        QCoreApplication::processEvents();
        QVERIFY(gui.toolbar->width() < expandedWidth);
        QVERIFY(gui.centralWidget()->rect().contains(gui.toolbar->geometry()));
        for (auto* action : {gui.overviewAction, gui.sendCoinsAction, gui.receiveCoinsAction,
                             gui.historyAction, gui.sparkNamesAction, gui.masternodeAction}) {
            auto* button = qobject_cast<QToolButton*>(gui.toolbar->widgetForAction(action));
            QVERIFY(button);
            QVERIFY(button->isVisible());
            QVERIFY(gui.toolbar->rect().contains(button->geometry()));
            QCOMPARE(button->toolButtonStyle(), Qt::ToolButtonIconOnly);
            QVERIFY(!button->toolTip().isEmpty());
        }
        QSignalSpy triggered(gui.historyAction, &QAction::triggered);
        QTest::mouseClick(gui.toolbar->widgetForAction(gui.historyAction), Qt::LeftButton);
        QCOMPARE(triggered.count(), 1);
        QVERIFY(gui.historyAction->isChecked());
        QTest::mouseClick(gui.navigationToggleButton, Qt::LeftButton);
        QCOMPARE(gui.toolbar->width(), expandedWidth);
        QVERIFY(gui.historyAction->isChecked());
    }
}

/**
 * Keep styled controls and painted text on the same brand fonts after theme changes and resizing.
 * @pre The Qt test application is initialized on the GUI thread.
 */
void WalletUiTests::brandTypography()
{
    GUIUtil::loadTheme();
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    SendCoinsDialog send(style.get());
    ReceiveCoinsDialog receive(style.get());
    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        for (const QSize size : {QSize(944, 625), QSize(2100, 1400)}) {
            for (QWidget* page : {static_cast<QWidget*>(&send), static_cast<QWidget*>(&receive)}) {
                page->setAttribute(Qt::WA_DontShowOnScreen);
                page->show();
                page->resize(size);
            }
            QCoreApplication::processEvents();
            for (const char* name : {"labelFeeHeadline", "labelFeeMinimized", "payTo", "labelBalance",
                                    "labelCoinControlFee", "labelCoinControlFeeText"}) {
                auto* widget = send.findChild<QWidget*>(name);
                QVERIFY(widget);
                QCOMPARE(widget->font().family(), QStringLiteral("Source Sans Pro"));
                QCOMPARE(widget->font().pixelSize(), 16);
            }
            auto* requests = receive.findChild<QTableView*>();
            QVERIFY(requests);
            QCOMPARE(requests->font().pixelSize(), 16);
        }
        for (const auto role : {GUIUtil::TextStyle::Body, GUIUtil::TextStyle::Heading1,
                                GUIUtil::TextStyle::Heading2, GUIUtil::TextStyle::Heading3}) {
            QLabel label(QStringLiteral("Typography 0123456789"));
            const auto expected = GUIUtil::brandFont(role);
            const QString token = role == GUIUtil::TextStyle::Body ? QStringLiteral("$FONT_BODY")
                : QStringLiteral("$FONT_H%1").arg(static_cast<int>(role));
            label.setStyleSheet(GUIUtil::themed(QStringLiteral("font: %1;").arg(token)));
            label.ensurePolished();
            QCOMPARE(label.font().pixelSize(), expected.pixelSize());
            // The minimal QPA plugin used by CI has no font database.
            QCOMPARE(label.font().family(), expected.family());
            QCOMPARE(label.font().weight(), expected.weight());
        }
    }
}

/** Verify all eight recent transactions fit when the list is at its minimum height. */
void WalletUiTests::recentActivityFitsBrandFont()
{
    GUIUtil::loadTheme();
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QStandardItemModel history(8, 1);
    OverviewPage overview(style.get());
    auto* list = overview.findChild<QListView*>(QStringLiteral("listTransactions"));
    QVERIFY(list);
    list->setModel(&history);
    list->setFixedHeight(list->minimumHeight());
    list->show();
    overview.setAttribute(Qt::WA_DontShowOnScreen);
    overview.show();
    overview.resize(944, 625);
    QTRY_VERIFY(list->viewport()->rect().contains(list->visualRect(history.index(7, 0))));

    const auto index = history.index(0, 0);
    history.setData(index, TransactionRecord::RecvSpark, TransactionTableModel::TypeRole);
    history.setData(index, QIcon(":/icons/transaction_confirmed"), TransactionTableModel::InstantSendDecorationRole);
    QStyleOptionViewItem option;
    option.initFrom(list);
    option.rect = QRect(0, 0, 220, list->itemDelegate()->sizeHint(option, index).height());
    const auto renderIcons = [&](qint64 amount) {
        history.setData(index, amount, TransactionTableModel::AmountRole);
        QImage image(option.rect.size(), QImage::Format_ARGB32_Premultiplied);
        image.fill(Qt::transparent);
        QPainter painter(&image);
        list->itemDelegate()->paint(&painter, option, index);
        painter.end();
        // Changing the amount must not paint over the transaction or lock icons.
        return image.copy(0, 0, 77, image.height());
    };
    QCOMPARE(renderIcons(0), renderIcons(21000000 * COIN));
}

/**
 * Verify payment-request details can scroll while copy and close actions stay visible in both themes.
 * @pre The Qt test application is initialized on the GUI thread.
 */
void WalletUiTests::paymentRequestFitsSmallScreen()
{
    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        GUIUtil::loadTheme();
        ReceiveRequestDialog dialog;
        dialog.setAttribute(Qt::WA_DontShowOnScreen);
        dialog.show();
        dialog.resize(640, 480);
        QCoreApplication::processEvents();

        QVERIFY(dialog.height() <= 480);
        auto* scroll = dialog.findChild<QScrollArea*>("paymentRequestScroll");
        QVERIFY(scroll);
        QVERIFY(scroll->viewport()->height() > 0);
        if (scroll->widget()->minimumSizeHint().height() > scroll->viewport()->height()) {
            QVERIFY(scroll->verticalScrollBar()->maximum() > 0);
        }
        for (const char* name : {"btnCopyURI", "btnCopyAddress", "closeButton"}) {
            auto* button = dialog.findChild<QPushButton*>(name);
            QVERIFY(button);
            QVERIFY(button->isVisible());
            QVERIFY(dialog.rect().contains(QRect(button->mapTo(&dialog, QPoint()), button->size())));
        }
    }
}

/**
 * Verify request controls remain reachable in small windows and fit in both themes.
 * @pre The Qt test application is initialized on the GUI thread.
 */
void WalletUiTests::receiveFormFitsSmallScreen()
{
    GUIUtil::loadTheme();
    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    QVERIFY(platformStyle);
    ReceiveCoinsDialog dialog(platformStyle.get());
    dialog.setAttribute(Qt::WA_DontShowOnScreen);
    dialog.show();
    dialog.resize(640, 480);
    QCoreApplication::processEvents();

    QVERIFY(dialog.height() <= 480);
    auto* scroll = dialog.findChild<QScrollArea*>("requestFormScroll");
    auto* button = dialog.findChild<QPushButton*>("receiveButton");
    QVERIFY(scroll);
    QVERIFY(button);
    scroll->ensureWidgetVisible(button, 0, 0);
    QCoreApplication::processEvents();
    QVERIFY(scroll->viewport()->rect().contains(QRect(button->mapTo(scroll->viewport(), QPoint()), button->size())));

    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    dialog.resize(944, 625);
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        QTRY_COMPARE(scroll->verticalScrollBar()->maximum(), 0);
        QVERIFY(scroll->viewport()->rect().contains(QRect(button->mapTo(scroll->viewport(), QPoint()), button->size())));
    }
}

/**
 * Verify send controls fit or remain reachable with long labels, multiple recipients and both themes.
 * @pre The Qt test application is initialized on the GUI thread.
 */
void WalletUiTests::sendFormFitsSmallScreen()
{
    QSettings settings;
    QVariantMap previousFeeSettings;
    for (const char* key : {"fFeeSectionMinimized", "nFeeRadio", "nCustomFeeRadio",
                            "nSmartFeeSliderPosition", "nTransactionFee", "fPayOnlyMinFee"})
        previousFeeSettings.insert(key, settings.value(key));
    const auto restore = qScopeGuard([&] {
        for (auto it = previousFeeSettings.cbegin(); it != previousFeeSettings.cend(); ++it) {
            if (it.value().isValid())
                settings.setValue(it.key(), it.value());
            else
                settings.remove(it.key());
        }
    });
    GUIUtil::loadTheme();
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    settings.setValue("fFeeSectionMinimized", true);
    SendCoinsDialog dialog(style.get());
    dialog.setAttribute(Qt::WA_DontShowOnScreen);
    dialog.show();
    dialog.resize(944, 625);
    auto* scroll = dialog.findChild<QScrollArea*>("scrollArea");
    QVERIFY(scroll);

    // Keep a single recipient, selected inputs, privacy warning and memo reachable at the body font size.
    auto* automatic = dialog.findChild<QLabel*>("labelCoinControlAutomaticallySelected");
    auto* warning = dialog.findChild<QLabel*>("textWarning");
    QVERIFY(automatic);
    QVERIFY(warning);
    automatic->hide();
    warning->setText(QStringLiteral("You are sending Firo from a transparent address to a Spark address."));
    for (const char* name : {"frameCoinControl", "widgetCoinControl", "addressWarningRow",
                            "textWarning", "iconWarning", "messageLabel", "messageTextLabel"}) {
        auto* field = dialog.findChild<QWidget*>(name);
        QVERIFY(field);
        field->show();
    }
    for (const char* name : {"labelCoinControlAmount", "labelCoinControlFee",
                            "labelCoinControlAfterFee", "labelCoinControlChange"}) {
        auto* value = dialog.findChild<QLabel*>(name);
        QVERIFY(value);
        value->setText(QStringLiteral("1234.12345678 FIRO"));
    }
    const auto previousTheme = GUIUtil::currentThemeMode();
    const auto restoreTheme = qScopeGuard([previousTheme] { GUIUtil::setThemeMode(previousTheme); });
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        QCoreApplication::processEvents();
        for (const char* name : {"labelCoinControlQuantity", "labelCoinControlBytes",
                                "labelCoinControlAmount", "labelCoinControlLowOutput",
                                "labelCoinControlFee", "labelCoinControlAfterFee", "labelCoinControlChange"}) {
            auto* value = dialog.findChild<QLabel*>(name);
            QVERIFY(value);
            QTRY_VERIFY2(value->height() >= value->minimumSizeHint().height() &&
                         value->width() >= value->minimumSizeHint().width(), name);
        }
        QTRY_COMPARE(scroll->horizontalScrollBar()->maximum(), 0);
        for (const char* name : {"payAmount", "checkboxSubtractFeeFromAmount", "messageTextLabel", "buttonChooseFee"}) {
            auto* field = dialog.findChild<QWidget*>(name);
            QVERIFY(field);
            QVERIFY(field->isVisible());
            scroll->ensureWidgetVisible(field);
            QCoreApplication::processEvents();
            QVERIFY(scroll->viewport()->rect().contains(QRect(field->mapTo(scroll->viewport(), QPoint()), field->size())));
        }
        auto* amount = dialog.findChild<QWidget*>("payAmount");
        QVERIFY(amount);
        // The composite amount widget must not clip the styled input or unit selector.
        for (auto* child : {static_cast<QWidget*>(amount->findChild<QAbstractSpinBox*>()),
                            static_cast<QWidget*>(amount->findChild<QComboBox*>())}) {
            QVERIFY(child);
            QVERIFY(amount->rect().contains(QRect(child->mapTo(amount, QPoint()), child->size())));
        }
    }

    dialog.resize(964, 480);
    dialog.addEntry();
    auto* chooseFee = dialog.findChild<QPushButton*>("buttonChooseFee");
    QVERIFY(chooseFee);
    chooseFee->click();
    QCoreApplication::processEvents();
    QVERIFY(dialog.height() <= 480);
    QVERIFY(dialog.width() <= 964);
    for (const char* name : {"sendButton", "clearButton", "addButton", "switchFundButton"}) {
        auto* button = dialog.findChild<QPushButton*>(name);
        QVERIFY(button);
        QVERIFY(button->isVisible());
        QVERIFY(button->width() >= button->minimumSizeHint().width());
        QVERIFY(dialog.rect().contains(QRect(button->mapTo(&dialog, QPoint()), button->size())));
    }
    for (const char* name : {"payTo", "payAmount", "customFee", "buttonMinimizeFee"}) {
        auto* field = dialog.findChild<QWidget*>(name);
        QVERIFY(field);
        scroll->ensureWidgetVisible(field);
        QCoreApplication::processEvents();
        QVERIFY(field->isVisible());
        QVERIFY(scroll->viewport()->rect().contains(QRect(field->mapTo(scroll->viewport(), QPoint()), field->size())));
    }

    // Long translated captions must not force the coin-control columns off screen.
    auto* quantityCaption = dialog.findChild<QLabel*>("labelCoinControlQuantityText");
    auto* afterFeeCaption = dialog.findChild<QLabel*>("labelCoinControlAfterFeeText");
    QVERIFY(quantityCaption);
    QVERIFY(afterFeeCaption);
    quantityCaption->setText(QStringLiteral("Anzahl der ausgewählten Eingaben:"));
    afterFeeCaption->setText(QStringLiteral("Betrag nach Abzug der Transaktionsgebühren:"));
    for (const char* name : {"labelCoinControlAmount", "labelCoinControlFee",
                            "labelCoinControlAfterFee", "labelCoinControlChange"}) {
        auto* value = dialog.findChild<QLabel*>(name);
        QVERIFY(value);
        value->setText(QStringLiteral("21000000.00000000 FIRO"));
    }
    auto* minimizeFee = dialog.findChild<QPushButton*>("buttonMinimizeFee");
    auto* coinControl = dialog.findChild<QWidget*>("widgetCoinControl");
    QVERIFY(minimizeFee);
    QVERIFY(coinControl);
    minimizeFee->click();
    dialog.resize(844, 480);
    for (const auto mode : {GUIUtil::ThemeMode::Light, GUIUtil::ThemeMode::Dark}) {
        GUIUtil::setThemeMode(mode);
        QCoreApplication::processEvents();
        QTRY_COMPARE(scroll->horizontalScrollBar()->maximum(), 0);
        for (auto* label : coinControl->findChildren<QLabel*>()) {
            QTRY_VERIFY2(label->width() >= label->minimumSizeHint().width() &&
                         label->height() >= label->minimumSizeHint().height(), qPrintable(label->objectName()));
            scroll->ensureWidgetVisible(label);
            QCoreApplication::processEvents();
            QVERIFY2(scroll->viewport()->rect().contains(QRect(label->mapTo(scroll->viewport(), QPoint()), label->size())),
                     qPrintable(label->objectName()));
        }
    }
}

void WalletUiTests::receiveMnemonics()
{
    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    QVERIFY(platformStyle);
    ReceiveCoinsDialog dialog(platformStyle.get());
    for (const char* name : {"label_2", "label", "label_3"}) {
        auto* label = dialog.findChild<QLabel*>(name);
        QVERIFY(label);
        QVERIFY(label->buddy());
        QVERIFY(label->text().contains(QLatin1Char('&')));
    }
}
