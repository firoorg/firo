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

#include <QAbstractItemDelegate>
#include <QAbstractSpinBox>
#include <QAction>
#include <QColor>
#include <QComboBox>
#include <QDialogButtonBox>
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

void WalletUiTests::manualConsolidation()
{
    CWallet wallet;
    CWallet* previousWallet = pwalletMain;
    CBlockIndex* previousTip = chainActive.Tip();
    const uint256 blockHash = uint256S("777");
    CBlockIndex tip;
    tip.phashBlock = &blockHash;
    tip.nHeight = 0;
    {
        LOCK(cs_main);
        QVERIFY(!mapBlockIndex.count(blockHash));
    }
    const auto restore = qScopeGuard([&] {
        LOCK(cs_main);
        chainActive.SetTip(previousTip);
        mapBlockIndex.erase(blockHash);
        pwalletMain = previousWallet;
    });
    {
        LOCK(cs_main);
        mapBlockIndex.emplace(blockHash, &tip);
        chainActive.SetTip(&tip);
        pwalletMain = &wallet;
    }
    OptionsModel options;
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    auto model = std::make_unique<WalletModel>(style.get(), &wallet, &options);
    CKey key;
    key.MakeNewKey(true);
    {
        LOCK(wallet.cs_wallet);
        QVERIFY(wallet.AddKeyPubKey(key, key.GetPubKey()));
        wallet.SetAddressBook(key.GetPubKey().GetID(), "Payouts", "receive");
    }
    CMutableTransaction funding;
    funding.vin.emplace_back(COutPoint(uint256S("01"), 0));
    funding.vout.assign(1700, CTxOut(COIN, GetScriptForDestination(key.GetPubKey().GetID())));
    CWalletTx received(&wallet, MakeTransactionRef(funding));
    received.hashBlock = blockHash;
    received.nIndex = 1;
    {
        LOCK(wallet.cs_wallet);
        wallet.mapWallet.emplace(received.GetHash(), received);
    }

    OverviewPage page(style.get());
    page.setWalletModel(model.get());
    QAction action;
    action.setEnabled(false);
    page.setConsolidationAction(&action);
    page.show();
    page.showOutOfSyncWarning(false);

    bool dialogOpened = false;
    QTimer dialogTimer;
    connect(&dialogTimer, &QTimer::timeout, &page, [&] {
        auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        dialogOpened = true;
        dialogTimer.stop();
        const auto close = qScopeGuard([&] { dialog->reject(); });
        const QSize available = GUIUtil::availableScreenSize(dialog);
        QVERIFY(dialog->width() <= qMax(available.width(), dialog->minimumSizeHint().width()));
        QVERIFY(dialog->height() <= qMax(available.height(), dialog->minimumSizeHint().height()));
        dialog->resize(400, 220);
        QCoreApplication::processEvents();
        auto* scroll = dialog->findChild<QScrollArea*>("consolidationScroll");
        auto* buttons = dialog->findChild<QDialogButtonBox*>();
        QVERIFY(scroll && buttons);
        QVERIFY(dialog->rect().contains(buttons->geometry()));
        QVERIFY(scroll->verticalScrollBar()->maximum() > 0);
        QCOMPARE(scroll->horizontalScrollBar()->maximum(), 0);
        auto* explanation = scroll->findChild<QLabel*>();
        QVERIFY(explanation);
        QVERIFY(explanation->height() >= explanation->heightForWidth(explanation->width()));
    });
    dialogTimer.start(10);
    QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
    QVERIFY(!dialogOpened); // A cleared chain warning must not bypass the full-sync action gate.
    action.setEnabled(true);
    QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
    QVERIFY(dialogOpened);
    QVERIFY(!QApplication::overrideCursor());

    page.hide();
    std::vector<WalletModel::ConsolidationCandidate> cached;
    bool scanFinished = false;
    QTRY_VERIFY(scanFinished || (scanFinished = model->pollConsolidationAddresses(cached)));
    cached = {{"previous scan", "", 1700, true}};
    QString busyMessage;
    bool chooserOpened = false;
    QTimer busyDialogTimer;
    connect(&busyDialogTimer, &QTimer::timeout, &page, [&] {
        if (auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget())) {
            if (auto* box = qobject_cast<QMessageBox*>(dialog))
                busyMessage = box->text();
            else
                chooserOpened = true;
            dialog->reject();
        }
    });
    // A regressed wait must fail without hanging the test suite.
    QTimer waitWatchdog;
    waitWatchdog.setSingleShot(true);
    connect(&waitWatchdog, &QTimer::timeout, &page, [&] { model.reset(); });
    {
        LOCK(wallet.cs_wallet);
        // Polling a manual scan must not block the GUI or discard its result buffer.
        QVERIFY(!model->pollConsolidationAddresses(cached));
        QTest::qWait(30);
        QVERIFY(!model->pollConsolidationAddresses(cached));
        QCOMPARE(cached.size(), size_t(1));
        QCOMPARE(cached[0].address, QString("previous scan"));
    }
    scanFinished = false;
    QTRY_VERIFY(scanFinished || (scanFinished = model->pollConsolidationAddresses(cached)));
    {
        std::promise<void> walletLocked, releaseWallet;
        auto locked = walletLocked.get_future();
        auto released = releaseWallet.get_future();
        auto holder = std::async(std::launch::async, [&] {
            LOCK(wallet.cs_wallet);
            walletLocked.set_value();
            released.wait();
        });
        const auto unlock = qScopeGuard([&] {
            releaseWallet.set_value();
            holder.wait();
        });
        locked.wait();
        waitWatchdog.start(8000);
        busyDialogTimer.start(10);
        QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
        busyDialogTimer.stop();
        waitWatchdog.stop();
    }
    QVERIFY(model);
    QCOMPARE(busyMessage, QString("The wallet is busy. Please try again later."));
    QVERIFY(!chooserOpened);
    scanFinished = false;
    QTRY_VERIFY(scanFinished || (scanFinished = model->pollConsolidationAddresses(cached)));
    QCOMPARE(cached[0].outputs, size_t(1700));

    page.show();
    busyMessage.clear();
    QTimer syncStart;
    syncStart.setSingleShot(true);
    connect(&syncStart, &QTimer::timeout, &page, [&] {
        QVERIFY(QApplication::overrideCursor());
        QCOMPARE(QApplication::overrideCursor()->shape(), Qt::WaitCursor);
        action.setEnabled(false);
    });
    QElapsedTimer syncWait;
    {
        std::promise<void> walletLocked, releaseWallet;
        auto locked = walletLocked.get_future();
        auto released = releaseWallet.get_future();
        auto holder = std::async(std::launch::async, [&] {
            LOCK(wallet.cs_wallet);
            walletLocked.set_value();
            released.wait();
        });
        const auto unlock = qScopeGuard([&] {
            releaseWallet.set_value();
            holder.wait();
        });
        locked.wait();
        waitWatchdog.start(8000);
        busyDialogTimer.start(10);
        syncStart.start(50);
        syncWait.start();
        QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
        syncStart.stop();
        busyDialogTimer.stop();
        waitWatchdog.stop();
    }
    QVERIFY(model);
    QVERIFY(syncWait.elapsed() < 4000);
    QVERIFY(busyMessage.isEmpty());
    QVERIFY(!chooserOpened);
    QVERIFY(!QApplication::overrideCursor());
    action.setEnabled(true);
    dialogTimer.start(10);
    QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
    page.hide();

    {
        LOCK(wallet.cs_wallet);
        wallet.LockCoin(COutPoint(received.GetHash(), 0));
    }
    WalletModelTransaction transaction{QList<SendCoinsRecipient>()};
    CMutableTransaction prepared;
    prepared.vin.emplace_back(COutPoint(received.GetHash(), 0));
    prepared.vin.emplace_back(COutPoint(received.GetHash(), 1));
    prepared.vout.emplace_back(COIN, GetScriptForDestination(key.GetPubKey().GetID()));
    *transaction.getTransaction() = CWalletTx(&wallet, MakeTransactionRef(prepared));
    size_t remainingOutputs = 0;
    bool anotherBatch = false;
    QCOMPARE(model->sendConsolidationTransaction(transaction, remainingOutputs, anotherBatch).status, WalletModel::TransactionCommitFailed);
    QVERIFY(!wallet.IsSpent(received.GetHash(), 0));
    {
        LOCK(wallet.cs_wallet);
        for (unsigned int i = 1; i < 1651; ++i)
            wallet.LockCoin(COutPoint(received.GetHash(), i));
    }
    std::vector<WalletModel::ConsolidationCandidate> manualAddresses;
    bool manualScanFinished = false;
    QTRY_VERIFY(manualScanFinished || (manualScanFinished = model->pollConsolidationAddresses(manualAddresses)));
    QCOMPARE(manualAddresses.size(), size_t(1));
    QCOMPARE(manualAddresses[0].outputs, size_t(49)); // Still available through File > Consolidate outputs.
    QVERIFY(!manualAddresses[0].sizeLimited);
    {
        LOCK(wallet.cs_wallet);
        for (unsigned int i = 1651; i < 1700; ++i)
            wallet.LockCoin(COutPoint(received.GetHash(), i));
    }
    // A manual candidate must have an affordable batch.
    funding.vout.assign(1700, CTxOut(1, GetScriptForDestination(key.GetPubKey().GetID())));
    CWalletTx dust(&wallet, MakeTransactionRef(funding));
    dust.hashBlock = blockHash;
    dust.nIndex = 1;
    {
        LOCK(wallet.cs_wallet);
        wallet.mapWallet.emplace(dust.GetHash(), dust);
    }
    manualScanFinished = false;
    QTRY_VERIFY(manualScanFinished || (manualScanFinished = model->pollConsolidationAddresses(manualAddresses)));
    QVERIFY(manualAddresses.empty());
    // A hidden-page manual scan remains safe if its model disappears while waiting.
    QTimer::singleShot(0, &page, [&] {
        model.reset();
        if (auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget()))
            dialog->reject();
    });
    QVERIFY(QMetaObject::invokeMethod(&page, "consolidateCoins", Qt::DirectConnection));
    QVERIFY(!model);
    QVERIFY(!QApplication::overrideCursor());
}

void WalletUiTests::consolidationResult()
{
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    OverviewPage page(style.get());
    for (const auto& batch : {std::make_pair(0ULL, false), std::make_pair(1ULL, false),
                             std::make_pair(2ULL, false), std::make_pair(2ULL, true)}) {
        const qulonglong remaining = batch.first;
        const bool anotherBatch = batch.second;
        QString message;
        QTimer::singleShot(0, &page, [&] {
            if (auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
                message = box->text();
                box->accept();
            }
        });
        QVERIFY(QMetaObject::invokeMethod(&page, "showConsolidationResult", Qt::DirectConnection, Q_ARG(qulonglong, remaining), Q_ARG(bool, anotherBatch)));
        QVERIFY(message.contains(QString("Eligible outputs remaining at this address: %1").arg(remaining)));
        QCOMPARE(message.contains("Another affordable batch"), anotherBatch);
        QCOMPARE(message.contains("remaining output at this same address"), remaining == 1);
        QCOMPARE(message.contains("cannot currently form an affordable batch"), remaining >= 2 && !anotherBatch);
        QVERIFY(message.contains("requires your confirmation and a network fee"));
    }
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
    const auto elapsed = timer.elapsed();
    release.set_value();
    validation.join();
    QVERIFY(initialSync);
    QVERIFY(elapsed < 1000);

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
}

void WalletUiTests::synchronizationProgress()
{
    const auto oldDisableWallet = GetArg("-disablewallet", "0");
    const auto oldNetwork = Params().NetworkIDString();
    const auto oldMasternodeSync = masternodeSync;
    CBlockIndex* oldTip = chainActive.Tip();
    const bool oldReindex = fReindex;
    const auto restoreNode = qScopeGuard([&] {
        ForceSetArg("-disablewallet", oldDisableWallet);
        SelectParams(oldNetwork);
        masternodeSync = oldMasternodeSync;
        fReindex = oldReindex;
        LOCK(cs_main);
        chainActive.SetTip(oldTip);
    });
    SelectParams(CBaseChainParams::TESTNET);
    fReindex = false;
    CBlockIndex tip;
    tip.nHeight = 0;
    const auto now = QDateTime::currentDateTime();
    tip.nTime = now.addDays(-1).toSecsSinceEpoch();
    {
        LOCK(cs_main);
        chainActive.SetTip(&tip);
    }

    CConnman connections(0, 0);
    masternodeSync.Reset();
    masternodeSync.SwitchToNextAsset(connections);
    masternodeSync.SwitchToNextAsset(connections);
    QVERIFY(masternodeSync.IsSynced());

    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    const std::unique_ptr<const NetworkStyle> networkStyle(NetworkStyle::instantiate("test"));
    QVERIFY(platformStyle);
    QVERIFY(networkStyle);
    ClientModel model(nullptr);
    model.cachedInitialBlockDownload = false;
    ForceSetArg("-disablewallet", "0");
    {
        BitcoinGUI gui(platformStyle.get(), networkStyle.get());
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setWalletActionsEnabled(true);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setClientModel(&model);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setWalletActionsEnabled(false);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setWalletActionsEnabled(true);
        gui.modalOverlay->setKnownBestHeight(100, now);
        // Headers are current and IBD has ended, but the validated tip is a day old.
        gui.updateNavigationSyncCard(QString(), 0.6251);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("62.51%"));
        gui.setAdditionalDataSyncProgress(1.0);
        QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("62.51%"));
        gui.setNumBlocks(0, now.addDays(-1), 0.6251, false);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QVERIFY(gui.navigationSyncFraction < 1.0);
        gui.modalOverlay->setKnownBestHeight(101, now.addDays(-10));
        gui.updateHeadersSyncProgressLabel();
        const double firstProgress = gui.navigationSyncFraction;
        gui.modalOverlay->setKnownBestHeight(102, now.addDays(-5));
        gui.updateHeadersSyncProgressLabel();
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        QVERIFY(gui.navigationSyncFraction > firstProgress);
        QVERIFY(gui.navigationSyncFraction < 1.0);

        fReindex = true;
        gui.setNumBlocks(0, now.addDays(-1), 0.25, false);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        const QString reindexStatus = gui.progressBarLabel->text();
        gui.updateHeadersSyncProgressLabel();
        QCOMPARE(gui.navigationSyncFraction, 0.25);
        QCOMPARE(gui.progressBarLabel->text(), reindexStatus);
        fReindex = false;

        tip.nTime = now.toSecsSinceEpoch();
        ClientModel alreadySynced(nullptr);
        QVERIFY(!alreadySynced.inInitialBlockDownload());
        gui.modalOverlay->setKnownBestHeight(103, now);
        gui.updateNavigationSyncCard(QString(), 1.0);
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        QVERIFY(gui.navigationSyncCard->isHidden());
        gui.modalOverlay->setKnownBestHeight(104, now.addDays(-1));
        gui.updateHeadersSyncProgressLabel();
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.modalOverlay->setKnownBestHeight(105, now);
        gui.updateHeadersSyncProgressLabel();
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        fReindex = true;
        gui.setNumBlocks(0, now, 0.25, false);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        fReindex = false;
        gui.setNumBlocks(0, now, 1.0, false);
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        auto* refreshTimer = gui.findChild<QTimer*>("syncStateTimer");
        QVERIFY(refreshTimer);
        masternodeSync.Reset();
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        masternodeSync.SwitchToNextAsset(connections);
        masternodeSync.SwitchToNextAsset(connections);
        gui.setAdditionalDataSyncProgress(1.0);
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        tip.nTime = now.addDays(-1).toSecsSinceEpoch();
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QVERIFY(gui.navigationSyncFraction < 1.0);
        const QString catchUpStatus = gui.progressBarLabel->text();
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QCOMPARE(gui.progressBarLabel->text(), catchUpStatus);
        tip.nTime = now.toSecsSinceEpoch();
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        gui.removeAllWallets();
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setWalletActionsEnabled(true);
        QVERIFY(gui.consolidateOutputsAction->isEnabled());
        gui.setClientModel(nullptr);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.setWalletActionsEnabled(true);
        QVERIFY(!gui.consolidateOutputsAction->isEnabled());
        gui.clientModel = &model;

        SelectParams(CBaseChainParams::REGTEST);
        QVERIFY(!gui.isActivelySyncing());
        fReindex = true;
        QVERIFY(gui.isActivelySyncing());
        fReindex = false;
        SelectParams(CBaseChainParams::TESTNET);
    }

    ForceSetArg("-disablewallet", "1");
    BitcoinGUI node(platformStyle.get(), networkStyle.get());
    node.clientModel = &model;
    QVERIFY(!node.navigationSyncCard);
    node.modalOverlay->setKnownBestHeight(100, now.addDays(-10));
    node.updateHeadersSyncProgressLabel();
    QVERIFY(!node.progressBar->isHidden());
    const int headerProgress = node.progressBar->value();
    node.modalOverlay->setKnownBestHeight(101, now.addDays(-5));
    node.updateHeadersSyncProgressLabel();
    QVERIFY(node.progressBar->value() > headerProgress);
    fReindex = true;
    node.setNumBlocks(0, now.addDays(-1), 0.25, false);
    QVERIFY(!node.progressBarLabel->isHidden());
    QVERIFY(!node.progressBar->isHidden());
    QCOMPARE(node.progressBar->value(), 250000000);
    fReindex = false;
    node.modalOverlay->setKnownBestHeight(102, now);
    tip.nTime = now.toSecsSinceEpoch();
    node.setNumBlocks(0, now, 1.0, false);
    QVERIFY(node.progressBarLabel->isHidden());
    QVERIFY(node.progressBar->isHidden());

    // Retry a header cache that was unavailable when a node-only GUI attached.
    node.modalOverlay->setKnownBestHeight(103, now.addDays(-5));
    node.updateHeadersSyncProgressLabel();
    QVERIFY(!node.progressBar->isHidden());
    model.cachedBestHeaderHeight = 104;
    model.cachedBestHeaderTime = now.toSecsSinceEpoch();
    auto* refreshTimer = node.findChild<QTimer*>("syncStateTimer");
    QVERIFY(refreshTimer);
    QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
    QVERIFY(node.progressBarLabel->isHidden());
    QVERIFY(node.progressBar->isHidden());
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
