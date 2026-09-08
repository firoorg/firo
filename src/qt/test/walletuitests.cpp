// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletuitests.h"

#include "bitcoingui.h"
#include "chainparams.h"
#include "clientmodel.h"
#include "guitheme.h"
#include "guiutil.h"
#include "masternode-sync.h"
#include "modaloverlay.h"
#include "networkstyle.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "receiverequestdialog.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "ui_interface.h"
#include "util.h"
#include "validation.h"

#include <QElapsedTimer>
#include <QFrame>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QScopeGuard>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalSpy>
#include <QTest>
#include <QTimer>

#include <memory>
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
        gui.clientModel = &model;
        gui.modalOverlay->setKnownBestHeight(100, now);
        // Headers are current and IBD has ended, but the validated tip is a day old.
        gui.updateNavigationSyncCard(QString(), 0.6251);
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("62.51%"));
        gui.setAdditionalDataSyncProgress(1.0);
        QCOMPARE(gui.navigationSyncPercent->text(), QStringLiteral("62.51%"));
        gui.setNumBlocks(0, now.addDays(-1), 0.6251, false);
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QVERIFY(gui.navigationSyncFraction < 1.0);
        gui.modalOverlay->setKnownBestHeight(101, now.addDays(-10));
        gui.updateHeadersSyncProgressLabel();
        const double firstProgress = gui.navigationSyncFraction;
        gui.modalOverlay->setKnownBestHeight(102, now.addDays(-5));
        gui.updateHeadersSyncProgressLabel();
        QVERIFY(gui.navigationSyncFraction > firstProgress);
        QVERIFY(gui.navigationSyncFraction < 1.0);

        fReindex = true;
        gui.setNumBlocks(0, now.addDays(-1), 0.25, false);
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
        QVERIFY(gui.navigationSyncCard->isHidden());
        tip.nTime = now.addDays(-1).toSecsSinceEpoch();
        auto* refreshTimer = gui.findChild<QTimer*>("syncStateTimer");
        QVERIFY(refreshTimer);
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QVERIFY(!gui.navigationSyncCard->isHidden());
        QVERIFY(gui.navigationSyncFraction < 1.0);
        const QString catchUpStatus = gui.progressBarLabel->text();
        QVERIFY(QMetaObject::invokeMethod(refreshTimer, "timeout"));
        QCOMPARE(gui.progressBarLabel->text(), catchUpStatus);

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

    dialog.resize(900, 1200);
    QTRY_COMPARE(scroll->verticalScrollBar()->maximum(), 0);
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
