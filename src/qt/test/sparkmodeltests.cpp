#include "sparkmodeltests.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "automintmodel.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "sparkmodel.h"

#include "masternode-sync.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QEvent>
#include <QTest>
#include <QTimer>

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <thread>

namespace {

// Exercise the GUI callback while another thread owns the real core lock.
// The timeout lets a blocking regression fail instead of hanging the suite.
bool WithContendedLock(CCriticalSection& mutex, const std::function<void()>& callback)
{
    std::promise<void> locked, release;
    auto released = release.get_future();
    bool timedOut = false;
    std::jthread worker([&] {
        LOCK(mutex);
        locked.set_value();
        timedOut = released.wait_for(std::chrono::seconds(5)) != std::future_status::ready;
    });
    locked.get_future().wait();
    callback();
    release.set_value();
    worker.join();
    return !timedOut;
}

} // namespace

void SparkModelTests::importRetries_data()
{
    QTest::addColumn<bool>("walletLock");
    QTest::newRow("chain-lock") << false;
    QTest::newRow("wallet-lock") << true;
}

void SparkModelTests::importRetries()
{
    QFETCH(bool, walletLock);
    CWallet wallet;
    IncomingFundNotifier notifier(&wallet);
    QTimer* timer = notifier.findChild<QTimer*>();
    QVERIFY(timer);

    bool deferred = false;
    const bool responsive = WithContendedLock(walletLock ? wallet.cs_wallet : cs_main, [&] {
        // Deliver the constructor's queued startup scan on the GUI thread.
        QCoreApplication::sendPostedEvents(&notifier, QEvent::MetaCall);
        deferred = !timer->isActive();
    });
    QVERIFY(responsive);
    QVERIFY(deferred);
    // No new block or transaction notification is needed to retry the scan.
    QTRY_VERIFY(timer->isActive());
}

void SparkModelTests::addressBookDefers()
{
    CWallet wallet;
    AddressTableModel model(&wallet);
    const std::unique_ptr<const PlatformStyle> style(PlatformStyle::instantiate("other"));
    QVERIFY(style);
    AddressBookPage page(style.get(), AddressBookPage::ForEditing, AddressBookPage::SendingTab);
    page.setModel(&model);
    QComboBox* types = page.findChild<QComboBox*>("addressType");
    QVERIFY(types);
    const int originalCount = types->count();
    types->addItem("Retain this selection while busy");
    types->setCurrentIndex(originalCount);

    bool updated = true;
    const bool responsive = WithContendedLock(cs_main, [&] { updated = page.updateSpark(); });
    QVERIFY(responsive);
    QVERIFY(!updated);
    QCOMPARE(types->count(), originalCount + 1);
    QCOMPARE(types->currentIndex(), originalCount);

    page.updateSpark();
    QCOMPARE(types->count(), originalCount);
}

void SparkModelTests::autoMintDefers()
{
    CWallet wallet;
    OptionsModel options;
    SparkModel model(nullptr, &wallet, &options);
    // Reach the activation check even though this test has no network peers.
    const CMasternodeSync savedSync = masternodeSync;
    CConnman connman(0, 0);
    masternodeSync.Reset();
    masternodeSync.SwitchToNextAsset(connman);
    masternodeSync.SwitchToNextAsset(connman);
    const bool responsive = WithContendedLock(cs_main, [&] {
        model.getAutoMintSparkModel()->checkAutoMintSpark();
    });
    masternodeSync = savedSync;
    QVERIFY(responsive);
    QVERIFY(!model.getAutoMintSparkModel()->isSparkAnonymizing());
}
