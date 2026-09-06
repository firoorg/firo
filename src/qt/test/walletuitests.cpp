// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletuitests.h"

#include "clientmodel.h"
#include "ui_interface.h"
#include "util.h"
#include "validation.h"

#include <QElapsedTimer>
#include <QTest>

#include <chrono>
#include <future>
#include <thread>

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
