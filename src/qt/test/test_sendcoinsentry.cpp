#include "test_sendcoinsentry.h"

#include "chain.h"
#include "clientmodel.h"
#include "coincontroldialog.h"
#include "platformstyle.h"
#include "sendcoinsdialog.h"
#include "ui_interface.h"

#include <QCheckBox>

#include <limits>
#include <memory>

void TestSendCoinsEntry::testGenerateWarningText()
{
    QCOMPARE(SendCoinsEntry::generateWarningText("EXRSxX8yJHudk4QswGf3N5aPVTUi5Q1ZdX56", false), QObject::tr(" You are sending Firo to an Exchange Address. Exchange Addresses can only receive funds from a transparent address."));
    QCOMPARE(SendCoinsEntry::generateWarningText("TLyNUvysvUyt2u6vL74NEkB6ed8LTQd3mz", false), QObject::tr(" You are sending Firo from a transparent address to another transparent address. To protect your privacy, we recommend using Spark addresses instead."));
    QCOMPARE(SendCoinsEntry::generateWarningText("sr1ek2uspg2v4qu0lmccrnj90tfkdpp5zmpykr4ffdprqlf0s4devl8n0674s4d4cthxsa5w9p66s5x0zgw982t80xx9uzmxysxuawmupgfa0xecj9shm6pj7l3rshqxqtg94k88fg5u856r", false), QObject::tr(" You are sending Firo from a transparent address to a Spark address."));
    QCOMPARE(SendCoinsEntry::generateWarningText("sr1ek2uspg2v4qu0lmccrnj90tfkdpp5zmpykr4ffdprqlf0s4devl8n0674s4d4cthxsa5w9p66s5x0zgw982t80xx9uzmxysxuawmupgfa0xecj9shm6pj7l3rshqxqtg94k88fg5u856r", true), QObject::tr(" You are sending Firo from a Spark address to another Spark address. This transaction is fully private."));
    QCOMPARE(SendCoinsEntry::generateWarningText("TLyNUvysvUyt2u6vL74NEkB6ed8LTQd3mz", true), QObject::tr(" You are sending Firo from a private Spark pool to a transparent address. Please note that some exchanges do not accept direct Spark deposits."));
}

void TestSendCoinsEntry::testTransactionCreationErrorDetails()
{
    const QString reason = "Transaction is too large. Select fewer inputs.";
    const WalletModel::SendCoinsReturn result(WalletModel::TransactionCreationFailed, reason);

    QCOMPARE(result.status, WalletModel::TransactionCreationFailed);
    QCOMPARE(result.reasonCommitFailed, reason);
}

void TestSendCoinsEntry::testPrivateModeUpdatesExistingEntries()
{
    const std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    QVERIFY(platformStyle);

    SendCoinsDialog dialog(platformStyle.get());
    SendCoinsEntry* firstEntry = dialog.entry;
    SendCoinsEntry* secondEntry = dialog.addEntry();
    QCheckBox* firstSubtractFee =
        firstEntry->findChild<QCheckBox*>("checkboxSubtractFeeFromAmount");
    QCheckBox* secondSubtractFee =
        secondEntry->findChild<QCheckBox*>("checkboxSubtractFeeFromAmount");
    QVERIFY(firstSubtractFee);
    QVERIFY(secondSubtractFee);

    QVERIFY(QMetaObject::invokeMethod(
        &dialog, "setAnonymizeMode", Qt::DirectConnection, Q_ARG(bool, false)));
    firstSubtractFee->setChecked(true);
    secondSubtractFee->setChecked(true);

    QVERIFY(QMetaObject::invokeMethod(
        &dialog, "setAnonymizeMode", Qt::DirectConnection, Q_ARG(bool, true)));
    QVERIFY(!firstSubtractFee->isChecked());
    QVERIFY(!secondSubtractFee->isChecked());
    QVERIFY(!firstSubtractFee->isEnabled());
    QVERIFY(!secondSubtractFee->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(
        &dialog, "setAnonymizeMode", Qt::DirectConnection, Q_ARG(bool, false)));
    QVERIFY(firstSubtractFee->isEnabled());
    QVERIFY(secondSubtractFee->isEnabled());
}

void TestSendCoinsEntry::testSparkCoinControlSizeEstimate()
{
    QCOMPARE(CoinControlDialog::estimateSparkTxBytes(1, 1, 0), 3'371U);
    QCOMPARE(CoinControlDialog::estimateSparkTxBytes(1, 0, 1), 3'083U);
    QCOMPARE(CoinControlDialog::estimateSparkTxBytes(1, 1, 1), 3'405U);
    QCOMPARE(CoinControlDialog::estimateSparkTxBytes(1, 1, 0, true), 3'403U);
    QCOMPARE(CoinControlDialog::estimateSparkTxBytes(2, 1, 0, true), 5'304U);
    QCOMPARE(
        CoinControlDialog::estimateSparkTxBytes(
            std::numeric_limits<size_t>::max(),
            std::numeric_limits<size_t>::max(),
            std::numeric_limits<size_t>::max(),
            true),
        std::numeric_limits<unsigned int>::max());
}

void TestSendCoinsEntry::testBlockHeightCacheIgnoresHeaders()
{
    ClientModel client(nullptr);
    CBlockIndex block;
    block.nHeight = 100;
    uiInterface.NotifyBlockTip(false, &block);
    QCOMPARE(client.cachedNumBlocks.load(), 100);

    // Spark send controls must not use a header-only activation height.
    CBlockIndex header;
    header.nHeight = 200;
    uiInterface.NotifyHeaderTip(false, &header);
    QCOMPARE(client.cachedBestHeaderHeight.load(), 200);
    QCOMPARE(client.cachedNumBlocks.load(), 100);

    block.nHeight = 99;
    uiInterface.NotifyBlockTip(false, &block);
    QCOMPARE(client.cachedNumBlocks.load(), 99);
}
