// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uritests.h"

#include "amount.h"
#include "base58.h"
#include "guiutil.h"
#include "key.h"
#include "paymentserver.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "rosenbridge.h"
#include "script/script.h"
#include "walletmodel.h"

#include <QCoreApplication>
#include <QUrl>

#include <array>

namespace {

const QString FIRO_ADDRESS = QStringLiteral("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs");

std::vector<unsigned char> RosenData(std::size_t payloadSize, uint8_t toChain = 3)
{
    std::vector<unsigned char> data(payloadSize, 0);
    if (payloadSize < 18) {
        return data;
    }

    data[0] = toChain;
    for (std::size_t i = 0; i < 8; ++i) {
        data[1 + i] = static_cast<unsigned char>(i + 1);
        data[9 + i] = static_cast<unsigned char>(0x11 + i);
    }

    const std::size_t addressSize = payloadSize - 18;
    data[17] = static_cast<unsigned char>(addressSize);
    for (std::size_t i = 0; i < addressSize; ++i) {
        data[18 + i] = static_cast<unsigned char>(0xa0 + i);
    }
    return data;
}

QString RosenUri(const QString& amount, const std::vector<unsigned char>& data, const QString& address = FIRO_ADDRESS)
{
    return QStringLiteral("firo:%1?amount=%2&op_return=%3")
        .arg(address, amount, RosenBridge::HexStr(data));
}

} // namespace

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("firo:MUVz3KZqgJdC3djwVCLD6ZMpDj5X1FqeKs?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    // Keep historical behavior for ordinary, non-Rosen Firo URIs.
    QVERIFY(GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=").arg(FIRO_ADDRESS), &rv));
    QCOMPARE(rv.amount, CAmount{0});
    QVERIFY(GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&amount=2").arg(FIRO_ADDRESS), &rv));
    QCOMPARE(rv.amount, 2 * COIN);

    QVERIFY(GUIUtil::parseBitcoinURI(QStringLiteral("firo://%1?amount=1").arg(FIRO_ADDRESS), &rv));
    QCOMPARE(rv.address, FIRO_ADDRESS);
    QCOMPARE(rv.amount, COIN);
}

void URITests::rosenUriTests()
{
    const std::vector<unsigned char> data = RosenData(40);
    SendCoinsRecipient rv;

    const QList<QPair<QString, CAmount>> validAmounts{
        {QStringLiteral("0.00000001"), 1},
        {QStringLiteral("1"), COIN},
        {QStringLiteral("1.23456789"), 123456789},
        {QStringLiteral("21000000"), MAX_MONEY},
    };
    for (const auto& test : validAmounts) {
        QVERIFY2(GUIUtil::parseBitcoinURI(RosenUri(test.first, data), &rv), qPrintable(test.first));
        QCOMPARE(rv.address, FIRO_ADDRESS);
        QCOMPARE(rv.amount, test.second);
        QVERIFY(rv.opReturnData == data);
    }

    const QStringList invalidAmounts{
        QString(),
        QStringLiteral("0"),
        QStringLiteral("-1"),
        QStringLiteral(".1"),
        QStringLiteral("1."),
        QStringLiteral("1.000000000"),
        QStringLiteral("21000000.00000001"),
        QStringLiteral("21000001"),
        QStringLiteral("9223372036854775807"),
        QStringLiteral("1e-8"),
        QStringLiteral("+1"),
    };
    for (const QString& amount : invalidAmounts) {
        QVERIFY2(!GUIUtil::parseBitcoinURI(RosenUri(amount, data), &rv), qPrintable(amount));
    }

    const QString hex = RosenBridge::HexStr(data);
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?op_return=%2").arg(FIRO_ADDRESS, hex), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&amount=2&op_return=%2").arg(FIRO_ADDRESS, hex), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&op_return=%2&op_return=%2").arg(FIRO_ADDRESS, hex), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&op_return=").arg(FIRO_ADDRESS), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&op_return=0").arg(FIRO_ADDRESS), &rv));
    QVERIFY(!GUIUtil::parseBitcoinURI(QStringLiteral("firo:%1?amount=1&op_return=zz").arg(FIRO_ADDRESS), &rv));

    rv.address = FIRO_ADDRESS;
    rv.amount = 123456789;
    rv.opReturnData = data;
    SendCoinsRecipient roundTrip;
    QVERIFY(GUIUtil::parseBitcoinURI(GUIUtil::formatBitcoinURI(rv), &roundTrip));
    QCOMPARE(roundTrip.address, rv.address);
    QCOMPARE(roundTrip.amount, rv.amount);
    QVERIFY(roundTrip.opReturnData == rv.opReturnData);
}

void URITests::rosenMetadataTests()
{
    const std::array<QString, 8> chainNames{{
        QStringLiteral("Ergo"),
        QStringLiteral("Cardano"),
        QStringLiteral("Bitcoin"),
        QStringLiteral("Ethereum"),
        QStringLiteral("Binance"),
        QStringLiteral("Doge"),
        QStringLiteral("Bitcoin Runes"),
        QStringLiteral("Firo"),
    }};

    for (std::size_t chain = 0; chain < chainNames.size(); ++chain) {
        const std::vector<unsigned char> data = RosenData(40, static_cast<uint8_t>(chain));
        RosenBridge::Metadata metadata;
        QVERIFY(RosenBridge::Parse(data, &metadata));
        QCOMPARE(metadata.toChain, static_cast<uint8_t>(chain));
        QCOMPARE(metadata.chainName, chainNames[chain]);
        QCOMPARE(metadata.bridgeFee, UINT64_C(0x0102030405060708));
        QCOMPARE(metadata.networkFee, UINT64_C(0x1112131415161718));
        QCOMPARE(metadata.address.size(), std::size_t{22});
    }

    QVERIFY(!RosenBridge::Parse(RosenData(40, 8)));
    QVERIFY(!RosenBridge::Parse(std::vector<unsigned char>(18, 0)));

    std::vector<unsigned char> inconsistent = RosenData(40);
    inconsistent[17] = static_cast<unsigned char>(inconsistent[17] + 1);
    QVERIFY(!RosenBridge::Parse(inconsistent));

    std::vector<unsigned char> trailing = RosenData(40);
    trailing.push_back(0);
    QVERIFY(!RosenBridge::Parse(trailing));

    QVERIFY(RosenBridge::Parse(RosenData(80)));
    QVERIFY(!RosenBridge::Parse(RosenData(81)));
}

void URITests::rosenScriptTests()
{
    struct TestCase {
        std::size_t payloadSize;
        std::size_t scriptSize;
        std::size_t outputSize;
        unsigned char pushOpcode;
    };
    const std::array<TestCase, 3> tests{{
        {75, 77, 86, 75},
        {76, 79, 88, OP_PUSHDATA1},
        {80, 83, 92, OP_PUSHDATA1},
    }};

    for (const TestCase& test : tests) {
        const std::vector<unsigned char> data = RosenData(test.payloadSize);
        QVERIFY(RosenBridge::Parse(data));

        const CScript script = RosenBridge::BuildOpReturnScript(data);
        QCOMPARE(script.size(), test.scriptSize);
        QCOMPARE(script[0], static_cast<unsigned char>(OP_RETURN));
        QCOMPARE(script[1], test.pushOpcode);
        if (test.payloadSize > 75) {
            QCOMPARE(script[2], static_cast<unsigned char>(test.payloadSize));
        }
        QVERIFY(script.IsUnspendable());

        const CTxOut output(0, script);
        QCOMPARE(output.GetDustThreshold(CFeeRate(DUST_RELAY_TX_FEE)), CAmount{0});
        QCOMPARE(RosenBridge::SerializedOutputSize(data), test.outputSize);
        QCOMPARE(::GetSerializeSize(output, SER_NETWORK, PROTOCOL_VERSION), test.outputSize);
    }
}

void URITests::paymentServerRosenUriTests()
{
    CKey key;
    key.MakeNewKey(true);
    const QString address = QString::fromStdString(CBitcoinAddress(key.GetPubKey().GetID()).ToString());
    const std::vector<unsigned char> data = RosenData(40);

    PaymentServer server(QCoreApplication::instance(), false);
    int requestCount = 0;
    SendCoinsRecipient received;
    connect(&server, &PaymentServer::receivedPaymentRequest, [&](SendCoinsRecipient recipient) {
        ++requestCount;
        received = recipient;
    });

    server.handleURIOrFile(RosenUri(QStringLiteral("1.25"), data, address));
    QCOMPARE(requestCount, 0);

    server.uiReady();
    QCOMPARE(requestCount, 1);
    QCOMPARE(received.address, address);
    QCOMPARE(received.amount, CAmount{125000000});
    QVERIFY(received.opReturnData == data);

    server.handleURIOrFile(RosenUri(QStringLiteral("2"), data, address));
    QCOMPARE(requestCount, 2);
    QCOMPARE(received.amount, 2 * COIN);
}
