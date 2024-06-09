#include "test_sendcoinsentry.h"

void TestSendCoinsEntry::testGenerateWarningText()
{
    QCOMPARE(SendCoinsEntry::generateWarningText("EXRSxX8yJHudk4QswGf3N5aPVTUi5Q1ZdX56", false), QObject::tr(" You are sending Firo to an Exchange Address. Exchange Addresses can only receive funds from a transparent address."));
    QCOMPARE(SendCoinsEntry::generateWarningText("TLyNUvysvUyt2u6vL74NEkB6ed8LTQd3mz", false), QObject::tr(" You are sending Firo from a transparent address to another transparent address. To protect your privacy, we recommend using Spark addresses instead."));
    QCOMPARE(SendCoinsEntry::generateWarningText("sr1ek2uspg2v4qu0lmccrnj90tfkdpp5zmpykr4ffdprqlf0s4devl8n0674s4d4cthxsa5w9p66s5x0zgw982t80xx9uzmxysxuawmupgfa0xecj9shm6pj7l3rshqxqtg94k88fg5u856r", false), QObject::tr(" You are sending Firo from a transparent address to a Spark address."));
    QCOMPARE(SendCoinsEntry::generateWarningText("sr1ek2uspg2v4qu0lmccrnj90tfkdpp5zmpykr4ffdprqlf0s4devl8n0674s4d4cthxsa5w9p66s5x0zgw982t80xx9uzmxysxuawmupgfa0xecj9shm6pj7l3rshqxqtg94k88fg5u856r", true), QObject::tr(" You are sending Firo from a Spark address to another Spark address. This transaction is fully private."));
    QCOMPARE(SendCoinsEntry::generateWarningText("TLyNUvysvUyt2u6vL74NEkB6ed8LTQd3mz", true), QObject::tr(" You are sending Firo from a private Spark pool to a transparent address. Please note that some exchanges do not accept direct Spark deposits."));
}
