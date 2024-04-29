#ifndef BITCOIN_QT_TEST_SENDCOINSENTRY_H
#define BITCOIN_QT_TEST_SENDCOINSENTRY_H

#include <QObject>
#include <QTest>
#include "sendcoinsentry.h"

class TestSendCoinsEntry : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testGenerateWarningText();
};

#endif // BITCOIN_QT_TEST_SENDCOINSENTRY_H