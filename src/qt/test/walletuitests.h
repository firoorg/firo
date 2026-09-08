// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_WALLETUITESTS_H
#define BITCOIN_QT_TEST_WALLETUITESTS_H

#include <QObject>

class WalletUiTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initialSyncQueryDoesNotBlock();
    void synchronizationProgress();
    void paymentRequestFitsSmallScreen();
    void receiveFormFitsSmallScreen();
    void receiveMnemonics();
    void confirmationRefresh();
    void themeTintColors();
    void deferredTransactionsKeepOrder();
    void themeChangePreservesWidgetState();
};

#endif // BITCOIN_QT_TEST_WALLETUITESTS_H
