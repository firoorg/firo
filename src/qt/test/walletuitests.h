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
    void synchronizationEstimates();
    void synchronizationWarnings();
    void collapsedNavigationRemainsUsable();
    void paymentRequestFitsSmallScreen();
    void receiveFormFitsSmallScreen();
    void sendFormFitsSmallScreen();
    void sendAmountVisibleWithAddressWarning();
    void dialogsFitWithoutScrolling();
    void receiveMnemonics();
    void emptyRecoverySeed();
    void confirmationRefresh();
    void manualConsolidation();
    void consolidationResult();
    void themeTintColors();
    void peerDetailsTheme();
    void transactionCalendarTheme();
    void brandTypography();
    void recentActivityFitsBrandFont();
    void deferredTransactionsKeepOrder();
    void paymentCodeIndexesWithoutAddressCache();
    void localizedAddressTypesKeepCanonicalRoles();
    void localizedRequestTypesKeepFilters();
    void splashMessageDoesNotProcessEvents();
    void splashShutdownControls();
    void failedAbandonKeepsTransactionVisible();
    void themeChangePreservesWidgetState();
    void sparkNamesRefreshAfterModelDestruction();
    void sparkNameRegistrationDetails();
    void masternodeStatusFollowsPoSe();
};

#endif // BITCOIN_QT_TEST_WALLETUITESTS_H
