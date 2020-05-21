// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETVIEW_H
#define BITCOIN_QT_WALLETVIEW_H

#if defined(HAVE_CONFIG_H)
#include "../config/bitcoin-config.h"
#endif

#include "amount.h"
#include "znodelist.h"
#include "paymentcodepage.h"
#include "masternodelist.h"
#include "sigmadialog.h"

#ifdef ENABLE_ELYSIUM
#include "elyassetsdialog.h"
#endif

#include <QStackedWidget>

class BitcoinGUI;
class ClientModel;
class OverviewPage;
class PlatformStyle;
class ReceiveCoinsDialog;
class SendCoinsDialog;
class SendMPDialog;
class TradeHistoryDialog;
class LookupSPDialog;
class LookupTXDialog;
class LookupAddressDialog;
class MetaDExDialog;
class MetaDExCancelDialog;
class SendCoinsRecipient;
class TransactionView;
class TXHistoryDialog;
class WalletModel;
class AddressBookPage;
class ZerocoinPage;
class PaymentcodePage;
class Zc2SigmaPage;

QT_BEGIN_NAMESPACE
class QModelIndex;
class QProgressDialog;
class QTabWidget;
QT_END_NAMESPACE

/*
  WalletView class. This class represents the view to a single wallet.
  It was added to support multiple wallet functionality. Each wallet gets its own WalletView instance.
  It communicates with both the client and the wallet models to give the user an up-to-date view of the
  current core state.
*/
class WalletView : public QStackedWidget
{
    Q_OBJECT

public:
    explicit WalletView(const PlatformStyle *platformStyle, QWidget *parent);
    ~WalletView();

    void setBitcoinGUI(BitcoinGUI *gui);
    /** Set the client model.
        The client model represents the part of the core that communicates with the P2P network, and is wallet-agnostic.
    */
    void setClientModel(ClientModel *clientModel);
    /** Set the wallet model.
        The wallet model represents a bitcoin wallet, and offers access to the list of transactions, address book and sending
        functionality.
    */
    void setWalletModel(WalletModel *walletModel);

    bool handlePaymentRequest(const SendCoinsRecipient& recipient);

    void showOutOfSyncWarning(bool fShow);

private:
    void setupTransactionPage();
    void setupSendCoinPage();
#ifdef ENABLE_ELYSIUM
    void setupToolboxPage();
#endif
    void setupSigmaPage();

private:
    ClientModel *clientModel;
    WalletModel *walletModel;

    OverviewPage *overviewPage;

    PaymentcodePage *paymentcodePage;

#ifdef ENABLE_ELYSIUM
    ElyAssetsDialog *elyAssetsPage;
    QWidget *toolboxPage;
    TXHistoryDialog *elysiumTransactionsView;
    QTabWidget *transactionTabs;
    SendMPDialog *sendElysiumView;
    QTabWidget *sendCoinsTabs;
#endif
    QWidget *transactionsPage;
    QWidget *smartPropertyPage;
    ReceiveCoinsDialog *receiveCoinsPage;
    AddressBookPage *usedSendingAddressesPage;
    AddressBookPage *usedReceivingAddressesPage;
    QWidget *sendCoinsPage;
    SendCoinsDialog *sendZcoinView;
    TradeHistoryDialog *tradeHistoryTab;
    MetaDExDialog *metaDExTab;
    MetaDExCancelDialog *cancelTab;
    ZerocoinPage *zerocoinPage;
    SigmaDialog *sigmaView;
    BlankSigmaDialog *blankSigmaView;
    QWidget *sigmaPage;
    Zc2SigmaPage *zc2SigmaPage;
    TransactionView *zcoinTransactionList;
    QWidget *zcoinTransactionsView;
    ZnodeList *znodeListPage;
    MasternodeList *masternodeListPage;

    QProgressDialog *progressDialog;
    const PlatformStyle *platformStyle;

public Q_SLOTS:
    /** Switch to overview (home) page */
    void gotoOverviewPage();
#ifdef ENABLE_ELYSIUM
    /** Switch to ExoAssets page */
    void gotoElyAssetsPage();
    /** Switch to utility page */
    void gotoToolboxPage();
    /** Switch specifically to elysium tx history tab */
    void gotoElysiumHistoryTab();
    /** Switch to elysium tx history tab and focus on specific transaction */
    void focusElysiumTransaction(const uint256& txid);
#endif
    /** Switch to history (transactions) page */
    void gotoHistoryPage();
    /** Switch specifically to bitcoin tx history tab */
    void gotoBitcoinHistoryTab();
    /** Switch to bitcoin tx history tab and focus on specific transaction */
    void focusBitcoinHistoryTab(const QModelIndex &idx);
    /** Switch to znode page */
    void gotoZnodePage();
    /** Switch to masternode page */
    void gotoMasternodePage();
    /** Switch to receive coins page */
    void gotoReceiveCoinsPage();
    /** Switch to send coins page */
    void gotoSendCoinsPage(QString addr = "");
    /** Switch to paymentcode page */
    void gotoPaymentcodePage();
    /** Switch to zerocoin page */
    void gotoZerocoinPage();
    /** Switch to sigma page */
    void gotoSigmaPage();
    /** Switch to ZC to Sigma page */
    void gotoZc2SigmaPage();

    /** Show Sign/Verify Message dialog and switch to sign message tab */
    void gotoSignMessageTab(QString addr = "");
    /** Show Sign/Verify Message dialog and switch to verify message tab */
    void gotoVerifyMessageTab(QString addr = "");

    /** Show incoming transaction notification for new transactions.

        The new items are those between start and end inclusive, under the given parent item.
    */
    void processNewTransaction(const QModelIndex& parent, int start, int /*end*/);
    /** Encrypt the wallet */
    void encryptWallet(bool status);
    /** Backup the wallet */
    void backupWallet();
    /** Change encrypted wallet passphrase */
    void changePassphrase();
    /** Ask for passphrase to unlock wallet temporarily */
    void unlockWallet();

    /** Show used sending addresses */
    void usedSendingAddresses();
    /** Show used receiving addresses */
    void usedReceivingAddresses();

    /** Re-emit encryption status signal */
    void updateEncryptionStatus();

    /** Show progress dialog e.g. for rescan */
    void showProgress(const QString &title, int nProgress);

    /** User has requested more information about the out of sync state */
    void requestedSyncWarningInfo();

Q_SIGNALS:
    /** Signal that we want to show the main window */
    void showNormalIfMinimized();
    /**  Fired when a message should be reported to the user */
    void message(const QString &title, const QString &message, unsigned int style);
    /** Encryption status of wallet changed */
    void encryptionStatusChanged(int status);
    /** HD-Enabled status of wallet changed (only possible during startup) */
    void hdEnabledStatusChanged(int hdEnabled);
    /** Notify that a new transaction appeared */
    void incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString& label);
    /** Notify that the out of sync warning icon has been pressed */
    void outOfSyncWarningClicked();
};

#endif // BITCOIN_QT_WALLETVIEW_H
