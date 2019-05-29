// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletview.h"

#include "addressbookpage.h"
#include "zerocoinpage.h"
#include "sigmadialog.h"
#include "askpassphrasedialog.h"
#include "bitcoingui.h"
#include "clientmodel.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "sendcoinsdialog.h"
#include "sendmpdialog.h"
#include "lookupspdialog.h"
#include "lookuptxdialog.h"
#include "lookupaddressdialog.h"
#include "metadexcanceldialog.h"
#include "metadexdialog.h"
#include "signverifymessagedialog.h"
#include "tradehistorydialog.h"
#include "transactiontablemodel.h"
#include "transactionview.h"
#include "txhistorydialog.h"
#include "walletmodel.h"

#include "ui_interface.h"

#include <exodus/exodus.h>

#include <QAction>
#include <QActionGroup>
#include <QDebug>
#include <QDialog>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QProgressDialog>
#include <QPushButton>
#include <QTableView>
#include <QVBoxLayout>

WalletView::WalletView(const PlatformStyle *platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    overviewPage(0),
    sendExodusView(0),
    sigmaView(0),
    exodusTransactionsView(0),
    zcoinTransactionsView(0),
    platformStyle(platformStyle),
    transactionTabs(0),
    sendCoinsTabs(0)
{
    overviewPage = new OverviewPage(platformStyle);
    transactionsPage = new QWidget(this);
    exoAssetsPage = new ExoAssetsDialog();
    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    zerocoinPage = new ZerocoinPage(platformStyle, ZerocoinPage::ForEditing, this);
    sigmaPage = new QWidget(this);
    sendCoinsPage = new QWidget(this);
    toolboxPage = new QWidget(this);
    znodeListPage = new ZnodeList(platformStyle);

    setupTransactionPage();
    setupSendCoinPage();
    setupToolboxPage();

    addWidget(overviewPage);
    addWidget(exoAssetsPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
    addWidget(zerocoinPage);
    addWidget(sigmaPage);
    addWidget(toolboxPage);
    addWidget(znodeListPage);

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(focusBitcoinHistoryTab(QModelIndex)));
    connect(overviewPage, SIGNAL(exodusTransactionClicked(uint256)), this, SLOT(focusExodusTransaction(uint256)));

    setupSigmaPage();

    // Subscribe message from sigma tab.
    //connect(sigmaPage, SIGNAL(message(QString, QString, unsigned int)), this, SIGNAL(message(QString, QString, unsigned int)));
}

WalletView::~WalletView()
{
}

void WalletView::setupTransactionPage()
{
    // Create Zcoin transactions list
    zcoinTransactionList = new TransactionView(platformStyle);

    connect(zcoinTransactionList, SIGNAL(doubleClicked(QModelIndex)), zcoinTransactionList, SLOT(showDetails()));
    connect(zcoinTransactionList, SIGNAL(message(QString, QString, unsigned int)), this, SIGNAL(message(QString, QString, unsigned int)));

    // Create export panel for Zcoin transactions
    auto exportButton = new QPushButton(tr("&Export"));

    exportButton->setToolTip(tr("Export the data in the current tab to a file"));

    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    connect(exportButton, SIGNAL(clicked()), zcoinTransactionList, SLOT(exportClicked()));

    auto exportLayout = new QHBoxLayout();
    exportLayout->addStretch();
    exportLayout->addWidget(exportButton);

    // Compose transaction list and export panel together
    auto zcoinLayout = new QVBoxLayout();
    zcoinLayout->addWidget(zcoinTransactionList);
    zcoinLayout->addLayout(exportLayout);

    zcoinTransactionsView = new QWidget();
    zcoinTransactionsView->setLayout(zcoinLayout);

    // Create tabs for transaction categories
    if (isExodusEnabled()) {
        exodusTransactionsView = new TXHistoryDialog();

        transactionTabs = new QTabWidget();
        transactionTabs->addTab(zcoinTransactionsView, tr("Zcoin"));
        transactionTabs->addTab(exodusTransactionsView, tr("Exodus"));
    }

    // Set layout for transaction page
    auto pageLayout = new QVBoxLayout();

    if (transactionTabs) {
        pageLayout->addWidget(transactionTabs);
    } else {
        pageLayout->addWidget(zcoinTransactionsView);
    }

    transactionsPage->setLayout(pageLayout);
}

void WalletView::setupSendCoinPage()
{
    sendZcoinView = new SendCoinsDialog(platformStyle);

    connect(sendZcoinView, SIGNAL(message(QString, QString, unsigned int)), this, SIGNAL(message(QString, QString, unsigned int)));

    // Create tab for coin type
    if (isExodusEnabled()) {
        sendExodusView = new SendMPDialog(platformStyle);

        sendCoinsTabs = new QTabWidget();
        sendCoinsTabs->addTab(sendZcoinView, tr("Zcoin"));
        sendCoinsTabs->addTab(sendExodusView, tr("Exodus"));
    }

    // Set layout for send coin page
    auto pageLayout = new QVBoxLayout();

    if (sendCoinsTabs) {
        pageLayout->addWidget(sendCoinsTabs);
    } else {
        pageLayout->addWidget(sendZcoinView);
    }

    sendCoinsPage->setLayout(pageLayout);
}

void WalletView::setupSigmaPage()
{
    sigmaView = new SigmaDialog(platformStyle);
    connect(sigmaView, SIGNAL(message(QString, QString, unsigned int)), this, SIGNAL(message(QString, QString, unsigned int)));

    // Set layout for Sigma page
    auto pageLayout = new QVBoxLayout();
    pageLayout->addWidget(sigmaView);
    sigmaPage->setLayout(pageLayout);
}

void WalletView::setupToolboxPage()
{
    // Create tools widget
    auto lookupAddress = new LookupAddressDialog();
    auto lookupProperty = new LookupSPDialog();
    auto lookupTransaction = new LookupTXDialog();

    // Create tab for each tool
    auto tabs = new QTabWidget();

    tabs->addTab(lookupAddress, tr("Lookup Address"));
    tabs->addTab(lookupProperty, tr("Lookup Property"));
    tabs->addTab(lookupTransaction, tr("Lookup Transaction"));

    // Set layout for toolbox page
    auto pageLayout = new QVBoxLayout();
    pageLayout->addWidget(tabs);
    toolboxPage->setLayout(pageLayout);
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), gui, SLOT(gotoBitcoinHistoryTab()));
        connect(overviewPage, SIGNAL(exodusTransactionClicked(uint256)), gui, SLOT(gotoExodusHistoryTab()));

        // Receive and report messages
        connect(this, SIGNAL(message(QString,QString,unsigned int)), gui, SLOT(message(QString,QString,unsigned int)));

        // Pass through encryption status changed signals
        connect(this, SIGNAL(encryptionStatusChanged(int)), gui, SLOT(setEncryptionStatus(int)));

        // Pass through transaction notifications
        connect(this, SIGNAL(incomingTransaction(QString,int,CAmount,QString,QString,QString)), gui, SLOT(incomingTransaction(QString,int,CAmount,QString,QString,QString)));
    }
}

void WalletView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;

    overviewPage->setClientModel(clientModel);
    sendZcoinView->setClientModel(clientModel);
    znodeListPage->setClientModel(clientModel);
    exoAssetsPage->setClientModel(clientModel);
    sigmaView->setClientModel(clientModel);

    if (exodusTransactionsView) {
        exodusTransactionsView->setClientModel(clientModel);
    }

    if (sendExodusView) {
        sendExodusView->setClientModel(clientModel);
    }
}

void WalletView::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;

    // Put transaction list in tabs
    zcoinTransactionList->setModel(walletModel);
    overviewPage->setWalletModel(walletModel);
    receiveCoinsPage->setModel(walletModel);
    zerocoinPage->setModel(walletModel->getAddressTableModel());
    sigmaView->setWalletModel(walletModel);
    usedReceivingAddressesPage->setModel(walletModel->getAddressTableModel());
    usedSendingAddressesPage->setModel(walletModel->getAddressTableModel());
    znodeListPage->setWalletModel(walletModel);
    sendZcoinView->setModel(walletModel);
    exoAssetsPage->setWalletModel(walletModel);

    if (exodusTransactionsView) {
        exodusTransactionsView->setWalletModel(walletModel);
    }

    if (sendExodusView) {
        sendExodusView->setWalletModel(walletModel);
    }

    if (walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));

        // Handle changes in encryption status
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SIGNAL(encryptionStatusChanged(int)));
        updateEncryptionStatus();

        // Balloon pop-up for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(processNewTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));

        // Show progress dialog
        connect(walletModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->inInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label);
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoExoAssetsPage()
{
    setCurrentWidget(exoAssetsPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoExodusHistoryTab()
{
    if (!transactionTabs) {
        return;
    }

    setCurrentWidget(transactionsPage);
    transactionTabs->setCurrentIndex(1);
}

void WalletView::gotoBitcoinHistoryTab()
{
    setCurrentWidget(transactionsPage);

    if (transactionTabs) {
        transactionTabs->setCurrentIndex(0);
    }
}

void WalletView::focusExodusTransaction(const uint256& txid)
{
    if (!exodusTransactionsView) {
        return;
    }

    gotoExodusHistoryTab();
    exodusTransactionsView->focusTransaction(txid);
}

void WalletView::focusBitcoinHistoryTab(const QModelIndex &idx)
{
    gotoBitcoinHistoryTab();
    zcoinTransactionList->focusTransaction(idx);
}

void WalletView::gotoZnodePage()
{
    setCurrentWidget(znodeListPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoZerocoinPage()
{
    setCurrentWidget(zerocoinPage);
}

void WalletView::gotoSigmaPage()
{
    setCurrentWidget(sigmaPage);
}


void WalletView::gotoToolboxPage()
{
    setCurrentWidget(toolboxPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty()){
        sendZcoinView->setAddress(addr);
    }
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    if (sendCoinsTabs) {
        sendCoinsTabs->setCurrentIndex(0);
    }

    return sendZcoinView->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged(walletModel->getEncryptionStatus());
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), NULL);

    if (filename.isEmpty())
        return;

    if (!walletModel->backupWallet(filename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    usedSendingAddressesPage->show();
    usedSendingAddressesPage->raise();
    usedSendingAddressesPage->activateWindow();
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    usedReceivingAddressesPage->show();
    usedReceivingAddressesPage->raise();
    usedReceivingAddressesPage->activateWindow();
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}
