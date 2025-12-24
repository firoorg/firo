// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletview.h"

#include "addressbookpage.h"
#include "askpassphrasedialog.h"
#include "automintdialog.h"
#include "automintmodel.h"
#include "bitcoingui.h"
#include "clientmodel.h"
#include "exportviewkeydialog.h"
#include "guiutil.h"
#include "sparkmodel.h"
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "transactiontablemodel.h"
#include "transactionview.h"
#include "walletmodel.h"


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

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    overviewPage(0),
    firoTransactionsView(0),
    platformStyle(_platformStyle)
{
    overviewPage = new OverviewPage(platformStyle);
    transactionsPage = new QWidget(this);
    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this, false);

    sendCoinsPage = new QWidget(this);
    masternodeListPage = new MasternodeList(platformStyle);

    automintSparkNotification = new AutomintSparkNotification(this);
    automintSparkNotification->setWindowModality(Qt::NonModal);

    setupTransactionPage();
    setupSendCoinPage();

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
    addWidget(masternodeListPage);

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::focusBitcoinHistoryTab);
}

WalletView::~WalletView()
{
}

void WalletView::setupTransactionPage()
{
    // Create Firo transactions list
    firoTransactionList = new TransactionView(platformStyle);

    connect(firoTransactionList, &TransactionView::message, this, &WalletView::message);

    // Create export panel for Firo transactions
    auto exportButton = new QPushButton(tr("&Export"));

    exportButton->setToolTip(tr("Export the data in the current tab to a file"));

    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    connect(exportButton, &QPushButton::clicked, firoTransactionList, &TransactionView::exportClicked);

    auto exportLayout = new QHBoxLayout();
    exportLayout->addStretch();
    exportLayout->addWidget(exportButton);

    // Compose transaction list and export panel together
    auto firoLayout = new QVBoxLayout();
    firoLayout->addWidget(firoTransactionList);
    firoLayout->addLayout(exportLayout);
    // TODO: fix this
    connect(overviewPage, &OverviewPage::transactionClicked, firoTransactionList, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));
    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::requestedSyncWarningInfo);

    firoTransactionsView = new QWidget();
    firoTransactionsView->setLayout(firoLayout);

    // Set layout for transaction page
    auto pageLayout = new QVBoxLayout();
        pageLayout->addWidget(firoTransactionsView);

    transactionsPage->setLayout(pageLayout);
}

void WalletView::setupSendCoinPage()
{
    sendFiroView = new SendCoinsDialog(platformStyle);

    connect(sendFiroView, &SendCoinsDialog::message, this, &WalletView::message);

    // Set layout for send coin page
    auto pageLayout = new QVBoxLayout();
        pageLayout->addWidget(sendFiroView);

    sendCoinsPage->setLayout(pageLayout);
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, &OverviewPage::transactionClicked, gui, &BitcoinGUI::gotoHistoryPage);

        // Receive and report messages
        connect(this, &WalletView::message, [gui](const QString &title, const QString &message, unsigned int style) {
            gui->message(title, message, style);
        });

        // Pass through encryption status changed signals
        connect(this, &WalletView::encryptionStatusChanged, gui, &BitcoinGUI::setEncryptionStatus);

        // Pass through transaction notifications
        connect(this, &WalletView::incomingTransaction, gui, &BitcoinGUI::incomingTransaction);

        // Connect HD enabled state signal
        connect(this, &WalletView::hdEnabledStatusChanged, gui, &BitcoinGUI::setHDStatus);
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(clientModel);
    sendFiroView->setClientModel(clientModel);
    masternodeListPage->setClientModel(clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    // Put transaction list in tabs
    firoTransactionList->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    // TODO: fix this
    //sendCoinsPage->setModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel->getAddressTableModel());
    usedSendingAddressesPage->setModel(_walletModel->getAddressTableModel());
    masternodeListPage->setWalletModel(_walletModel);
    sendFiroView->setModel(_walletModel);
    automintSparkNotification->setModel(_walletModel);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, &WalletModel::message, this, &WalletView::message);

        // Handle changes in encryption status
        connect(_walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged(_walletModel->hdEnabled());

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

        // Ask for passphrase if needed
        connect(_walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

        // Show progress dialog
        connect(_walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);

        // Check mintable amount
        connect(_walletModel, &WalletModel::balanceChanged, this, &WalletView::checkMintableSparkAmount);

        auto sparkModel = _walletModel->getSparkModel();
        if (sparkModel) {
            connect(sparkModel, &SparkModel::askMintSparkAll, this, &WalletView::askMintSparkAll);
            auto autoMintSparkModel = sparkModel->getAutoMintSparkModel();
            connect(autoMintSparkModel, &AutoMintSparkModel::message, this, &WalletView::message);
            connect(autoMintSparkModel, &AutoMintSparkModel::requireShowAutomintSparkNotification, this, &WalletView::showAutomintSparkNotification);
            connect(autoMintSparkModel, &AutoMintSparkModel::closeAutomintSparkNotification, this, &WalletView::closeAutomintSparkNotification);
        }
        walletModel->setClientModel(clientModel);
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

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoBitcoinHistoryTab()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::focusBitcoinHistoryTab(const QModelIndex &idx)
{
    gotoBitcoinHistoryTab();
    firoTransactionList->focusTransaction(idx);
}

void WalletView::gotoMasternodePage()
{
    setCurrentWidget(masternodeListPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty()){
        sendFiroView->setAddress(addr);
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
    return sendFiroView->handlePaymentRequest(recipient);
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

void WalletView::exportViewKey()
{
    ExportViewKeyDialog dlg(this, walletModel->getWallet()->GetSparkViewKeyStr());
    dlg.exec();
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet(const QString &info)
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this, info);
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

void WalletView::updateAddressbook()
{
    usedReceivingAddressesPage->updateSpark();
    usedSendingAddressesPage->updateSpark();
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

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}

void WalletView::showAutomintSparkNotification()
{
    auto sparkModel = walletModel->getSparkModel();
    auto wallet = walletModel->getWallet();
   if (!sparkModel || !wallet || !wallet->sparkWallet) {
        return;
    }

    if (!isActiveWindow() || !underMouse()) {
        sparkModel->sendAckMintSparkAll(AutoMintSparkAck::WaitUserToActive);
        return;
    }

    automintSparkNotification->setWindowFlags(automintSparkNotification->windowFlags() | Qt::Popup | Qt::FramelessWindowHint);

    QRect rect(this->mapToGlobal(QPoint(0, 0)), this->size());
    auto pos = QStyle::alignedRect(
        Qt::LeftToRight,
        Qt::AlignRight | Qt::AlignBottom,
        automintSparkNotification->size(),
        rect).topLeft();

    pos.setX(pos.x());
    pos.setY(pos.y());
    automintSparkNotification->move(pos);

    automintSparkNotification->show();
    automintSparkNotification->raise();
}

void WalletView::repositionAutomintSparkNotification()
{
    if (automintSparkNotification->isVisible()) {
        QRect rect(this->mapToGlobal(QPoint(0, 0)), this->size());
        auto pos = QStyle::alignedRect(
            Qt::LeftToRight,
            Qt::AlignRight | Qt::AlignBottom,
            automintSparkNotification->size(),
            rect).topLeft();

        pos.setX(pos.x());
        pos.setY(pos.y());
        automintSparkNotification->move(pos);
    }
}

void WalletView::checkMintableSparkAmount(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount anonymizableBalance)
{
    if (automintSparkNotification->isVisible() && anonymizableBalance == 0) {
        // hide if notification is showing but there no any fund to anonymize
        closeAutomintSparkNotification();
    }
}

void WalletView::closeAutomintSparkNotification()
{
    automintSparkNotification->close();
}

void WalletView::askMintSparkAll(AutoMintSparkMode mode)
{
    automintSparkNotification->setVisible(false);

    if (!walletModel) {
        return;
    }

    AutoMintSparkDialog dlg(mode, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

bool WalletView::eventFilter(QObject *watched, QEvent *event)
{
    switch (event->type()) {
    case QEvent::Type::Resize:
    case QEvent::Type::Move:
        repositionAutomintSparkNotification();
        break;
    default:
        break;
    }

    return QStackedWidget::eventFilter(watched, event);
}
