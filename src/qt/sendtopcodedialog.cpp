// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sendtopcodedialog.h"
#include "ui_sendtopcodedialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "pcodemodel.h"
#include "bip47/paymentchannel.h"
#include "lelantusmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

namespace {
void OnTransactionChanged(SendtoPcodeDialog *dialog, CWallet *wallet, uint256 const &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(status);
    if (status == ChangeType::CT_NEW || status == ChangeType::CT_UPDATED) {
        QMetaObject::invokeMethod(dialog, "onTransactionChanged", Qt::QueuedConnection,
            Q_ARG(uint256, hash));
    }
}
}

SendtoPcodeDialog::SendtoPcodeDialog(QWidget *parent, std::string const & pcode, std::string const & label) :
    QDialog(parent),
    ui(new Ui::SendtoPcodeDialog),
    model(0),
    result(Result::cancelled),
    label(label)
{
    ui->setupUi(this);
    try {
        paymentCode = std::make_shared<bip47::CPaymentCode>(pcode);
    } catch (std::runtime_error const &) {
        LogBip47("Cannot parse the payment code: " + pcode);
    }
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    status.pcodeValid = true;
}

SendtoPcodeDialog::~SendtoPcodeDialog()
{
    delete ui;

    if (!model) return;
    model->getWallet()->NotifyTransactionChanged.disconnect(boost::bind(OnTransactionChanged, this, _1, _2, _3));
}

void SendtoPcodeDialog::setModel(WalletModel *_model)
{
    model = _model;
    result = Result::cancelled;

    if (!model || !paymentCode)
        return;

    model->getWallet()->NotifyTransactionChanged.connect(boost::bind(OnTransactionChanged, this, _1, _2, _3));

    if (model->getPcodeModel()->getNotificationTxid(*paymentCode, notificationTxHash)) {
        setNotifTxId();
        setUseAddr();
    } else {
        ui->notificationTxIdLabel->setText(tr("None"));
        ui->nextAddressLabel->setText(tr("None"));
    }

    ui->notificationTxIdLabel->setTextFormat(Qt::RichText);
    ui->notificationTxIdLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    ui->notificationTxIdLabel->setOpenExternalLinks(true);

    std::pair<CAmount, CAmount> lelantusBalance = model->getLelantusModel()->getPrivateBalance();
    setLelantusBalance(lelantusBalance.first, lelantusBalance.second);

    connect(
        model,
        SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)),
        this,
        SLOT(onBalanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));

    updateButtons();
}

void SendtoPcodeDialog::updateButtons()
{
    if (!status.pcodeValid) {
        ui->sendButton->setEnabled(false);
        ui->useButton->setEnabled(false);
        return;
    }

    if (!status.balanceOk || status.notifTxSent || status.notifTxConfirmed) {
        ui->sendButton->setEnabled(false);
    } else {
        ui->sendButton->setEnabled(true);
    }

    if (!status.notifTxSent || !status.notifTxConfirmed) {
        ui->useButton->setEnabled(false);
        ui->useButton->setText(tr("Waiting to confirm"));
    } else if (status.notifTxConfirmed) {
        ui->useButton->setEnabled(true);
        ui->useButton->setText(tr("Send to"));
    }

    QString hintText = tr("<i>Please click Connect button to start.</i>");
    if(!status.balanceOk)
        hintText = tr("<i>The balance is not enough.</i>");
    if(status.notifTxSent)
        hintText = tr("<i>Please wait until the connection transaction has at least 1 confirmation or cancel this dialog to send funds later.</i>");
    if(status.notifTxConfirmed)
        hintText = tr("<i>FIRO can be send now.</i>");
    ui->hintLabel->setText(hintText);
}

std::pair<SendtoPcodeDialog::Result, CBitcoinAddress> SendtoPcodeDialog::getResult() const
{
    if (result == Result::addressSelected) {
        return std::pair<Result, CBitcoinAddress>(result, addressToUse);
    }
    return std::pair<Result, CBitcoinAddress>(Result::cancelled, CBitcoinAddress());
}

std::unique_ptr<WalletModel::UnlockContext> SendtoPcodeDialog::getUnlockContext()
{
    return std::move(unlockContext);
}

void SendtoPcodeDialog::close()
{
    if (!label.empty())
         model->getPcodeModel()->labelPcode(paymentCode->toString(), label);
    QDialog::close();
}

int SendtoPcodeDialog::exec()
{
    if (notificationTxHash == uint256{})
        return QDialog::exec();
    result = Result::addressSelected;
    close();
    return 0;
}


void SendtoPcodeDialog::on_sendButton_clicked()
{
    if (!model || !paymentCode || !model->getPcodeModel())
        return;

    unlockContext = std::unique_ptr<WalletModel::UnlockContext>(new WalletModel::UnlockContext(model->requestUnlock()));
    if (!unlockContext->isValid())
        return;

    try {
        notificationTxHash = model->getPcodeModel()->sendNotificationTx(*paymentCode);
        setNotifTxId();
        setUseAddr();
        status.notifTxSent = true;
        updateButtons();
    }
    catch (std::runtime_error const & e)
    {
        QMessageBox msgBox;
        msgBox.setText(tr(
            "During creation of the notification tx the following error occurred:\n"));
        msgBox.setInformativeText(e.what());
        msgBox.setWindowTitle(tr("RAP error"));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.setDefaultButton(QMessageBox::Ok);
        msgBox.exec();
    }
}

void SendtoPcodeDialog::on_useButton_clicked()
{
    result = Result::addressSelected;
    close();
}

void SendtoPcodeDialog::on_cancelButton_clicked()
{
    result = Result::cancelled;
    close();
}

void SendtoPcodeDialog::on_helpButton_clicked()
{
    QMessageBox msgBox;
    msgBox.setText(tr(
        "Sending funds to a RAP code requires a notification transaction to be sent by the payer prior to the first payment. \n"
        "Notification transactions use Lelantus facilities to enhance privacy.\n"
        "After the notification transaction is received by the RAP code issuer, funds can be privately sent to the RAP secret addresses.\n"));
    msgBox.setInformativeText(tr(
        "The recommended workflow is as follows:\n"
        "1. Send a notification transaction\n"
        "2. Make sure it is included in a block with a block explorer\n"
        "3. Send funds to the RAP code in one or more transactions"));
    msgBox.setWindowTitle(tr("RAP info"));
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.setDefaultButton(QMessageBox::Ok);
    msgBox.exec();
}

void SendtoPcodeDialog::showEvent( QShowEvent* event ) {
    QDialog::showEvent( event);
    adjustSize();
    ui->balanceSpacer->sizeHint().setHeight(ui->sendButton->size().height());

    QTimer::singleShot(10, this, SLOT(onWindowShown()));
}

void SendtoPcodeDialog::setNotifTxId()
{
    std::ostringstream ostr;
    ostr << "<a href=\"https://";
    if(Params().GetConsensus().IsTestnet())
        ostr << "test";
    ostr << "explorer.firo.org/tx/" << notificationTxHash.GetHex() << "\">" << notificationTxHash.GetHex() << "</a>";
    ui->notificationTxIdLabel->setText(ostr.str().c_str());

    CWalletTx const * notifTx = model->getWallet()->GetWalletTx(notificationTxHash);
    if (!notifTx) return;
    int notifTxDepth = 0;
    {
        LOCK(cs_main);
        notifTxDepth = notifTx->GetDepthInMainChain();
    }

    if (notifTxDepth > 0)
    {
        status.notifTxConfirmed = true;
    }
}

void SendtoPcodeDialog::setUseAddr()
{
    {
        LOCK(model->getWallet()->cs_wallet);
        addressToUse = model->getWallet()->GetTheirNextAddress(*paymentCode);
    }
    ui->nextAddressLabel->setText(addressToUse.ToString().c_str());
}

void SendtoPcodeDialog::setLelantusBalance(CAmount const & lelantusBalance, CAmount const & unconfirmedLelantusBalance)
{
    int const unit = model->getOptionsModel()->getDisplayUnit();
    QString balancePretty = BitcoinUnits::formatWithUnit(unit, lelantusBalance, false, BitcoinUnits::separatorAlways);
    if (lelantusBalance < bip47::NotificationTxValue)
        balancePretty += " (pending: " + BitcoinUnits::formatWithUnit(unit, unconfirmedLelantusBalance, false, BitcoinUnits::separatorAlways) + ")";

    ui->balanceLabel->setText(balancePretty);

    QColor color(GUIUtil::GUIColors::checkPassed);
    if (lelantusBalance < bip47::NotificationTxValue) {
        color = QColor(GUIUtil::GUIColors::warning);
        status.balanceOk = false;
    } else {
        status.balanceOk = true;
    }
    ui->balanceLabel->setStyleSheet("QLabel { color: " + color.name() + "; }");
    updateButtons();
}

void SendtoPcodeDialog::onTransactionChanged(uint256 txHash)
{
    if (txHash != notificationTxHash) return;
    setNotifTxId();
}

void SendtoPcodeDialog::onWindowShown()
{
    if(!model->getPcodeModel()->hasSendingPcodes()) {
        QMessageBox msgBox;
        msgBox.setText(tr(
            "A one time connection fee is required when sending to a new RAP address.\n"
            "Once this fee is paid, all future sends to this RAP address do not incur any additional fee.\n"
            ));
        msgBox.setWindowTitle(tr("RAP info"));
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.setDefaultButton(QMessageBox::Ok);
        msgBox.exec();
    }
}

void SendtoPcodeDialog::onBalanceChanged(
    const CAmount& balance,
    const CAmount& unconfirmedBalance,
    const CAmount& immatureBalance,
    const CAmount& watchOnlyBalance,
    const CAmount& watchUnconfBalance,
    const CAmount& watchImmatureBalance,
    const CAmount& privateBalance,
    const CAmount& unconfirmedPrivateBalance,
    const CAmount& anonymizableBalance)
{
    setLelantusBalance(privateBalance, unconfirmedPrivateBalance);
}
