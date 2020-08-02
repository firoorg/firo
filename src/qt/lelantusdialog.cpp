#include "../lelantus.h"
#include "../validation.h"

#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "ui_lelantusdialog.h"
#include "lelantusdialog.h"
#include "sendcoinsdialog.h"

#define SEND_CONFIRM_DELAY   3

LelantusDialog::LelantusDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LelantusDialog),
    clientModel(0),
    walletModel(0),
    platformStyle(platformStyle),
    cachedPrivateBalance(0),
    cachedUnconfirmedPrivateBalance(0),
    cachedAnonymizableBalance(0),
    currentUnit(BitcoinUnits::Unit::BTC)
{
    ui->setupUi(this);
    setWindowTitle(tr("Lelantus"));

    // hide amount of global pool
    ui->globalTotalCoinsAmount->setVisible(false);
    ui->globalUnspentAmount->setVisible(false);
}

LelantusDialog::~LelantusDialog()
{
    delete ui;
}

void LelantusDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(
            _clientModel,
            SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
            this,
            SLOT(updateGlobalState()));

        updateGlobalState();
    }
}

void LelantusDialog::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    if (_walletModel) {
        connect(
            _walletModel,
            SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)),
            this,
            SLOT(setBalance(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));

        connect(
            _walletModel->getOptionsModel(),
            SIGNAL(displayUnitChanged(int)),
            this,
            SLOT(updateDisplayUnit(int)));

        setBalance(0, 0, 0, 0, 0, 0,
            _walletModel->getPrivateBalance(),
            _walletModel->getUnconfirmedPrivateBalance(),
            _walletModel->getAnonymizableBalance());

        auto unit = _walletModel->getOptionsModel()->getDisplayUnit();
        currentUnit = unit;
        updateDisplayUnit(unit);
    }
}

void LelantusDialog::clear()
{
    ui->anonymizeAmount->setValue(0);
}

void LelantusDialog::accept()
{
    clear();
}

void LelantusDialog::setBalance(
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
    if (cachedPrivateBalance != privateBalance
        || cachedUnconfirmedPrivateBalance != unconfirmedPrivateBalance
        || cachedAnonymizableBalance != anonymizableBalance)
    {
        cachedPrivateBalance = privateBalance;
        cachedUnconfirmedPrivateBalance = unconfirmedPrivateBalance;
        cachedAnonymizableBalance = anonymizableBalance;

        updateBalanceDisplay();
    }
}

void LelantusDialog::updateDisplayUnit(int unit)
{
    ui->anonymizeUnit->setText(BitcoinUnits::name(unit));

    auto amountText = ui->anonymizeAmount->text();
    size_t prec;

    switch(unit) {
    case BitcoinUnits::Unit::BTC:  prec = 8; break;
    case BitcoinUnits::Unit::mBTC: prec = 5; break;
    case BitcoinUnits::Unit::uBTC: prec = 2; break;
    default: prec = 8; break;
    }

    ui->anonymizeAmount->setDecimals(prec);

    CAmount out;
    if (BitcoinUnits::parse(currentUnit, amountText, &out)) {
        ui->anonymizeAmount->setValue(
            (double)(out) / BitcoinUnits::factor(unit)
        );
    }

    updateBalanceDisplay(unit);
    updateGlobalState();

    currentUnit = unit;
}

void LelantusDialog::updateGlobalState()
{
    auto state = lelantus::CLelantusState::GetState();
    auto mintCount = state->GetMints().size();
    auto spendCount = state->GetSpends().size();

    auto sigmaState = sigma::CSigmaState::GetState();
    auto remainingSigmaMints = sigmaState->GetMints().size() - sigmaState->GetSpends().size();

    mintCount += remainingSigmaMints;

    ui->globalTotalCoins->setText(QString::fromStdString(std::to_string(mintCount)));
    ui->globalUnspent->setText(QString::fromStdString(std::to_string(mintCount - spendCount)));
}

void LelantusDialog::on_anonymizeButton_clicked()
{
    CAmount val = 0;
    if (!BitcoinUnits::parse(
        walletModel->getOptionsModel()->getDisplayUnit(),
        ui->anonymizeAmount->text(),
        &val)) {
        val = 0;
    }

    if (val < 0 || val > BitcoinUnits::maxMoney()) {
        val = 0;
    }

    std::vector<WalletModelTransaction> wtxs;
    std::list<CReserveKey> reserveKeys;
    std::vector<CHDMint> mints;
    auto prepareStatus = walletModel->prepareAnonymizingTransactions(
        val,
        wtxs,
        reserveKeys,
        mints,
        nullptr);

    CAmount allAmount = 0;
    CAmount allFee = 0;
    unsigned int allTxSize = 0;
    for (auto &wtx : wtxs) {
        allAmount += wtx.getTotalTransactionAmount();
        allFee += wtx.getTransactionFee();
        allTxSize += wtx.getTransactionSize();
    }

    processSendCoinsReturn(
        prepareStatus,
        BitcoinUnits::formatWithUnit(
            walletModel->getOptionsModel()->getDisplayUnit(),
            allFee)
        );

    if (prepareStatus.status != WalletModel::OK) {
        return;
    }

    QStringList formatted;

    QString questionString = tr("Are you sure you want to anonymize %1?")
        .arg(BitcoinUnits::formatWithUnit(
            walletModel->getOptionsModel()->getDisplayUnit(),
            allAmount,
            false,
            BitcoinUnits::separatorAlways
        ));

    questionString.append("<br /><br />%1");

    if (allFee > 0) {
        // append fee string if a fee is required
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), allFee));
        questionString.append("</span> ");
        questionString.append(tr("added as transaction fee"));

        // append transaction size
        questionString.append(" (" + QString::number((double)allTxSize / 1000) + " kB)");
    }

    // add total amount in all subdivision units
    questionString.append("<hr />");
    CAmount totalAmount = allAmount + allFee;
    QStringList alternativeUnits;
    for (auto u : BitcoinUnits::availableUnits()) {
        if(u != walletModel->getOptionsModel()->getDisplayUnit()) {
            alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
        }
    }

    questionString.append(tr("Total Amount %1")
        .arg(BitcoinUnits::formatHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), totalAmount)));
    questionString.append(QString("<span style='font-size:10pt;font-weight:normal;'><br />(=%2)</span>")
        .arg(alternativeUnits.join(" " + tr("or") + "<br />")));

    SendConfirmationDialog confirmationDialog(tr("Confirm anonymize coins"),
        questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY, this);

    confirmationDialog.exec();
    QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();

    if (retval != QMessageBox::Yes)
    {
        return;
    }

    auto sendStatus = walletModel->sendAnonymizingCoins(wtxs, reserveKeys, mints);

    processSendCoinsReturn(sendStatus);

    if (sendStatus.status == WalletModel::OK) {
        accept();
    }
}

void LelantusDialog::updateBalanceDisplay(int unit)
{
    if (unit == -1) {
        if (walletModel && walletModel->getOptionsModel()) {
            unit = walletModel->getOptionsModel()->getDisplayUnit();
        } else {
            unit = BitcoinUnits::Unit::BTC;
        }
    }

    CAmount confirmedAmount = 0, unconfirmedAmount = 0;
    auto confirmedCoins =
        cachedPrivateBalance = walletModel->countPrivateCoins(confirmedAmount);
    auto unconfirmedCoins =
        cachedUnconfirmedPrivateBalance = walletModel->countUnconfirmedPrivateCoins(unconfirmedAmount);

    auto totalCoins = confirmedCoins + unconfirmedCoins;
    auto totalAmount = confirmedAmount + unconfirmedAmount;

    // set available amount
    auto avaiableAmountToAnonymizeText = tr("Available amount to anonymize %1")
        .arg(BitcoinUnits::formatWithUnit(unit, cachedAnonymizableBalance, false, BitcoinUnits::separatorAlways));
    ui->availableAmounToAnonymize->setText(avaiableAmountToAnonymizeText);

    // set coins count
    ui->spendable->setText(QString::fromStdString(std::to_string(confirmedCoins)));
    ui->unconfirmed->setText(QString::fromStdString(std::to_string(unconfirmedCoins)));
    ui->total->setText(QString::fromStdString(std::to_string(totalCoins)));

    // set amount
    ui->spendableAmount->setText(BitcoinUnits::formatWithUnit(
        unit, confirmedAmount, false, BitcoinUnits::separatorAlways));
    ui->unconfirmedAmount->setText(BitcoinUnits::formatWithUnit(
        unit, unconfirmedAmount, false, BitcoinUnits::separatorAlways));
    ui->totalAmount->setText(BitcoinUnits::formatWithUnit(
        unit, totalAmount, false, BitcoinUnits::separatorAlways));
}

void LelantusDialog::processSendCoinsReturn(
    const WalletModel::SendCoinsReturn &sendCoinsReturn,
    const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    msgParams.second = CClientUIInterface::MSG_WARNING;

    switch (sendCoinsReturn.status)
    {
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::TransactionCommitFailed:
        msgParams.first = tr("The transaction was rejected with the following reason: %1").arg(sendCoinsReturn.reasonCommitFailed);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), maxTxFee));
        break;
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Anonymize Coins"), msgParams.first, msgParams.second);
}