#include "../lelantus.h"
#include "../script/standard.h"
#include "../validation.h"
#include "../wallet/coincontrol.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "ui_lelantusdialog.h"
#include "lelantusdialog.h"
#include "lelantusmodel.h"
#include "sendcoinsdialog.h"
#include "walletmodel.h"

#include <QSettings>

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
    ui->globalLatestGroupCoinsAmount->setVisible(false);
    ui->globalUnspentAmount->setVisible(false);

    // Coin Control
    connect(
        ui->pushButtonCoinControl, SIGNAL(clicked()),
        this, SLOT(coinControlButtonClicked()));

    connect(
        ui->checkBoxCoinControlChange, SIGNAL(stateChanged(int)),
        this, SLOT(coinControlChangeChecked(int)));

    connect(
        ui->lineEditCoinControlChange,
        SIGNAL(textEdited(const QString &)),
        this,
        SLOT(coinControlChangeEdited(const QString &)));

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardFee()));
    connect(clipboardAfterFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAfterFee()));
    connect(clipboardBytesAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardBytes()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardChange()));

    // init transaction fee section.
    QSettings settings;
    if (!settings.contains("lelantus::fFeeSectionMinimized"))
        settings.setValue("lelantus::fFeeSectionMinimized", true);

    if (!settings.contains("lelantus::nFeeRadio")
        && settings.contains("lelantus::nTransactionFee")
        && settings.value("lelantus::nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("lelantus::nFeeRadio", 1); // custom

    if (!settings.contains("lelantus::nFeeRadio"))
        settings.setValue("lelantus::nFeeRadio", 0); // recommended

    if (!settings.contains("lelantus::nCustomFeeRadio")
        && settings.contains("lelantus::nTransactionFee")
        && settings.value("lelantus::nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("lelantus::nCustomFeeRadio", 1); // total at least

    if (!settings.contains("lelantus::nCustomFeeRadio"))
        settings.setValue("lelantus::nCustomFeeRadio", 0); // per kilobyte

    if (!settings.contains("lelantus::nTransactionFee"))
        settings.setValue("lelantus::nTransactionFee",
            (qint64)DEFAULT_TRANSACTION_FEE);

    if (!settings.contains("lelantus::fPayOnlyMinFee"))
        settings.setValue("lelantus::fPayOnlyMinFee", false);

    ui->groupCustomFee->setId(ui->radioCustomPerKilobyte, 0);
    ui->groupCustomFee->setId(ui->radioCustomAtLeast, 1);
    ui->groupCustomFee->button((int)std::max(0, std::min(1, settings.value("lelantus::nCustomFeeRadio").toInt())))->setChecked(true);
    ui->customFee->setValue(settings.value("lelantus::nTransactionFee").toLongLong());
    ui->checkBoxMinimumFee->setChecked(settings.value("lelantus::fPayOnlyMinFee").toBool());
    minimizeFeeSection(settings.value("lelantus::fFeeSectionMinimized").toBool());
}

LelantusDialog::~LelantusDialog()
{
    QSettings settings;
    settings.setValue("lelantus::fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("lelantus::nFeeRadio", true);
    settings.setValue("lelantus::nCustomFeeRadio", ui->groupCustomFee->checkedId());
    settings.setValue("lelantus::nSmartFeeSliderPosition", ui->sliderSmartFee->value());
    settings.setValue("lelantus::nTransactionFee", (qint64)ui->customFee->value());
    settings.setValue("lelantus::fPayOnlyMinFee", ui->checkBoxMinimumFee->isChecked());

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
            SLOT(updateSmartFeeLabel()));

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

        auto privateBalance = _walletModel->getLelantusModel()->getPrivateBalance();
        setBalance(0, 0, 0, 0, 0, 0,
            privateBalance.first,
            privateBalance.second,
            _walletModel->getAnonymizableBalance());

        // Coin Control
        connect(
            _walletModel->getOptionsModel(),
            SIGNAL(displayUnitChanged(int)),
            this, SLOT(coinControlUpdateLabels()));
        connect(
            _walletModel->getOptionsModel(),
            SIGNAL(coinControlFeaturesChanged(bool)),
            this,
            SLOT(coinControlFeatureChanged(bool)));
        ui->frameCoinControl->setVisible(
            _walletModel->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        auto unit = _walletModel->getOptionsModel()->getDisplayUnit();
        currentUnit = unit;
        updateDisplayUnit(unit);

        // fee section
        connect(ui->sliderSmartFee, SIGNAL(valueChanged(int)), this, SLOT(updateSmartFeeLabel()));
        connect(ui->sliderSmartFee, SIGNAL(valueChanged(int)), this, SLOT(updateGlobalFeeVariables()));
        connect(ui->sliderSmartFee, SIGNAL(valueChanged(int)), this, SLOT(coinControlUpdateLabels()));
        connect(ui->groupFee, SIGNAL(buttonClicked(int)), this, SLOT(updateFeeSectionControls()));
        connect(ui->groupFee, SIGNAL(buttonClicked(int)), this, SLOT(updateGlobalFeeVariables()));
        connect(ui->groupFee, SIGNAL(buttonClicked(int)), this, SLOT(coinControlUpdateLabels()));
        connect(ui->groupCustomFee, SIGNAL(buttonClicked(int)), this, SLOT(updateGlobalFeeVariables()));
        connect(ui->groupCustomFee, SIGNAL(buttonClicked(int)), this, SLOT(coinControlUpdateLabels()));
        connect(ui->customFee, SIGNAL(valueChanged()), this, SLOT(updateGlobalFeeVariables()));
        connect(ui->customFee, SIGNAL(valueChanged()), this, SLOT(coinControlUpdateLabels()));
        connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(setMinimumFee()));
        connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(updateFeeSectionControls()));
        connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(updateGlobalFeeVariables()));
        connect(ui->checkBoxMinimumFee, SIGNAL(stateChanged(int)), this, SLOT(coinControlUpdateLabels()));
        ui->customFee->setSingleStep(CWallet::GetRequiredFee(1000));
        updateFeeSectionControls();
        updateMinFeeLabel();
        updateSmartFeeLabel();
        updateGlobalFeeVariables();

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("lelantus::nSmartFeeSliderPosition").toInt() == 0)
        {
            ui->sliderSmartFee->setValue(ui->sliderSmartFee->maximum()
                - walletModel->getDefaultConfirmTarget() + 2);
        }
        else
        {
            ui->sliderSmartFee->setValue(
                settings.value("lelantus::nSmartFeeSliderPosition").toInt());
        }
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

    updateMinFeeLabel();
    updateSmartFeeLabel();

    currentUnit = unit;
}

void LelantusDialog::updateGlobalState()
{
    auto state = lelantus::CLelantusState::GetState();
    auto mintCount = state->GetMints().size();
    auto spendCount = state->GetSpends().size();
    size_t mintsInLatestGroup = 0;

    if (mintCount) {
        lelantus::CLelantusState::LelantusCoinGroupInfo group;
        if (state->GetCoinGroupInfo(state->GetLatestCoinID(), group)) {
            mintsInLatestGroup = group.nCoins;
        }
    }

    auto sigmaState = sigma::CSigmaState::GetState();
    auto remainingSigmaMints = sigmaState->GetMints().size() - sigmaState->GetSpends().size();

    mintCount += remainingSigmaMints;

    ui->globalTotalCoins->setText(QString::fromStdString(std::to_string(mintCount)));
    ui->globalLatestGroupCoins->setText(QString::fromStdString(std::to_string(mintsInLatestGroup)));
    ui->globalUnspent->setText(QString::fromStdString(std::to_string(mintCount - spendCount)));
}

void LelantusDialog::on_anonymizeButton_clicked()
{
    updateGlobalFeeVariables();

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

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid())
    {
        // Unlock wallet was cancelled
        return;
    }

    std::vector<WalletModelTransaction> wtxs;
    std::list<CReserveKey> reserveKeys;
    std::vector<CHDMint> mints;

    CCoinControl ctrl;
    if (walletModel->getOptionsModel()->getCoinControlFeatures()) {
        ctrl = coinControlStorage.coinControl;
        removeUnmatchedOutput(ctrl);
    }

    auto coinControl = coinControlStorage.coinControl;
    auto prepareStatus = walletModel->prepareMintTransactions(
        val,
        wtxs,
        reserveKeys,
        mints,
        &ctrl);

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
        coinControlStorage.coinControl.UnSelectAll();
        coinControlUpdateLabels();
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

    size_t confirmeds, unconfirmeds;
    std::tie(cachedPrivateBalance, cachedUnconfirmedPrivateBalance) = walletModel->getLelantusModel()->getPrivateBalance(confirmeds, unconfirmeds);

    auto totalCoins = confirmeds + unconfirmeds;
    auto totalAmount = cachedPrivateBalance + cachedUnconfirmedPrivateBalance;

    // set available amount
    auto avaiableAmountToAnonymizeText = tr("Available amount to anonymize %1")
        .arg(BitcoinUnits::formatWithUnit(unit, cachedAnonymizableBalance, false, BitcoinUnits::separatorAlways));
    ui->availableAmounToAnonymize->setText(avaiableAmountToAnonymizeText);

    // set coins count
    ui->spendable->setText(QString::fromStdString(std::to_string(confirmeds)));
    ui->unconfirmed->setText(QString::fromStdString(std::to_string(unconfirmeds)));
    ui->total->setText(QString::fromStdString(std::to_string(totalCoins)));

    // set amount
    ui->spendableAmount->setText(BitcoinUnits::formatWithUnit(
        unit, cachedPrivateBalance, false, BitcoinUnits::separatorAlways));
    ui->unconfirmedAmount->setText(BitcoinUnits::formatWithUnit(
        unit, cachedUnconfirmedPrivateBalance, false, BitcoinUnits::separatorAlways));
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

void LelantusDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void LelantusDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void LelantusDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void LelantusDialog::setMinimumFee()
{
    ui->radioCustomPerKilobyte->setChecked(true);
    ui->customFee->setValue(CWallet::GetRequiredFee(1000));
}

void LelantusDialog::updateFeeSectionControls()
{
    ui->sliderSmartFee          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFeeNormal     ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFeeFast       ->setEnabled(ui->radioSmartFee->isChecked());

    ui->confirmationTargetLabel ->setEnabled(ui->radioSmartFee->isChecked());
    ui->checkBoxMinimumFee      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelMinFeeWarning      ->setEnabled(ui->radioCustomFee->isChecked());
    ui->radioCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
    ui->radioCustomAtLeast      ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked() && coinControlStorage.coinControl.HasSelected());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked() && !ui->checkBoxMinimumFee->isChecked());
}

void LelantusDialog::updateGlobalFeeVariables()
{
    auto &coinControl = coinControlStorage.coinControl;
    if (ui->radioSmartFee->isChecked())
    {
        int nConfirmTarget = ui->sliderSmartFee->maximum() - ui->sliderSmartFee->value() + 2;
        payTxFee = CFeeRate(0);

        // set nMinimumTotalFee to 0 to not accidentally pay a custom fee
        coinControl.nMinimumTotalFee = 0;

        // show the estimated required time for confirmation
        ui->confirmationTargetLabel->setText(
            GUIUtil::formatDurationStr(nConfirmTarget * Params().GetConsensus().nPowTargetSpacing)
            + " / " + tr("%n block(s)", "", nConfirmTarget));
    }
    else
    {
        payTxFee = CFeeRate(ui->customFee->value());

        // if user has selected to set a minimum absolute fee, pass the value to coincontrol
        // set nMinimumTotalFee to 0 in case of user has selected that the fee is per KB
        coinControl.nMinimumTotalFee = ui->radioCustomAtLeast->isChecked() ? ui->customFee->value() : 0;
    }
}

void LelantusDialog::updateFeeMinimizedLabel()
{
    if(!walletModel || !walletModel->getOptionsModel())
        return;
    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) +
            ((ui->radioCustomPerKilobyte->isChecked()) ? "/kB" : ""));
    }
}

CAmount LelantusDialog::getAmount(int unit)
{
    CAmount val;

    return BitcoinUnits::parse(
        unit == -1 ? BitcoinUnits::Unit::BTC : unit,
        ui->anonymizeAmount->text(),
        &val) ? val : 0;
}

void LelantusDialog::removeUnmatchedOutput(CCoinControl &coinControl)
{
    std::vector<COutPoint> outpoints;
    coinControl.ListSelected(outpoints);

    for (auto const &out : outpoints) {
        auto it = pwalletMain->mapWallet.find(out.hash);
        if (it == pwalletMain->mapWallet.end()) {
            coinControl.UnSelect(out);
            continue;
        }
    }
}

void LelantusDialog::updateMinFeeLabel()
{
    if (walletModel && walletModel->getOptionsModel())
        ui->checkBoxMinimumFee->setText(tr("Pay only the required fee of %1").arg(
            BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), CWallet::GetRequiredFee(1000)) + "/kB")
        );
}

void LelantusDialog::updateSmartFeeLabel()
{
    if(!walletModel || !walletModel->getOptionsModel())
        return;

    int nBlocksToConfirm = ui->sliderSmartFee->maximum() - ui->sliderSmartFee->value() + 2;
    int estimateFoundAtBlocks = nBlocksToConfirm;
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocksToConfirm, &estimateFoundAtBlocks);
    if (feeRate <= CFeeRate(0)) // not enough data => minfee
    {
        ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(
            walletModel->getOptionsModel()->getDisplayUnit(),
            std::max(CWallet::fallbackFee.GetFeePerK(), CWallet::GetRequiredFee(1000))) + "/kB");
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(QFontMetrics(ui->fallbackFeeWarningLabel->font()).width("x"));
    }
    else
    {
        ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(
            walletModel->getOptionsModel()->getDisplayUnit(),
            std::max(feeRate.GetFeePerK(), CWallet::GetRequiredFee(1000))) + "/kB");
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", estimateFoundAtBlocks));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// coin controls
void LelantusDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && walletModel) {
        coinControlStorage.coinControl.SetNull();
    }

    // make sure we set back the confirmation target
    updateGlobalFeeVariables();
    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void LelantusDialog::coinControlButtonClicked()
{
    LelantusCoinControlDialog dlg(&coinControlStorage, platformStyle);
    dlg.setModel(walletModel);
    dlg.exec();

    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void LelantusDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked) {
        coinControlStorage.coinControl.destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    } else {
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());
    }

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void LelantusDialog::coinControlChangeEdited(const QString& text)
{
    if (walletModel && walletModel->getAddressTableModel()) {
        // Default to no change address until verified
        coinControlStorage.coinControl.destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        CBitcoinAddress addr = CBitcoinAddress(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!addr.IsValid()) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Zcoin address"));
        }
        else // Valid address
        {
            CKeyID keyid;
            addr.GetKeyID(keyid);
            if (!walletModel->havePrivKey(keyid)) // Unknown change address
            {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    coinControlStorage.coinControl.destChange = addr.Get();
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = walletModel
                    ->getAddressTableModel()
                    ->labelForAddress(text);

                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                coinControlStorage.coinControl.destChange = addr.Get();
            }
        }
    }
}

// Coin Control: update labels
void LelantusDialog::coinControlUpdateLabels()
{
    if (!walletModel || !walletModel->getOptionsModel())
        return;

    if (walletModel->getOptionsModel()->getCoinControlFeatures())
    {
        // enable minimum absolute fee UI controls
        ui->radioCustomAtLeast->setVisible(true);

        // only enable the feature if inputs are selected
        ui->radioCustomAtLeast->setEnabled(ui->radioCustomFee->isChecked()
            && !ui->checkBoxMinimumFee->isChecked()
            && coinControlStorage.coinControl.HasSelected());
    }
    else
    {
        // in case coin control is disabled (=default), hide minimum absolute fee UI controls
        ui->radioCustomAtLeast->setVisible(false);
        return;
    }

    // set pay amounts
    coinControlStorage.payAmounts = {getAmount()};
    coinControlStorage.fSubtractFeeFromAmount = false;

    if (coinControlStorage.coinControl.HasSelected())
    {
        // actual coin control calculation
        coinControlStorage.updateLabels(walletModel, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

// Coin Control: copy label "Quantity" to clipboard
void LelantusDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void LelantusDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void LelantusDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void LelantusDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void LelantusDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void LelantusDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void LelantusDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}