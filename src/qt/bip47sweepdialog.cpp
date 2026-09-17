#include "bip47sweepdialog.h"
#include "ui_bip47sweepdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"

#include "../wallet/wallet.h"

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>

Bip47SweepDialog::Bip47SweepDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Bip47SweepDialog),
    platformStyle(_platformStyle),
    model(0)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));

    GUIUtil::setupAddressWidget(ui->address, this, true);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &Bip47SweepDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &Bip47SweepDialog::reject);
    connect(ui->newTransparent, &QRadioButton::toggled, this, &Bip47SweepDialog::destinationChanged);
    connect(ui->newSpark, &QRadioButton::toggled, this, &Bip47SweepDialog::destinationChanged);
    connect(ui->existing, &QRadioButton::toggled, this, &Bip47SweepDialog::destinationChanged);
    connect(ui->address, &QValidatedLineEdit::textChanged, this, &Bip47SweepDialog::destinationChanged);
}

Bip47SweepDialog::~Bip47SweepDialog()
{
    delete ui;
}

void Bip47SweepDialog::setModel(WalletModel *_model)
{
    model = _model;
    if (!model)
        return;

    /* An older wallet holds no spark wallet to mint into. */
    CWallet * const wallet = model->getWallet();
    if (!wallet || !wallet->sparkWallet)
        ui->newSpark->setVisible(false);

    CAmount available = 0, locked = 0;
    size_t outputs = 0, lockedOutputs = 0;
    model->getBip47Balance(available, outputs, locked, lockedOutputs);

    int const unit = model->getOptionsModel() ? model->getOptionsModel()->getDisplayUnit() : BitcoinUnits::BTC;
    ui->availableLabel->setText(tr("%1 on %2 output(s)")
        .arg(BitcoinUnits::formatWithUnit(unit, available))
        .arg(outputs));

    /* The wallet locks the output of every notification transaction it receives, so that the
     * payment channel it opened is not spent away by accident. */
    if (lockedOutputs > 0) {
        ui->lockedLabel->setText(tr("%1 on %2 notification output(s)")
            .arg(BitcoinUnits::formatWithUnit(unit, locked))
            .arg(lockedOutputs));
    } else {
        ui->lockedTextLabel->setVisible(false);
        ui->lockedLabel->setVisible(false);
        ui->includeLocked->setVisible(false);
    }

    if (available == 0 && locked == 0) {
        ui->introLabel->setText(tr("The BIP47 (RAP) addresses of this wallet hold no funds. There is nothing to move."));
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    }

    destinationChanged();
}

void Bip47SweepDialog::destinationChanged()
{
    bool const useExisting = ui->existing->isChecked();
    ui->address->setEnabled(useExisting);
    ui->pasteButton->setEnabled(useExisting);
    ui->addressBookButton->setEnabled(useExisting);
}

void Bip47SweepDialog::on_pasteButton_clicked()
{
    ui->address->setText(QApplication::clipboard()->text());
}

void Bip47SweepDialog::on_addressBookButton_clicked()
{
    if (!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
    dlg.setModel(model->getAddressTableModel());
    if (dlg.exec())
        ui->address->setText(dlg.getReturnValue());
}

QString Bip47SweepDialog::resolveDestination()
{
    if (ui->existing->isChecked()) {
        QString const address = ui->address->text().trimmed();
        if (address.isEmpty() || (!model->validateAddress(address) && !model->validateSparkAddress(address))) {
            ui->address->setValid(false);
            QMessageBox::warning(this, windowTitle(), tr("Enter a transparent Firo address or a Spark address to move the funds to."));
            return QString();
        }
        return address;
    }

    QString const addressType = ui->newSpark->isChecked() ? AddressTableModel::Spark : AddressTableModel::Transparent;
    QString const address = model->getAddressTableModel()->addRow(
        AddressTableModel::Receive, tr("Moved from RAP addresses"), "", addressType);
    if (address.isEmpty())
        QMessageBox::warning(this, windowTitle(), tr("A new address could not be generated."));
    return address;
}

void Bip47SweepDialog::accept()
{
    if (!model)
        return;

    /* Both generating an address and signing the sweep need the keys. */
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QString const destination = resolveDestination();
    if (destination.isEmpty())
        return;

    bool const includeLocked = ui->includeLocked->isVisible() && ui->includeLocked->isChecked();

    CBip47SweepResult result;
    Bip47SweepStatus const status = model->sweepBip47(destination, includeLocked, result);

    if (status != Bip47SweepStatus::OK) {
        QString message;
        switch (status) {
        case Bip47SweepStatus::InvalidAddress:
            message = tr("%1 is not a valid Firo or Spark address.").arg(destination);
            break;
        case Bip47SweepStatus::WrongNetwork:
            message = tr("%1 is a Spark address of another network.").arg(destination);
            break;
        case Bip47SweepStatus::SparkUnavailable:
            message = tr("This wallet cannot hold Spark funds.");
            break;
        case Bip47SweepStatus::SparkNotActivated:
            message = tr("Spark is not activated yet.");
            break;
        case Bip47SweepStatus::P2PDisabled:
            message = tr("Peer-to-peer functionality is missing or disabled, so the transaction cannot be broadcast.");
            break;
        case Bip47SweepStatus::NoAddresses:
            message = tr("This wallet has no BIP47 (RAP) addresses.");
            break;
        case Bip47SweepStatus::NoFunds:
            message = result.lockedCount > 0
                ? tr("The BIP47 (RAP) addresses hold no spendable funds. Tick the box above to move the locked notification outputs as well.")
                : tr("The BIP47 (RAP) addresses hold no spendable funds.");
            break;
        case Bip47SweepStatus::FeeExceedsAmount:
            message = tr("The amount held on the BIP47 (RAP) addresses does not cover the transaction fee.");
            break;
        default:
            message = QString::fromStdString(result.strError);
            break;
        }
        QMessageBox::warning(this, windowTitle(), message);
        return;
    }

    int const unit = model->getOptionsModel() ? model->getOptionsModel()->getDisplayUnit() : BitcoinUnits::BTC;
    QString message = tr("%1 was moved to %2, with %3 paid in fees.")
        .arg(BitcoinUnits::formatWithUnit(unit, result.amount))
        .arg(destination)
        .arg(BitcoinUnits::formatWithUnit(unit, result.fee));
    if (result.fLockedSkipped) {
        message += "\n\n" + tr("%1 on %2 locked notification output(s) was left behind.")
            .arg(BitcoinUnits::formatWithUnit(unit, result.lockedAmount))
            .arg(result.lockedCount);
    }
    QMessageBox::information(this, windowTitle(), message);

    /* With the addresses emptied there is nothing left to remind the user about. Anything left
     * behind is still worth a reminder on the next run. */
    if (!result.fLockedSkipped)
        model->dismissBip47Sweep();

    QDialog::accept();
}
