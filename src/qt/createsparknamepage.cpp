#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"

#include "platformstyle.h"
#include "validation.h"

#include <QStyle>
#include <QMessageBox>

CreateSparkNamePage::CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateSparkNamePage)
{
    ui->setupUi(this);

    feeText = ui->feeTextLabel->text();
    updateFee();
}

CreateSparkNamePage::~CreateSparkNamePage()
{
    delete ui;
}

void CreateSparkNamePage::setModel(WalletModel *model)
{
    this->model = model;
}

void CreateSparkNamePage::on_generateButton_clicked()
{
    QString newSparkAddress = model->generateSparkAddress();
    ui->sparkAddressEdit->setText(newSparkAddress);
}

void CreateSparkNamePage::on_sparkNameEdit_textChanged(const QString &text)
{
    updateFee();
}

void CreateSparkNamePage::on_numberOfYearsEdit_valueChanged(int value)
{
    updateFee();
}

void CreateSparkNamePage::updateFee() {
    QString sparkName = ui->sparkNameEdit->text();
    int numberOfYears = ui->numberOfYearsEdit->value();

    if (sparkName.isEmpty() || sparkName.length() > CSparkNameManager::maximumSparkNameLength || numberOfYears == 0 || numberOfYears > 10)
        ui->feeTextLabel->setText(feeText.arg("?"));
    else
        ui->feeTextLabel->setText(feeText.arg(QString::number(Params().GetConsensus().nSparkNamesFee[sparkName.length()]*numberOfYears)));
}

WalletModelTransaction CreateSparkNamePage::CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo)
{
    WalletModelTransaction tx({});

    try {
        LOCK(cs_main);
        LOCK(pwalletMain->cs_wallet);

        const auto &consensusParams = Params().GetConsensus();
        CSparkNameManager *sparkNameManager = CSparkNameManager::GetInstance();

        CSparkNameTxData sparkNameData;
        sparkNameData.name = name;
        sparkNameData.sparkAddress = address;
        sparkNameData.additionalInfo = additionalInfo;

        std::string strError;

        if (!sparkNameManager->ValidateSparkNameData(sparkNameData, strError)) {
            QMessageBox::critical(this, tr("Error validating spark name paramaeter"), strError.c_str());
            return tx;
        }

        assert(!name.empty() && name.length() <= CSparkNameManager::maximumSparkNameLength);

        CAmount sparkNameFee = consensusParams.nSparkNamesFee[name.length()]*COIN;
        CAmount txFee;

        WalletModel::SendCoinsReturn prepareStatus = model->prepareSparkNameTransaction(tx, sparkNameData, sparkNameFee, nullptr);
        if (prepareStatus.status != WalletModel::StatusCode::OK) {
            QMessageBox::critical(this, tr("Error"), tr("Failed to prepare spark name transaction"));
        }
    }
    catch (const std::exception &) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to create spark name transaction"));
    }

    return tx;
}

