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
}

CreateSparkNamePage::~CreateSparkNamePage()
{
    delete ui;
}


CWalletTx CreateSparkNamePage::CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo)
{
    CWalletTx wtx;

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
            return wtx;
        }

        assert(!name.empty() && name.length() <= CSparkNameManager::maximumSparkNameLength);

        CAmount sparkNameFee = consensusParams.nSparkNamesFee[name.length()];
        CAmount txFee;

        CWalletTx wtx = pwalletMain->CreateSparkNameTransaction(sparkNameData, sparkNameFee, txFee);
    }
    catch (const std::exception &) {
        QMessageBox::critical(this, tr("Error"), tr("Failed to create spark name transaction"));
    }

    return wtx;
}

