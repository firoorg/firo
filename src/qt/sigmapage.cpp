#include "ui_sigmapage.h"
#include "sigmapage.h"
#include "sendcoinsentry.h"
#include "platformstyle.h"

#include "manualmintdialog.h"

SigmaPage::SigmaPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SigmaPage),
    platformStyle(platformStyle)
{
    ui->setupUi(this);
    setWindowTitle(tr("Sigma"));

    if (platformStyle->getImagesOnButtons()) {
        ui->spendButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
        ui->clearAllButton->setIcon(platformStyle->SingleColorIcon(":/icons/quit"));
        ui->addRecipientButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));

        ui->mintButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->selectDenomsButton->setIcon(platformStyle->SingleColorIcon(":/icons/edit"));
    } else {
        ui->spendButton->setIcon(QIcon());
        ui->clearAllButton->setIcon(QIcon());
        ui->addRecipientButton->setIcon(QIcon());

        ui->mintButton->setIcon(QIcon());
        ui->selectDenomsButton->setIcon(QIcon());
    }

    connect(ui->selectDenomsButton, SIGNAL(clicked()), this, SLOT(coinSelectionButtonClicked()));
}

void SigmaPage::coinSelectionButtonClicked() {
    ManualMintDialog dlg(platformStyle);
    // TODO: need this in the future
    // dlg.setModel();
    dlg.exec();
}
