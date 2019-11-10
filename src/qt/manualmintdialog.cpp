#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>

#include "manualmintdialog.h"
#include "ui_manualmintdialog.h"
#include "platformstyle.h"

ManualMintDialog::ManualMintDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ManualMintDialog),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    if (platformStyle->getImagesOnButtons()) {
        ui->mintButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearAllButton->setIcon(QIcon(platformStyle->SingleColorIcon(":/icons/remove")));
    } else {
        ui->mintButton->setIcon(QIcon());
        ui->clearAllButton->setIcon(QIcon());
    }
}

ManualMintDialog::~ManualMintDialog()
{
    delete ui;
}