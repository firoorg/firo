#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "createsparknamepage.h"
#include "ui_createsparkname.h"

#include "platformstyle.h"

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

