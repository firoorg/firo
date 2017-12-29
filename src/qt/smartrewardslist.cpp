
#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "smartrewardslist.h"
#include "ui_smartrewardslist.h"

#include "clientmodel.h"
#include "init.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "addresstablemodel.h"
#include "bitcoingui.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "platformstyle.h"

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>

SmartrewardsList::SmartrewardsList(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SmartrewardsList),
    model(0)
{
    ui->setupUi(this);
}

SmartrewardsList::~SmartrewardsList()
{
    delete ui;
}

void SmartrewardsList::setModel(AddressTableModel *model)
{
    this->model = model;
    if(!model) {
       return;
    }

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

}
