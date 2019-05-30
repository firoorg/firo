// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "zc2sigmapage.h"
#include "ui_zc2sigmapage.h"

#include "addresstablemodel.h"
#include "bitcoingui.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "zc2sigmamodel.h"

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>

Zc2SigmaPage::Zc2SigmaPage(const PlatformStyle *platformStyle, QWidget *parent)
: QWidget(parent)
, ui(new Ui::Zc2SigmaPage)
, model(0)
{
    ui->setupUi(this);

    setWindowTitle(tr("Zerocoin to Sigma"));

    ui->explanationLabel->setText(
            tr("Here you can remint your unspent Zerocoin as Sigma mints"));
}

Zc2SigmaPage::~Zc2SigmaPage() {
    delete ui;
}

void Zc2SigmaPage::createModel() {
    model = std::make_shared<Zc2SigmaModel>();

    ui->availMintsTable->setModel(model.get());
    ui->availMintsTable->sortByColumn(1, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->availMintsTable->horizontalHeader()->setResizeMode(Zc2SigmaModel::MintCount, QHeaderView::Stretch);
    ui->availMintsTable->horizontalHeader()->setResizeMode(Zc2SigmaModel::Denomination, QHeaderView::Stretch);
    ui->availMintsTable->horizontalHeader()->setResizeMode(Zc2SigmaModel::Version, QHeaderView::ResizeToContents);
#else
    ui->availMintsTable->horizontalHeader()->setSectionResizeMode(Zc2SigmaModel::MintCount, QHeaderView::Stretch);
    ui->availMintsTable->horizontalHeader()->setSectionResizeMode(Zc2SigmaModel::Denomination, QHeaderView::Stretch);
    ui->availMintsTable->horizontalHeader()->setSectionResizeMode(Zc2SigmaModel::Version, QHeaderView::ResizeToContents);
#endif

}

#include <iostream>
void Zc2SigmaPage::on_remintButton_clicked() {
    //std::string RemintZerocoinToSigma(int version, libzerocoin::CoinDenomination d)
    std::cerr << "on_remintButton_clicked" << std::endl;
}
