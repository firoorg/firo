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

#include "../wallet/wallet.h"

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
    ui->availMintsTable->setSortingEnabled(false);

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

    connect(ui->availMintsTable->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this, SLOT(selectionChanged()));
    ui->remintButton->setDisabled(true);
}

void Zc2SigmaPage::on_remintButton_clicked() {
    QItemSelectionModel * select = ui->availMintsTable->selectionModel();

    if(!select->hasSelection())
        return;

    QModelIndexList idxs = select->selectedRows();
    for(int i = 0; i < idxs.size(); ++i) {
        int const row = idxs[i].row();
        bool ok;
        uint denom =  select->currentIndex().child(row , 1).data().toUInt(&ok); //denomination
        if(!ok) {
            QMessageBox::critical(this, "Unable to remint", QString("Failed to parse denomination."));
            break;
        }
        uint version = select->currentIndex().child(row , 2).data().toUInt(&ok); //version
        if(!ok) {
            QMessageBox::critical(this, "Unable to remint", QString("Failed to parse version."));
            break;
        }

        std::string error;
        bool result;
        {
            LOCK(pwalletMain->cs_wallet);
            result = pwalletMain->CreateZerocoinToSigmaRemintModel(error, int(version), libzerocoin::CoinDenomination(denom));
        }
        if(!result)
            QMessageBox::critical(this, "Unable to remint", QString("Failed to remint: ").append(error.c_str()));
        else
            QMessageBox::information(this, "Reminted", QString("Successfully reminted."));
    }
}

void Zc2SigmaPage::selectionChanged() {
    QItemSelectionModel * select = ui->availMintsTable->selectionModel();
    bool enabled = false;
    QModelIndexList idxs = select->selectedRows();
    for(int i = 0; i < idxs.size(); ++i) {
        int const row = idxs[i].row();
        bool ok;
        uint num =  select->currentIndex().child(row , 0).data().toUInt(&ok); //number
        if(!ok)
            continue;
        if(num > 0) {
            enabled = true;
            break;
        }
    }
    ui->remintButton->setDisabled(!enabled);
}
