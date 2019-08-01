// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "zerocoinpage.h"
#include "ui_zerocoinpage.h"

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

ZerocoinPage::ZerocoinPage(const PlatformStyle *platformStyle, Mode mode, QWidget *parent) :
        QWidget(parent),
        ui(new Ui::ZerocoinPage),
        model(0),
        mode(mode){
    ui->setupUi(this);

    if (!platformStyle->getImagesOnButtons()) {
        ui->exportButton->setIcon(QIcon());
    } else {
        ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    switch (mode) {
        case ForSelection:
            setWindowTitle(tr("Zerocoin"));
            connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
            ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            ui->tableView->setFocus();
            ui->exportButton->hide();
            break;
        case ForEditing:
            setWindowTitle(tr("Zerocoin"));
    }
    ui->labelExplanation->setText(
            tr("Here you can use your zcoin to mint a new, private Zerocoin or spend a previously-minted Zerocoin to a 3rd party Zcoin address or your own wallet"));
    ui->zerocoinAmount->setVisible(true);
    ui->zerocoinMintButton->setVisible(true);
    ui->zerocoinSpendButton->setVisible(true);
    ui->zerocoinAmount->addItem("1");
    ui->zerocoinAmount->addItem("10");
    ui->zerocoinAmount->addItem("25");
    ui->zerocoinAmount->addItem("50");
    ui->zerocoinAmount->addItem("100");

    // Context menu actions
//    QAction *showQRCodeAction = new QAction(ui->showQRCode->text(), this);

    // Build context menu
    contextMenu = new QMenu(this);
//    contextMenu->addAction(showQRCodeAction);

    // Connect signals for context menu actions
//    connect(showQRCodeAction, SIGNAL(triggered()), this, SLOT(on_showQRCode_clicked()));
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(ui->zerocoinSpendToMeCheckBox, SIGNAL(stateChanged(int)), this, SLOT(zerocoinSpendToMeCheckBoxChecked(int)));

}

ZerocoinPage::~ZerocoinPage() {
    delete ui;
}

void ZerocoinPage::setModel(AddressTableModel *model) {
    this->model = model;
    if (!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterRole(AddressTableModel::TypeRole);
    proxyModel->setFilterFixedString(AddressTableModel::Zerocoin);

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Address, QHeaderView::ResizeToContents);
#endif

//    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
//            this, SLOT(selectionChanged()));

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(selectNewAddress(QModelIndex, int, int)));

//    selectionChanged();
}

void ZerocoinPage::on_zerocoinMintButton_clicked() {
    QString amount = ui->zerocoinAmount->currentText();
    std::string denomAmount = amount.toStdString();
    std::string stringError;
    if(!model->zerocoinMint(stringError, denomAmount)){
        QString t = tr(stringError.c_str());

        QMessageBox::critical(this, tr("Error"),
                              tr("You cannot mint zerocoin because %1").arg(t),
                              QMessageBox::Ok, QMessageBox::Ok);
    }else{
    	QMessageBox::information(this, tr("Success"),
    	                              tr("Zerocoin successfully minted"),
    	                              QMessageBox::Ok, QMessageBox::Ok);

    }
}

void ZerocoinPage::on_zerocoinSpendButton_clicked() {

    QString amount = ui->zerocoinAmount->currentText();
    QString address = ui->spendToThirdPartyAddress->text();
    std::string denomAmount = amount.toStdString();
    std::string thirdPartyAddress = address.toStdString();
    std::string stringError;

	if(ui->zerocoinSpendToMeCheckBox->isChecked() == false && thirdPartyAddress == ""){
		QMessageBox::critical(this, tr("Error"),
		                              tr("Your \"Spend To\" field is empty, please check again"),
		                              QMessageBox::Ok, QMessageBox::Ok);
	}else{

		if(!model->zerocoinSpend(stringError, thirdPartyAddress, denomAmount)){
			QString t = tr(stringError.c_str());

			QMessageBox::critical(this, tr("Error"),
								  tr("You cannot spend zerocoin because %1").arg(t),
								  QMessageBox::Ok, QMessageBox::Ok);
		}else{
			QMessageBox::information(this, tr("Success"),
										  tr("Zerocoin successfully spent"),
										  QMessageBox::Ok, QMessageBox::Ok);

		}
		ui->spendToThirdPartyAddress->clear();
		ui->spendToThirdPartyAddress->setEnabled(false);

		ui->zerocoinSpendToMeCheckBox->setChecked(true);
	}
}

void ZerocoinPage::zerocoinSpendToMeCheckBoxChecked(int state) {
    if (state == Qt::Checked)
    {
        ui->spendToThirdPartyAddress->clear();
        ui->spendToThirdPartyAddress->setEnabled(false);
    }else{
    	ui->spendToThirdPartyAddress->setEnabled(true);
    }
}


//void ZerocoinPage::on_showQRCode_clicked()
//{
//#ifdef USE_QRCODE
//    QTableView *table = ui->tableView;
//    QModelIndexList indexes = table->selectionModel()->selectedRows(AddressTableModel::Address);
//
//    Q_FOREACH(const QModelIndex &index, indexes) {
//    {
//        QString address = index.data().toString();
//        QString label = index.sibling(index.row(), 0).data(Qt::EditRole).toString();
//
//        QRCodeDialog *dialog = new QRCodeDialog(address, label, tab == ReceivingTab, this);
//        dialog->setModel(optionsModel);
//        dialog->setAttribute(Qt::WA_DeleteOnClose);
//        dialog->show();
//    }
//#endif
//}

//void ZerocoinPage::done(int retval) {
//    QTableView *table = ui->tableView;
//    if (!table->selectionModel() || !table->model())
//        return;
//
//    // Figure out which address was selected, and return it
//    QModelIndexList indexes = table->selectionModel()->selectedRows(AddressTableModel::Address);
//
//    Q_FOREACH(const QModelIndex &index, indexes) {
//        QVariant address = table->model()->data(index);
//        returnValue = address.toString();
//    }
//
//    if (returnValue.isEmpty()) {
//        // If no address entry selected, return rejected
////        retval = Rejected;
//    }
//
//    QDialog::done(retval);
//}

void ZerocoinPage::on_exportButton_clicked() {
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(this, tr("Export Address List"), QString(), tr("Comma-separated file (*.csv)"), NULL);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Label", AddressTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", AddressTableModel::Address, Qt::EditRole);

    if (!writer.write()) {
        QMessageBox::critical(this, tr("Export Failed"), tr("There was an error trying to save the address list to %1. Please try again.").arg(
                filename));
    }
}

void ZerocoinPage::contextualMenu(const QPoint &point) {
    QModelIndex index = ui->tableView->indexAt(point);
    if (index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void ZerocoinPage::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/) {
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, AddressTableModel::Address, parent));
    if (idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect)) {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
