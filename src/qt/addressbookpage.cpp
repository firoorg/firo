// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "addressbookpage.h"
#include "ui_addressbookpage.h"

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
#include <QTabWidget>
#include <iostream>


AddressBookPage::AddressBookPage(const PlatformStyle *platformStyle, Mode _mode, Tabs _tab, QWidget *parent) :
        QDialog(parent),
        ui(new Ui::AddressBookPage),
        model(0),
        pcodeModel(0),
        pageMode(0),
        mode(_mode),
        tab(_tab)
{
    ui->setupUi(this);

    if (!platformStyle->getImagesOnButtons()) {
        ui->newAddress->setIcon(QIcon());
        ui->copyAddress->setIcon(QIcon());
        ui->deleteAddress->setIcon(QIcon());
        ui->exportButton->setIcon(QIcon());
    } else {
        ui->newAddress->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->copyAddress->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
        ui->deleteAddress->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
        ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }

    switch(mode)
    {
    case ForSelection:
        switch(tab)
        {
        case SendingTab: setWindowTitle(tr("Choose the address to send coins to")); break;
        case ReceivingTab: setWindowTitle(tr("Choose the address to receive coins with")); break;
        }
        connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        connect(ui->paymentcodeTableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
        ui->paymentcodeTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->tableView->setFocus();
        ui->closeButton->setText(tr("C&hoose"));
        ui->exportButton->hide();
        break;
    case ForEditing:
        switch(tab)
        {
        case SendingTab: setWindowTitle(tr("Sending addresses")); break;
        case ReceivingTab: setWindowTitle(tr("Receiving addresses")); break;
        }
        break;
    }
    switch(tab)
    {
    case SendingTab:
        ui->labelExplanation->setText(tr("These are your Firo addresses for sending payments. Always check the amount and the receiving address before sending coins."));
        ui->deleteAddress->setVisible(true);
        break;
    case ReceivingTab:
        ui->labelExplanation->setText(tr("These are your Firo addresses for receiving payments. It is recommended to use a new receiving address for each transaction."));
        ui->deleteAddress->setVisible(false);
        break;
    }

    // Context menu actions
    copyAddressAction = new QAction(tr("&Copy Address"), this);
    QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    editAction = new QAction(tr("&Edit"), this);
    deleteAction = new QAction(ui->deleteAddress->text(), this);

    // Build context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(editAction);
    if (tab == SendingTab)
        contextMenu->addAction(deleteAction);
    contextMenu->addSeparator();

    // Connect signals for context menu actions
    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(on_copyAddress_clicked()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(onCopyLabelAction()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));
    connect(deleteAction, SIGNAL(triggered()), this, SLOT(on_deleteAddress_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(ui->paymentcodeTableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    connect(ui->closeButton, SIGNAL(clicked()), this, SLOT(accept()));
    setActiveModel();
}

AddressBookPage::~AddressBookPage()
{
    delete ui;
}

void AddressBookPage::setModel(AddressTableModel *_model)
{
    this->model = _model;
    if (!_model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(_model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    switch(tab)
    {
    case ReceivingTab:
        // Receive filter
        proxyModel->setFilterRole(AddressTableModel::TypeRole);
        proxyModel->setFilterFixedString(AddressTableModel::Receive);
        break;
    case SendingTab:
        // Send filter
        proxyModel->setFilterRole(AddressTableModel::TypeRole);
        proxyModel->setFilterFixedString(AddressTableModel::Send);
        break;
    }
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Label, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Address, QHeaderView::Stretch);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Label, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Address, QHeaderView::Stretch);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
        this, SLOT(selectionChanged()));

    // Select row for newly created address
    connect(_model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewAddress(QModelIndex,int,int)));

    selectionChanged();
    setActiveModel();
}

void AddressBookPage::setModel(PaymentCodeTableModel *pcodeModel)
{
    this->pcodeModel = pcodeModel;
    if(!pcodeModel)
        return;
    pcodeProxyModel = new QSortFilterProxyModel(this);
    pcodeProxyModel->setSourceModel(pcodeModel);
    pcodeProxyModel->setDynamicSortFilter(true);
    pcodeProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    pcodeProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    switch (tab) {
        case ReceivingTab:
            // Receive filter
            pcodeProxyModel->setFilterRole(PaymentCodeTableModel::TypeRole);
            pcodeProxyModel->setFilterFixedString(PaymentCodeTableModel::Receive);
            break;
        case SendingTab:
            // Send filter
            pcodeProxyModel->setFilterRole(PaymentCodeTableModel::TypeRole);
            pcodeProxyModel->setFilterFixedString(PaymentCodeTableModel::Send);
            break;
    }
    ui->paymentcodeTableView->setModel(pcodeProxyModel);
    ui->paymentcodeTableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->paymentcodeTableView->horizontalHeader()->setResizeMode(PaymentCodeTableModel::Label, QHeaderView::ResizeToContents);
    ui->paymentcodeTableView->horizontalHeader()->setResizeMode(PaymentCodeTableModel::Address, QHeaderView::Stretch);
#else
    ui->paymentcodeTableView->horizontalHeader()->setSectionResizeMode(ZCoinTableModel::Label, QHeaderView::ResizeToContents);
    ui->paymentcodeTableView->horizontalHeader()->setSectionResizeMode(ZCoinTableModel::Address, QHeaderView::Stretch);
#endif

    connect(ui->paymentcodeTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this, SLOT(pcodeSelectionChanged()));

    // Select row for newly created address
    connect(pcodeModel, SIGNAL(rowsInserted(QModelIndex, int, int)), this, SLOT(selectNewPaymentCode(QModelIndex, int, int)));
    pcodeSelectionChanged();
    setActiveModel();
}

void AddressBookPage::on_copyAddress_clicked() {
    GUIUtil::copyEntryData(pActiveTableView, ZCoinTableModel::Address);
}

void AddressBookPage::onCopyLabelAction() {
    GUIUtil::copyEntryData(pActiveTableView, ZCoinTableModel::Label);
}


void AddressBookPage::onEditAction() {
    if (!pActiveAddressModel)
        return;

    if (!pActiveTableView->selectionModel())
        return;

    QModelIndexList indexes = pActiveTableView->selectionModel()->selectedRows(); 
    if (indexes.isEmpty())
        return;

    EditAddressDialog dlg(
            tab == SendingTab ?
            EditAddressDialog::EditSendingAddress :
            EditAddressDialog::EditReceivingAddress, this);
    dlg.setIsForAddress(pageMode == 0);
    dlg.setModel(pActiveAddressModel);
    QModelIndex origIndex = pActiveProxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void AddressBookPage::on_tabWidget_currentChanged(int index) {
    pageMode = index;
    //change all tool tips
    setActiveModel();
}

void AddressBookPage::setActiveModel()
{
    if (pageMode == 0) {
        this->ui->newAddress->setToolTip("Create a new address");
        this->ui->copyAddress->setToolTip("Copy the currently selected address to the system clipboard");
        this->ui->deleteAddress->setToolTip("Delete the currently selected address from the list");
        this->copyAddressAction->setText("&Copy Address");
        this->pActiveAddressModel = this->model;
        this->pActiveProxyModel = this->proxyModel;
        this->pActiveTableView = this->ui->tableView;
        editAction->setEnabled(true);
        deleteAction->setEnabled(true);
        this->ui->newAddress->setEnabled(true);
        this->ui->deleteAddress->setEnabled(true);
    } else {
        this->ui->newAddress->setToolTip("Import a new payment code");
        this->ui->copyAddress->setToolTip("Copy the currently selected payment code to the system clipboard");
        this->ui->deleteAddress->setToolTip("Delete the currently selected payment code from the list");
        this->copyAddressAction->setText("&Copy Payment Code");
        this->pActiveAddressModel = this->pcodeModel;
        this->pActiveProxyModel = this->pcodeProxyModel;
        this->pActiveTableView = this->ui->paymentcodeTableView;
        deleteAction->setEnabled(false);
        this->ui->deleteAddress->setEnabled(false);
    }
}

void AddressBookPage::on_newAddress_clicked() 
{
    if (!pActiveAddressModel)
        return;

    EditAddressDialog dlg(
            tab == SendingTab ?
            EditAddressDialog::NewSendingAddress :
            EditAddressDialog::NewReceivingAddress, this);
    dlg.setIsForAddress(pageMode == 0);
    dlg.setModel(pActiveAddressModel);
    if (dlg.exec()) {
        newAddressToSelect = dlg.getAddress();
    }
}

void AddressBookPage::on_deleteAddress_clicked() {
    QTableView *table = pActiveTableView;
    if (!table->selectionModel())
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows();
    if (!indexes.isEmpty()) {
        std::cout << "deleting:" << indexes.at(0).row() << std::endl;
        table->model()->removeRow(indexes.at(0).row());
    }
}

void AddressBookPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    selectionChanged(ui->tableView);
}

void AddressBookPage::pcodeSelectionChanged() {
    // Set button states based on selected tab and selection
    selectionChanged(ui->paymentcodeTableView);
}

void AddressBookPage::selectionChanged(const QTableView *table) 
{
    if (!table) return;
    if (!table->selectionModel())
        return;

    if (table->selectionModel()->hasSelection())
    {
        switch(tab)
        {
        case SendingTab:
            // In sending tab, allow deletion of selection
            ui->deleteAddress->setEnabled(true);
            ui->deleteAddress->setVisible(true);
            deleteAction->setEnabled(true);
            break;
        case ReceivingTab:
            // Deleting receiving addresses, however, is not allowed
            ui->deleteAddress->setEnabled(false);
            ui->deleteAddress->setVisible(false);
            deleteAction->setEnabled(false);
            break;
        }
        ui->copyAddress->setEnabled(true);
    }
    else
    {
        ui->deleteAddress->setEnabled(false);
        ui->copyAddress->setEnabled(false);
    }
}

void AddressBookPage::done(int retval) {

    QTableView *table = pActiveTableView;
    if (!table->selectionModel() || !table->model())
        return;

    // Figure out which address was selected, and return it
    QModelIndexList indexes;
    indexes = table->selectionModel()->selectedRows(ZCoinTableModel::Address);

    Q_FOREACH(
    const QModelIndex &index, indexes) {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    if (returnValue.isEmpty())
    {
        // If no address entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void AddressBookPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export Address List"), QString(),
        tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Label", AddressTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", AddressTableModel::Address, Qt::EditRole);

    if (!writer.write()) {
        QMessageBox::critical(this, tr("Exporting Failed"),
            tr("There was an error trying to save the address list to %1. Please try again.").arg(filename));
    }
}

void AddressBookPage::contextualMenu(const QPoint &point) {
    QModelIndex index = pActiveTableView->indexAt(point);
    if (index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void AddressBookPage::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/) {
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, ZCoinTableModel::Address, parent));
    if (idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect)) {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}

void AddressBookPage::selectNewPaymentCode(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = pcodeProxyModel->mapFromSource(pcodeModel->index(begin, ZCoinTableModel::Address, parent));
    if (idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect)) {
        // Select row of newly created address, once
        ui->paymentcodeTableView->setFocus();
        ui->paymentcodeTableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}

