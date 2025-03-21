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
#include "createsparknamepage.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "bip47/paymentcode.h"
#include "bip47/paymentchannel.h"

#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QSortFilterProxyModel>

AddressBookPage::AddressBookPage(const PlatformStyle *platformStyle, Mode _mode, Tabs _tab, QWidget *parent, bool isReused) :
    QDialog(parent),
    ui(new Ui::AddressBookPage),
    model(0),
    mode(_mode),
    tab(_tab)
{
    ui->setupUi(this);
    this->isReused = isReused;

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
        connect(ui->tableView, &QTableView::doubleClicked, this, &QDialog::accept);
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
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
    QAction *editAction = new QAction(tr("&Edit"), this);
    deleteAction = new QAction(ui->deleteAddress->text(), this);

    // Build context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(editAction);
    if(tab == SendingTab)
        contextMenu->addAction(deleteAction);
    contextMenu->addSeparator();

    // Connect signals for context menu actions
    connect(copyAddressAction, &QAction::triggered, this, &AddressBookPage::on_copyAddress_clicked);
    connect(copyLabelAction, &QAction::triggered, this, &AddressBookPage::onCopyLabelAction);
    connect(editAction, &QAction::triggered, this, &AddressBookPage::onEditAction);
    connect(deleteAction, &QAction::triggered, this, &AddressBookPage::on_deleteAddress_clicked);

    connect(ui->tableView, &QWidget::customContextMenuRequested, this, &AddressBookPage::contextualMenu);

    connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

AddressBookPage::~AddressBookPage()
{
    delete ui;
}

void AddressBookPage::setModel(AddressTableModel *_model)
{
    this->model = _model;
    if(!_model)
        return;
    bool spark = this->model->IsSparkAllowed();

    if (tab == SendingTab) {
        if (spark)
            ui->addressType->addItem(tr("Spark"), Spark);
        ui->addressType->addItem(tr("Transparent"), Transparent);
        if (spark) {
            ui->addressType->addItem(tr("Spark names"), SparkName);
            ui->addressType->addItem(tr("My own spark names"), SparkNameMine);
        }
    } else if(tab == ReceivingTab && !this->isReused) {
        if (spark) {
            ui->addressType->addItem(tr("Spark"), Spark);
        }
        ui->addressType->addItem(tr("Transparent"), Transparent);
    } else {
        ui->addressType->addItem(tr(""), Transparent);
        ui->addressType->addItem(tr("Transparent"), Transparent);
        ui->addressType->hide();
    }

    proxyModel = new QSortFilterProxyModel(this);
    fproxyModel = new AddressBookFilterProxy(this);
    proxyModel->setSourceModel(model);
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
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);  
        
    fproxyModel->setSourceModel(proxyModel);
    fproxyModel->setDynamicSortFilter(true);
    fproxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    fproxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ui->tableView->setModel(fproxyModel);
    // Set column widths
    #if QT_VERSION < 0x050000
        ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
        ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::Address, QHeaderView::Stretch);
        ui->tableView->horizontalHeader()->setResizeMode(AddressTableModel::AddressType, QHeaderView::Stretch);
    #else
        ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Label, QHeaderView::Stretch);
        ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::Address, QHeaderView::Stretch);
        ui->tableView->horizontalHeader()->setSectionResizeMode(AddressTableModel::AddressType, QHeaderView::Stretch);
    #endif
        ui->tableView->setTextElideMode(Qt::ElideMiddle);
    connect(ui->tableView->selectionModel(), &QItemSelectionModel::selectionChanged, this, &AddressBookPage::selectionChanged);

    // Select row for newly created address
    connect(model, &AddressTableModel::rowsInserted, this, &AddressBookPage::selectNewAddress);

    selectionChanged();
    chooseAddressType(0);
    connect(ui->addressType, qOverload<int>(&QComboBox::activated), this, &AddressBookPage::chooseAddressType);
}

void AddressBookPage::updateSpark() {
    ui->addressType->clear();
    if (tab == SendingTab) {
        ui->addressType->addItem(tr("Spark"), Spark);
        ui->addressType->addItem(tr("Transparent"), Transparent);
    } else if(tab == ReceivingTab && !this->isReused) {
        ui->addressType->addItem(tr("Spark"), Spark);
        ui->addressType->addItem(tr("Transparent"), Transparent);
    } else {
        ui->addressType->addItem(tr(""), Transparent);
        ui->addressType->addItem(tr("Transparent"), Transparent);
        ui->addressType->hide();
    }

    chooseAddressType(0);
}

void AddressBookPage::on_copyAddress_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, AddressTableModel::Address);
}

void AddressBookPage::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, AddressTableModel::Label);
}

void AddressBookPage::onEditAction()
{
    QModelIndexList indexes;

    if (ui->addressType->currentText() == AddressTableModel::SparkName)
        return;

    EditAddressDialog::Mode mode;
    AddressTableModel * pmodel;
    pmodel = model;
    if (ui->addressType->currentText() == AddressTableModel::Transparent) {
        mode = tab == SendingTab ? EditAddressDialog::EditSendingAddress : EditAddressDialog::EditReceivingAddress;
    } else {
        mode = tab == SendingTab ? EditAddressDialog::EditSparkSendingAddress : EditAddressDialog::EditSparkReceivingAddress;
    }

    if (!ui->tableView->selectionModel())
        return;
    indexes = ui->tableView->selectionModel()->selectedRows();
    if (!pmodel || indexes.isEmpty())
        return;

    EditAddressDialog dlg(mode, this);
    dlg.setModel(pmodel);
    QModelIndex origIndex1, origIndex2;
    origIndex1 = fproxyModel->mapToSource(indexes.at(0));
    origIndex2 = proxyModel->mapToSource(origIndex1);
    dlg.loadRow(origIndex2.row());
    dlg.exec();
}

void AddressBookPage::on_newAddress_clicked()
{
    if(!model)
        return;

    if (ui->addressType->currentText() == AddressTableModel::SparkName) {
        CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getWalletModel());
        dialog->show();
        return;
    }

    AddressTableModel *pmodel;
    EditAddressDialog::Mode mode;
    pmodel = model;
    if (ui->addressType->currentText() == AddressTableModel::Spark) {
        mode = tab == SendingTab ? EditAddressDialog::NewSparkSendingAddress : EditAddressDialog::NewSparkReceivingAddress;
    } else {
        mode = tab == SendingTab ? EditAddressDialog::NewSendingAddress : EditAddressDialog::NewReceivingAddress;
    }

    EditAddressDialog dlg(mode, this);
    dlg.setModel(pmodel);
    if(dlg.exec())
    {
        newAddressToSelect = dlg.getAddress();
    }
}

void AddressBookPage::on_deleteAddress_clicked()
{
    QTableView *table;
    table = ui->tableView;

    if(!table->selectionModel() || ui->addressType->currentText() == AddressTableModel::SparkName)
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows();

    if(!indexes.isEmpty())
    {
        table->model()->removeRow(indexes.at(0).row());
    }
}

void AddressBookPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table;
    table = ui->tableView;

    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        bool fSparkNames = ui->addressType->currentText() == AddressTableModel::SparkName;
        switch(tab)
        {
        case SendingTab:
            // In sending tab, allow deletion of selection
            ui->deleteAddress->setEnabled(true);
            ui->deleteAddress->setVisible(!fSparkNames);
            deleteAction->setEnabled(!fSparkNames);
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

void AddressBookPage::done(int retval)
{
    QTableView *table;
    table = ui->tableView;

    if(!table->selectionModel() || !table->model())
        return;

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(AddressTableModel::Address);

    for (const QModelIndex& index : indexes) {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    if(returnValue.isEmpty())
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

    QTableView *table;
    writer.setModel(proxyModel);
    if (ui->addressType->currentText() == AddressTableModel::Transparent) {
        writer.addColumn("Label", AddressTableModel::Label, Qt::EditRole);
        writer.addColumn("Transparent Address", AddressTableModel::Address, Qt::EditRole);
        writer.addColumn("Address Type", AddressTableModel::AddressType, Qt::EditRole);
    } else {
        writer.addColumn("Label", AddressTableModel::Label, Qt::EditRole);
        writer.addColumn("Spark Address", AddressTableModel::Address, Qt::EditRole);
        writer.addColumn("Address Type", AddressTableModel::AddressType, Qt::EditRole);
    }

    if(!writer.write()) {
        QMessageBox::critical(this, tr("Exporting Failed"),
            tr("There was an error trying to save the address list to %1. Please try again.").arg(filename));
    }
}

void AddressBookPage::contextualMenu(const QPoint &point)
{
    QModelIndex index;
    index = ui->tableView->indexAt(point);

    int currentType = ui->addressType->currentData().toInt();
    if (currentType == (int)Spark || currentType == (int)SparkName || currentType == (int)SparkNameMine) {
        copyAddressAction->setText(tr("&Copy Spark Address"));
    } else {
        copyAddressAction->setText(tr("&Copy Transparent Address"));
    }
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void AddressBookPage::selectNewAddress(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, AddressTableModel::Address, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}

void AddressBookPage::chooseAddressType(int idx)
{
    if(!proxyModel)
        return;

    if (idx == 2) {
        model->ProcessPendingSparkNameChanges();
        ui->deleteAddress->setEnabled(false);
        deleteAction->setEnabled(false);
    }
    else {
        selectionChanged();
    }
    
    fproxyModel->setTypeFilter(
        ui->addressType->itemData(idx).toInt());
}

AddressBookFilterProxy::AddressBookFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent)
{
}

bool AddressBookFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex index = sourceModel()->index(sourceRow, 2, sourceParent);
    QString dataStr = sourceModel()->data(index).toString();

    switch (typeFilter) {
    case (int)AddressBookPage::Spark:
        return dataStr == "spark";
    case (int)AddressBookPage::Transparent:
        return dataStr == "transparent";
    case (int)AddressBookPage::SparkName:
        return dataStr.contains("spark name");
    case (int)AddressBookPage::SparkNameMine:
        return dataStr == "own spark name";
    default:
        return false;
    }
}

void AddressBookFilterProxy::setTypeFilter(quint32 modes)
{
    this->typeFilter = modes;
    invalidateFilter();
}
