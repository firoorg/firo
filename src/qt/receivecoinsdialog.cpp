// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "createsparknamepage.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QComboBox>
#include <QPushButton>
#include <QButtonGroup>
#include <QScreen>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveCoinsDialog),
    model(0),
    platformStyle(_platformStyle),
    recentRequestsProxyModel(0)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->receiveButton->setIcon(QIcon());
        ui->showRequestButton->setIcon(QIcon());
        ui->removeRequestButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->receiveButton->setIcon(_platformStyle->SingleColorIcon(":/icons/receiving_addresses"));
        ui->showRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/edit"));
        ui->removeRequestButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
    }

    ui->addressTypeCombobox->addItem(tr("Spark"), Spark);
    ui->addressTypeCombobox->addItem(tr("Transparent"), Transparent);

    if(ui->addressTypeCombobox->currentText() == "Spark"){
        ui->reuseAddress->hide();
        ui->createSparkNameButton->setVisible(true);
    } else {
        ui->reuseAddress->show();
        ui->createSparkNameButton->setVisible(false);
    }

    ui->addressTypeHistoryCombobox->addItem(tr("All"), All);
    ui->addressTypeHistoryCombobox->addItem(tr("Spark"), Spark);
    ui->addressTypeHistoryCombobox->addItem(tr("Transparent"), Transparent);

    // context menu actions
    QAction *copyURIAction = new QAction(tr("Copy URI"), this);
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyMessageAction = new QAction(tr("Copy message"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyURIAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    // context menu signals
    connect(ui->recentRequestsView, &QWidget::customContextMenuRequested, this, &ReceiveCoinsDialog::showMenu);
    connect(copyURIAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyURI);
    connect(copyLabelAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyLabel);
    connect(copyMessageAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyMessage);
    connect(copyAmountAction, &QAction::triggered, this, &ReceiveCoinsDialog::copyAmount);

    connect(ui->clearButton, &QPushButton::clicked, this, &ReceiveCoinsDialog::clear);
    connect(ui->addressTypeHistoryCombobox, qOverload<int>(&QComboBox::activated), this, &ReceiveCoinsDialog::chooseType);
    connect(ui->addressTypeCombobox, qOverload<int>(&QComboBox::activated), this, &ReceiveCoinsDialog::displayCheckBox);

    connect(ui->createSparkNameButton, &QPushButton::clicked, this, &ReceiveCoinsDialog::createSparkName);
}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        recentRequestsProxyModel = new RecentRequestsFilterProxy(this);
        recentRequestsProxyModel->setSourceModel(_model->getRecentRequestsTableModel());
        recentRequestsProxyModel->setDynamicSortFilter(true);
        recentRequestsProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
        recentRequestsProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
        chooseType(0);

        _model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &ReceiveCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        QTableView* tableView = ui->recentRequestsView;

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(recentRequestsProxyModel);
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::AddressType, ADDRESSTYPE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setMinimumSectionSize(23);
        tableView->horizontalHeader()->setStretchLastSection(true);

        connect(tableView->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &ReceiveCoinsDialog::recentRequestsView_selectionChanged);
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");
    ui->reuseAddress->setChecked(false);
    displayCheckBox(ui->addressTypeCombobox->currentIndex());
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();
    QString addressType = ui->addressTypeCombobox->currentText();
    if(ui->reuseAddress->isChecked() && ui->addressTypeCombobox->currentText() == AddressTableModel::Transparent)
    {
        /* Choose existing receiving address */
        AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
        dlg.setModel(model->getAddressTableModel());
        if(dlg.exec())
        {
            address = dlg.getReturnValue();
            if(label.isEmpty()) /* If no label provided, use the previously used label */
            {
                label = model->getAddressTableModel()->labelForAddress(address);
            }
        } else {
            return;
        }
    } else {
        /* Generate new receiving address */
        if(ui->addressTypeCombobox->currentText() == AddressTableModel::Transparent) {
            address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", AddressTableModel::Transparent);
        } else if(ui->addressTypeCombobox->currentText() == AddressTableModel::Spark) {
            address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", AddressTableModel::Spark);
        }
    }
    SendCoinsRecipient info(address, addressType, label,
        ui->reqAmount->value(), ui->reqMessage->text());
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(info);
    dialog->show();
    clear();

    /* Store request for later reference */
    model->getRecentRequestsTableModel()->addNewRequest(info);
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    QModelIndex targetIdx = recentRequestsProxyModel->mapToSource(index);
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(submodel->entry(targetIdx.row()).recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    ui->showRequestButton->setEnabled(enable);
    ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_showRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();

    for (const QModelIndex& index : selection) {
        on_recentRequestsView_doubleClicked(index);
    }
}

void ReceiveCoinsDialog::on_removeRequestButton_clicked()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    // correct for selection mode ContiguousSelection
    QModelIndex index = selection.at(0);
    QModelIndex firstIndex = recentRequestsProxyModel->mapToSource(index);
    model->getRecentRequestsTableModel()->removeRows(firstIndex.row(), selection.length(), firstIndex.parent());
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return)
    {
        // press return -> submit form
        if (ui->reqLabel->hasFocus() || ui->reqAmount->hasFocus() || ui->reqMessage->hasFocus())
        {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

QModelIndex ReceiveCoinsDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->index(firstIndex.row(), column).data(Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

// context menu action: copy URI
void ReceiveCoinsDialog::copyURI()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }

    const RecentRequestsTableModel * const submodel = model->getRecentRequestsTableModel();
    const QString uri = GUIUtil::formatBitcoinURI(submodel->entry(sel.row()).recipient);
    GUIUtil::setClipboard(uri);
}

// context menu action: copy label
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    copyColumnToClipboard(RecentRequestsTableModel::Amount);
}

void ReceiveCoinsDialog::displayCheckBox(int idx)
{
    if(idx==0){
        ui->reuseAddress->hide();
        ui->createSparkNameButton->setVisible(true);
    } else {
        ui->reuseAddress->show();
        ui->createSparkNameButton->setVisible(false);
    }
}

void ReceiveCoinsDialog::chooseType(int idx)
{
    if(!recentRequestsProxyModel)
        return;
    recentRequestsProxyModel->setTypeFilter(
        ui->addressTypeHistoryCombobox->itemData(idx).toInt());
}

RecentRequestsFilterProxy::RecentRequestsFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent),
    typeFilter(ALL_TYPES)
{
}

bool RecentRequestsFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex index = sourceModel()->index(sourceRow, 2, sourceParent);
    bool res0 = sourceModel()->data(index).toString().contains("spark");
    bool res1 = sourceModel()->data(index).toString().contains("transparent");
    if(res0 && typeFilter == 0)
        return true;
    if(res1 && typeFilter == 1)
        return true;
    if(typeFilter == 2)
        return true;

    return false;
}

void RecentRequestsFilterProxy::setTypeFilter(quint32 modes)
{
    this->typeFilter = modes;
    invalidateFilter();
}

// Handles resize events for the ReceiveCoinsDialog widget by adjusting internal component sizes.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QDialog::resizeEvent(event); 

    // Get new size from the event
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();
    
    adjustTextSize(newWidth,newHeight);
    // Set fixed, minimum, and maximum sizes for ComboBoxes
    int comboBoxMinHeight = 20;
    int comboBoxMaxHeight = 40;
    int comboBoxWidth = newWidth * 0.08; 
    int comboBoxMinWidth = newWidth * 0.05; 
    int comboBoxMaxWidth = newWidth * 0.1; 

    ui->addressTypeCombobox->setMinimumWidth(comboBoxMinWidth);
    ui->addressTypeCombobox->setMaximumWidth(comboBoxMaxWidth);
    ui->addressTypeCombobox->setMinimumHeight(comboBoxMinHeight);
    ui->addressTypeCombobox->setMaximumHeight(comboBoxMaxHeight);

    ui->addressTypeHistoryCombobox->setMinimumWidth(comboBoxMinWidth);
    ui->addressTypeHistoryCombobox->setMaximumWidth(comboBoxMaxWidth);
    ui->addressTypeHistoryCombobox->setMinimumHeight(comboBoxMinHeight);
    ui->addressTypeHistoryCombobox->setMaximumHeight(comboBoxMaxHeight);

    // Set sizes for buttons dynamically
    int buttonMinHeight = 20;
    int buttonMaxHeight = 35;
    int buttonWidth = newWidth * 0.15; 
    int buttonMinWidth = newWidth * 0.1; 
    int buttonMaxWidth = newWidth * 0.4; 

    ui->clearButton->setMinimumWidth(buttonMinWidth);
    ui->clearButton->setMaximumWidth(buttonMaxWidth);
    ui->clearButton->setMinimumHeight(buttonMinHeight);
    ui->clearButton->setMaximumHeight(buttonMaxHeight);

    ui->receiveButton->setMinimumWidth(buttonMinWidth);
    ui->receiveButton->setMaximumWidth(buttonMaxWidth);
    ui->receiveButton->setMinimumHeight(buttonMinHeight);
    ui->receiveButton->setMaximumHeight(buttonMaxHeight);

    ui->showRequestButton->setMinimumWidth(buttonMinWidth);
    ui->showRequestButton->setMaximumWidth(buttonMaxWidth);
    ui->showRequestButton->setMinimumHeight(buttonMinHeight);
    ui->showRequestButton->setMaximumHeight(buttonMaxHeight);

    ui->removeRequestButton->setMinimumWidth(buttonMinWidth);
    ui->removeRequestButton->setMaximumWidth(buttonMaxWidth);
    ui->removeRequestButton->setMinimumHeight(buttonMinHeight);
    ui->removeRequestButton->setMaximumHeight(buttonMaxHeight);

    // Adjust column widths proportionally
    int dateColumnWidth = newWidth * 0.25;
    int labelColumnWidth = newWidth * 0.25;
    int addressTypeColumnWidth = newWidth * 0.25;
    int amountColumnWidth = newWidth * 0.25;

    ui->recentRequestsView->setColumnWidth(RecentRequestsTableModel::Date, dateColumnWidth);
    ui->recentRequestsView->setColumnWidth(RecentRequestsTableModel::Label, labelColumnWidth);
    ui->recentRequestsView->setColumnWidth(RecentRequestsTableModel::AddressType, addressTypeColumnWidth);
    ui->recentRequestsView->setColumnWidth(RecentRequestsTableModel::Amount, amountColumnWidth);
}
void ReceiveCoinsDialog::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 70.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    // Set font size for all labels
    ui->reuseAddress->setFont(font);
    ui->label_4->setFont(font);
    ui->label_3->setFont(font);
    ui->addressTypeLabel->setFont(font);
    ui->label_5->setFont(font);
    ui->label_2->setFont(font);
    ui->label->setFont(font);
    ui->label_7->setFont(font);
    ui->label_6->setFont(font);
    ui->receiveButton->setFont(font);
    ui->clearButton->setFont(font);
    ui->showRequestButton->setFont(font);
    ui->removeRequestButton->setFont(font);
    ui->addressTypeCombobox->setFont(font);
    ui->addressTypeHistoryCombobox->setFont(font);
    ui->recentRequestsView->setFont(font);
    ui->recentRequestsView->horizontalHeader()->setFont(font);
    ui->recentRequestsView->verticalHeader()->setFont(font);
}

void ReceiveCoinsDialog::createSparkName() {
    CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model);
    dialog->show();
}