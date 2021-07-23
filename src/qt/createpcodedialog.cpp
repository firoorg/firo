// Copyright (c) 2019-2021 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "createpcodedialog.h"
#include "ui_createpcodedialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "pcodemodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

CreatePcodeDialog::CreatePcodeDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreatePcodeDialog),
    columnResizingFixer(0),
    model(0),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->clearButton->setIcon(QIcon());
        ui->createPcodeButton->setIcon(QIcon());
    } else {
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->createPcodeButton->setIcon(_platformStyle->SingleColorIcon(":/icons/paymentcode"));
    }

    // context menu actions
    QAction *copyPcodeAction = new QAction(tr("Copy RAP Address"), this);
    QAction *copyNotificationAddrAction = new QAction(tr("Copy Notification Address"), this);
    QAction *showQrcodeAction = new QAction(tr("Show QR Code"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyPcodeAction);
    contextMenu->addAction(copyNotificationAddrAction);
    contextMenu->addAction(showQrcodeAction);

    // context menu signals
    connect(ui->pcodesView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyPcodeAction, SIGNAL(triggered()), this, SLOT(copyPcode()));
    connect(copyNotificationAddrAction, SIGNAL(triggered()), this, SLOT(copyNotificationAddr()));
    connect(showQrcodeAction, SIGNAL(triggered()), this, SLOT(showQrcode()));

    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    ui->statusLabel->setStyleSheet("QLabel { color: " + QColor(GUIUtil::GUIColors::warning).name() + "; }");
}

void CreatePcodeDialog::setModel(WalletModel *_model)
{
    model = _model;

    if(_model && _model->getOptionsModel())
    {
        _model->getPcodeModel()->sort(int(PcodeModel::ColumnIndex::Number), Qt::DescendingOrder);

        QTableView* tableView = ui->pcodesView;

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(_model->getPcodeModel());
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(static_cast<int>(PcodeModel::ColumnIndex::Number), static_cast<int>(ColumnWidths::Number));
        tableView->setColumnWidth(static_cast<int>(PcodeModel::ColumnIndex::Pcode), static_cast<int>(ColumnWidths::Pcode));
        tableView->setItemDelegateForColumn(int(PcodeModel::ColumnIndex::Pcode), new GUIUtil::TextElideStyledItemDelegate(tableView));

        connect(tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
                this, SLOT(pcodesView_selectionChanged(QItemSelection const &, QItemSelection const &)));
        // Last 2 columns are set by the columnResizingFixer, when the table geometry is ready.
        columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, 70, 70, this, int(PcodeModel::ColumnIndex::Pcode));
        columnResizingFixer->stretchColumnWidth(int(PcodeModel::ColumnIndex::Pcode));

        ui->createPcodeButton->setEnabled(false);
        ui->statusLabel->setText(tr("The label should not be empty."));
    }
}

CreatePcodeDialog::~CreatePcodeDialog()
{
    delete ui;
}

void CreatePcodeDialog::clear()
{
    ui->labelText->setText("");
}

void CreatePcodeDialog::reject()
{
    clear();
}

void CreatePcodeDialog::accept()
{
    clear();
}

void CreatePcodeDialog::on_createPcodeButton_clicked()
{
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid()) return;
    try {
        model->getWallet()->GeneratePcode(ui->labelText->text().toStdString());
    }
    catch (std::runtime_error const & e)
    {
        QMessageBox::critical(0, tr(PACKAGE_NAME),
            tr("RAP address creation failed with error: \"%1\"").arg(e.what()));
    }
    on_labelText_textChanged();
}

void CreatePcodeDialog::on_labelText_textChanged()
{
    QString status = "";
    if (ui->labelText->text().size() == 0)
        status = tr("The label should not be empty.");
    for (bip47::CPaymentCodeDescription const & desr : model->getPcodeModel()->getItems()) {
        if (std::get<2>(desr) == ui->labelText->text().toStdString())
            status = tr("The label should be unique.");
    }
    ui->statusLabel->setText(status);
    ui->createPcodeButton->setEnabled(status.size() == 0);
}

void CreatePcodeDialog::on_pcodesView_doubleClicked(const QModelIndex &index)
{
    if(index.column() == int(PcodeModel::ColumnIndex::Label))
    {
        ui->pcodesView->edit(index);
        return;
    }
    showQrcode();
}

void CreatePcodeDialog::on_showPcodeButton_clicked()
{
    showQrcode();
}

void CreatePcodeDialog::pcodesView_selectionChanged(QItemSelection const & selected, QItemSelection const & deselected)
{
    bool const enable = !ui->pcodesView->selectionModel()->selectedRows().isEmpty();
    ui->showPcodeButton->setEnabled(enable);
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void CreatePcodeDialog::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    columnResizingFixer->stretchColumnWidth(int(PcodeModel::ColumnIndex::Pcode));
}

void CreatePcodeDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return)
    {
        // press return -> submit form
        if (ui->labelText->hasFocus())
        {
            event->ignore();
            on_createPcodeButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

QModelIndex CreatePcodeDialog::selectedRow()
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->pcodesView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->pcodesView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    return firstIndex;
}

// copy column of selected row to clipboard
void CreatePcodeDialog::copyColumnToClipboard(int column)
{
    QModelIndex firstIndex = selectedRow();
    if (!firstIndex.isValid()) {
        return;
    }
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->data(firstIndex.child(firstIndex.row(), column), Qt::EditRole).toString());
}

// context menu
void CreatePcodeDialog::showMenu(const QPoint &point)
{
    if (!selectedRow().isValid()) {
        return;
    }
    contextMenu->exec(QCursor::pos());
}

void CreatePcodeDialog::copyPcode()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }
    GUIUtil::setClipboard(std::get<1>(model->getPcodeModel()->getItems().at(sel.row())).toString().c_str());
}

void CreatePcodeDialog::copyNotificationAddr()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }
    GUIUtil::setClipboard(std::get<3>(model->getPcodeModel()->getItems().at(sel.row())).ToString().c_str());
}

void CreatePcodeDialog::showQrcode()
{
    QModelIndex sel = selectedRow();
    if (!sel.isValid()) {
        return;
    }
    recipient.address = QString(std::get<1>(model->getPcodeModel()->getItems().at(sel.row())).toString().c_str());
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}
