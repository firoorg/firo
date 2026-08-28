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
#include "guitheme.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "bip47/paymentcode.h"
#include "bip47/paymentchannel.h"

#include <QFrame>
#include <QCoreApplication>
#include <QHeaderView>
#include <QIcon>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>
#include <QTableView>

namespace {

class AddressBookCardDelegate final : public QStyledItemDelegate
{
public:
    explicit AddressBookCardDelegate(QTableView* view)
        : QStyledItemDelegate(view)
        , view_(view)
    {
    }

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);
        painter->setClipRect(option.rect, Qt::IntersectClip);

        const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
        const bool selected = option.state & QStyle::State_Selected;
        painter->fillRect(option.rect, QColor(tc.panel));

        if (view_) {
            const QRect left = view_->visualRect(index.sibling(index.row(), AddressTableModel::Label));
            const QRect right = view_->visualRect(index.sibling(index.row(), AddressTableModel::AddressType));
            const QRect card(left.left() + 4, option.rect.top() + 4,
                             qMax(40, right.right() - left.left() - 8),
                             option.rect.height() - 8);
            QPainterPath cardPath;
            cardPath.addRoundedRect(QRectF(card).adjusted(0.5, 0.5, -0.5, -0.5), 12, 12);
            painter->setPen(QPen(selected ? QColor(tc.wine) : QColor(tc.border), 1));
            painter->setBrush(selected ? QColor(tc.panelSoft) : QColor(tc.panel));
            painter->drawPath(cardPath);
        }

        switch (index.column()) {
        case AddressTableModel::Label: {
            const QString text = index.data(Qt::DisplayRole).toString();
            QFont font = option.font;
            font.setPixelSize(12);
            font.setBold(true);
            painter->setFont(font);
            painter->setPen(QColor(tc.ink));
            const QRect textRect = option.rect.adjusted(12, 0, -8, 0);
            painter->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft,
                              QFontMetrics(font).elidedText(
                                  text.isEmpty() ? QCoreApplication::translate("AddressBookPage", "(no label)") : text,
                                  Qt::ElideRight, textRect.width()));
            break;
        }
        case AddressTableModel::Address: {
            const QString text = index.data(Qt::DisplayRole).toString();
            QFont font = GUIUtil::fixedPitchFont();
            font.setPixelSize(12);
            painter->setFont(font);
            painter->setPen(QColor(tc.inkSoft));
            painter->drawText(option.rect.adjusted(10, 0, -8, 0), Qt::AlignVCenter | Qt::AlignLeft,
                              QFontMetrics(font).elidedText(text, Qt::ElideMiddle, option.rect.width() - 18));
            break;
        }
        case AddressTableModel::AddressType: {
            const QString text = index.data(Qt::DisplayRole).toString();
            const QString addressType = index.data(AddressTableModel::AddressTypeRole).toString();
            const bool spark = addressType == AddressTableModel::Spark ||
                               addressType == AddressTableModel::SparkName;
            QFont badgeFont = option.font;
            badgeFont.setPixelSize(12);
            badgeFont.setBold(true);
            painter->setFont(badgeFont);
            const int w = qMin(option.rect.width() - 16, QFontMetrics(badgeFont).boundingRect(text).width() + 18);
            const QRect badge(option.rect.left() + 8, option.rect.center().y() - 11, w, 22);
            painter->setPen(Qt::NoPen);
            painter->setBrush(spark ? QColor(tc.wineTint) : QColor(tc.border));
            painter->drawRoundedRect(badge, 11, 11);
            painter->setPen(spark ? QColor(tc.ink) : QColor(tc.inkSoft));
            painter->drawText(badge, Qt::AlignCenter, text);
            break;
        }
        default:
            break;
        }
        painter->restore();
    }

private:
    QTableView* view_;
};

}

AddressBookPage::AddressBookPage(const PlatformStyle *_platformStyle, Mode _mode, Tabs _tab, QWidget *parent, bool isReused) :
    QDialog(parent),
    ui(new Ui::AddressBookPage),
    platformStyle(_platformStyle),
    model(0),
    mode(_mode),
    tab(_tab),
    initialAddressType(-1)
{
    ui->setupUi(this);
    this->isReused = isReused;

    if (!_platformStyle->getImagesOnButtons()) {
        ui->newAddress->setIcon(QIcon());
        ui->extendAddress->setIcon(QIcon());
        ui->copyAddress->setIcon(QIcon());
        ui->deleteAddress->setIcon(QIcon());
        ui->exportButton->setIcon(QIcon());
    } else {
        ui->newAddress->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->extendAddress->setIcon(_platformStyle->SingleColorIcon(":/icons/plus"));
        ui->copyAddress->setIcon(_platformStyle->SingleColorIcon(":/icons/editcopy"));
        ui->deleteAddress->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->exportButton->setIcon(_platformStyle->SingleColorIcon(":/icons/export"));
    }
    ui->extendAddress->setVisible(false); // hide extend address button for now

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
    QAction *extendAction = new QAction(tr("&Extend"), this);

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
    connect(extendAction, &QAction::triggered, this, &AddressBookPage::on_extendAddress_clicked);

    connect(ui->tableView, &QWidget::customContextMenuRequested, this, &AddressBookPage::contextualMenu);

    connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::accept);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &AddressBookPage::applyTheme);
    applyTheme();
}

void AddressBookPage::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));
    ui->labelExplanation->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-size: 12px; }")));
    ui->tableView->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QTableView { background: transparent; border: none; gridline-color: $BORDER; }"
        "QHeaderView::section {"
        " background: transparent; border: none; color: $INK_SOFT;"
        " font-size: 12px; font-weight: 700; padding: 6px;"
        "}"
        "QTableView::item { padding: 6px; }")));
    if (ui->tableView->viewport())
        ui->tableView->viewport()->update();
    ui->addressType->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QComboBox {"
        " background: $PANEL;"
        " border: 1px solid $BORDER;"
        " border-radius: 10px;"
        " padding: 8px 12px;"
        " color: $INK;"
        "}")));

    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle();
    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle();
    ui->newAddress->setStyleSheet(primaryButtonStyle);
    ui->closeButton->setStyleSheet(primaryButtonStyle);
    ui->extendAddress->setStyleSheet(secondaryButtonStyle);
    ui->copyAddress->setStyleSheet(secondaryButtonStyle);
    ui->deleteAddress->setStyleSheet(secondaryButtonStyle);
    ui->exportButton->setStyleSheet(secondaryButtonStyle);
}

AddressBookPage::~AddressBookPage()
{
    delete ui;
}

void AddressBookPage::populateAddressTypes(bool sparkAllowed)
{
    ui->addressType->clear();
    ui->addressType->show();

    if (tab == SendingTab || (tab == ReceivingTab && !this->isReused)) {
        if (sparkAllowed)
            ui->addressType->addItem(tr("Spark"), Spark);
        ui->addressType->addItem(tr("Transparent"), Transparent);
        if (sparkAllowed) {
            ui->addressType->addItem(tr("Spark names"), SparkName);
            ui->addressType->addItem(tr("My own spark names"), SparkNameMine);
        }
    } else {
        ui->addressType->addItem(tr(""), Transparent);
        ui->addressType->addItem(tr("Transparent"), Transparent);
        ui->addressType->hide();
    }
}

int AddressBookPage::currentAddressType() const
{
    return ui->addressType->currentData().toInt();
}

bool AddressBookPage::isSparkNameType(int type)
{
    return type == (int)SparkName || type == (int)SparkNameMine;
}

void AddressBookPage::setModel(AddressTableModel *_model)
{
    this->model = _model;
    if(!_model)
        return;
    populateAddressTypes(this->model->IsSparkAllowed());

    proxyModel = new QSortFilterProxyModel(this);
    fproxyModel = new AddressBookFilterProxy(this);
    proxyModel->setSourceModel(model);
    // Spark names are always stored with Send type, so skip the
    // Send/Receive filter when we specifically want spark names.
    if (initialAddressType == SparkName || initialAddressType == SparkNameMine) {
        // No TypeRole filter — let fproxyModel handle filtering by address type
    } else {
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
    }
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);  
        
    fproxyModel->setSourceModel(proxyModel);
    fproxyModel->setDynamicSortFilter(true);
    fproxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    fproxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ui->tableView->setModel(fproxyModel);
    ui->tableView->setShowGrid(false);
    ui->tableView->setFrameShape(QFrame::NoFrame);
    ui->tableView->setAlternatingRowColors(false);
    ui->tableView->verticalHeader()->setDefaultSectionSize(56);
    ui->tableView->setItemDelegate(new AddressBookCardDelegate(ui->tableView));
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
    int startIdx = 0;
    if (initialAddressType >= 0) {
        for (int i = 0; i < ui->addressType->count(); ++i) {
            if (ui->addressType->itemData(i).toInt() == initialAddressType) {
                startIdx = i;
                ui->addressType->setCurrentIndex(i);
                break;
            }
        }
    }
    chooseAddressType(startIdx);
    connect(ui->addressType, qOverload<int>(&QComboBox::activated), this, &AddressBookPage::chooseAddressType);
}

bool AddressBookPage::updateSpark()
{
    const bool sparkAllowed = model && model->IsSparkAllowed();
    populateAddressTypes(sparkAllowed);

    chooseAddressType(0);
    return sparkAllowed;
}

void AddressBookPage::setInitialAddressType(AddressTypeEnum type) {
    initialAddressType = static_cast<int>(type);
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
    const int selectedType = currentAddressType();

    if (isSparkNameType(selectedType))
        return;

    EditAddressDialog::Mode mode;
    AddressTableModel * pmodel;
    pmodel = model;
    if (selectedType == (int)Transparent) {
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

    const int selectedType = currentAddressType();
    if (isSparkNameType(selectedType)) {
        CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModel(model->getWalletModel());
        dialog->show();
        return;
    }

    AddressTableModel *pmodel;
    EditAddressDialog::Mode mode;
    pmodel = model;
    if (selectedType == (int)Spark) {
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
    const int selectedType = currentAddressType();

    if(!table->selectionModel() || isSparkNameType(selectedType))
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows();

    if(!indexes.isEmpty())
    {
        table->model()->removeRow(indexes.at(0).row());
    }
}

void AddressBookPage::on_extendAddress_clicked()
{
    if (!model)
        return;
    if (!ui->tableView || !ui->tableView->selectionModel())
        return;

    QModelIndexList selectionLabel = ui->tableView->selectionModel()->selectedRows(AddressTableModel::Label);
    QModelIndexList selectionAddress = ui->tableView->selectionModel()->selectedRows(AddressTableModel::Address);

    if (selectionLabel.isEmpty() || selectionAddress.isEmpty())
        return;

    QString rawLabel = selectionLabel.at(0).data(Qt::EditRole).toString();
    QString name = rawLabel.startsWith('@') ? rawLabel.mid(1) : rawLabel;
    QString address = selectionAddress.at(0).data(Qt::EditRole).toString();
    CreateSparkNamePage *dialog = new CreateSparkNamePage(platformStyle, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model->getWalletModel());
    dialog->setExtendMode(name, address);
    dialog->show();
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
        bool fSparkNames = isSparkNameType(currentAddressType());
        switch(tab)
        {
        case SendingTab:
            // In sending tab, allow deletion of selection
            ui->deleteAddress->setEnabled(!fSparkNames);
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
        ui->extendAddress->setEnabled(true);
    }
    else
    {
        ui->deleteAddress->setEnabled(false);
        ui->copyAddress->setEnabled(false);
        ui->extendAddress->setEnabled(false);
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
    QModelIndexList labelIndexes = table->selectionModel()->selectedRows(AddressTableModel::Label);

    for (const QModelIndex& index : indexes) {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    for (const QModelIndex& index : labelIndexes) {
        QVariant label = table->model()->data(index);
        returnLabel = label.toString();
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

    FIRO_UNUSED QTableView *table;
    writer.setModel(proxyModel);
    const int selectedType = currentAddressType();
    if (selectedType == (int)Transparent) {
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

    const int selectedType = ui->addressType->itemData(idx).toInt();

    if (isSparkNameType(selectedType)) {
        model->ProcessPendingSparkNameChanges();
        ui->deleteAddress->setEnabled(false);
        ui->deleteAddress->setVisible(false);
        deleteAction->setEnabled(false);
        // Remove TypeRole filter so spark names (stored as Send) are visible.
        proxyModel->setFilterRole(0);
        proxyModel->setFilterFixedString(QString());
    } else {
        ui->deleteAddress->setVisible(tab == SendingTab);
        // Restore TypeRole filter for non-spark-name types.
        switch(tab)
        {
        case ReceivingTab:
            proxyModel->setFilterRole(AddressTableModel::TypeRole);
            proxyModel->setFilterFixedString(AddressTableModel::Receive);
            break;
        case SendingTab:
            proxyModel->setFilterRole(AddressTableModel::TypeRole);
            proxyModel->setFilterFixedString(AddressTableModel::Send);
            break;
        }
        selectionChanged();
    }

    if (selectedType == (int)SparkNameMine) {
        ui->newAddress->setVisible(false);
        ui->extendAddress->setVisible(true);
    } else {
        ui->extendAddress->setVisible(false);
        ui->newAddress->setVisible(true);
    }
    
    fproxyModel->setTypeFilter(selectedType);
}

AddressBookFilterProxy::AddressBookFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent),
    typeFilter(AddressBookPage::Transparent)
{
}

bool AddressBookFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    const QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);
    const QString addressType = sourceModel()->data(
        index, AddressTableModel::AddressTypeRole).toString();
    
    switch (typeFilter) {
    case (int)AddressBookPage::Spark:
        return addressType == AddressTableModel::Spark;
    case (int)AddressBookPage::Transparent:
        return addressType == AddressTableModel::Transparent;
    case (int)AddressBookPage::SparkName:
        return addressType == AddressTableModel::SparkName;
    case (int)AddressBookPage::SparkNameMine:
        return addressType == AddressTableModel::SparkName &&
               sourceModel()->data(index, AddressTableModel::IsMineRole).toBool();
    default:
        return false;
    }
}

void AddressBookFilterProxy::setTypeFilter(quint32 modes)
{
    this->typeFilter = modes;
    invalidateFilter();
}
