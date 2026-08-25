// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QLabel>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QScrollBar>
#include <QStyledItemDelegate>
#include <QTextDocument>
#include <QComboBox>
#include <QPushButton>
#include <QButtonGroup>
#include <QScreen>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>

namespace {

class PaymentRequestCardDelegate final : public QStyledItemDelegate
{
public:
    explicit PaymentRequestCardDelegate(QTableView* view)
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
            const QRect left = view_->visualRect(index.sibling(index.row(), RecentRequestsTableModel::Date));
            const QRect right = view_->visualRect(index.sibling(index.row(), RecentRequestsTableModel::Amount));
            const QRect card(left.left() + 4, option.rect.top() + 5,
                             qMax(40, right.right() - left.left() - 8),
                             option.rect.height() - 10);
            QPainterPath cardPath;
            cardPath.addRoundedRect(QRectF(card).adjusted(0.5, 0.5, -0.5, -0.5), 14, 14);
            painter->setPen(QPen(selected ? QColor(tc.wine) : QColor(tc.border), 1));
            painter->setBrush(selected ? QColor(tc.panelSoft) : QColor(tc.panel));
            painter->drawPath(cardPath);
        }

        switch (index.column()) {
        case RecentRequestsTableModel::Date: {
            QRect icon(option.rect.left() + 14, option.rect.center().y() - 16, 32, 32);
            painter->setPen(Qt::NoPen);
            painter->setBrush(QColor(tc.wineTint));
            painter->drawRoundedRect(icon, 10, 10);
            QFont iconFont = option.font;
            iconFont.setPixelSize(14);
            iconFont.setBold(true);
            painter->setFont(iconFont);
            painter->setPen(QColor(tc.wine));
            painter->drawText(icon, Qt::AlignCenter, QStringLiteral("↙"));

            const QString raw = index.data(Qt::DisplayRole).toString();
            const QString dateText = raw.section(QLatin1Char(' '), 0, -2);
            const QString timeText = raw.section(QLatin1Char(' '), -1);
            QFont dateFont = option.font;
            dateFont.setPixelSize(12);
            dateFont.setBold(true);
            painter->setFont(dateFont);
            painter->setPen(QColor(tc.ink));
            const QRect dateRect(icon.right() + 10, option.rect.top() + 14,
                                 option.rect.right() - icon.right() - 16, 18);
            painter->drawText(dateRect, Qt::AlignLeft | Qt::AlignVCenter, dateText);

            QFont timeFont = option.font;
            timeFont.setPixelSize(10);
            painter->setFont(timeFont);
            painter->setPen(QColor(tc.inkFaint));
            painter->drawText(QRect(dateRect.left(), dateRect.bottom() - 2, dateRect.width(), 16),
                              Qt::AlignLeft | Qt::AlignVCenter, timeText);
            break;
        }
        case RecentRequestsTableModel::Label: {
            const QString text = index.data(Qt::DisplayRole).toString();
            QFont font = option.font;
            font.setPixelSize(12);
            font.setBold(true);
            painter->setFont(font);
            painter->setPen(QColor(tc.ink));
            painter->drawText(option.rect.adjusted(10, 0, -8, 0), Qt::AlignVCenter | Qt::AlignLeft,
                              QFontMetrics(font).elidedText(text, Qt::ElideRight, option.rect.width() - 18));
            break;
        }
        case RecentRequestsTableModel::AddressType: {
            const QString text = index.data(Qt::DisplayRole).toString();
            const bool spark = text.compare(QLatin1String("spark"), Qt::CaseInsensitive) == 0;
            QFont badgeFont = option.font;
            badgeFont.setPixelSize(10);
            badgeFont.setBold(true);
            painter->setFont(badgeFont);
            const int w = qMin(option.rect.width() - 16, QFontMetrics(badgeFont).boundingRect(text).width() + 18);
            const QRect badge(option.rect.left() + 8, option.rect.center().y() - 11, w, 22);
            painter->setPen(Qt::NoPen);
            painter->setBrush(spark ? QColor(tc.wineTint) : QColor(tc.border));
            painter->drawRoundedRect(badge, 11, 11);
            painter->setPen(spark ? QColor(tc.wine) : QColor(tc.inkSoft));
            painter->drawText(badge, Qt::AlignCenter, text);
            break;
        }
        case RecentRequestsTableModel::Message: {
            const QString text = index.data(Qt::DisplayRole).toString();
            QFont font = option.font;
            font.setPixelSize(11);
            painter->setFont(font);
            painter->setPen(QColor(tc.inkSoft));
            painter->drawText(option.rect.adjusted(10, 0, -8, 0), Qt::AlignVCenter | Qt::AlignLeft,
                              QFontMetrics(font).elidedText(text, Qt::ElideRight, option.rect.width() - 18));
            break;
        }
        case RecentRequestsTableModel::Amount: {
            const QString amountText = index.data(Qt::DisplayRole).toString();
            QFont capFont = option.font;
            capFont.setPixelSize(8);
            capFont.setBold(true);
            painter->setFont(capFont);
            painter->setPen(QColor(tc.inkFaint));
            painter->drawText(option.rect.adjusted(8, 12, -14, -28),
                              Qt::AlignRight | Qt::AlignVCenter, QObject::tr("REQUESTED"));

            QFont amtFont = option.font;
            amtFont.setPixelSize(13);
            amtFont.setBold(true);
            painter->setFont(amtFont);
            painter->setPen(QColor(tc.ink));
            painter->drawText(option.rect.adjusted(8, 28, -14, -12),
                              Qt::AlignRight | Qt::AlignVCenter,
                              QFontMetrics(amtFont).elidedText(amountText, Qt::ElideLeft, option.rect.width() - 24));
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

    if(ui->addressTypeCombobox->currentData().toInt() == Spark){
        ui->reuseAddress->hide();
    } else {
        ui->reuseAddress->show();
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

    ui->frame2->setAttribute(Qt::WA_StyledBackground, true);
    ui->frame->setAttribute(Qt::WA_StyledBackground, true);

    requestsEmptyState = new QWidget(ui->frame);
    requestsEmptyState->setObjectName(QStringLiteral("requestsEmptyState"));
    auto* emptyLayout = new QVBoxLayout(requestsEmptyState);
    emptyLayout->setContentsMargins(0, 24, 0, 24);
    emptyLayout->setSpacing(7);
    emptyIcon_ = new QLabel(QStringLiteral("↙"), requestsEmptyState);
    emptyIcon_->setFixedSize(48, 48);
    emptyIcon_->setAlignment(Qt::AlignCenter);
    emptyTitle_ = new QLabel(tr("No payment requests yet"), requestsEmptyState);
    emptyTitle_->setAlignment(Qt::AlignCenter);
    emptyHint_ = new QLabel(
        tr("Requests you create will be listed here"), requestsEmptyState);
    emptyHint_->setAlignment(Qt::AlignCenter);
    emptyHint_->setWordWrap(true);
    emptyLayout->addStretch();
    emptyLayout->addWidget(emptyIcon_, 0, Qt::AlignHCenter);
    emptyLayout->addWidget(emptyTitle_);
    emptyLayout->addWidget(emptyHint_);
    emptyLayout->addStretch();
    ui->verticalLayout_2->insertWidget(2, requestsEmptyState, 1);
    requestsEmptyState->setVisible(false);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &ReceiveCoinsDialog::applyTheme);
    applyTheme();
}

void ReceiveCoinsDialog::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));

    const QString cardStyle = GUIUtil::themed(QStringLiteral(
        "QFrame#frame2, QFrame#frame {"
        " background: $PANEL;"
        " border: 1px solid $BORDER;"
        " border-radius: 18px;"
        "}"));
    ui->frame2->setStyleSheet(cardStyle);
    ui->frame->setStyleSheet(cardStyle);

    const QString captionStyle = GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_FAINT; font-size: 11px; font-weight: 700; }"));
    for (QLabel* caption : {ui->addressTypeLabel, ui->label_2, ui->label, ui->label_3}) {
        caption->setStyleSheet(captionStyle);
    }
    ui->label_5->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_FAINT; font-size: 11px; }")));
    ui->label_6->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-size: 15px; font-weight: 700; }")));

    const QString fieldStyle = GUIUtil::themed(QStringLiteral(
        "QLineEdit, AmountSpinBox {"
        " background: $PANEL_SOFT;"
        " border: 1px solid $BORDER;"
        " border-radius: 10px;"
        " padding: 8px 12px;"
        " color: $INK;"
        "}"
        "AmountSpinBox QLineEdit { %1 }"
        "QLineEdit[invalidInput=\"true\"], AmountSpinBox[invalidInput=\"true\"] {"
        " border-color: #E5484D;"
        "}"
        "QLineEdit:focus, AmountSpinBox:focus {"
        " background: $PANEL_SOFT;"
        " border: 1px solid $WINE;"
        " border-radius: 10px;"
        " padding: 8px 12px;"
        " color: $INK;"
        "}")).arg(GUIUtil::spinBoxInnerLineEditReset());
    ui->reqLabel->setStyleSheet(fieldStyle);
    ui->reqMessage->setStyleSheet(fieldStyle);
    ui->reqAmount->setStyleSheet(fieldStyle);

    const QString comboStyle = GUIUtil::themed(QStringLiteral(
        "QComboBox {"
        " background: $PANEL;"
        " border: 1px solid $BORDER;"
        " border-radius: 10px;"
        " padding: 8px 12px;"
        " color: $INK;"
        "}"
        "QComboBox QAbstractItemView {"
        " background: $PANEL;"
        " border: 1px solid $BORDER;"
        " border-radius: 10px;"
        " padding: 4px;"
        " outline: none;"
        "}"
        "QComboBox::item {"
        " padding: 8px 10px;"
        " border-radius: 8px;"
        " color: $INK;"
        "}"
        "QComboBox::item:alternate {"
        " background: $PANEL;"
        " color: $INK;"
        "}"
        "QComboBox::item:selected {"
        " background: $WINE;"
        " color: #FFFFFF;"
        "}"));
    ui->addressTypeCombobox->setStyleSheet(comboStyle);
    ui->addressTypeHistoryCombobox->setStyleSheet(comboStyle);

    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle(QStringLiteral("10px 18px"));
    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle(QStringLiteral("10px 18px"));
    ui->receiveButton->setStyleSheet(primaryButtonStyle);
    GUIUtil::applyPrimaryButtonShadow(ui->receiveButton);
    ui->clearButton->setStyleSheet(secondaryButtonStyle);
    ui->showRequestButton->setStyleSheet(secondaryButtonStyle);
    ui->removeRequestButton->setStyleSheet(secondaryButtonStyle);

    ui->recentRequestsView->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QTableView { background: transparent; border: none; gridline-color: $BORDER; }"
        "QHeaderView::section {"
        " background: transparent; border: none; color: $INK_FAINT;"
        " font-size: 10px; font-weight: 700; padding: 6px;"
        "}"
        "QTableView::item { padding: 6px; }")));
    if (ui->recentRequestsView->viewport())
        ui->recentRequestsView->viewport()->update();

    if (emptyIcon_) {
        emptyIcon_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { color: $WINE; background: $WINE_TINT; border-radius: 14px;"
            " font-size: 22px; font-weight: 700; }")));
    }
    if (emptyTitle_) {
        emptyTitle_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK_SOFT; font-size: 11px; font-weight: 700; }")));
    }
    if (emptyHint_) {
        emptyHint_->setStyleSheet(GUIUtil::themed(QStringLiteral(
            "QLabel { background: transparent; color: $INK_FAINT; font-size: 9px; }")));
    }
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
        tableView->setAlternatingRowColors(false);
        tableView->setShowGrid(false);
        tableView->setFrameShape(QFrame::NoFrame);
        tableView->verticalHeader()->setDefaultSectionSize(72);
        tableView->setItemDelegate(new PaymentRequestCardDelegate(tableView));
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::AddressType, ADDRESSTYPE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);
        tableView->horizontalHeader()->setMinimumSectionSize(23);
        tableView->horizontalHeader()->setStretchLastSection(true);

        auto wallet = _model->getWallet();
        if (!wallet || !wallet->sparkWallet) {
            ui->addressTypeCombobox->removeItem(0);
            ui->reuseAddress->show();
        }

        connect(tableView->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &ReceiveCoinsDialog::recentRequestsView_selectionChanged);

        connect(recentRequestsProxyModel, &QAbstractItemModel::rowsInserted, this, [this] { updateRequestsEmptyState(); });
        connect(recentRequestsProxyModel, &QAbstractItemModel::rowsRemoved, this, [this] { updateRequestsEmptyState(); });
        connect(recentRequestsProxyModel, &QAbstractItemModel::modelReset, this, [this] { updateRequestsEmptyState(); });
        updateRequestsEmptyState();
    }
}

void ReceiveCoinsDialog::updateRequestsEmptyState()
{
    const bool hasRequests = recentRequestsProxyModel && recentRequestsProxyModel->rowCount() > 0;
    if (requestsEmptyState) {
        requestsEmptyState->setVisible(!hasRequests);
        ui->recentRequestsView->setVisible(hasRequests);
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
    const int selectedAddressType = ui->addressTypeCombobox->currentData().toInt();
    if(ui->reuseAddress->isChecked() && selectedAddressType == Transparent)
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
        if(selectedAddressType == Transparent) {
            address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", AddressTableModel::Transparent);
        } else if(selectedAddressType == Spark) {
            address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "", AddressTableModel::Spark);
        }
    }
    if(address.isEmpty())
        return;

    SendCoinsRecipient info(address, addressType, label,
        ui->reqAmount->value(), ui->reqMessage->text());
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model);
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
    dialog->setModel(model);
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
    if(!model || !model->getRecentRequestsTableModel() || !recentRequestsProxyModel || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;

    QVector<int> sourceRows;
    sourceRows.reserve(selection.size());
    for (const QModelIndex& index : selection) {
        QModelIndex sourceIndex = recentRequestsProxyModel->mapToSource(index);
        if (sourceIndex.isValid())
            sourceRows.append(sourceIndex.row());
    }

    std::sort(sourceRows.begin(), sourceRows.end(), [](int left, int right) {
        return left > right;
    });

    for (int row : sourceRows) {
        model->getRecentRequestsTableModel()->removeRows(row, 1);
    }
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
    if(!model || !model->getRecentRequestsTableModel() || !recentRequestsProxyModel || !ui->recentRequestsView->selectionModel())
        return QModelIndex();
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return QModelIndex();
    QModelIndex firstIndex = selection.at(0);
    return recentRequestsProxyModel->mapToSource(firstIndex);
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
    if(ui->addressTypeCombobox->itemData(idx).toInt() == Spark){
        ui->reuseAddress->hide();
    } else {
        ui->reuseAddress->show();
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
    FIRO_UNUSED int comboBoxWidth = newWidth * 0.08;
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
    FIRO_UNUSED int buttonWidth = newWidth * 0.15;
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
    ui->label_3->setFont(font);
    ui->addressTypeLabel->setFont(font);
    ui->label_5->setFont(font);
    ui->label_2->setFont(font);
    ui->label->setFont(font);
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
