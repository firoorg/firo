// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionview.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "csvmodelwriter.h"
#include "editaddressdialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactiondescdialog.h"
#include "transactionfilterproxy.h"
#include "transactionrecord.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"


#include <QComboBox>
#include <QDateTimeEdit>
#include <QDesktopServices>
#include <QDoubleValidator>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPoint>
#include <QScrollBar>
#include <QTableView>
#include <QUrl>
#include <QVBoxLayout>
#include <QCalendarWidget>

namespace {
char const * CopyLabelText{"Copy label"};
char const * CopyRapText{"Copy RAP address/label"};
}

TransactionView::TransactionView(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent), model(0), transactionProxyModel(0),
    transactionView(0), abandonAction(0)
{
    // Build filter row
    setContentsMargins(0,0,0,0);

    headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0,0,0,0);

    if (platformStyle->getUseExtraSpacing()) {
        headerLayout->setSpacing(5);
        headerLayout->addSpacing(26);
    } else {
        headerLayout->setSpacing(0);
        headerLayout->addSpacing(23);
    }

    watchOnlyWidget = new QComboBox(this);
    watchOnlyWidget->setFixedWidth(24);
    watchOnlyWidget->addItem("", TransactionFilterProxy::WatchOnlyFilter_All);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_plus"), "", TransactionFilterProxy::WatchOnlyFilter_Yes);
    watchOnlyWidget->addItem(platformStyle->SingleColorIcon(":/icons/eye_minus"), "", TransactionFilterProxy::WatchOnlyFilter_No);
    headerLayout->addWidget(watchOnlyWidget);

    instantsendWidget = new QComboBox(this);
    instantsendWidget->addItem(tr("All"), TransactionFilterProxy::InstantSendFilter_All);
    instantsendWidget->addItem(tr("Locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_Yes);
    instantsendWidget->addItem(tr("Not locked by InstantSend"), TransactionFilterProxy::InstantSendFilter_No);
    headerLayout->addWidget(instantsendWidget);

    dateWidget = new QComboBox(this);
    if (platformStyle->getUseExtraSpacing()) {
        dateWidget->setFixedWidth(121);
    } else {
        dateWidget->setFixedWidth(120);
    }
    dateWidget->addItem(tr("All"), All);
    dateWidget->addItem(tr("Today"), Today);
    dateWidget->addItem(tr("This week"), ThisWeek);
    dateWidget->addItem(tr("This month"), ThisMonth);
    dateWidget->addItem(tr("Last month"), LastMonth);
    dateWidget->addItem(tr("This year"), ThisYear);
    dateWidget->addItem(tr("Range..."), Range);
    headerLayout->addWidget(dateWidget);

    typeWidget = new QComboBox(this);
    if (platformStyle->getUseExtraSpacing()) {
        typeWidget->setFixedWidth(121);
    } else {
        typeWidget->setFixedWidth(120);
    }

    typeWidget->addItem(tr("All"), TransactionFilterProxy::ALL_TYPES);
    typeWidget->addItem(tr("Received with"), TransactionFilterProxy::TYPE(TransactionRecord::RecvWithAddress) |
                                        TransactionFilterProxy::TYPE(TransactionRecord::RecvFromOther));
    typeWidget->addItem(tr("Sent to"), TransactionFilterProxy::TYPE(TransactionRecord::SendToAddress) |
                                  TransactionFilterProxy::TYPE(TransactionRecord::SendToOther));
    typeWidget->addItem(tr("To yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SendToSelf));
    typeWidget->addItem(tr("Mined"), TransactionFilterProxy::TYPE(TransactionRecord::Generated));
    typeWidget->addItem(tr("Other"), TransactionFilterProxy::TYPE(TransactionRecord::Other));
    typeWidget->addItem(tr("Spend to"), TransactionFilterProxy::TYPE(TransactionRecord::SpendToAddress));
    typeWidget->addItem(tr("Spend to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SpendToSelf));
    typeWidget->addItem(tr("Anonymize"), TransactionFilterProxy::TYPE(TransactionRecord::Anonymize));
    typeWidget->addItem(tr("Sent to RAP address"), TransactionFilterProxy::TYPE(TransactionRecord::SendToPcode));
    typeWidget->addItem(tr("Received with RAP address"), TransactionFilterProxy::TYPE(TransactionRecord::RecvWithPcode));
    typeWidget->addItem(tr("Mint spark to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::MintSparkToSelf));
    typeWidget->addItem(tr("Spend spark to yourself"), TransactionFilterProxy::TYPE(TransactionRecord::SpendSparkToSelf));
    typeWidget->addItem(tr("Mint spark to"), TransactionFilterProxy::TYPE(TransactionRecord::MintSparkTo));
    typeWidget->addItem(tr("Spend spark to"), TransactionFilterProxy::TYPE(TransactionRecord::SpendSparkTo));
    typeWidget->addItem(tr("Received Spark"), TransactionFilterProxy::TYPE(TransactionRecord::RecvSpark));

    headerLayout->addWidget(typeWidget);

    addressWidget = new QLineEdit(this);
#if QT_VERSION >= 0x040700
    addressWidget->setPlaceholderText(tr("Enter address or label to search"));
#endif
    headerLayout->addWidget(addressWidget);

    amountWidget = new QLineEdit(this);
#if QT_VERSION >= 0x040700
    amountWidget->setPlaceholderText(tr("Min amount"));
#endif
    if (platformStyle->getUseExtraSpacing()) {
        amountWidget->setFixedWidth(97);
    } else {
        amountWidget->setFixedWidth(100);
    }
    amountWidget->setValidator(new QDoubleValidator(0, 1e20, 8, this));
    headerLayout->addWidget(amountWidget);

    QVBoxLayout *vlayout = new QVBoxLayout(this);
    vlayout->setContentsMargins(0,0,0,0);
    vlayout->setSpacing(0);

    QTableView *view = new QTableView(this);
    vlayout->addLayout(headerLayout);
    vlayout->addWidget(createDateRangeWidget());
    vlayout->addWidget(view);
    vlayout->setSpacing(0);
    int width = view->verticalScrollBar()->sizeHint().width();
    // Cover scroll bar width with spacing
    if (platformStyle->getUseExtraSpacing()) {
        headerLayout->addSpacing(width+2);
    } else {
        headerLayout->addSpacing(width);
    }
    // Always show scroll bar
    view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    view->setTabKeyNavigation(false);
    view->setContextMenuPolicy(Qt::CustomContextMenu);
    view->setItemDelegateForColumn(TransactionTableModel::ToAddress, new GUIUtil::TextElideStyledItemDelegate(view));

    view->installEventFilter(this);

    transactionView = view;

    // Actions
    abandonAction = new QAction(tr("Abandon transaction"), this);
    resendAction = new QAction(tr("Re-broadcast transaction"), this);

    QAction *copyAddressAction = new QAction(tr("Copy address"), this);
    copyLabelAction = new QAction(tr(CopyLabelText), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);
    QAction *copyTxIDAction = new QAction(tr("Copy transaction ID"), this);
    QAction *copyTxHexAction = new QAction(tr("Copy raw transaction"), this);
    QAction *copyTxPlainText = new QAction(tr("Copy full transaction details"), this);
    QAction *editLabelAction = new QAction(tr("Edit label"), this);
    QAction *showDetailsAction = new QAction(tr("Show transaction details"), this);

    contextMenu = new QMenu(this);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTxIDAction);
    contextMenu->addAction(copyTxHexAction);
    contextMenu->addAction(copyTxPlainText);
    contextMenu->addAction(showDetailsAction);
    contextMenu->addSeparator();
    contextMenu->addAction(abandonAction);
    contextMenu->addAction(editLabelAction);
    contextMenu->addAction(resendAction);

    // Connect actions

    connect(dateWidget, qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseDate);
    connect(typeWidget, qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseType);
    connect(watchOnlyWidget, qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseWatchonly);
    connect(instantsendWidget, qOverload<int>(&QComboBox::activated), this, &TransactionView::chooseInstantSend);
    connect(addressWidget, &QLineEdit::textChanged, this, &TransactionView::changedPrefix);
    connect(amountWidget, &QLineEdit::textChanged, this, &TransactionView::changedAmount);

    connect(view, &QTableView::doubleClicked, this, &TransactionView::doubleClicked);
    connect(view, &QTableView::customContextMenuRequested, this, &TransactionView::contextualMenu);
    connect(view->horizontalHeader(), &QHeaderView::sectionResized, this, &TransactionView::updateHeaderSizes);

    connect(abandonAction, &QAction::triggered, this, &TransactionView::abandonTx);
    connect(copyAddressAction, &QAction::triggered, this, &TransactionView::copyAddress);
    connect(copyLabelAction, &QAction::triggered, this, &TransactionView::copyLabel);
    connect(copyAmountAction, &QAction::triggered, this, &TransactionView::copyAmount);
    connect(copyTxIDAction, &QAction::triggered, this, &TransactionView::copyTxID);
    connect(copyTxHexAction, &QAction::triggered, this, &TransactionView::copyTxHex);
    connect(copyTxPlainText, &QAction::triggered, this, &TransactionView::copyTxPlainText);
    connect(editLabelAction, &QAction::triggered, this, &TransactionView::editLabel);
    connect(showDetailsAction, &QAction::triggered, this, &TransactionView::showDetails);
    connect(this, &TransactionView::doubleClicked, this, &TransactionView::showDetails);
    connect(resendAction, &QAction::triggered, this, &TransactionView::rebroadcastTx);
}

void TransactionView::setModel(WalletModel *_model)
{
    this->model = _model;
    if(_model)
    {
        transactionProxyModel = new TransactionFilterProxy(this);
        transactionProxyModel->setSourceModel(_model->getTransactionTableModel());
        transactionProxyModel->setDynamicSortFilter(true);
        transactionProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
        transactionProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

        transactionProxyModel->setSortRole(Qt::EditRole);

        transactionView->setModel(transactionProxyModel);
        transactionView->setAlternatingRowColors(true);
        transactionView->setSelectionBehavior(QAbstractItemView::SelectRows);
        transactionView->setSelectionMode(QAbstractItemView::ExtendedSelection);
        transactionView->horizontalHeader()->setSortIndicator(TransactionTableModel::Date, Qt::DescendingOrder);
        transactionView->setSortingEnabled(true);
        transactionView->verticalHeader()->hide();

        transactionView->setColumnWidth(TransactionTableModel::Status, STATUS_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Watchonly, WATCHONLY_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::InstantSend, INSTANTSEND_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Date, DATE_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::Type, TYPE_COLUMN_WIDTH);
        transactionView->setColumnWidth(TransactionTableModel::ToAddress, ADDRESS_COLUMN_WIDTH);
        transactionView->horizontalHeader()->setSectionResizeMode(TransactionTableModel::Amount, QHeaderView::Fixed);
        transactionView->horizontalHeader()->setMinimumSectionSize(23);
        transactionView->horizontalHeader()->setStretchLastSection(true);
        transactionView->horizontalHeader()->setMaximumSectionSize(300);

        if (_model->getOptionsModel())
        {
            // Add third party transaction URLs to context menu
            QStringList listUrls = _model->getOptionsModel()->getThirdPartyTxUrls().split("|", Qt::SkipEmptyParts);
            for (int i = 0; i < listUrls.size(); ++i)
            {
                QString url = listUrls[i].trimmed();
                QString host = QUrl(url, QUrl::StrictMode).host();
                if (!host.isEmpty())
                {
                    QAction *thirdPartyTxUrlAction = new QAction(host, this); // use host as menu item label
                    if (i == 0)
                        contextMenu->addSeparator();
                    contextMenu->addAction(thirdPartyTxUrlAction);
                    connect(thirdPartyTxUrlAction, &QAction::triggered, [this, url] { openThirdPartyTxUrl(url); });
                }
            }
        }

        // show/hide column Watch-only
        updateWatchOnlyColumn(_model->haveWatchOnly());

        // Watch-only signal
        connect(_model, &WalletModel::notifyWatchonlyChanged, this, &TransactionView::updateWatchOnlyColumn);
    }
}

void TransactionView::chooseDate(int idx)
{
    if(!transactionProxyModel)
        return;
    QDate current = QDate::currentDate();
    dateRangeWidget->setVisible(false);
    switch(dateWidget->itemData(idx).toInt())
    {
    case All:
        transactionProxyModel->setDateRange(
                TransactionFilterProxy::MIN_DATE,
                TransactionFilterProxy::MAX_DATE);
        break;
    case Today:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(current)),
                TransactionFilterProxy::MAX_DATE);
        break;
    case ThisWeek: {
        // Find last Monday
        QDate startOfWeek = current.addDays(-(current.dayOfWeek()-1));
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(startOfWeek)),
                TransactionFilterProxy::MAX_DATE);

        } break;
    case ThisMonth:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1))),
                TransactionFilterProxy::MAX_DATE);
        break;
    case LastMonth:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1).addMonths(-1))),
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), current.month(), 1))));
        break;
    case ThisYear:
        transactionProxyModel->setDateRange(
                QDateTime(GUIUtil::StartOfDay(QDate(current.year(), 1, 1))),
                TransactionFilterProxy::MAX_DATE);
        break;
    case Range:
        dateRangeWidget->setVisible(true);
        dateRangeChanged();
        break;
    }
}

void TransactionView::chooseType(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setTypeFilter(
        typeWidget->itemData(idx).toInt());
}

void TransactionView::chooseWatchonly(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setWatchOnlyFilter(
        (TransactionFilterProxy::WatchOnlyFilter)watchOnlyWidget->itemData(idx).toInt());
}

void TransactionView::chooseInstantSend(int idx)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setInstantSendFilter(
        (TransactionFilterProxy::InstantSendFilter)instantsendWidget->itemData(idx).toInt());
}

void TransactionView::changedPrefix(const QString &prefix)
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setAddressPrefix(prefix);
}

void TransactionView::changedAmount(const QString &amount)
{
    if(!transactionProxyModel)
        return;
    CAmount amount_parsed = 0;
    if(BitcoinUnits::parse(model->getOptionsModel()->getDisplayUnit(), amount, &amount_parsed))
    {
        transactionProxyModel->setMinAmount(amount_parsed);
    }
    else
    {
        transactionProxyModel->setMinAmount(0);
    }
}

void TransactionView::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export Transaction History"), QString(),
        tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(transactionProxyModel);
    writer.addColumn(tr("Confirmed"), 0, TransactionTableModel::ConfirmedRole);
    if (model && model->haveWatchOnly())
        writer.addColumn(tr("Watch-only"), TransactionTableModel::Watchonly);
    writer.addColumn(tr("Date"), 0, TransactionTableModel::DateRole);
    writer.addColumn(tr("Type"), TransactionTableModel::Type, Qt::EditRole);
    writer.addColumn(tr("Label"), 0, TransactionTableModel::LabelRole);
    writer.addColumn(tr("Address"), 0, TransactionTableModel::AddressRole);
    writer.addColumn(BitcoinUnits::getAmountColumnTitle(model->getOptionsModel()->getDisplayUnit()), 0, TransactionTableModel::FormattedAmountRole);
    writer.addColumn(tr("ID"), 0, TransactionTableModel::TxIDRole);

    if(!writer.write()) {
        Q_EMIT message(tr("Exporting Failed"), tr("There was an error trying to save the transaction history to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
    }
    else {
        Q_EMIT message(tr("Exporting Successful"), tr("The transaction history was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void TransactionView::contextualMenu(const QPoint &point)
{
    QModelIndex index = transactionView->indexAt(point);
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if (selection.empty())
        return;

    // check if transaction can be abandoned, disable context menu action in case it doesn't
    uint256 hash;
    hash.SetHex(selection.at(0).data(TransactionTableModel::TxHashRole).toString().toStdString());
    if(selection.at(0).data(TransactionTableModel::PcodeRole).toString().size() > 0)
        copyLabelAction->setText(tr(CopyRapText));
    else
        copyLabelAction->setText(tr(CopyLabelText));
    abandonAction->setEnabled(model->transactionCanBeAbandoned(hash));
    resendAction->setEnabled(model->transactionCanBeRebroadcast(hash));

    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void TransactionView::updateHeaderSizes(int logicalIndex, int oldSize, int newSize)
{
    static std::vector<std::pair<int, QWidget*>> const headerWidgets{
        {TransactionTableModel::Watchonly, watchOnlyWidget},
        {TransactionTableModel::InstantSend, instantsendWidget},
        {TransactionTableModel::Date, dateWidget},
        {TransactionTableModel::Type, typeWidget},
        {TransactionTableModel::ToAddress, addressWidget},
        {TransactionTableModel::Amount, amountWidget}
    };

    if(logicalIndex <= TransactionTableModel::Amount)
        return;

    for(std::pair<int, QWidget*> const & p : headerWidgets) {
        int const w = transactionView->columnWidth(p.first) - headerLayout->spacing() / 2;
        if(p.second->width() != w)
            p.second->setFixedWidth(w);
    }
}

void TransactionView::abandonTx()
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);

    // get the hash from the TxHashRole (QVariant / QString)
    uint256 hash;
    QString hashQStr = selection.at(0).data(TransactionTableModel::TxHashRole).toString();
    hash.SetHex(hashQStr.toStdString());

    // Abandon the wallet transaction over the walletModel
    model->abandonTransaction(hash);

    // Update the table
    model->getTransactionTableModel()->updateTransaction(hashQStr, CT_UPDATED, false);
}

void TransactionView::rebroadcastTx()
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);

    // get the hash from the TxHashRole (QVariant / QString)
    uint256 hash;
    QString hashQStr = selection.at(0).data(TransactionTableModel::TxHashRole).toString();
    hash.SetHex(hashQStr.toStdString());

    CValidationState state;
    if (model->rebroadcastTransaction(hash, state))
        Q_EMIT message(tr("Re-broadcast"), tr("Broadcast succeeded"), CClientUIInterface::MSG_INFORMATION);
    else
        Q_EMIT message(tr("Re-broadcast"), tr("There was an error trying to broadcast the message: %1").arg(QString::fromUtf8(state.GetDebugMessage().c_str())),
            CClientUIInterface::MSG_ERROR);

    // Update the table
    model->getTransactionTableModel()->updateTransaction(hashQStr, CT_UPDATED, true);
}

void TransactionView::copyAddress()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::AddressRole);
}

void TransactionView::copyLabel()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::LabelRole);
}

void TransactionView::copyAmount()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::FormattedAmountRole);
}

void TransactionView::copyTxID()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxIDRole);
}

void TransactionView::copyTxHex()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxHexRole);
}

void TransactionView::copyTxPlainText()
{
    GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxPlainTextRole);
}

void TransactionView::editLabel()
{
    if(!transactionView->selectionModel() ||!model)
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        AddressTableModel *addressBook;
        EditAddressDialog::Mode mode;
        QString address = selection.at(0).data(TransactionTableModel::PcodeRole).toString();

        if(!address.isEmpty())
        {
            addressBook = model->getPcodeAddressTableModel();
            mode = EditAddressDialog::NewPcode;
        }
        else
        {
            address = selection.at(0).data(TransactionTableModel::AddressRole).toString();
            addressBook = model->getAddressTableModel();
            mode = model->validateAddress(address) ? EditAddressDialog::NewSendingAddress : EditAddressDialog::NewSparkSendingAddress;
        }

        if(!addressBook || address.isEmpty())
            return;
        // Is address in address book? Address book can miss address when a transaction is
        // sent from outside the UI.
        int idx = addressBook->lookupAddress(address);
        if(idx != -1)
        {
            // Edit sending / receiving address
            QModelIndex modelIdx = addressBook->index(idx, 0, QModelIndex());
            // Determine type of address, launch appropriate editor dialog type
            QString type = modelIdx.data(AddressTableModel::TypeRole).toString();

            if(mode == EditAddressDialog::NewSendingAddress)
            {
                mode = type == AddressTableModel::Receive
                    ? EditAddressDialog::EditReceivingAddress
                    : EditAddressDialog::EditSendingAddress;
            }
            else if(mode == EditAddressDialog::NewSparkSendingAddress)
            {
                mode = type == AddressTableModel::Receive
                    ? EditAddressDialog::EditSparkReceivingAddress
                    : EditAddressDialog::EditSparkSendingAddress;
            }
            else
                mode = EditAddressDialog::EditPcode;

            EditAddressDialog dlg(mode, this);
            dlg.setModel(addressBook);
            dlg.loadRow(idx);
            dlg.exec();
        }
        else
        {
            // Add sending address
            EditAddressDialog dlg(mode, this);
            dlg.setModel(addressBook);
            dlg.setAddress(address);
            dlg.exec();
        }
    }
}

void TransactionView::showDetails()
{
    if(!transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        TransactionDescDialog *dlg = new TransactionDescDialog(selection.at(0));
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }
}

void TransactionView::openThirdPartyTxUrl(QString url)
{
    if(!transactionView || !transactionView->selectionModel())
        return;
    QModelIndexList selection = transactionView->selectionModel()->selectedRows(0);
    if(!selection.isEmpty())
         QDesktopServices::openUrl(QUrl::fromUserInput(url.replace("%s", selection.at(0).data(TransactionTableModel::TxHashRole).toString())));
}

QWidget *TransactionView::createDateRangeWidget()
{
    dateRangeWidget = new QFrame();
    dateRangeWidget->setFrameStyle(QFrame::Panel | QFrame::Raised);
    dateRangeWidget->setContentsMargins(1,1,1,1);
    QHBoxLayout *layout = new QHBoxLayout(dateRangeWidget);
    layout->setContentsMargins(0,0,0,0);
    layout->addSpacing(23);
    layout->addWidget(new QLabel(tr("Range:")));

    dateFrom = new QDateTimeEdit(this);
    dateFrom->setDisplayFormat("dd/MM/yy");
    dateFrom->setCalendarPopup(true);
    dateFrom->setMinimumWidth(100);
    dateFrom->setDate(QDate::currentDate().addDays(-7));
    layout->addWidget(dateFrom);
    layout->addWidget(new QLabel(tr("to")));

    dateTo = new QDateTimeEdit(this);
    dateTo->setDisplayFormat("dd/MM/yy");
    dateTo->setCalendarPopup(true);
    dateTo->setMinimumWidth(100);
    dateTo->setDate(QDate::currentDate());
    layout->addWidget(dateTo);
    layout->addStretch();

    // Hide by default
    dateRangeWidget->setVisible(false);

    // Notify on change
    connect(dateFrom, &QDateTimeEdit::dateChanged, this, &TransactionView::dateRangeChanged);
    connect(dateTo, &QDateTimeEdit::dateChanged, this, &TransactionView::dateRangeChanged);

    updateCalendarWidgets();
    return dateRangeWidget;
}

void TransactionView::dateRangeChanged()
{
    if(!transactionProxyModel)
        return;
    transactionProxyModel->setDateRange(
            GUIUtil::StartOfDay(dateFrom->date()),
            GUIUtil::StartOfDay(dateTo->date()).addDays(1));
}

void TransactionView::updateCalendarWidgets()
{
    auto adjustWeekEndColors = [](QCalendarWidget* w) {
        QTextCharFormat format = w->weekdayTextFormat(Qt::Saturday);
        format.setForeground(QBrush(QColor(61,57,57), Qt::SolidPattern));

        w->setWeekdayTextFormat(Qt::Saturday, format);
        w->setWeekdayTextFormat(Qt::Sunday, format);
    };

    adjustWeekEndColors(dateFrom->calendarWidget());
    adjustWeekEndColors(dateTo->calendarWidget());
}

void TransactionView::focusTransaction(const QModelIndex &idx)
{
    if(!transactionProxyModel)
        return;
    QModelIndex targetIdx = transactionProxyModel->mapFromSource(idx);
    transactionView->scrollTo(targetIdx);
    transactionView->setCurrentIndex(targetIdx);
    transactionView->setFocus();
}

// Need to override default Ctrl+C action for amount as default behaviour is just to copy DisplayRole text
bool TransactionView::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_C && ke->modifiers().testFlag(Qt::ControlModifier))
        {
             GUIUtil::copyEntryData(transactionView, 0, TransactionTableModel::TxPlainTextRole);
             return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

// show/hide column Watch-only
void TransactionView::updateWatchOnlyColumn(bool fHaveWatchOnly)
{
    watchOnlyWidget->setVisible(fHaveWatchOnly);
    transactionView->setColumnHidden(TransactionTableModel::Watchonly, !fHaveWatchOnly);
}

// Handles resize events for the TransactionView widget by adjusting internal component sizes.
void TransactionView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event); 

    // Retrieve new dimensions from the resize event
    const int newWidth = event->size().width();
    const int newHeight = event->size().height();

    adjustTextSize(newWidth, newHeight);

    int headerHeight = newHeight * 0.1; 

    // Calculate the height of widgets in the header subtracting a small margin
    int widgetHeight = headerHeight - 5; 

    // Determine widths for specific widgets as percentages of total width
    int comboBoxesWidgetWidth = newWidth * 0.10; 
    int addressWidgetWidth = newWidth * 0.25; 

    dateWidget->setFixedWidth(comboBoxesWidgetWidth);
    typeWidget->setFixedWidth(comboBoxesWidgetWidth);
    amountWidget->setFixedWidth(comboBoxesWidgetWidth);
    instantsendWidget->setFixedWidth(comboBoxesWidgetWidth);

    int tableViewHeight = newHeight - headerHeight; 
    
    // Calculate and set column widths based on new width, keeping proportions
    int statusColumnWidth = newWidth * 0.05;
    int watchOnlyColumnWidth = newWidth * 0.05;
    int instantSendColumnWidth = newWidth * 0.05;
    int dateColumnWidth = newWidth * 0.08;
    int typeColumnWidth = newWidth * 0.10;
    int addressColumnWidth = newWidth * 0.25; 

    transactionView->setColumnWidth(TransactionTableModel::Status, statusColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Watchonly, watchOnlyColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::InstantSend, instantSendColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Date, dateColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::Type, typeColumnWidth);
    transactionView->setColumnWidth(TransactionTableModel::ToAddress, addressColumnWidth);
}
void TransactionView::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 65.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    // Set font size for all labels
    transactionView->setFont(font);
    transactionView->horizontalHeader()->setFont(font);
    transactionView->verticalHeader()->setFont(font);
    dateWidget->setFont(font);
    typeWidget->setFont(font);
    amountWidget->setFont(font);
    instantsendWidget->setFont(font);
    addressWidget->setFont(font);
}