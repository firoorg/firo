// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiondescdialog.h"
#include "ui_transactiondescdialog.h"

#include "guitheme.h"
#include "guiutil.h"
#include "transactiontablemodel.h"

#include <QDialogButtonBox>
#include <QGuiApplication>
#include <QModelIndex>
#include <QPushButton>
#include <QScreen>
#include <QTextDocument>

TransactionDescDialog::TransactionDescDialog(const QModelIndex &idx, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TransactionDescDialog)
{
    ui->setupUi(this);

    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog { background: $BG; }
        QTextEdit#detailText {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 14px;
            padding: 14px 16px;
            color: $INK;
            selection-background-color: $WINE_TINT;
            selection-color: $INK;
        }
    )")));
    if (QPushButton *closeButton = ui->buttonBox->button(QDialogButtonBox::Close)) {
        closeButton->setStyleSheet(GUIUtil::primaryButtonStyle(QStringLiteral("8px 24px")));
        closeButton->setCursor(Qt::PointingHandCursor);
    }

    setWindowTitle(tr("Details for %1").arg(idx.data(TransactionTableModel::TxIDRole).toString()));
    const QString desc = idx.data(TransactionTableModel::LongDescriptionRole).toString();
    ui->detailText->setHtml(desc);

    const QScreen *screen = QGuiApplication::primaryScreen();
    const QSize avail = screen ? screen->availableGeometry().size() : QSize(1200, 800);
    const int dialogWidth = qMin(760, avail.width() - 80);
    const int maxHeight = static_cast<int>(avail.height() * 0.85);

    resize(dialogWidth, qMax(minimumHeight(), 400));
    ensurePolished();
    layout()->activate();

    const QMargins textMargins = ui->detailText->contentsMargins();
    QTextDocument *doc = ui->detailText->document();
    doc->setTextWidth(ui->detailText->width() - textMargins.left() - textMargins.right());
    const int contentHeight = qRound(doc->size().height()) + textMargins.top() + textMargins.bottom();

    const int chrome = height() - ui->detailText->height();
    const int dialogHeight = qBound(280, contentHeight + chrome, maxHeight);
    resize(dialogWidth, dialogHeight);
}

TransactionDescDialog::~TransactionDescDialog()
{
    delete ui;
}
