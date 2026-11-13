// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spendproofdialog.h"

#include "guitheme.h"
#include "guiutil.h"
#include "walletmodel.h"

#include "spark/state.h"
#include "uint256.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QStyle>
#include <QTextOption>
#include <QVBoxLayout>

SpendProofDialog::SpendProofDialog(QWidget *parent, WalletModel *_model, const QString &_txid) :
    QDialog(parent),
    model(_model),
    txid(_txid)
{
    const bool generating = model != nullptr;
    setWindowTitle(generating ? tr("Generate Spend Proof") : tr("Verify Spend Proof"));
    setMinimumWidth(620);

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *intro = new QLabel(generating
        ? tr("Prove that this wallet holds the spending keys of the transaction below, without revealing the keys or which coins were spent. "
             "Enter the message the verifier asked you to include, then send them the proof together with that message. "
             "Anyone who holds the proof can link this wallet to the transaction.")
        : tr("Check a spend proof against this node's copy of the blockchain. "
             "A valid proof shows that its creator holds the spending keys of the transaction it names, and that the proof was made for this exact message. "
             "It does not show the amount or who was paid."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    if (generating) {
        layout->addWidget(new QLabel(tr("Transaction ID"), this));
        QLineEdit *txidEdit = new QLineEdit(txid, this);
        txidEdit->setReadOnly(true);
        txidEdit->setFont(GUIUtil::fixedPitchFont());
        layout->addWidget(txidEdit);
    }

    QLabel *messageLabel = new QLabel(tr("Message"), this);
    messageEdit = new QPlainTextEdit(this);
    messageEdit->setObjectName(QStringLiteral("messageEdit"));
    messageEdit->setPlaceholderText(generating
        ? tr("Enter the message the verifier asked you to include")
        : tr("Enter the message the proof was made for"));
    messageEdit->setFixedHeight(80);

    QLabel *proofLabel = new QLabel(tr("Spend proof"), this);
    proofEdit = new QPlainTextEdit(this);
    proofEdit->setObjectName(QStringLiteral("proofEdit"));
    proofEdit->setFont(GUIUtil::fixedPitchFont());
    proofEdit->setWordWrapMode(QTextOption::WrapAnywhere);
    proofEdit->setReadOnly(generating);
    proofEdit->setPlaceholderText(generating
        ? tr("Click \"Generate proof\" to create the proof")
        : tr("Paste the spend proof here"));
    proofEdit->setMinimumHeight(110);

    // The input comes first: the message when generating, the proof when verifying.
    for (QWidget *widget : generating
            ? QList<QWidget*>{messageLabel, messageEdit, proofLabel, proofEdit}
            : QList<QWidget*>{proofLabel, proofEdit, messageLabel, messageEdit}) {
        layout->addWidget(widget);
    }

    statusLabel = new QLabel(this);
    statusLabel->setObjectName(QStringLiteral("statusLabel"));
    statusLabel->setWordWrap(true);
    statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(statusLabel);

    const auto clearStatus = [this] {
        statusLabel->clear();
        statusLabel->setProperty("status", QString());
    };
    connect(proofEdit, &QPlainTextEdit::textChanged, this, clearStatus);
    connect(messageEdit, &QPlainTextEdit::textChanged, this, [this, generating, clearStatus] {
        clearStatus();
        if (generating)
            proofEdit->clear();
    });

    QHBoxLayout *buttons = new QHBoxLayout();
    if (generating) {
        QPushButton *copyButton = new QPushButton(tr("&Copy proof"), this);
        copyButton->setObjectName(QStringLiteral("copyButton"));
        copyButton->setEnabled(false);
        connect(copyButton, &QPushButton::clicked, this, [this] {
            GUIUtil::setClipboard(proofEdit->toPlainText());
        });
        connect(proofEdit, &QPlainTextEdit::textChanged, copyButton, [this, copyButton] {
            copyButton->setEnabled(!proofEdit->toPlainText().isEmpty());
        });
        buttons->addWidget(copyButton);
    }
    buttons->addStretch();
    QPushButton *actionButton = new QPushButton(generating ? tr("&Generate proof") : tr("&Verify proof"), this);
    actionButton->setObjectName(QStringLiteral("actionButton"));
    actionButton->setDefault(true);
    connect(actionButton, &QPushButton::clicked, this,
            generating ? &SpendProofDialog::generateProof : &SpendProofDialog::verifyProof);
    buttons->addWidget(actionButton);
    QPushButton *closeButton = new QPushButton(tr("C&lose"), this);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::close);
    buttons->addWidget(closeButton);
    layout->addLayout(buttons);

    // Same field, button and status styling as the Sign/Verify Message dialog.
    const auto applyTheme = [this, actionButton] {
        setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog { background: $BG; }
        QLineEdit, QPlainTextEdit {
            background: $PANEL_SOFT;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
        }
        QPlainTextEdit:focus { background: $PANEL; border: 2px solid $WINE; padding: 7px 11px; }
        QPushButton {
            color: $INK;
            background: $PANEL;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            font-weight: 700;
            padding: 7px 16px;
        }
        QPushButton:hover:enabled { background: $HOVER; }
        QLabel[status="error"] { color: $ERROR; font-weight: 700; }
        QLabel[status="success"] { color: $TEAL; font-weight: 700; }
    )")));
        actionButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    };
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged, this, applyTheme);
    applyTheme();
}

void SpendProofDialog::setStatus(bool success, const QString &text)
{
    statusLabel->setProperty("status", success ? QStringLiteral("success") : QStringLiteral("error"));
    statusLabel->style()->unpolish(statusLabel);
    statusLabel->style()->polish(statusLabel);
    statusLabel->setText(text);
}

void SpendProofDialog::generateProof()
{
    proofEdit->clear();

    // A proof without a message is not tied to any request, so whoever sees
    // it could present it as their own answer to a different verifier.
    const QString message = messageEdit->toPlainText();
    if (message.isEmpty()) {
        setStatus(false, tr("Enter the message the verifier asked you to include."));
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid()) {
        setStatus(false, tr("Wallet unlock was cancelled."));
        return;
    }

    uint256 hash;
    hash.SetHex(txid.toStdString());
    QString error;
    const QString proof = model->createSpendProof(hash, message, error);
    if (proof.isEmpty()) {
        setStatus(false, error);
        return;
    }
    proofEdit->setPlainText(proof);
    setStatus(true, tr("Spend proof generated. Send the proof and the message to the verifier."));
}

void SpendProofDialog::verifyProof()
{
    // Proofs are often pasted from email or chat, which may wrap them.
    QString proof = proofEdit->toPlainText();
    proof.remove(QRegularExpression(QStringLiteral("\\s")));

    uint256 hash;
    const spark::SpendProofResult result = spark::VerifySpendProof(
        proof.toStdString(), messageEdit->toPlainText().toStdString(), hash);
    const QString id = QString::fromStdString(hash.GetHex());

    switch (result) {
    case spark::SpendProofResult::Ok:
        setStatus(true, tr("Valid. The prover holds the spending keys of this transaction and made the proof for this exact message. "
                           "Check that it is the transaction you expect:\n%1").arg(id));
        return;
    case spark::SpendProofResult::Mismatch:
        setStatus(false, tr("Not valid. The proof does not match this message and transaction:\n%1").arg(id));
        return;
    case spark::SpendProofResult::Malformed:
        setStatus(false, tr("This is not a spend proof."));
        return;
    case spark::SpendProofResult::TxNotFound:
        setStatus(false, tr("This node could not find the transaction the proof names:\n%1").arg(id));
        return;
    case spark::SpendProofResult::TxNotConfirmed:
        setStatus(false, tr("The transaction the proof names is not confirmed yet:\n%1").arg(id));
        return;
    case spark::SpendProofResult::NotSparkSpend:
        setStatus(false, tr("The transaction the proof names is not a Spark spend:\n%1").arg(id));
        return;
    }
}
