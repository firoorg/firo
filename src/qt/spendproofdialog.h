// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SPENDPROOFDIALOG_H
#define BITCOIN_QT_SPENDPROOFDIALOG_H

#include <QDialog>

class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QPlainTextEdit;
QT_END_NAMESPACE

/**
 * Generates or verifies an off-chain Spark spend proof: evidence that someone
 * knows the spending keys of a confirmed Spark spend, bound to a message.
 */
class SpendProofDialog : public QDialog
{
    Q_OBJECT

public:
    /** Verify a proof against this node's chain. Needs no wallet. */
    explicit SpendProofDialog(QWidget *parent);
    /** Generate a proof for one of the wallet's own confirmed Spark spends. */
    SpendProofDialog(WalletModel *model, const QString &txid, QWidget *parent);

private Q_SLOTS:
    void generateProof();
    void verifyProof();

private:
    void setStatus(bool success, const QString &text);

    WalletModel *model; //!< null when verifying
    QString txid;
    QPlainTextEdit *messageEdit;
    QPlainTextEdit *proofEdit;
    QLabel *statusLabel;
};

#endif // BITCOIN_QT_SPENDPROOFDIALOG_H
