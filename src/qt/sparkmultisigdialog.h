// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_QT_SPARKMULTISIGDIALOG_H
#define FIRO_QT_SPARKMULTISIGDIALOG_H

#include "pubkey.h"
#include "walletmodel.h"

#include <QDialog>

#include <univalue.h>

namespace spark {
class MultisigKey;
}

class QFormLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QStackedWidget;

// The GUI of Spark multisig wallets (doc/spark-multisig-wallet.md). Both dialogs go
// through the functions behind the RPCs, so that a co-signer using the GUI and one
// using the RPCs can share a wallet: what they exchange is the same hex data.

/**
 * Turns a wallet into a multisig wallet together with its co-signers. It runs the
 * passes of addsparkmultisigaddress as the user enters what the co-signers send, and
 * keeps what was entered in the wallet, so it can be closed while waiting for them.
 * @pre The wallet is unlocked and stays so while the dialog is open.
 */
class SparkMultisigSetupDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SparkMultisigSetupDialog(WalletModel* model, QWidget* parent = nullptr);

    //! Accepted means the wallet now holds the group's keys and Firo has to restart
    void done(int result) override;

private:
    void applyTheme();
    void loadDraft();
    void saveDraft();
    //! Run a pass with what has been entered and show where the setup stands
    void refresh();
    void finish();
    //! The two exchanges have a page each: the keys (0), then the setup data (1)
    void showPage(int page);

    WalletModel* model;
    CPubKey ownKey; //!< this wallet's co-signer key
    UniValue args;  //!< for SetupSparkMultisig, as of the last refresh that could run a pass
    bool fCreated = false; //!< the keys are stored and the draft is erased

    QLineEdit* ownKeyEdit;
    QPlainTextEdit* cosignerKeys;
    QSpinBox* required;
    QLabel* requiredOf;
    QLabel* ownDataLabel;
    QLineEdit* ownData;
    QPlainTextEdit* cosignerData;
    QLabel* progress;
    QLabel* status;
    QStackedWidget* pages;
    QPushButton* backButton;
    QPushButton* nextButton;
    QPushButton* finishButton;
};

/**
 * Shows one transaction of a multisig wallet on its way through the co-signers, and
 * lets this co-signer approve it, sign it, pass it on and finally send it.
 */
class SparkMultisigSpendDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SparkMultisigSpendDialog(WalletModel* model, QWidget* parent = nullptr);

    /**
     * Create a transaction that pays `recipients` and put it on screen.
     * @return false, after telling the user why, if it could not be created.
     */
    bool createSpend(const QList<SendCoinsRecipient>& recipients);

protected:
    void showEvent(QShowEvent* event) override;

private:
    void applyTheme();
    //! The keys of the group, null in a wallet that is not a multisig wallet. Not to be kept: the wallet may replace it.
    const spark::MultisigKey* groupKey() const;
    QString ownAddress() const;
    //! Take in a transaction from a co-signer; a copy of the one on screen is merged into it
    bool load(const QString& hex);
    //! Take the result of signing or combining
    void apply(const UniValue& result);
    void updateView();
    void sign();
    void send();
    //! Ask before a fully signed transaction that was not sent is replaced
    bool mayReplace();

    WalletModel* model;
    QString spend;    //!< the transaction while it collects signatures, as the co-signers exchange it
    QString rawTx;    //!< the transaction once it is fully signed
    UniValue details; //!< what `spend` does, from decodesparkmultisigspend

    QLabel* summary;
    QLabel* address;
    QWidget* detailsBox;
    QFormLayout* detailsForm;
    QLabel* pays;
    QLabel* fee;
    QLabel* returns;
    QLabel* approvals;
    QLabel* status;
    QPushButton* copyButton;
    QPushButton* saveButton;
    QPushButton* actionButton;
};

#endif // FIRO_QT_SPARKMULTISIGDIALOG_H
