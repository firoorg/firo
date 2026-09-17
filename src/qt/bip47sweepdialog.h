#ifndef FIRO_QT_BIP47SWEEPDIALOG_H
#define FIRO_QT_BIP47SWEEPDIALOG_H

#include <QDialog>

class PlatformStyle;
class WalletModel;

namespace Ui {
    class Bip47SweepDialog;
}

/**
 * Moves everything held on the wallet's own bip47 addresses to a single destination. The
 * destination is either an address newly generated here, transparent or spark, or one the user
 * enters.
 */
class Bip47SweepDialog : public QDialog
{
    Q_OBJECT;

public:
    explicit Bip47SweepDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~Bip47SweepDialog();

    void setModel(WalletModel *model);

private Q_SLOTS:
    void on_pasteButton_clicked();
    void on_addressBookButton_clicked();
    void destinationChanged();
    void accept() override;

private:
    /** Resolves the destination the user picked, generating a new address if that is what it is. */
    QString resolveDestination();

    Ui::Bip47SweepDialog *ui;
    const PlatformStyle *platformStyle;
    WalletModel *model;
};

#endif // FIRO_QT_BIP47SWEEPDIALOG_H
