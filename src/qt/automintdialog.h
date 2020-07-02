#ifndef ZCOIN_QT_AUTOMINT_H
#define ZCOIN_QT_AUTOMINT_H

#include "walletmodel.h"

#include <QDialog>

namespace Ui {
    class AutoMintDialog;
}

class AutoMintDialog : public QDialog
{
    Q_OBJECT;

public:
    explicit AutoMintDialog(QWidget *parent = 0);
    ~AutoMintDialog();

public:
    int exec();
    void setModel(WalletModel *model);

private Q_SLOTS:
    void accept();
    void reject();

private:
    Ui::AutoMintDialog *ui;
    WalletModel *model;
    LelantusModel *lelantusModel;

    void ensureLelantusModel();
};

#endif // ZCOIN_QT_AUTOMINT_H