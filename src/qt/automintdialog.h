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

public:
    void accept();
    int exec();
    void setModel(WalletModel *model);

private Q_SLOTS:
    void cancelEvent();

private:
    Ui::AutoMintDialog *ui;
    WalletModel *model;
};

#endif // ZCOIN_QT_AUTOMINT_H