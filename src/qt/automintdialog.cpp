#include "../validation.h"

#include "automintdialog.h"
#include "ui_automintdialog.h"

AutoMintDialog::AutoMintDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutoMintDialog),
    model(nullptr)
{
    ui->setupUi(this);
    // TODO
}

void AutoMintDialog::accept()
{
    LOCK2(cs_main, pwalletMain->cs_wallet);
    auto balance = model->getBalance();

    if (balance > 0) {
        model->lelantusMint(balance);
    } else {
        // TODO: handle error
    }
}

int AutoMintDialog::exec()
{
    return QDialog::exec();
}

void AutoMintDialog::setModel(WalletModel *model)
{
    this->model = model;
    // TODO: remove passphase box if wallet isn't locked
}