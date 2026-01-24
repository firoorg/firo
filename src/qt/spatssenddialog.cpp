#include "spatssenddialog.h"
#include "ui_spatssenddialog.h"

SpatsSendDialog::SpatsSendDialog(const PlatformStyle *, QWidget *parent)
    : QDialog(parent), ui(new Ui::SpatsSendDialog)
{
    ui->setupUi(this);
    connect(ui->btnSend, &QPushButton::clicked, this, &QDialog::accept);
    connect(ui->btnCancel, &QPushButton::clicked, this, &QDialog::reject);
}

SpatsSendDialog::~SpatsSendDialog() { delete ui; }

QString SpatsSendDialog::getRecipient() const { return ui->editRecipient->text(); }
double SpatsSendDialog::getAmount() const { return ui->spinAmount->value(); }
