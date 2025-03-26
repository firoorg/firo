#include "exportviewkeydialog.h"
#include "ui_exportviewkeydialog.h"

ExportViewKeyDialog::ExportViewKeyDialog(QWidget *parent, std::string sparkViewKeyStr) : QDialog(parent), ui(new Ui::ExportViewKeyDialog)
{
    ui->setupUi(this);
    QString text(QString::fromStdString(sparkViewKeyStr));
    ui->key->setText(text);
}

ExportViewKeyDialog::~ExportViewKeyDialog() {
    delete ui;
}
