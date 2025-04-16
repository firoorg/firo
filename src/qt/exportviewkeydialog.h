#ifndef VIEWKEYDIALOG_H
#define VIEWKEYDIALOG_H

#include <QMessageBox>
#include <QPushButton>
#include <QDialog>

namespace Ui {
    class ExportViewKeyDialog;
}

class ExportViewKeyDialog : public QDialog
{
    Q_OBJECT
public:
    ExportViewKeyDialog(QWidget *parent, std::string sparkViewKeyStr);
    ~ExportViewKeyDialog();

private:
    Ui::ExportViewKeyDialog *ui;
    QDialog *viewkey;
};


#endif

