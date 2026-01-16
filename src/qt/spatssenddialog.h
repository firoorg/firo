#ifndef SPATS_SEND_DIALOG_H
#define SPATS_SEND_DIALOG_H

#include <QDialog>
#include <QString>
#include <QLineEdit>
#include <QDoubleSpinBox>
#include <QPushButton>

class PlatformStyle;

namespace Ui {
class SpatsSendDialog;
}

class SpatsSendDialog : public QDialog {
    Q_OBJECT
public:
    explicit SpatsSendDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~SpatsSendDialog();
    QString getRecipient() const;
    double getAmount() const;
private:
    Ui::SpatsSendDialog *ui;
};

#endif // SPATS_SEND_DIALOG_H
