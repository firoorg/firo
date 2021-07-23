#ifndef CANCELPASSWORDDIALOG_H
#define CANCELPASSWORDDIALOG_H

#include <QMessageBox>
#include <QTimer>


class CancelPasswordDialog : public QMessageBox
{
    Q_OBJECT

public:
    CancelPasswordDialog(const QString &title, const QString &text, int secDelay = 0, QWidget *parent = 0);
    int exec();

private Q_SLOTS:
    void countDown();
    void updateCancelButton();

private:
    QAbstractButton *cancelButton;
    QTimer countDownTimer;
    int secDelay;
};


#endif /* CANCELPASSWORDDIALOG_H */

