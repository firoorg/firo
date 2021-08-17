#include "cancelpassworddialog.h"

#include <QAbstractButton>

CancelPasswordDialog::CancelPasswordDialog(const QString &title, const QString &text, int _secDelay,
    QWidget *parent) :
    QMessageBox(QMessageBox::Question, title, text, QMessageBox::Yes | QMessageBox::Cancel, parent), secDelay(_secDelay)
{
    setDefaultButton(QMessageBox::Yes);
    cancelButton = button(QMessageBox::Cancel);
    updateCancelButton();
    connect(&countDownTimer, SIGNAL(timeout()), this, SLOT(countDown()));
}

int CancelPasswordDialog::exec()
{
    updateCancelButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void CancelPasswordDialog::countDown()
{
    secDelay--;
    updateCancelButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void CancelPasswordDialog::updateCancelButton()
{
    if(secDelay > 0)
    {
        cancelButton->setEnabled(false);
        cancelButton->setText(tr("Cancel") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        cancelButton->setEnabled(true);
        cancelButton->setText(tr("Cancel"));
    }
}
