#ifndef FIRO_QT_SEND_CONFIRMATION_DIALOG_H_INCLUDED
#define FIRO_QT_SEND_CONFIRMATION_DIALOG_H_INCLUDED

#include <QMessageBox>
#include <QTimer>

class SendConfirmationDialog : public QMessageBox {
    Q_OBJECT

public:
    SendConfirmationDialog( const QString &title, const QString &text, int secDelay = 0, QWidget *parent = nullptr );
    int exec();

private Q_SLOTS:
    void countDown();
    void updateYesButton();

private:
    QAbstractButton *yesButton;
    QTimer countDownTimer;
    int secDelay;
};

#endif // FIRO_QT_SEND_CONFIRMATION_DIALOG_H_INCLUDED
