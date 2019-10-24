#ifndef ZCOIN_NOTIFYMNEMONIC_H
#define ZCOIN_NOTIFYMNEMONIC_H


#include <QDialog>
#include <QThread>

namespace Ui {
    class NotifyMnemonic;
}

class NotifyMnemonic : public QDialog
{
    Q_OBJECT
public:
    explicit NotifyMnemonic(QWidget *parent = 0);
    ~NotifyMnemonic();

    static void notify();
private:
    Ui::NotifyMnemonic *ui;
};

#endif //ZCOIN_NOTIFYMNEMONIC_H
