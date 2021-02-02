#ifndef FIRO_QT_AUTOMINTNOTIFICATION_H
#define FIRO_QT_AUTOMINTNOTIFICATION_H

#include "lelantusmodel.h"
#include "walletmodel.h"

#include <QDialog>

namespace Ui {
    class AutomintNotification;
}

class AutomintNotification : public QDialog
{
    Q_OBJECT;

public:
    explicit AutomintNotification(QWidget *parent = 0);
    ~AutomintNotification();

public:
    void setModel(WalletModel *model);

Q_SIGNALS:
    void ackMintAll(AutoMintAck, CAmount, QString);

public Q_SLOTS:
    bool close();

private Q_SLOTS:
    void accept();
    void reject();

private:
    Ui::AutomintNotification *ui;
    LelantusModel *lelantusModel;
};

#endif // FIRO_QT_AUTOMINTNOTIFICATION_H