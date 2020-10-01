#include "automintnotification.h"
#include "automintmodel.h"

#include "ui_automintnotification.h"

#include <QPushButton>

AutomintNotification::AutomintNotification(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutomintNotification)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText("Anonymize");
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText("Dismiss");

    setWindowFlags(windowFlags() | Qt::FramelessWindowHint);
}

AutomintNotification::~AutomintNotification()
{
    if (lelantusModel) {
        disconnect(this, SIGNAL(ackMintAll(AutoMintAck, CAmount, QString)),
            lelantusModel, SLOT(ackMintAll(AutoMintAck, CAmount, QString)));
    }

    delete ui;
}

void AutomintNotification::setModel(WalletModel *model)
{
    if (model) {
        lelantusModel = model->getLelantusModel();

        if (lelantusModel) {
            connect(this, SIGNAL(ackMintAll(AutoMintAck, CAmount, QString)),
                lelantusModel, SLOT(ackMintAll(AutoMintAck, CAmount, QString)));
        }
    }
}

bool AutomintNotification::close()
{
    Q_EMIT ackMintAll(AutoMintAck::NotEnoughFund, 0, QString());
    return QDialog::close();
}

void AutomintNotification::accept()
{
    Q_EMIT ackMintAll(AutoMintAck::AskToMint, 0, QString());
    QDialog::accept();
}

void AutomintNotification::reject()
{
    Q_EMIT ackMintAll(AutoMintAck::UserReject, 0, QString());
    QDialog::reject();
}