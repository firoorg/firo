#include "automintnotification.h"
#include "automintmodel.h"

#include "ui_automintnotification.h"

#include <QPushButton>

AutomintNotification::AutomintNotification(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutomintNotification),
    lelantusModel(nullptr)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Anonymize"));
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Dismiss"));

    setWindowFlags(windowFlags() | Qt::FramelessWindowHint);
}

AutomintNotification::~AutomintNotification()
{
    delete ui;
}

void AutomintNotification::setModel(WalletModel *model)
{
    if (model) {
        lelantusModel = model->getLelantusModel();

        if (!lelantusModel) {
            return;
        }

        auto automintModel = lelantusModel->getAutoMintModel();
        if (!automintModel) {
            return;
        }

        connect(this, &AutomintNotification::ackMintAll, automintModel, &AutoMintModel::ackMintAll);
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

AutomintSparkNotification::AutomintSparkNotification(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutomintNotification),
    sparkModel(nullptr)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Anonymize"));
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Dismiss"));

    setWindowFlags(windowFlags() | Qt::FramelessWindowHint);
}

AutomintSparkNotification::~AutomintSparkNotification()
{
    delete ui;
}

void AutomintSparkNotification::setModel(WalletModel *model)
{
    if (model) {
        sparkModel = model->getSparkModel();

        if (!sparkModel) {
            return;
        }

        auto automintModel = sparkModel->getAutoMintSparkModel();
        if (!automintModel) {
            return;
        }

        connect(this, &AutomintSparkNotification::ackMintSparkAll, automintModel, &AutoMintSparkModel::ackMintSparkAll);
    }
}

bool AutomintSparkNotification::close()
{
    Q_EMIT ackMintSparkAll(AutoMintSparkAck::NotEnoughFund, 0, QString());
    return QDialog::close();
}

void AutomintSparkNotification::accept()
{
    Q_EMIT ackMintSparkAll(AutoMintSparkAck::AskToMint, 0, QString());
    QDialog::accept();
}

void AutomintSparkNotification::reject()
{
    Q_EMIT ackMintSparkAll(AutoMintSparkAck::UserReject, 0, QString());
    QDialog::reject();
}