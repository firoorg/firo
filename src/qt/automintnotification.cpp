#include "automintnotification.h"
#include "automintmodel.h"

#include "ui_automintnotification.h"

#include <QPushButton>

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