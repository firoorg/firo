#include "automintnotification.h"
#include "automintmodel.h"
#include "guitheme.h"
#include "guiutil.h"

#include "ui_automintnotification.h"

#include <QPushButton>

AutomintSparkNotification::AutomintSparkNotification(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AutomintNotification),
    sparkModel(nullptr)
{
    ui->setupUi(this);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setText(tr("Make Private"));
    ui->buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("Dismiss"));

    setWindowFlags(windowFlags() | Qt::FramelessWindowHint);

    applyTheme();
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &AutomintSparkNotification::applyTheme);
}

void AutomintSparkNotification::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QDialog { background: $PANEL; border: 1px solid $BORDER; }"
        "QLabel { background: transparent; color: $INK_SOFT; }")));
    ui->warningLabel->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-weight: 700; }")));
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setStyleSheet(GUIUtil::primaryButtonStyle());
        GUIUtil::applyPrimaryButtonShadow(okButton);
    }
    if (QPushButton* cancelButton = ui->buttonBox->button(QDialogButtonBox::Cancel))
        cancelButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
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
