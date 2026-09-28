#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
#include <QTimer>

#include "manualmintdialog.h"
#include "ui_manualmintdialog.h"
#include "guitheme.h"
#include "guiutil.h"
#include "platformstyle.h"

ManualMintDialog::ManualMintDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ManualMintDialog),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    if (platformStyle->getImagesOnButtons()) {
        ui->mintButton->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearAllButton->setIcon(QIcon(platformStyle->SingleColorIcon(":/icons/remove")));
    } else {
        ui->mintButton->setIcon(QIcon());
        ui->clearAllButton->setIcon(QIcon());
    }

    applyTheme();
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &ManualMintDialog::applyTheme);
}

void ManualMintDialog::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QDialog { background: $BG; }"
        "QLabel { background: transparent; color: $INK_SOFT; }"
        "QSpinBox {"
        " background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 8px;"
        " padding: 4px 8px; color: $INK;"
        "}"
        "QSpinBox:focus { border: 1px solid $WINE; }"
        "QSpinBox QLineEdit { %1 }"))
        .arg(GUIUtil::spinBoxInnerLineEditReset()));
    ui->availableAmount->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-weight: 700; }")));
    ui->totalAmount->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK; font-weight: 700; }")));
    ui->mintButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    GUIUtil::applyPrimaryButtonShadow(ui->mintButton);
    ui->clearAllButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
}

ManualMintDialog::~ManualMintDialog()
{
    delete ui;
}
