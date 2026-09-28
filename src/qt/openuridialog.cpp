// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "openuridialog.h"
#include "ui_openuridialog.h"

#include "guitheme.h"
#include "guiutil.h"
#include "walletmodel.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QUrl>

OpenURIDialog::OpenURIDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OpenURIDialog)
{
    ui->setupUi(this);
#if QT_VERSION >= 0x040700
    ui->uriEdit->setPlaceholderText("firo:");
#endif

    applyTheme();
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &OpenURIDialog::applyTheme);
}

void OpenURIDialog::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));
    ui->label->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: transparent; color: $INK_SOFT; font-weight: 700; }")));
    ui->uriEdit->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QValidatedLineEdit {"
        " background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 10px;"
        " padding: 8px 12px; color: $INK;"
        "}"
        "QValidatedLineEdit:focus { border: 1px solid $WINE; }"
        "QValidatedLineEdit[invalidInput=\"true\"] { border-color: $ERROR; }")));

    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle();
    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle();
    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setStyleSheet(primaryButtonStyle);
        GUIUtil::applyPrimaryButtonShadow(okButton);
    }
    if (QPushButton* cancelButton = ui->buttonBox->button(QDialogButtonBox::Cancel))
        cancelButton->setStyleSheet(secondaryButtonStyle);
}

OpenURIDialog::~OpenURIDialog()
{
    delete ui;
}

QString OpenURIDialog::getURI()
{
    return ui->uriEdit->text();
}

void OpenURIDialog::accept()
{
    SendCoinsRecipient rcp;
    if(GUIUtil::parseBitcoinURI(getURI(), &rcp))
    {
        /* Only accept value URIs */
        QDialog::accept();
    } else {
        ui->uriEdit->setValid(false);
    }
}
