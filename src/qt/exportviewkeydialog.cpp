#include "exportviewkeydialog.h"
#include "ui_exportviewkeydialog.h"

#include "guitheme.h"
#include "guiutil.h"

#include <QDialogButtonBox>
#include <QEvent>
#include <QPushButton>
#include <QTextEdit>

ExportViewKeyDialog::ExportViewKeyDialog(QWidget *parent, std::string sparkViewKeyStr) : QDialog(parent), ui(new Ui::ExportViewKeyDialog)
{
    ui->setupUi(this);
    QString text(QString::fromStdString(sparkViewKeyStr));
    const int mid = text.size() / 2;
    ui->key->setPlainText(text.left(mid) + QChar('\n') + text.mid(mid));
    ui->key->setAlignment(Qt::AlignCenter);
    ui->key->viewport()->installEventFilter(this);

    if (QPushButton* okButton = ui->buttonBox->button(QDialogButtonBox::Ok)) {
        okButton->setStyleSheet(GUIUtil::primaryButtonStyle());
        GUIUtil::applyPrimaryButtonShadow(okButton);
    }

    applyTheme();
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &ExportViewKeyDialog::applyTheme);
}

ExportViewKeyDialog::~ExportViewKeyDialog() {
    delete ui;
}

void ExportViewKeyDialog::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));
    ui->key->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QTextEdit {"
        " background: $PANEL_SOFT; border: 1px solid $BORDER; border-radius: 10px;"
        " padding: 10px 12px; color: $INK; font-family: monospace; font-size: 12px;"
        "}")));
}

bool ExportViewKeyDialog::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == ui->key->viewport() && event->type() == QEvent::MouseButtonDblClick) {
        ui->key->selectAll();
        return true;
    }
    return QDialog::eventFilter(watched, event);
}
