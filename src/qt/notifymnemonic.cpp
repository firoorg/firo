#include "notifymnemonic.h"
#include "ui_notifymnemonic.h"

#include "guitheme.h"
#include "guiutil.h"

#include "util.h"
#include "random.h"

#ifdef ENABLE_WALLET
#include "walletmodel.h"
#endif

#include <QFileDialog>
#include <QFont>
#include <QSettings>
#include <QMessageBox>
#include <QAbstractButton>
#include <QApplication>
#include <QClipboard>
#include <QDate>
#include <QMimeData>
#include <QPointer>
#include <QTimer>

NotifyMnemonic::NotifyMnemonic(const QString& mnemonic, QWidget *parent) :
        QWizard(parent),
        ui(new Ui::NotifyMnemonic),
        mnemonicWords(mnemonic.split(' ', Qt::SkipEmptyParts))
{
    ui->setupUi(this);
    ui->walletBirthDate->setText(tr("Wallet creation date:  %1").arg(QDate::currentDate().toString("dd-MM-yyyy")));
    Q_ASSERT(mnemonicWords.size() == 12 || mnemonicWords.size() == 24);
    QStringList numberedWords;
    // Keep each number with its word when the label wraps.
    for (qsizetype i = 0; i < mnemonicWords.size(); ++i)
        numberedWords << QStringLiteral("%1.\u00a0%2").arg(i + 1).arg(mnemonicWords[i]);
    ui->mnemonic->setText(numberedWords.join(QStringLiteral("  ")));
    const int groupSize = static_cast<int>(mnemonicWords.size()) / 3;
    const std::array<QLabel*, 3> labels{ui->wordLabel1, ui->wordLabel2, ui->wordLabel3};
    for (int i = 0; i < 3; ++i) {
        wordIndexes[i] = i * groupSize + GetRandInt(groupSize);
        labels[i]->setText(tr("Word %1").arg(wordIndexes[i] + 1));
    }
    connect(ui->copyButton, &QPushButton::clicked, this, [this] {
        if (QMessageBox::warning(this, tr("Copy recovery phrase"), tr("Other applications and clipboard history may read and keep your recovery phrase. Anyone who gets it can take your funds. While Firo is running, it will try to clear this clipboard copy after one minute. Copy it anyway?"), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
            return;

        auto* clipboard = QApplication::clipboard();
        QPointer<QMimeData> copiedData = new QMimeData;
        copiedData->setText(mnemonicWords.join(QLatin1Char(' ')));
        clipboard->setMimeData(copiedData.data(), QClipboard::Clipboard);
        auto* expiry = new QTimer(qApp);
        expiry->setObjectName(QStringLiteral("seedClipboardExpiry"));
        expiry->setSingleShot(true);
        connect(expiry, &QTimer::timeout, expiry, [clipboard, copiedData, expiry] {
            // Compare item identity without requesting another application's clipboard text.
            const QMimeData* current = clipboard->mimeData(QClipboard::Clipboard);
            if (copiedData && current == copiedData.data())
                clipboard->clear(QClipboard::Clipboard);
            expiry->deleteLater();
        });
        expiry->start(60 * 1000);
    });
    applyTheme();
}

void NotifyMnemonic::applyTheme()
{
    GUIUtil::loadTheme();

    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QWizard#NotifyMnemonic { background: $BG; }
        QWizard#NotifyMnemonic QWizardPage { background: $BG; }
        QWizard#NotifyMnemonic QScrollArea,
        QWizard#NotifyMnemonic QWidget#seedContents { background: $BG; }
        QWizard#NotifyMnemonic QLabel { background: transparent; color: $INK; }
        QWizard#NotifyMnemonic QLabel#textLabel4 { color: $INK_SOFT; font-weight: 700; }
        QWizard#NotifyMnemonic QLabel#errorMessage { color: $ERROR; font-weight: 700; }
        QWizard#NotifyMnemonic QFrame#mnemonicBox {
            background: $WINE_TINT;
            border: 1.5px solid $WINE;
            border-radius: 14px;
        }
        QWizard#NotifyMnemonic QLabel#mnemonic {
            color: $INK;
        }
        QWizard#NotifyMnemonic QLineEdit {
            background: $PANEL_SOFT;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
        }
    )")));

    if (QAbstractButton* nextButton = QWizard::button(QWizard::NextButton))
        nextButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    if (QAbstractButton* finishButton = QWizard::button(QWizard::FinishButton))
        finishButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    if (QAbstractButton* backButton = QWizard::button(QWizard::BackButton))
        backButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
    if (QAbstractButton* cancelButton = QWizard::button(QWizard::CancelButton))
        cancelButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
    ui->copyButton->setStyleSheet(GUIUtil::secondaryButtonStyle());
}

NotifyMnemonic::~NotifyMnemonic()
{
    delete ui;
}

void NotifyMnemonic::reject()
{
    if (QMessageBox::question(this, tr("Warning"), tr("Are you sure you wish to proceed without confirming whether you have written down your seed words correctly?"), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        QWizard::reject();
}

bool NotifyMnemonic::validateCurrentPage()
{
    if (currentPage() != ui->wizardPage2)
        return QWizard::validateCurrentPage();

    const std::array<QLineEdit*, 3> inputs{ui->word1, ui->word2, ui->word3};
    for (size_t i = 0; i < inputs.size(); ++i) {
        if (inputs[i]->text().trimmed().compare(mnemonicWords.at(wordIndexes[i]), Qt::CaseInsensitive) != 0) {
            ui->errorMessage->setText(tr("The word at position %1 does not match. Go back to check your recovery phrase.").arg(wordIndexes[i] + 1));
            inputs[i]->setFocus();
            inputs[i]->selectAll();
            return false;
        }
    }
    ui->errorMessage->clear();
    return true;
}

void NotifyMnemonic::notify()
{
#ifdef ENABLE_WALLET
    SecureString mnemonic;
    pwalletMain->GetMnemonicContainer().GetMnemonic(mnemonic);
    NotifyMnemonic notify(QString::fromUtf8(mnemonic.c_str()));
    notify.setWindowIcon(QIcon(":icons/firo"));
    notify.show();
    notify.restart();
    notify.exec();
#endif
}
