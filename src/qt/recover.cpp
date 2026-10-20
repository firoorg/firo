#include "recover.h"
#include "ui_recover.h"

#include "guitheme.h"
#include "guiutil.h"

#include "util.h"

#ifdef ENABLE_WALLET
#include "../wallet/wallet.h"
#endif // ENABLE_WALLET
#include "../wallet/bip39.h"
#include "../wallet/bip39_english.h"
#include "support/allocators/secure.h"

#include <boost/filesystem.hpp>

#include <QAction>
#include <QCalendarWidget>
#include <QCompleter>
#include <QFileDialog>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QMessageBox>
#include <QStyle>
#include <QVBoxLayout>

namespace {
const int MAX_WORDS = 24;

const QStringList& Bip39Words()
{
    static const QStringList list = [] {
        QStringList words;
        for (const char* const* word = wordlist; *word; ++word)
            words << QString::fromLatin1(*word);
        return words;
    }();
    return list;
}

bool IsWord(const QString& text)
{
    return Bip39Words().contains(text.trimmed().toLower());
}
} // namespace

Recover::Recover(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Recover),
    thread(0)
{
    // load stylesheet
    GUIUtil::loadTheme();
    
    ui->setupUi(this);

    // Each number gets its own grid column, so a word can never run into it.
    auto* completer = new QCompleter(Bip39Words(), this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    QWidget* previous = ui->restore24;
    for (int i = 0; i < MAX_WORDS; ++i) {
        auto* number = new QLabel(QString::number(i + 1), ui->restorePage);
        number->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        number->setMinimumWidth(28);
        number->setProperty("help", true);
        auto* word = new QLineEdit(ui->restorePage);
        word->setObjectName(QStringLiteral("word%1").arg(i + 1));
        word->setAccessibleName(tr("Word %1").arg(i + 1));
        word->setCompleter(completer);
        number->setBuddy(word);
        ui->wordGrid->addWidget(number, i / 4, (i % 4) * 2);
        ui->wordGrid->addWidget(word, i / 4, (i % 4) * 2 + 1);
        connect(word, &QLineEdit::textEdited, this, [this, i] { wordEdited(i); });
        connect(word, &QLineEdit::editingFinished, this, [this, word] {
            markWord(word, !word->text().trimmed().isEmpty() && !IsWord(word->text()));
        });
        setTabOrder(previous, word);
        previous = word;
        numbers << number;
        words << word;
    }

    auto* scrollContents = new QWidget(this);
    scrollContents->setObjectName(QStringLiteral("recoverScrollContents"));
    auto* scrollLayout = new QVBoxLayout(scrollContents);
    scrollLayout->setContentsMargins(0, 0, 0, 0);
    scrollLayout->setSpacing(ui->verticalLayout->spacing());
    while (ui->verticalLayout->count() > 1) {
        QLayoutItem* item = ui->verticalLayout->takeAt(0);
        if (QWidget* widget = item->widget()) {
            widget->setParent(scrollContents);
            scrollLayout->addWidget(widget);
            delete item;
        } else if (QLayout* layout = item->layout()) {
            layout->setParent(nullptr);
            scrollLayout->addLayout(layout);
        } else {
            scrollLayout->addItem(item);
        }
    }

    auto* scroll = new QScrollArea(this);
    scroll->setObjectName(QStringLiteral("recoverScroll"));
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(scrollContents);
    scroll->setStyleSheet(QStringLiteral(
        "QScrollArea#recoverScroll, QWidget#recoverScrollContents { background: transparent; border: none; }"));
    ui->verticalLayout->insertWidget(0, scroll, 1);

    const QSize available = GUIUtil::availableScreenSize(this);
    resize(qMin(width(), qMax(1, available.width() - 40)),
           qMin(height(), qMax(1, available.height() - 40)));

    // A push button paints its text in one font, so each choice's title and description are child labels.
    const auto makeChoice = [](QPushButton* button, const QString& icon, const QString& title, const QString& description) {
        auto* iconLabel = new QLabel(button);
        iconLabel->setPixmap(GUIUtil::tintedIconPixmap(QIcon(icon), QSize(24, 24), QColor(GUIUtil::themeColors().wineText)));
        auto* titleLabel = new QLabel(title, button);
        titleLabel->setObjectName(QStringLiteral("choiceTitle"));
        auto* descriptionLabel = new QLabel(description, button);
        descriptionLabel->setObjectName(QStringLiteral("choiceDescription"));
        auto* layout = new QGridLayout(button);
        layout->setSizeConstraint(QLayout::SetMinimumSize);
        layout->setContentsMargins(16, 12, 16, 12);
        layout->setHorizontalSpacing(14);
        layout->addWidget(iconLabel, 0, 0, 2, 1);
        layout->addWidget(titleLabel, 0, 1);
        layout->addWidget(descriptionLabel, 1, 1);
        layout->setColumnStretch(1, 1);
        for (QLabel* label : {iconLabel, titleLabel, descriptionLabel})
            label->setAttribute(Qt::WA_TransparentForMouseEvents);
        button->setAccessibleName(title);
        button->setAccessibleDescription(description);
    };
    makeChoice(ui->createNew, QStringLiteral(":/icons/add"), tr("Create a new wallet"), tr("Start fresh with a new recovery phrase."));
    makeChoice(ui->recoverExisting, QStringLiteral(":/icons/key"), tr("Restore a wallet"), tr("Use a recovery phrase you already have."));

    const auto updateIntro = [this] {
        ui->createIntro->setText(tr("Next, you'll see your recovery phrase: %1 words that can restore this wallet on any device.")
                                     .arg(ui->use12->isChecked() ? 12 : 24));
    };
    updateIntro();
    connect(ui->use12, &QRadioButton::toggled, this, updateIntro);
    connect(ui->restore12, &QRadioButton::toggled, this, [this](bool twelve) { setWordCount(twelve ? 12 : MAX_WORDS); });
    connect(ui->advancedToggle, &QToolButton::toggled, this, [this](bool open) {
        ui->advancedOptions->setVisible(open);
        ui->advancedToggle->setArrowType(open ? Qt::DownArrow : Qt::RightArrow);
    });
    connect(ui->usePassphrase, &QCheckBox::toggled, ui->passphraseFields, &QWidget::setVisible);
    connect(ui->restoreUsePassphrase, &QCheckBox::toggled, ui->restorePassphraseFields, &QWidget::setVisible);

    QAction* reveal = ui->restorePassPhrase->addAction(QIcon(), QLineEdit::TrailingPosition);
    GUIUtil::setThemedIcon(reveal, QStringLiteral(":/icons/eye"));
    reveal->setToolTip(tr("Show passphrase"));
    connect(reveal, &QAction::triggered, this, [this, reveal] {
        const bool show = ui->restorePassPhrase->echoMode() == QLineEdit::Password;
        ui->restorePassPhrase->setEchoMode(show ? QLineEdit::Normal : QLineEdit::Password);
        reveal->setToolTip(show ? tr("Hide passphrase") : tr("Show passphrase"));
    });

    connect(ui->createNew, &QPushButton::clicked, this, [this] { showPage(ui->createPage); });
    connect(ui->recoverExisting, &QPushButton::clicked, this, [this] { showPage(ui->restorePage); });
    connect(ui->backButton, &QPushButton::clicked, this, [this] {
        if (ui->pages->currentWidget() == ui->welcomePage)
            reject();
        else
            showPage(ui->welcomePage);
    });
    connect(ui->okButton, &QPushButton::clicked, this, &Recover::submit);

    // The minimum date reads "Not sure" and leaves the scan start where recovery phrases began.
    ui->dateInput->setMinimumDate(QDate(2019, 12, 11));
    ui->dateInput->setMaximumDate(QDate::currentDate());
    ui->dateInput->setSpecialValueText(tr("Not sure"));
    ui->dateInput->setDate(ui->dateInput->minimumDate());
    // Only blocks already on disk get rescanned, so the date can't speed up a fresh install.
    ui->dateRow->setVisible(boost::filesystem::exists(GetDataDir(true) / "blocks"));

    applyTheme();
    showPage(ui->welcomePage);
    thread = new QThread(this);

    connect(this, &Recover::stopThread, thread, &QThread::quit);
    thread->start();
}

void Recover::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog#Recover { background: $BG; }
        QDialog#Recover QLabel { background: transparent; color: $INK; }
        QDialog#Recover QLabel#errorMessage { color: $ERROR; font-weight: 700; }
        QDialog#Recover QLabel#welcomeTitle,
        QDialog#Recover QLabel#createTitle,
        QDialog#Recover QLabel#restoreTitle { font: $FONT_H2; }
        QDialog#Recover QLabel#choiceTitle { font-weight: 700; }
        QDialog#Recover QLabel#choiceDescription { color: $INK_SOFT; }
        QDialog#Recover QLabel[help="true"] { color: $INK_SOFT; font-size: 13px; }
        QDialog#Recover QFrame { background: transparent; }
        QDialog#Recover QLineEdit,
        QDialog#Recover QDateEdit {
            background: $PANEL_SOFT;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
            selection-background-color: $WINE_DEEP;
            selection-color: #FFFFFF;
        }
        QDialog#Recover QLineEdit:focus,
        QDialog#Recover QDateEdit:focus {
            border: 2px solid $WINE;
            padding: 7px 11px;
        }
        QDialog#Recover QLineEdit[invalid="true"] {
            border: 2px solid $ERROR;
            padding: 7px 11px;
        }
        QDialog#Recover QLineEdit:disabled,
        QDialog#Recover QDateEdit:disabled {
            color: $INK_FAINT;
        }
        QDialog#Recover QAbstractSpinBox QLineEdit { %1 }
        QDialog#Recover QPushButton#createNew,
        QDialog#Recover QPushButton#recoverExisting {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 12px;
            padding: 0;
        }
        QDialog#Recover QPushButton#createNew:hover,
        QDialog#Recover QPushButton#recoverExisting:hover,
        QDialog#Recover QPushButton#createNew:focus,
        QDialog#Recover QPushButton#recoverExisting:focus { border: 1px solid $WINE; }
        QDialog#Recover QToolButton#advancedToggle {
            background: transparent;
            border: none;
            color: $WINE_TEXT;
            font-weight: 700;
        }
        QDialog#Recover QRadioButton,
        QDialog#Recover QCheckBox {
            background: transparent;
            color: $INK;
        }
        QDialog#Recover QRadioButton:disabled,
        QDialog#Recover QCheckBox:disabled {
            color: $INK_FAINT;
        }
        QDialog#Recover QRadioButton::indicator:unchecked {
            image: url(:/images/radio_normal_$ASSET_THEME);
        }
        QDialog#Recover QRadioButton::indicator:checked {
            image: url(:/images/radio_checked_$ASSET_THEME);
        }
        QDialog#Recover QCheckBox::indicator:unchecked {
            image: url(:/images/checkbox_normal_$ASSET_THEME);
        }
        QDialog#Recover QCheckBox::indicator:checked {
            image: url(:/images/checkbox_checked_$ASSET_THEME);
        }
    )")).arg(GUIUtil::spinBoxInnerLineEditReset()));

    ui->okButton->setStyleSheet(GUIUtil::primaryButtonStyle());
    ui->backButton->setStyleSheet(GUIUtil::secondaryButtonStyle());

    if (QCalendarWidget* calendar = ui->dateInput->calendarWidget()) {
        calendar->setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
            QCalendarWidget { background: $PANEL; border: 1px solid $BORDER; }
            #qt_calendar_navigationbar { background: $WINE; min-height: 42px; border: none; }
            #qt_calendar_prevmonth, #qt_calendar_nextmonth {
                background: transparent; border: none; width: 32px; height: 32px;
                border-radius: 10px; qproperty-iconSize: 14px 14px;
            }
            #qt_calendar_prevmonth { qproperty-icon: url(:/images/arrow_light_left_hover); }
            #qt_calendar_nextmonth { qproperty-icon: url(:/images/arrow_light_right_hover); }
            #qt_calendar_monthbutton, #qt_calendar_yearbutton {
                background: transparent; border: none; color: #FFFFFF;
                font-weight: 700; border-radius: 10px; padding: 4px 10px;
            }
            #qt_calendar_prevmonth:hover, #qt_calendar_nextmonth:hover,
            #qt_calendar_monthbutton:hover, #qt_calendar_yearbutton:hover {
                background: rgba(255,255,255,0.16);
            }
            #qt_calendar_calendarview {
                background: $PANEL; border: none; outline: none;
                gridline-color: transparent;
                selection-background-color: $WINE_DEEP; selection-color: #FFFFFF;
            }
            QCalendarWidget QWidget { alternate-background-color: $PANEL_SOFT; }
            QCalendarWidget QToolButton::menu-indicator { image: none; }
            QCalendarWidget QAbstractItemView:enabled {
                color: $INK; selection-background-color: $WINE_DEEP; selection-color: #FFFFFF;
            }
            QCalendarWidget QAbstractItemView:disabled { color: $INK_FAINT; }
            QCalendarWidget QMenu {
                background: $PANEL; color: $INK; border: 1px solid $BORDER;
            }
            QCalendarWidget QSpinBox {
                background: $PANEL; color: $INK; border: 1px solid $FIELD_BORDER;
            }
        )")));
    }
}

Recover::~Recover()
{
    delete ui;
    /* Ensure thread is finished before it is deleted */
    Q_EMIT stopThread();
    thread->wait();
}

void Recover::showPage(QWidget* page)
{
    const bool welcome = page == ui->welcomePage;
    ui->pages->setCurrentWidget(page);
    ui->backButton->setText(welcome ? tr("Quit") : tr("Back"));
    ui->okButton->setVisible(!welcome);
    ui->okButton->setText(page == ui->restorePage ? tr("Restore wallet") : tr("Create wallet"));
    ui->errorMessage->clear();
    if (welcome)
        ui->createNew->setFocus();
    else if (page == ui->restorePage)
        words.first()->setFocus();
    else
        ui->okButton->setFocus();
}

void Recover::setWordCount(int count)
{
    for (int i = 0; i < MAX_WORDS; ++i) {
        numbers[i]->setVisible(i < count);
        words[i]->setVisible(i < count);
    }
}

int Recover::wordCount() const
{
    return ui->restore12->isChecked() ? 12 : MAX_WORDS;
}

void Recover::wordEdited(int index)
{
    QLineEdit* word = words[index];
    markWord(word, false);
    const QString text = word->text();
    if (text == text.simplified() && !text.contains(QLatin1Char(' ')))
        return;

    // Whitespace means a pasted phrase or the end of a typed word: spread the words over the boxes from here on.
    const QStringList parts = text.simplified().split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int end = index + parts.size();
    word->clear();
    // Never drop or hide words: refuse more than fit, and show all 24 boxes when the words need them.
    if (end > MAX_WORDS) {
        ui->errorMessage->setText(tr("That's %1 words, more than the boxes left. Recovery phrases have 12 or 24 words.").arg(parts.size()));
        return;
    }
    if (end > 12)
        ui->restore24->setChecked(true);
    else if (index == 0 && parts.size() == 12)
        ui->restore12->setChecked(true);
    ui->errorMessage->clear();
    int next = index;
    for (const QString& part : parts) {
        words[next]->setText(part);
        markWord(words[next], !IsWord(part));
        ++next;
    }
    if (next < wordCount())
        words[next]->setFocus();
}

void Recover::markWord(QLineEdit* word, bool invalid)
{
    if (word->property("invalid").toBool() == invalid)
        return;
    word->setProperty("invalid", invalid);
    word->style()->unpolish(word);
    word->style()->polish(word);
}

void Recover::fail(const QString& message, QWidget* focus)
{
    ui->errorMessage->setText(message);
    focus->setFocus();
}

QString Recover::mnemonic() const
{
    QStringList phrase;
    for (int i = 0; i < wordCount(); ++i)
        phrase << words[i]->text().trimmed().toLower();
    return phrase.join(QLatin1Char(' '));
}

void Recover::submit()
{
    // CreateWalletFromFile refuses passphrases over 256 bytes of UTF-8.
    const auto passphraseError = [](const QString& passphrase) {
        if (passphrase.isEmpty())
            return tr("Enter a passphrase, or untick this option.");
        if (passphrase.toStdString().size() > 256)
            return tr("That passphrase is too long. Shorten it and try again.");
        return QString();
    };

    if (ui->pages->currentWidget() == ui->restorePage) {
        // Restore from everything entered or nothing: words hidden by the 12-word choice still count.
        for (int i = wordCount(); i < MAX_WORDS; ++i) {
            if (!words[i]->text().trimmed().isEmpty())
                return fail(tr("Boxes 13 to 24 still have words in them. Switch to 24 words to check them."), ui->restore24);
        }
        for (int i = 0; i < wordCount(); ++i) {
            if (words[i]->text().trimmed().isEmpty())
                return fail(tr("Enter all %1 words.").arg(wordCount()), words[i]);
            if (!IsWord(words[i]->text())) {
                markWord(words[i], true);
                return fail(tr("Word %1 isn't on the recovery word list. Check the spelling.").arg(i + 1), words[i]);
            }
        }
        const std::string phrase = mnemonic().toStdString();
        if (!Mnemonic::mnemonic_check(SecureString(phrase.begin(), phrase.end())))
            return fail(tr("These words don't form a valid recovery phrase. Check the spelling and order."), words.first());
        if (ui->restoreUsePassphrase->isChecked()) {
            const QString error = passphraseError(ui->restorePassPhrase->text());
            if (!error.isEmpty())
                return fail(error, ui->restorePassPhrase);
        }
    } else if (ui->usePassphrase->isChecked()) {
        const QString error = passphraseError(ui->mnemonicPassPhrase->text());
        if (!error.isEmpty())
            return fail(error, ui->mnemonicPassPhrase);
        if (ui->mnemonicPassPhrase->text() != ui->mnemonicPassPhrase2->text())
            return fail(tr("Passphrases don't match."), ui->mnemonicPassPhrase2);
    }
    accept();
}

bool Recover::askRecover(bool& newWallet)
{
#ifdef ENABLE_WALLET
    namespace fs = boost::filesystem;
    fs::path walletFile = GetDataDir(true) / GetArg("-wallet", DEFAULT_WALLET_DAT);

    if (!fs::exists(walletFile))
    {
        Recover recover;
        recover.setWindowIcon(QIcon(":icons/firo"));
        if (!recover.exec())
        {
            /* Quit clicked */
            return false;
        }

        // submit() accepts only input that passed every check, so the args come from the final input alone.
        newWallet = recover.ui->pages->currentWidget() == recover.ui->createPage;
        if (newWallet) {
            SoftSetBoolArg("-newwallet", true);
            if (recover.ui->use12->isChecked())
                SoftSetBoolArg("-use12", true);
            if (recover.ui->usePassphrase->isChecked())
                SoftSetArg("-mnemonicpassphrase", recover.ui->mnemonicPassPhrase->text().toStdString());
        } else {
            SoftSetArg("-mnemonic", recover.mnemonic().toStdString());
            if (recover.wordCount() == 12)
                SoftSetBoolArg("-use12", true);
            // Scan from one day before the picked date.
            const QDate date = recover.ui->dateInput->date();
            if (date > recover.ui->dateInput->minimumDate())
                SoftSetArg("-wcdate", date.addDays(-1).toString("dd-MM-yyyy").toStdString());
            if (recover.ui->restoreUsePassphrase->isChecked())
                SoftSetArg("-mnemonicpassphrase", recover.ui->restorePassPhrase->text().toStdString());
        }
    }
#endif // ENABLE_WALLET
    return true;
}
