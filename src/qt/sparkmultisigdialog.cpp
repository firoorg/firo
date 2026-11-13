// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "sparkmultisigdialog.h"

#include "bitcoinunits.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"

#include "libspark/multisig.h"
#include "rpc/server.h"
#include "spark/sparkwallet.h"
#include "spark/state.h"
#include "streams.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"
#include "wallet/rpcsparkmultisig.h"
#include "wallet/wallet.h"

#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QFile>
#include <QFontMetrics>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStyle>
#include <QVBoxLayout>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

UniValue sendrawtransaction(const JSONRPCRequest& request); // rpc/rawtransaction.cpp

namespace
{
const qint64 MAX_FILE_SIZE = 16 << 20; // a spend is a few hundred KB at most

// The message of an error thrown by an RPC handler
QString ErrorText(const UniValue& e)
{
    const UniValue message = find_value(e, "message");
    return message.isStr() ? QString::fromStdString(message.get_str()) : QCoreApplication::translate("SparkMultisigDialog", "Unknown error.");
}

// Run one of the multisig RPC handlers in this process. False with the handler's message in `error` if it fails.
bool Call(UniValue (*rpc)(const JSONRPCRequest&), const UniValue& param, UniValue& result, QString& error)
{
    JSONRPCRequest request;
    request.params = UniValue(UniValue::VARR);
    request.params.push_back(param);
    try {
        UniValue value;
        GUIUtil::runWalletOperation([&] { value = rpc(request); });
        result = value;
        return true;
    } catch (const UniValue& e) {
        error = ErrorText(e);
    } catch (const std::exception& e) {
        error = QString::fromStdString(e.what());
    }
    return false;
}

QString Str(const UniValue& value)
{
    return value.isStr() ? QString::fromStdString(value.get_str()) : QString();
}

QString ShortKey(const QString& hex)
{
    if (hex.size() <= 12) return hex;
    return hex.left(8) + QChar(0x2026) + hex.right(4);
}

// A Spark address is longer than a line, and a label breaks text only at spaces. In
// groups it wraps, and is easier to compare by eye; the Copy buttons give the address itself.
QString Grouped(const QString& address)
{
    if (address.size() <= 40) return address;
    QString out;
    for (int i = 0; i < address.size(); i += 6) {
        if (i) out += QLatin1Char(' ');
        out += address.mid(i, 6);
    }
    return out;
}

// Every label shows pasted data at some point, so none of them takes rich text.
QLabel* MakeLabel(const QString& text, QWidget* parent, const char* name = nullptr)
{
    auto* label = new QLabel(text, parent);
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    if (name) label->setObjectName(QString::fromLatin1(name));
    return label;
}

QLabel* MakeHelp(const QString& text, QWidget* parent)
{
    QLabel* label = MakeLabel(text, parent);
    label->setProperty("help", true);
    return label;
}

QLabel* MakeValue(QWidget* parent, const char* name)
{
    QLabel* label = MakeLabel(QString(), parent, name);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return label;
}

// Enter in a field must not press a button
QPushButton* MakeButton(const QString& text, const char* name, QWidget* parent)
{
    auto* button = new QPushButton(text, parent);
    button->setObjectName(QString::fromLatin1(name));
    button->setAutoDefault(false);
    return button;
}

void SetStatus(QLabel* label, const QString& text, bool fError)
{
    label->setText(text);
    if (label->property("error").toBool() == fError) return;
    label->setProperty("error", fError);
    label->style()->unpolish(label);
    label->style()->polish(label);
}

void FitToScreen(QDialog* dialog, int width, int height)
{
    const QSize available = GUIUtil::availableScreenSize(dialog);
    const int maxWidth = qMax(1, available.width() - 40);
    dialog->setMinimumWidth(qMin(560, maxWidth));
    dialog->resize(qMin(width, maxWidth), qMin(height, qMax(1, available.height() - 40)));
}

QString DialogStyle(const char* name)
{
    return GUIUtil::themed(QStringLiteral(R"(
        QDialog#%1 { background: $BG; }
        QDialog#%1 QLabel { background: transparent; color: $INK; }
        QDialog#%1 QLabel#title { font: $FONT_H2; }
        QDialog#%1 QLabel#section { font-weight: 700; }
        QDialog#%1 QLabel[help="true"] { color: $INK_SOFT; font-size: 13px; }
        QDialog#%1 QLabel#status {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 10px;
            padding: 10px 12px;
        }
        QDialog#%1 QLabel#status[error="true"] { color: $ERROR; font-weight: 700; }
        QDialog#%1 QScrollArea#multisigScroll,
        QDialog#%1 QWidget#multisigContents { background: transparent; border: none; }
        QDialog#%1 QLineEdit,
        QDialog#%1 QPlainTextEdit,
        QDialog#%1 QSpinBox {
            background: $PANEL_SOFT;
            border: 1px solid $FIELD_BORDER;
            border-radius: 10px;
            padding: 8px 12px;
            color: $INK;
            selection-background-color: $WINE_DEEP;
            selection-color: #FFFFFF;
        }
        QDialog#%1 QLineEdit:focus,
        QDialog#%1 QPlainTextEdit:focus,
        QDialog#%1 QSpinBox:focus {
            border: 2px solid $WINE;
            padding: 7px 11px;
        }
        QDialog#%1 QLineEdit:disabled,
        QDialog#%1 QPlainTextEdit:disabled,
        QDialog#%1 QSpinBox:disabled { color: $INK_FAINT; }
        QDialog#%1 QAbstractSpinBox QLineEdit { %2 }
    )")).arg(QString::fromLatin1(name), GUIUtil::spinBoxInnerLineEditReset());
}

// Only the buttons that take the dialog's work forward are primary
void StyleButtons(QDialog* dialog)
{
    for (QPushButton* button : dialog->findChildren<QPushButton*>()) {
        button->setStyleSheet(button->property("primary").toBool() ? GUIUtil::primaryButtonStyle() : GUIUtil::secondaryButtonStyle());
    }
}

void SaveText(QWidget* parent, const QString& caption, const QString& text)
{
    const QString name = GUIUtil::getSaveFileName(parent, caption, QString(), QCoreApplication::translate("SparkMultisigDialog", "Text files (*.txt)"), nullptr);
    if (name.isEmpty()) return;
    QFile file(name);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text) || file.write(QString(text + QLatin1Char('\n')).toUtf8()) < 0) {
        QMessageBox::critical(parent, caption, QCoreApplication::translate("SparkMultisigDialog", "The file could not be written."));
    }
}

// The text of a file the user picks; empty if none
QString OpenText(QWidget* parent, const QString& caption)
{
    const QString name = GUIUtil::getOpenFileName(parent, caption, QString(), QCoreApplication::translate("SparkMultisigDialog", "Text files (*.txt);;All files (*)"), nullptr);
    if (name.isEmpty()) return QString();
    QFile file(name);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(parent, caption, QCoreApplication::translate("SparkMultisigDialog", "The file could not be read."));
        return QString();
    }
    return QString::fromUtf8(file.read(MAX_FILE_SIZE)).trimmed();
}

// The non-empty lines of a text with their line numbers, trimmed
std::vector<std::pair<int, std::string>> Lines(const QString& text)
{
    std::vector<std::pair<int, std::string>> lines;
    const QStringList parts = text.split(QLatin1Char('\n'));
    for (int i = 0; i < parts.size(); ++i) {
        const QString line = parts[i].trimmed();
        if (!line.isEmpty()) lines.emplace_back(i + 1, line.toStdString());
    }
    return lines;
}

bool ParseKey(const std::string& hex, CPubKey& key)
{
    if (hex.size() != 66 || !IsHex(hex)) return false;
    key = CPubKey(ParseHex(hex));
    return key.IsFullyValid() && key.IsCompressed();
}

// Who a co-signer's setup data is from, and whether it is the second of its two parts
bool ParseSetupData(const std::string& hex, CPubKey& sender, bool& fSecond)
{
    if (!IsHex(hex)) return false;
    try {
        CDataStream stream(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
        spark::MultisigKeygenMessage message;
        stream >> message;
        if (!stream.empty()) return false;
        sender = CPubKey(spark::MultisigKey::serialize_participant(message.key));
        fSecond = !message.shares.empty();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
} // namespace

// ---------------------------------------------------------------------------

SparkMultisigSetupDialog::SparkMultisigSetupDialog(WalletModel* walletModel, QWidget* parent) :
    QDialog(parent), model(walletModel)
{
    setObjectName(QStringLiteral("SparkMultisigSetupDialog"));
    setWindowTitle(tr("Set up multisig wallet"));

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(16);
    layout->addWidget(MakeLabel(tr("Set up a multisig wallet"), this, "title"));

    // The two exchanges have a page each, so that neither has to scroll
    pages = new QStackedWidget(this);
    pages->setObjectName(QStringLiteral("multisigContents"));
    auto* keysPage = new QWidget(pages);
    auto* body = new QVBoxLayout(keysPage);
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(10);
    auto* dataPage = new QWidget(pages);
    auto* dataBody = new QVBoxLayout(dataPage);
    dataBody->setContentsMargins(0, 0, 0, 0);
    dataBody->setSpacing(10);
    pages->addWidget(keysPage);
    pages->addWidget(dataPage);

    // 1. Keys
    body->addWidget(MakeLabel(tr("A multisig wallet is shared with your co-signers. Each of you sees its private balance, and sending takes the approval of several of you."), keysPage));
    body->addWidget(MakeLabel(tr("Step 1 of 2: exchange keys"), keysPage, "section"));
    ownKeyEdit = new QLineEdit(keysPage);
    ownKeyEdit->setObjectName(QStringLiteral("ownKey"));
    ownKeyEdit->setReadOnly(true);
    ownKeyEdit->setAccessibleName(tr("Your co-signer key"));
    QPushButton* copyKey = MakeButton(tr("Copy"), "copyKey", keysPage);
    auto* keyRow = new QHBoxLayout();
    keyRow->addWidget(ownKeyEdit, 1);
    keyRow->addWidget(copyKey);
    body->addLayout(keyRow);
    body->addWidget(MakeHelp(tr("Send this key to your co-signers, and enter their keys below, one per line."), keysPage));

    cosignerKeys = new QPlainTextEdit(keysPage);
    cosignerKeys->setObjectName(QStringLiteral("cosignerKeys"));
    cosignerKeys->setAccessibleName(tr("Co-signer keys"));
    body->addWidget(cosignerKeys, 1);

    required = new QSpinBox(keysPage);
    required->setObjectName(QStringLiteral("required"));
    required->setAccessibleName(tr("Approvals needed to send"));
    required->setRange(1, int(spark::MULTISIG_MAX_PARTICIPANTS));
    required->setValue(2);
    QLabel* requiredLabel = MakeLabel(tr("Approvals needed to send"), keysPage);
    requiredLabel->setWordWrap(false);
    requiredOf = MakeLabel(QString(), keysPage, "requiredOf");
    requiredOf->setWordWrap(false);
    auto* requiredRow = new QHBoxLayout();
    requiredRow->addWidget(requiredLabel);
    requiredRow->addWidget(required);
    requiredRow->addWidget(requiredOf);
    requiredRow->addStretch(1);
    body->addLayout(requiredRow);

    // 2. Setup data
    dataBody->addWidget(MakeLabel(tr("Step 2 of 2: exchange setup data"), dataPage, "section"));
    ownDataLabel = MakeLabel(tr("Your setup data (part 1 of 2)"), dataPage, "ownDataLabel");
    dataBody->addWidget(ownDataLabel);
    ownData = new QLineEdit(dataPage);
    ownData->setObjectName(QStringLiteral("ownData"));
    ownData->setReadOnly(true);
    ownData->setAccessibleName(tr("Your setup data"));
    QPushButton* copyData = MakeButton(tr("Copy"), "copyData", dataPage);
    QPushButton* saveData = MakeButton(tr("Save…"), "saveData", dataPage);
    auto* dataRow = new QHBoxLayout();
    dataRow->addWidget(ownData, 1);
    dataRow->addWidget(copyData);
    dataRow->addWidget(saveData);
    dataBody->addLayout(dataRow);
    dataBody->addWidget(MakeHelp(tr("Send your setup data to every co-signer, and enter what they send you below, one per line. Your data changes once, when everyone's part 1 is in: send it again then."), dataPage));

    cosignerData = new QPlainTextEdit(dataPage);
    cosignerData->setObjectName(QStringLiteral("cosignerData"));
    cosignerData->setAccessibleName(tr("Setup data of the co-signers"));
    cosignerData->setLineWrapMode(QPlainTextEdit::NoWrap);
    QPushButton* pasteData = MakeButton(tr("Paste"), "pasteData", dataPage);
    QPushButton* loadData = MakeButton(tr("Open file…"), "loadData", dataPage);
    auto* pasteColumn = new QVBoxLayout();
    pasteColumn->addWidget(pasteData);
    pasteColumn->addWidget(loadData);
    pasteColumn->addStretch(1);
    auto* pasteRow = new QHBoxLayout();
    pasteRow->addWidget(cosignerData, 1);
    pasteRow->addLayout(pasteColumn);
    dataBody->addLayout(pasteRow, 1);

    progress = MakeLabel(QString(), dataPage, "progress");
    dataBody->addWidget(progress);

    auto* scroll = new QScrollArea(this);
    scroll->setObjectName(QStringLiteral("multisigScroll"));
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(pages);
    layout->addWidget(scroll, 1);

    status = MakeLabel(QString(), this, "status");
    status->setProperty("error", false);
    layout->addWidget(status);
    layout->addWidget(MakeHelp(tr("You can close this window and continue later from File > Multisig wallet: what you entered is saved in this wallet."), this));

    QPushButton* closeButton = MakeButton(tr("Close"), "closeButton", this);
    backButton = MakeButton(tr("Back"), "backButton", this);
    nextButton = MakeButton(tr("Next"), "nextButton", this);
    nextButton->setProperty("primary", true);
    nextButton->setEnabled(false);
    finishButton = MakeButton(tr("Create multisig wallet"), "finishButton", this);
    finishButton->setProperty("primary", true);
    finishButton->setEnabled(false);
    auto* footer = new QHBoxLayout();
    footer->addWidget(closeButton);
    footer->addStretch(1);
    footer->addWidget(backButton);
    footer->addWidget(nextButton);
    footer->addWidget(finishButton);
    layout->addLayout(footer);

    connect(copyKey, &QPushButton::clicked, this, [this] { GUIUtil::setClipboard(ownKeyEdit->text()); });
    connect(copyData, &QPushButton::clicked, this, [this] { GUIUtil::setClipboard(ownData->text()); });
    connect(saveData, &QPushButton::clicked, this, [this] { SaveText(this, tr("Save setup data"), ownData->text()); });
    connect(pasteData, &QPushButton::clicked, this, [this] {
        const QString text = QApplication::clipboard()->text().trimmed();
        if (!text.isEmpty()) cosignerData->appendPlainText(text);
    });
    connect(loadData, &QPushButton::clicked, this, [this] {
        const QString text = OpenText(this, tr("Open setup data"));
        if (!text.isEmpty()) cosignerData->appendPlainText(text);
    });
    connect(closeButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(backButton, &QPushButton::clicked, this, [this] { showPage(0); });
    connect(nextButton, &QPushButton::clicked, this, [this] { showPage(1); });
    connect(finishButton, &QPushButton::clicked, this, &SparkMultisigSetupDialog::finish);
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged, this, &SparkMultisigSetupDialog::applyTheme);

    applyTheme();
    // Three lines at least, in the font the theme gives them, and what the window has to
    // spare. Their own size hint is taller than that and would make the page scroll.
    for (QPlainTextEdit* box : {cosignerKeys, cosignerData}) {
        box->ensurePolished();
        box->setMinimumHeight(box->fontMetrics().lineSpacing() * 3 + 28);
        box->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    }
    FitToScreen(this, 700, 640);

    loadDraft();
    if (ownKey.IsValid()) {
        connect(cosignerKeys, &QPlainTextEdit::textChanged, this, &SparkMultisigSetupDialog::refresh);
        connect(cosignerData, &QPlainTextEdit::textChanged, this, &SparkMultisigSetupDialog::refresh);
        connect(required, &QSpinBox::valueChanged, this, &SparkMultisigSetupDialog::refresh);
        refresh();
    }
    // Someone who comes back has the keys in, and is here for the data
    showPage(nextButton->isEnabled() ? 1 : 0);
}

void SparkMultisigSetupDialog::applyTheme()
{
    setStyleSheet(DialogStyle("SparkMultisigSetupDialog"));
    StyleButtons(this);
}

void SparkMultisigSetupDialog::showPage(int page)
{
    pages->setCurrentIndex(page);
    backButton->setVisible(page == 1);
    nextButton->setVisible(page == 0);
    finishButton->setVisible(page == 1);
    if (ownKey.IsValid()) refresh();
}

void SparkMultisigSetupDialog::loadDraft()
{
    CWallet* wallet = model->getWallet();
    int nrequired = 2;
    QString keys, data;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        bool fFound = false;
        for (const auto& entry : wallet->mapAddressBook) {
            const auto draft = entry.second.destdata.find("sparkmultisig");
            const CKeyID* keyID = boost::get<CKeyID>(&entry.first);
            if (draft == entry.second.destdata.end() || !keyID || !wallet->GetPubKey(*keyID, ownKey)) continue;
            fFound = true;
            UniValue json;
            if (json.read(draft->second) && json.isObject()) {
                if (json["nrequired"].isNum()) nrequired = json["nrequired"].get_int();
                keys = Str(json["keys"]);
                data = Str(json["data"]);
            }
            break;
        }
        if (!fFound) {
            // The key of this wallet in the group; the same one comes back next time
            if (!wallet->IsLocked()) wallet->TopUpKeyPool();
            if (wallet->GetKeyFromPool(ownKey)) {
                wallet->SetAddressBook(ownKey.GetID(), tr("Multisig co-signer key").toStdString(), "receive");
                wallet->AddDestData(ownKey.GetID(), "sparkmultisig", "{}");
            }
        }
    }

    if (!ownKey.IsValid()) {
        SetStatus(status, tr("This wallet has no key to give. Unlock it, or refill its key pool, and open this window again."), true);
        for (QWidget* widget : {static_cast<QWidget*>(cosignerKeys), static_cast<QWidget*>(required), static_cast<QWidget*>(cosignerData)}) {
            widget->setEnabled(false);
        }
        return;
    }

    const QSignalBlocker keysBlocker(cosignerKeys), dataBlocker(cosignerData), requiredBlocker(required);
    ownKeyEdit->setText(QString::fromStdString(HexStr(ownKey)));
    ownKeyEdit->setCursorPosition(0); // show where it starts
    required->setValue(nrequired);
    cosignerKeys->setPlainText(keys);
    cosignerData->setPlainText(data);
}

void SparkMultisigSetupDialog::saveDraft()
{
    if (!ownKey.IsValid()) return;
    UniValue draft(UniValue::VOBJ);
    draft.pushKV("nrequired", required->value());
    draft.pushKV("keys", cosignerKeys->toPlainText().toStdString());
    draft.pushKV("data", cosignerData->toPlainText().toStdString());
    CWallet* wallet = model->getWallet();
    LOCK(wallet->cs_wallet);
    wallet->EraseDestData(ownKey.GetID(), "sparkmultisig"); // AddDestData does not replace an entry
    wallet->AddDestData(ownKey.GetID(), "sparkmultisig", draft.write());
}

void SparkMultisigSetupDialog::done(int result)
{
    if (!fCreated) saveDraft();
    QDialog::done(result);
}

void SparkMultisigSetupDialog::refresh()
{
    // Setup data that no longer goes with what is entered must not stay on screen to be sent
    const auto fail = [this](const QString& message) {
        SetStatus(status, message, true);
        ownData->clear();
        progress->clear();
        finishButton->setEnabled(false);
    };
    nextButton->setEnabled(false);

    std::vector<CPubKey> others;
    for (const auto& [number, line] : Lines(cosignerKeys->toPlainText())) {
        CPubKey key;
        if (!ParseKey(line, key)) return fail(tr("Line %1 of the co-signer keys is not a valid key.").arg(number));
        if (key == ownKey) continue; // people paste the whole list
        if (std::find(others.begin(), others.end(), key) != others.end()) return fail(tr("Line %1 of the co-signer keys repeats an earlier key.").arg(number));
        others.push_back(key);
    }

    const int total = int(others.size()) + 1;
    requiredOf->setText(tr("of %1").arg(total));
    if (!others.empty()) {
        // Without keys the range stays, so that the number from the draft survives until they are in
        const QSignalBlocker blocker(required);
        required->setMaximum(qMin(total, int(spark::MULTISIG_MAX_PARTICIPANTS)));
    }

    if (others.empty()) {
        SetStatus(status, tr("Send your key to your co-signers and enter theirs to begin."), false);
        ownDataLabel->setText(tr("Your setup data (part 1 of 2)"));
        ownData->clear();
        progress->clear();
        finishButton->setEnabled(false);
        return;
    }
    if (size_t(total) > spark::MULTISIG_MAX_PARTICIPANTS) {
        return fail(tr("A multisig wallet can have at most %1 co-signers.").arg(qulonglong(spark::MULTISIG_MAX_PARTICIPANTS)));
    }
    nextButton->setEnabled(true);
    if (pages->currentIndex() == 0) {
        SetStatus(status, tr("When the keys of all your co-signers are in, go on to the next step."), false);
        return;
    }

    // The latest data of each co-signer: 0 nothing, 1 part 1, 2 part 2
    std::vector<int> part(others.size(), 0);
    std::vector<std::string> kept(others.size());
    for (const auto& [number, line] : Lines(cosignerData->toPlainText())) {
        CPubKey sender;
        bool fSecond = false;
        if (!ParseSetupData(line, sender, fSecond)) return fail(tr("Entry %1 of the setup data is not setup data.").arg(number));
        if (sender == ownKey) continue;
        const auto known = std::find(others.begin(), others.end(), sender);
        if (known == others.end()) return fail(tr("Entry %1 of the setup data comes from a key that is not among your co-signers.").arg(number));
        const size_t i = known - others.begin();
        const int latest = fSecond ? 2 : 1;
        if (latest >= part[i]) {
            part[i] = latest;
            kept[i] = line;
        }
    }
    const bool fAllData = std::none_of(part.begin(), part.end(), [](int p) { return p == 0; });

    UniValue keyList(UniValue::VARR);
    keyList.push_back(HexStr(ownKey));
    for (const CPubKey& key : others) keyList.push_back(HexStr(key));
    UniValue newArgs(UniValue::VARR);
    newArgs.push_back(UniValue(required->value()));
    newArgs.push_back(keyList);
    if (fAllData) {
        UniValue dataList(UniValue::VARR);
        for (const std::string& line : kept) dataList.push_back(line);
        newArgs.push_back(dataList);
    }

    UniValue result;
    try {
        result = SetupSparkMultisig(model->getWallet(), newArgs, false);
    } catch (const UniValue& e) {
        return fail(ErrorText(e));
    } catch (const std::exception& e) {
        return fail(QString::fromStdString(e.what()));
    }
    args = newArgs;

    if (result.exists("hex")) {
        ownData->setText(Str(result["hex"]));
        ownData->setCursorPosition(0);
    }
    ownDataLabel->setText(fAllData ? tr("Your setup data (part 2 of 2)") : tr("Your setup data (part 1 of 2)"));

    QStringList lines;
    for (size_t i = 0; i < others.size(); ++i) {
        const QString state = part[i] == 2 ? tr("part 2 received") : part[i] == 1 ? tr("part 1 received") : tr("nothing received yet");
        lines << ShortKey(QString::fromStdString(HexStr(others[i]))) + QStringLiteral(": ") + state;
    }
    progress->setText(lines.join(QLatin1Char('\n')));

    // The list above says whose data is missing
    finishButton->setEnabled(result.exists("address"));
    if (result.exists("address")) {
        SetStatus(status, tr("Everything checks out. Make sure every co-signer has part 2 of your setup data, then create the wallet."), false);
    } else if (fAllData) {
        SetStatus(status, tr("Send part 2 of your setup data to every co-signer, and enter theirs as it arrives."), false);
    } else {
        SetStatus(status, tr("Send part 1 of your setup data to every co-signer, and enter theirs as it arrives."), false);
    }
}

void SparkMultisigSetupDialog::finish()
{
    const int nrequired = args[0].get_int();
    const int total = int(args[1].size());
    const auto answer = QMessageBox::question(this, tr("Create multisig wallet"),
        tr("This wallet becomes the shared wallet of you and your co-signers: %1 of %2 have to approve each payment. This cannot be undone.\n\nYour co-signers need part 2 of your setup data to finish too. Send it to them first if you have not.").arg(nrequired).arg(total),
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (answer != QMessageBox::Yes) return;

    UniValue result;
    try {
        // Storing waits for the wallet's scans to finish, so not on this thread
        GUIUtil::runWalletOperation([&] { result = SetupSparkMultisig(model->getWallet(), args, true); });
    } catch (const UniValue& e) {
        SetStatus(status, ErrorText(e), true);
        return;
    } catch (const std::exception& e) {
        SetStatus(status, QString::fromStdString(e.what()), true);
        return;
    }

    {
        CWallet* wallet = model->getWallet();
        LOCK(wallet->cs_wallet);
        wallet->EraseDestData(ownKey.GetID(), "sparkmultisig");
    }
    fCreated = true;

    QMessageBox created(QMessageBox::Information, tr("Multisig wallet created"),
        tr("This is now a %1-of-%2 multisig wallet. Its address:\n\n%3\n\nBefore anyone sends funds to it, check with every co-signer that their wallet shows the same address.\n\nNext you can save a backup of this wallet. Keep one: your recovery phrase alone cannot restore a multisig wallet. Firo then closes; start it again to use the wallet.").arg(nrequired).arg(total).arg(Grouped(Str(result["address"]))),
        QMessageBox::Ok, this);
    created.setTextFormat(Qt::PlainText);
    created.setTextInteractionFlags(Qt::TextSelectableByMouse);
    created.exec();
    accept();
}

// ---------------------------------------------------------------------------

SparkMultisigSpendDialog::SparkMultisigSpendDialog(WalletModel* walletModel, QWidget* parent) :
    QDialog(parent), model(walletModel)
{
    setObjectName(QStringLiteral("SparkMultisigSpendDialog"));
    setWindowTitle(tr("Multisig wallet"));

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(16);

    auto* contents = new QWidget(this);
    contents->setObjectName(QStringLiteral("multisigContents"));
    auto* body = new QVBoxLayout(contents);
    body->setContentsMargins(0, 0, 0, 0);
    body->setSpacing(10);

    body->addWidget(MakeLabel(tr("Multisig wallet"), contents, "title"));
    summary = MakeLabel(QString(), contents, "summary");
    body->addWidget(summary);

    address = MakeValue(contents, "address");
    QPushButton* copyAddress = MakeButton(tr("Copy"), "copyAddress", contents);
    auto* addressRow = new QHBoxLayout();
    addressRow->addWidget(MakeLabel(tr("Address"), contents), 0, Qt::AlignTop);
    addressRow->addWidget(address, 1);
    addressRow->addWidget(copyAddress, 0, Qt::AlignTop);
    body->addLayout(addressRow);
    body->addWidget(MakeHelp(tr("Check that every co-signer's wallet shows this address before it receives funds. Keep a backup of this wallet file: the recovery phrase alone cannot restore a multisig wallet."), contents));
    body->addSpacing(8);

    body->addWidget(MakeLabel(tr("Transaction"), contents, "section"));
    QPushButton* pasteButton = MakeButton(tr("Paste transaction"), "pasteButton", contents);
    QPushButton* openButton = MakeButton(tr("Open file…"), "openButton", contents);
    auto* loadRow = new QHBoxLayout();
    loadRow->addWidget(pasteButton);
    loadRow->addWidget(openButton);
    loadRow->addStretch(1);
    body->addLayout(loadRow);

    detailsBox = new QWidget(contents);
    detailsForm = new QFormLayout(detailsBox);
    detailsForm->setContentsMargins(0, 0, 0, 0);
    detailsForm->setSpacing(10);
    detailsForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
    pays = MakeValue(detailsBox, "pays");
    fee = MakeValue(detailsBox, "fee");
    returns = MakeValue(detailsBox, "returns");
    approvals = MakeValue(detailsBox, "approvals");
    // A caption stays with the first line of what it names
    const auto addRow = [this](const QString& caption, QLabel* value) {
        QLabel* label = MakeLabel(caption, detailsBox);
        label->setWordWrap(false);
        label->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        detailsForm->addRow(label, value);
    };
    addRow(tr("Pays"), pays);
    addRow(tr("Fee"), fee);
    addRow(tr("Returns"), returns);
    addRow(tr("Approvals"), approvals);
    body->addWidget(detailsBox);

    status = MakeLabel(QString(), contents, "status");
    status->setProperty("error", false);
    body->addWidget(status);
    body->addStretch(1);

    auto* scroll = new QScrollArea(this);
    scroll->setObjectName(QStringLiteral("multisigScroll"));
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setWidget(contents);
    layout->addWidget(scroll, 1);

    copyButton = MakeButton(tr("Copy transaction"), "copyButton", this);
    saveButton = MakeButton(tr("Save to file…"), "saveButton", this);
    actionButton = MakeButton(QString(), "actionButton", this);
    actionButton->setProperty("primary", true);
    QPushButton* closeButton = MakeButton(tr("Close"), "closeButton", this);
    auto* footer = new QHBoxLayout();
    footer->addWidget(copyButton);
    footer->addWidget(saveButton);
    footer->addStretch(1);
    footer->addWidget(closeButton);
    footer->addWidget(actionButton);
    layout->addLayout(footer);

    connect(copyAddress, &QPushButton::clicked, this, [this] { GUIUtil::setClipboard(ownAddress()); });
    connect(pasteButton, &QPushButton::clicked, this, [this] { load(QApplication::clipboard()->text()); });
    connect(openButton, &QPushButton::clicked, this, [this] { load(OpenText(this, tr("Open transaction"))); });
    connect(copyButton, &QPushButton::clicked, this, [this] { GUIUtil::setClipboard(spend); });
    connect(saveButton, &QPushButton::clicked, this, [this] { SaveText(this, tr("Save transaction"), spend); });
    connect(actionButton, &QPushButton::clicked, this, [this] {
        if (!rawTx.isEmpty()) {
            send();
        } else {
            sign();
        }
    });
    connect(closeButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged, this, &SparkMultisigSpendDialog::applyTheme);

    applyTheme();
    FitToScreen(this, 640, 700);
    updateView();
}

void SparkMultisigSpendDialog::applyTheme()
{
    setStyleSheet(DialogStyle("SparkMultisigSpendDialog"));
    StyleButtons(this);
}

const spark::MultisigKey* SparkMultisigSpendDialog::groupKey() const
{
    CWallet* wallet = model->getWallet();
    return wallet->sparkWallet ? wallet->sparkWallet->getMultisigKey() : nullptr;
}

QString SparkMultisigSpendDialog::ownAddress() const
{
    CWallet* wallet = model->getWallet();
    if (!wallet->sparkWallet) return QString();
    try {
        return QString::fromStdString(wallet->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType()));
    } catch (const std::exception&) {
        return QString();
    }
}

void SparkMultisigSpendDialog::showEvent(QShowEvent* event)
{
    updateView();
    QDialog::showEvent(event);
}

bool SparkMultisigSpendDialog::mayReplace()
{
    if (rawTx.isEmpty()) return true;
    return QMessageBox::question(this, tr("Multisig wallet"), tr("The transaction on screen is fully signed but has not been sent. Replace it?"),
               QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes;
}

bool SparkMultisigSpendDialog::createSpend(const QList<SendCoinsRecipient>& recipients)
{
    if (!mayReplace()) return false;

    QSet<QString> seen;
    UniValue payments(UniValue::VOBJ);
    for (const SendCoinsRecipient& recipient : recipients) {
        if (seen.contains(recipient.address)) {
            QMessageBox::critical(this, tr("Multisig wallet"), tr("Each address can be paid only once per transaction."));
            return false;
        }
        seen.insert(recipient.address);
        UniValue payment(UniValue::VOBJ);
        payment.pushKV("amount", ValueFromAmount(recipient.amount));
        payment.pushKV("memo", recipient.message.toStdString());
        payment.pushKV("subtractFee", UniValue(recipient.fSubtractFeeFromAmount)); // not the int overload
        payments.pushKV(recipient.address.toStdString(), payment);
    }

    UniValue result;
    QString error;
    if (!Call(createsparkmultisigspend, payments, result, error)) {
        QMessageBox::critical(this, tr("Multisig wallet"), error);
        return false;
    }
    spend.clear();
    rawTx.clear();
    details = UniValue();
    return load(Str(result["hex"]));
}

bool SparkMultisigSpendDialog::load(const QString& hex)
{
    const QString cleaned = hex.simplified().remove(QLatin1Char(' '));
    if (cleaned.isEmpty()) return false;
    if (!mayReplace()) return false;

    UniValue decoded;
    QString error;
    if (!Call(decodesparkmultisigspend, UniValue(cleaned.toStdString()), decoded, error)) {
        SetStatus(status, error, true); // it says whether the data is foreign or the wallet behind
        return false;
    }

    // A copy of the transaction on screen merges into it; anything else replaces it
    UniValue result;
    bool fMerged = false;
    if (!spend.isEmpty()) {
        UniValue both(UniValue::VARR);
        both.push_back(spend.toStdString());
        both.push_back(cleaned.toStdString());
        fMerged = Call(combinesparkmultisigspend, both, result, error);
    }
    if (!fMerged) {
        UniValue alone(UniValue::VARR);
        alone.push_back(cleaned.toStdString());
        if (!Call(combinesparkmultisigspend, alone, result, error)) {
            SetStatus(status, error, true);
            return false;
        }
        details = decoded;
    }
    apply(result);
    return true;
}

void SparkMultisigSpendDialog::apply(const UniValue& result)
{
    const QString hex = Str(result["hex"]);
    if (result["complete"].isTrue()) {
        rawTx = hex;
        spend.clear();
        updateView();
        return;
    }
    spend = hex;
    rawTx.clear();
    UniValue fresh;
    QString error;
    const bool fDecoded = Call(decodesparkmultisigspend, UniValue(hex.toStdString()), fresh, error);
    details = fDecoded ? fresh : UniValue();
    updateView();
    if (!fDecoded) SetStatus(status, error, true);
}

void SparkMultisigSpendDialog::sign()
{
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid()) return;

    UniValue result;
    QString error;
    if (!Call(signsparkmultisigspend, UniValue(spend.toStdString()), result, error)) {
        SetStatus(status, error, true);
        return;
    }
    apply(result);
}

void SparkMultisigSpendDialog::send()
{
    UniValue result;
    QString error;
    if (!Call(sendrawtransaction, UniValue(rawTx.toStdString()), result, error)) {
        SetStatus(status, error, true);
        return;
    }
    rawTx.clear();
    spend.clear();
    details = UniValue();
    updateView();
    SetStatus(status, tr("Transaction sent. You can follow it on the Transactions page."), false);
}

void SparkMultisigSpendDialog::updateView()
{
    const spark::MultisigKey* key = groupKey();
    QString ownKeyHex;
    if (key) {
        summary->setText(tr("%1 of %2 co-signers approve each payment.").arg(uint(key->threshold)).arg(qulonglong(key->participants.size())));
        if (key->index >= 1 && key->index <= key->participants.size()) {
            ownKeyHex = QString::fromStdString(HexStr(spark::MultisigKey::serialize_participant(key->participants[key->index - 1])));
        }
    } else {
        summary->clear();
    }
    address->setText(Grouped(ownAddress()));

    // What the signers' list says about this co-signer
    bool fMine = false, fMineSigned = false;
    int count = 0, need = 0;
    QStringList pending; //!< short keys of the signers that have not signed

    const bool fDetails = details.isObject();
    detailsBox->setVisible(fDetails);
    if (fDetails) {
        const int unit = model->getOptionsModel()->getDisplayUnit();
        const auto amountOf = [unit](const UniValue& entry) { return BitcoinUnits::formatWithUnit(unit, AmountFromValue(entry["amount"])); };

        QStringList payments;
        for (const UniValue& out : details["transparent_outputs"].getValues()) {
            payments << tr("%1 to %2").arg(amountOf(out), Grouped(out.exists("address") ? Str(out["address"]) : Str(out["script"])));
        }
        CAmount returned = 0;
        for (const UniValue& out : details["outputs"].getValues()) {
            if (out["ismine"].isTrue()) {
                returned += AmountFromValue(out["amount"]);
                continue;
            }
            QString line = tr("%1 to %2").arg(amountOf(out), Grouped(Str(out["address"])));
            const QString memo = Str(out["memo"]);
            if (!memo.isEmpty()) line += tr(" (%1)").arg(memo);
            payments << line;
        }
        pays->setText(payments.isEmpty() ? tr("Nothing") : payments.join(QLatin1Char('\n')));
        fee->setText(BitcoinUnits::formatWithUnit(unit, AmountFromValue(details["fee"])));
        returns->setText(tr("%1 back to this wallet").arg(BitcoinUnits::formatWithUnit(unit, returned)));
        detailsForm->setRowVisible(returns, returned > 0);

        need = details["nrequired"].isNum() ? details["nrequired"].get_int() : 0;
        QStringList lines;
        for (const UniValue& signer : details["signers"].getValues()) {
            const QString signerKey = Str(signer["key"]);
            const bool fOwn = !ownKeyHex.isEmpty() && signerKey == ownKeyHex;
            const bool fSigned = signer["signed"].isTrue();
            ++count;
            if (fOwn) {
                fMine = true;
                fMineSigned = fSigned;
            } else if (!fSigned) {
                pending << ShortKey(signerKey);
            }
            lines << (fOwn ? tr("You") : ShortKey(signerKey)) + (fSigned || !rawTx.isEmpty() ? tr(": signed") : tr(": approved"));
        }
        if (count < need && rawTx.isEmpty()) lines << tr("%1 more needed").arg(need - count);
        approvals->setText(lines.join(QLatin1Char('\n')));
    }

    copyButton->setEnabled(!spend.isEmpty());
    saveButton->setEnabled(!spend.isEmpty());

    const auto setAction = [this](const QString& text, bool fEnabled) {
        actionButton->setText(text);
        actionButton->setEnabled(fEnabled);
        actionButton->setVisible(true);
    };
    if (!rawTx.isEmpty()) {
        setAction(tr("Send transaction"), true);
        SetStatus(status, tr("Fully signed. Send it to the network."), false);
    } else if (spend.isEmpty() || !fDetails) {
        actionButton->setVisible(false);
        SetStatus(status, tr("To pay from this wallet, use the Send page. To approve a co-signer's transaction, paste it or open its file."), false);
    } else if (!fMine) {
        if (count < need) {
            setAction(tr("Approve"), true);
            QString text = tr("Check the payment before you approve it.");
            if (count + 1 == need) text += tr(" Yours is the last approval needed, so approving also signs.");
            SetStatus(status, text, false);
        } else {
            setAction(tr("Approve"), false);
            SetStatus(status, tr("This transaction already has its %1 signers, and you are not one of them.").arg(need), false);
        }
    } else if (fMineSigned) {
        setAction(tr("Sign"), false);
        SetStatus(status, tr("You have signed. Pass the transaction on to the co-signers who still have to sign: %1.").arg(pending.join(QStringLiteral(", "))), false);
    } else if (count < need) {
        setAction(tr("Sign"), false);
        SetStatus(status, tr("You have approved. Pass the transaction on to a co-signer: it needs %1 more. Keep Firo running until you have signed. After a restart this transaction has to be created again.").arg(need - count), false);
    } else {
        setAction(tr("Sign"), true);
        SetStatus(status, tr("All approvals are in. Sign to add your signature."), false);
    }
}
