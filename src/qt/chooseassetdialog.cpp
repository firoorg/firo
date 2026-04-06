// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chooseassetdialog.h"
#include "ui_chooseassetdialog.h"

#include "platformstyle.h"
#include "guiutil.h"

#include "../spark/state.h"
#include "../spats/base_asset.hpp"
#include "../spats/spark_asset.hpp"

#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QVBoxLayout>
#include <QCoreApplication>

#include <boost/lexical_cast.hpp>

#include <algorithm>

namespace {

QString displayNameFor(spats::universal_asset_id_t id)
{
    if (id == spats::base::universal_id) {
        const std::string nameStd = std::string(spats::base::naming().name);
        return QString::fromUtf8(nameStd.c_str());
    }
    auto& mgr = spark::CSparkState::GetState()->GetSpatsManager();
    if (const auto located = mgr.registry().get_asset(id.first, id.second)) {
        const spats::SparkAssetDisplayAttributes a(located->asset);
        return QString::fromUtf8(a.name.c_str());
    }
    return QCoreApplication::translate("ChooseAssetDialog", "Unknown asset");
}

QString displaySymbolFor(spats::universal_asset_id_t id)
{
    if (id == spats::base::universal_id) {
        const std::string symStd = std::string(spats::base::naming().symbol);
        return QString::fromUtf8(symStd.c_str());
    }
    auto& mgr = spark::CSparkState::GetState()->GetSpatsManager();
    if (const auto located = mgr.registry().get_asset(id.first, id.second)) {
        const spats::SparkAssetDisplayAttributes a(located->asset);
        return QString::fromUtf8(a.symbol.c_str());
    }
    return QString();
}

} // namespace

QString FormatSpatsAssetSummary(const spats::Wallet::asset_balances_t& balances, spats::universal_asset_id_t id)
{
    auto it = balances.find(id);
    QString balStr = QCoreApplication::translate("ChooseAssetDialog", "n/a");
    if (it != balances.end()) {
        balStr = QString::fromStdString(boost::lexical_cast<std::string>(it->second.available));
    }

    if (id == spats::base::universal_id) {
        const QString sym = QString::fromStdString(std::string(spats::base::naming().symbol));
        return QCoreApplication::translate("ChooseAssetDialog", "%1 — %2 available").arg(sym, balStr);
    }

    const QString sym = displaySymbolFor(id);
    const QString name = displayNameFor(id);
    if (!sym.isEmpty()) {
        return QCoreApplication::translate("ChooseAssetDialog", "%1 (%2) — %3 available").arg(sym, name, balStr);
    }
    return QCoreApplication::translate("ChooseAssetDialog", "%1 — %2 available").arg(name, balStr);
}

ChooseAssetDialog::ChooseAssetDialog(const PlatformStyle* platformStyle, QWidget* parent)
    : QDialog(parent),
      ui(new Ui::ChooseAssetDialog),
      platformStyle(platformStyle),
      model_(nullptr),
      selected_(spats::base::universal_id)
{
    ui->setupUi(this);
    setWindowTitle(tr("Choose asset"));

    ui->layoutCards->setAlignment(Qt::AlignTop);

    connect(ui->lineSearch, &QLineEdit::textChanged, this, &ChooseAssetDialog::onSearchTextChanged);

    if (platformStyle && !platformStyle->getImagesOnButtons()) {
        ui->buttonCancel->setIcon(QIcon());
    }
}

ChooseAssetDialog::~ChooseAssetDialog()
{
    delete ui;
}

void ChooseAssetDialog::setWalletModel(WalletModel* model)
{
    model_ = model;
}

void ChooseAssetDialog::setPreselected(spats::universal_asset_id_t id)
{
    selected_ = id;
}

void ChooseAssetDialog::reloadAndApplyFilter()
{
    if (model_) {
        balances_ = model_->getSpatsBalances();
    } else {
        balances_.clear();
    }
    rebuildCardWidgets();
    applyFilter(ui->lineSearch->text());
}

bool ChooseAssetDialog::eventFilter(QObject* watched, QEvent* event)
{
    if (event->type() == QEvent::MouseButtonRelease) {
        auto* me = static_cast<QMouseEvent*>(event);
        if (me->button() != Qt::LeftButton) {
            return QDialog::eventFilter(watched, event);
        }
        auto* frame = qobject_cast<QFrame*>(watched);
        if (!frame) {
            return QDialog::eventFilter(watched, event);
        }
        const QVariant keyVar = frame->property("assetKey");
        if (!keyVar.isValid()) {
            return QDialog::eventFilter(watched, event);
        }
        if (auto id = parseAssetKey(keyVar.toString())) {
            selected_ = *id;
            accept();
            return true;
        }
    }
    return QDialog::eventFilter(watched, event);
}

void ChooseAssetDialog::onSearchTextChanged(const QString& text)
{
    applyFilter(text);
}

QString ChooseAssetDialog::assetKeyString(spats::universal_asset_id_t id)
{
    return QString::number(static_cast<qulonglong>(id.first)) + QLatin1Char(':') +
           QString::number(static_cast<qulonglong>(id.second));
}

std::optional<spats::universal_asset_id_t> ChooseAssetDialog::parseAssetKey(const QString& key)
{
    const int colon = key.indexOf(QLatin1Char(':'));
    if (colon <= 0) {
        return std::nullopt;
    }
    bool ok1 = false, ok2 = false;
    const qulonglong t = key.left(colon).toULongLong(&ok1);
    const qulonglong i = key.mid(colon + 1).toULongLong(&ok2);
    if (!ok1 || !ok2) {
        return std::nullopt;
    }
    return spats::universal_asset_id_t{
        static_cast<spats::asset_type_t>(static_cast<spats::asset_type_underlying_type>(t)),
        static_cast<spats::identifier_t>(static_cast<spats::identifier_underlying_type>(i))};
}

void ChooseAssetDialog::rebuildCardWidgets()
{
    QLayoutItem* child = nullptr;
    while ((child = ui->layoutCards->takeAt(0)) != nullptr) {
        if (QWidget* w = child->widget()) {
            w->removeEventFilter(this);
            w->deleteLater();
        }
        delete child;
    }

    std::vector<spats::universal_asset_id_t> ids;
    ids.reserve(balances_.size());
    for (const auto& entry : balances_) {
        ids.push_back(entry.first);
    }

    std::sort(ids.begin(), ids.end(), [](const spats::universal_asset_id_t& a, const spats::universal_asset_id_t& b) {
        if (a == spats::base::universal_id) {
            return true;
        }
        if (b == spats::base::universal_id) {
            return false;
        }
        return displayNameFor(a).compare(displayNameFor(b), Qt::CaseInsensitive) < 0;
    });

    const QString paletteStart = QStringLiteral("#E8EDF2");
    const QString paletteMid = QStringLiteral("#B7C3D0");
    const QString paletteEnd = QStringLiteral("#A3AFBA");

    for (const auto& asset_id : ids) {
        const auto balIt = balances_.find(asset_id);
        if (balIt == balances_.end()) {
            continue;
        }
        const QString idText = assetKeyString(asset_id);
        const QString nameText = displayNameFor(asset_id);
        const QString symText = displaySymbolFor(asset_id);
        const QString availableText =
            QString::fromStdString(boost::lexical_cast<std::string>(balIt->second.available));

        const QString searchBlob =
            (nameText + QLatin1Char(' ') + symText + QLatin1Char(' ') + idText).toLower();

        auto* frame = new QFrame(ui->scrollAreaWidgetContents);
        frame->setObjectName(QStringLiteral("chooseAssetCard"));
        frame->setProperty("assetKey", idText);
        frame->setProperty("searchBlob", searchBlob);
        frame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        frame->setFixedHeight(54);
        frame->setCursor(Qt::PointingHandCursor);
        frame->setStyleSheet(QStringLiteral(R"(
            QFrame#chooseAssetCard {
                border: 1px solid rgba(255, 255, 255, 0);
                border-radius: 10px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 %1,
                    stop:0.52 %2,
                    stop:1 %3);
            }
            QFrame#chooseAssetCard:hover {
                border: 1px solid rgba(255, 255, 255, 0);
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #D1D8E2,
                    stop:0.52 #C0CBD6,
                    stop:1 #A3AFBA);
            }
        )")
                                   .arg(paletteStart, paletteMid, paletteEnd));

        auto* cardLayout = new QVBoxLayout(frame);
        cardLayout->setSpacing(0);
        cardLayout->setContentsMargins(0, 0, 0, 0);

        auto* gloss = new QFrame(frame);
        gloss->setFixedHeight(5);
        gloss->setStyleSheet(QStringLiteral(R"(
            QFrame {
                border: none;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                border-bottom-left-radius: 7px;
                border-bottom-right-radius: 7px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 255, 255, 48),
                    stop:0.45 rgba(220, 228, 236, 14),
                    stop:1 rgba(170, 180, 190, 5));
            }
        )"));
        cardLayout->addWidget(gloss);

        auto* row = new QHBoxLayout();
        row->setContentsMargins(10, 0, 10, 4);
        row->setSpacing(8);

        auto makeCaption = [frame](const QString& t) {
            auto* l = new QLabel(t, frame);
            l->setStyleSheet(QStringLiteral(
                "QLabel { "
                "color: rgba(17, 24, 39, 150); "
                "font-size: 8pt; "
                "font-weight: 600; "
                "background: transparent; "
                "border: none; "
                "padding: 0px; "
                "margin: 0px; "
                "}"));
            return l;
        };
        auto makeValue = [frame](const QString& t, const QString& size) {
            auto* l = new QLabel(t, frame);
            l->setStyleSheet(QStringLiteral(
                "QLabel { "
                "color: #111827; "
                "font-size: %1; "
                "font-weight: 700; "
                "background: transparent; "
                "border: none; "
                "padding: 0px; "
                "margin: 0px; "
                "}").arg(size));
            return l;
        };

        auto* leftCol = new QVBoxLayout();
        leftCol->setSpacing(1);
        leftCol->addWidget(makeCaption(tr("Asset")));

        const bool symbolHasNonAscii =
            std::any_of(symText.begin(), symText.end(), [](const QChar ch) { return ch.unicode() > 127; });
        QString primary =
            symText.isEmpty() || symbolHasNonAscii ? nameText : (symText + QStringLiteral(" \u2014 ") + nameText);
        if (primary.length() > 34) {
            primary = primary.left(31) + QStringLiteral("\u2026");
        }
        leftCol->addWidget(makeValue(primary, QStringLiteral("9pt")));

        auto* midCol = new QVBoxLayout();
        midCol->setSpacing(1);
        midCol->addWidget(makeCaption(tr("ID")));
        midCol->addWidget(makeValue(idText, QStringLiteral("8.5pt")));

        auto* rightCol = new QVBoxLayout();
        rightCol->setSpacing(1);
        auto* capAvail = makeCaption(tr("Available"));
        capAvail->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto* valAvail = makeValue(availableText, QStringLiteral("9pt"));
        valAvail->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        rightCol->addWidget(capAvail);
        rightCol->addWidget(valAvail);

        row->addLayout(leftCol, 3);
        row->addLayout(midCol, 2);
        row->addLayout(rightCol, 2);

        auto* icon = new QLabel(frame);
        icon->setPixmap(GUIUtil::sparkAssetBadgePixmap(18));
        icon->setStyleSheet(QStringLiteral("background: transparent; border: none; padding: 0px; margin: 0px;"));
        icon->setAlignment(Qt::AlignTop | Qt::AlignRight);
        row->addWidget(icon, 0, Qt::AlignTop);

        cardLayout->addLayout(row);
        ui->layoutCards->addWidget(frame);
        frame->installEventFilter(this);
    }

    ui->layoutCards->addStretch();
}

void ChooseAssetDialog::applyFilter(const QString& filter)
{
    const QString f = filter.trimmed().toLower();
    for (int i = 0; i < ui->layoutCards->count(); ++i) {
        QLayoutItem* it = ui->layoutCards->itemAt(i);
        if (!it) {
            continue;
        }
        auto* w = qobject_cast<QFrame*>(it->widget());
        if (!w || w->objectName() != QLatin1String("chooseAssetCard")) {
            continue;
        }
        const QString blob = w->property("searchBlob").toString();
        const bool match = f.isEmpty() || blob.contains(f);
        w->setVisible(match);
    }
}

QString ChooseAssetDialog::selectedSummary() const
{
    return FormatSpatsAssetSummary(balances_, selected_);
}
