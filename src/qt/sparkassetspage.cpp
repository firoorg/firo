#include "sparkassetspage.h"
#include "ui_sparkassetspage.h"

#include <QGraphicsDropShadowEffect>
#include <QHeaderView>
#include <QAbstractItemView>
#include <QMessageBox>
#include <QFont>
#include <cassert>
#include <algorithm>
#include <ranges>
#include "random.h"
#include "../spats/manager.hpp"

#include "../spark/state.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"
#include "spatsburndialog.h"

#include "walletmodel.h"
#include "sparkassetdialog.h"
#include "spatsmintdialog.h"
#include "spatsuserconfirmationdialog.h"
#include "spatssenddialog.h"

#include <boost/numeric/conversion/cast.hpp>
#include "../utils/math.hpp"


namespace {

enum MyOwnSpatsColumns {
    ColumnAssetType = 0,
    ColumnIdentifier,
    ColumnSymbol,
    ColumnName,
    ColumnDescription,
    ColumnTotalSupply,
    ColumnFungible,
    ColumnResupplyable,
    ColumnPrecision,
    ColumnMetadata,
    ColumnCount
};

}

namespace spats {

SparkAssetsPage::SparkAssetsPage(const PlatformStyle *platform_style, QWidget *parent)
    : QWidget(parent)
    , platform_style_(platform_style)
    , ui(new Ui::SparkAssetsPage)
{
    ui->setupUi(this);


    connect(ui->chkFungible, &QCheckBox::toggled, this, [this](bool fungible){
        ui->labelSupply->setVisible(fungible);
        ui->editSupply->setVisible(fungible);

        ui->labelPrecision->setVisible(fungible);
        ui->comboPrecision->setVisible(fungible);

        ui->labelResupply->setVisible(fungible);
        ui->comboResupply->setVisible(fungible);

        ui->labelIdentifier->setVisible(!fungible);
        ui->editIdentifier->setVisible(!fungible);
        ui->btnAutoId->setVisible(!fungible);
        ui->btnGenerateId->setVisible(!fungible);
    });

    ui->chkFungible->setChecked(true);
    ui->chkFungible->toggled(true);

    ui->tableAssets->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableAssets->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->tableAssets->verticalHeader()->setVisible(false);
    ui->tableAssets->setShowGrid(false);
    ui->tableAssets->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableAssets->setSelectionBehavior(QAbstractItemView::SelectRows);

    ui->btnPortfolio->setCheckable(true);
    ui->btnMyCreations->setCheckable(true);
    ui->btnCreateAsset->setCheckable(true);

    connect(ui->btnPortfolio, &QPushButton::clicked, this, [this]() {
        ui->stackedAssets->setCurrentWidget(ui->pagePortfolio);
        ui->searchContainer->show();

        ui->btnPortfolio->setChecked(true);
        ui->btnMyCreations->setChecked(false);
        ui->btnCreateAsset->setChecked(false);

        display_all_assets();
    });


    connect(ui->btnMyCreations, &QPushButton::clicked, this, [this]() {
        ui->stackedAssets->setCurrentWidget(ui->pageMyCreations);
        ui->searchContainer->hide();
        ui->btnPortfolio->setChecked(false);
        ui->btnMyCreations->setChecked(true);
        ui->btnCreateAsset->setChecked(false);
    });

    connect(
        ui->tableAssets->selectionModel(),
        &QItemSelectionModel::selectionChanged,
        this,
        &SparkAssetsPage::onAssetRowClicked
    );


    connect(ui->btnCreateAsset, &QPushButton::clicked, this, [this]() {
        ui->stackedAssets->setCurrentWidget(ui->pageCreateAsset);
        ui->searchContainer->hide();
        ui->btnPortfolio->setChecked(false);
        ui->btnMyCreations->setChecked(false);
        ui->btnCreateAsset->setChecked(true);
    });

    connect(ui->searchAssets, &QLineEdit::textChanged,
        this, &SparkAssetsPage::filterPortfolioTable);
    
    connect(ui->btnRefresh, &QPushButton::clicked,
        this, &SparkAssetsPage::onRefreshButtonClicked);

    connect(ui->btnClear, &QPushButton::clicked,
        this, &SparkAssetsPage::onClearCreateForm);


    ui->tableMyCreated->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableMyCreated->verticalHeader()->setVisible(false);
    ui->tableActivity->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableActivity->verticalHeader()->setVisible(false);

    ui->tableMyCreated->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableMyCreated->setSelectionMode(QAbstractItemView::SingleSelection);

    setupMyCreatedTableColumns();

    addShadow(ui->btnMint);
    addShadow(ui->btnBurn);
    addShadow(ui->btnMetadata);
    addShadow(ui->btnResupply);
    addShadow(ui->btnRevoke);

    addShadow(ui->frameMyCreated);
    addShadow(ui->frameActivity);

    addShadow(ui->assetsCard);
    addShadow(ui->detailsCard);

    addShadow(ui->btnSend);
    addShadow(ui->btnReceive);
    addShadow(ui->btnAddWatch);
    addShadow(ui->btnRemove);
    addShadow(ui->btnExport);
    addShadow(ui->btnDetailsSend);
    addShadow(ui->btnDetailsReceive);
    addShadow(ui->btnCopy);
    addShadow(ui->btnPortfolio);
    addShadow(ui->btnMyCreations);
    addShadow(ui->btnCreateAsset);

    addShadow(ui->btnAll);
    addShadow(ui->btnHeld);
    addShadow(ui->btnWatchOnly);
    addShadow(ui->btnRefresh);
    addShadow(ui->frameCreateAsset);

    connect(ui->btnDoCreate,  &QPushButton::clicked, this, &SparkAssetsPage::onCreateButtonClicked);
    connect(ui->btnMint,      &QPushButton::clicked, this, &SparkAssetsPage::onMintButtonClicked);
    connect(ui->btnMetadata,  &QPushButton::clicked, this, &SparkAssetsPage::onModifyButtonClicked);
    connect(ui->btnResupply,  &QPushButton::clicked, this, &SparkAssetsPage::onModifyButtonClicked);
    connect(ui->btnRevoke,    &QPushButton::clicked, this, &SparkAssetsPage::onUnregisterButtonClicked);
    connect(ui->btnBurn, &QPushButton::clicked, this, &SparkAssetsPage::onBurnButtonClicked);
    connect(ui->btnSend, &QPushButton::clicked, this, &SparkAssetsPage::onSendButtonClicked);

    connect(ui->tableMyCreated->selectionModel(),
            &QItemSelectionModel::selectionChanged,
            this,
            &SparkAssetsPage::updateButtonStates);

    connect(this, &SparkAssetsPage::displayMyOwnSpatsSignal,
            this, &SparkAssetsPage::handleDisplayMyOwnSpatsSignal);

    connect(ui->btnAutoId, &QPushButton::clicked, this, [this]() {
        ui->editIdentifier->setText("0");
    });

    connect(ui->btnGenerateId, &QPushButton::clicked, this, [this]() {
        uint64_t new_id = GetRand(UINT64_MAX);

        ui->editIdentifier->setText(QString::number(new_id));
    });
    ui->chkFungible->setChecked(true);
    ui->chkFungible->toggled(true);

    updateButtonStates();
}

SparkAssetsPage::~SparkAssetsPage()
{
    spark::CSparkState::GetState()->GetSpatsManager().remove_updates_observer(*this);
    delete ui;
}

void SparkAssetsPage::onAssetRowClicked()
{
    int row = ui->tableAssets->currentRow();
    if (row < 0)
        return;

    QString symbol = ui->tableAssets->item(row, 1)->text();

    auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();

    std::optional<spats::SparkAsset> found;

    {
        std::shared_lock lock(registry.mutex_);

        for (const auto &p : registry.fungible_assets_) {
            spats::SparkAssetDisplayAttributes a(p.second);
            if (QString::fromStdString(a.symbol) == symbol) {
                found = p.second;
                break;
            }
        }

        if (!found) {
            for (const auto &line : registry.nft_lines_) {
                for (const auto &kv : line.second) {
                    spats::SparkAssetDisplayAttributes a(kv.second);
                    if (QString::fromStdString(a.symbol) == symbol) {
                        found = kv.second;
                        break;
                    }
                }
                if (found) break;
            }
        }
    }
    if (!found)
        return;

    showAssetDetails(spats::SparkAssetDisplayAttributes(*found));
}

void SparkAssetsPage::addShadow(QWidget *w)
{
    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(18);
    shadow->setOffset(0, 4);
    shadow->setColor(QColor(0, 0, 0, 60));
    w->setGraphicsEffect(shadow);
}

void SparkAssetsPage::setupMyCreatedTableColumns()
{
    ui->tableMyCreated->setColumnCount(ColumnCount);

    QStringList headers;
    headers << tr("Asset type")
            << tr("Identifier")
            << tr("Symbol")
            << tr("Name")
            << tr("Description")
            << tr("Total supply")
            << tr("Fungible")
            << tr("Resupplyable")
            << tr("Precision")
            << tr("Metadata");

    ui->tableMyCreated->setHorizontalHeaderLabels(headers);
    ui->tableMyCreated->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

void SparkAssetsPage::setClientModel(ClientModel *model)
{
    client_model_ = model;
}

void SparkAssetsPage::setWalletModel(WalletModel *model)
{
    wallet_model_ = model;

    if (model) {
        spark::CSparkState::GetState()->GetSpatsManager().add_updates_observer(*this);
        display_my_own_spats();
        updateAssetTypeField();
        display_all_assets();
    }
}

void SparkAssetsPage::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    adjustTextSize(width(), height());
}

void SparkAssetsPage::adjustTextSize(int width, int height)
{
    const double font_size_scaling_factor = 70.0;
    const int base_font_size = std::min(width, height) / font_size_scaling_factor;
    const int font_size = std::min(15, std::max(12, base_font_size));
    QFont font = this->font();
    font.setPointSize(font_size);

    ui->labelMyAssetsTitle->setFont(font);
    ui->labelActivityTitle->setFont(font);
    ui->tableMyCreated->setFont(font);
    ui->tableMyCreated->horizontalHeader()->setFont(font);
    ui->tableMyCreated->verticalHeader()->setFont(font);
}

void SparkAssetsPage::showAssetDetails(const spats::SparkAssetDisplayAttributes& d)
{
    QString txt;

    txt += "<b>Name:</b> " + QString::fromStdString(d.name) + "<br>";
    txt += "<b>Symbol:</b> " + QString::fromStdString(d.symbol) + "<br>";

    if (!d.fungible)
        txt += "<b>Identifier:</b> " + QString::number(d.identifier) + "<br>";

    txt += "<b>Type:</b> " + QString(d.fungible ? "Fungible" : "NFT") + "<br>";
    txt += "<b>Precision:</b> " + QString::number(d.precision) + "<br>";

    txt += "<b>Total Supply:</b> " +
           QString::fromStdString(d.total_supply) + "<br>";

    txt += "<b>Resupplyable:</b> " + QString(d.resupplyable ? "Yes" : "No") + "<br>";

    txt += "<br><b>Description:</b><br>" +
           QString::fromStdString(d.description) + "<br><br>";

    txt += "<b>Metadata (read-only)</b><br>";
    txt += "<pre style='font-size:10pt;'>" +
           QString::fromStdString(d.metadata) +
           "</pre>";

    ui->textDetails->setHtml(txt);

    ui->btnDetailsSend->setEnabled(true);
    ui->btnDetailsReceive->setEnabled(true);
    ui->btnCopy->setEnabled(true);
}

void SparkAssetsPage::display_my_own_spats()
{
    if (!wallet_model_)
        return;

    const auto &my_public_address =
        wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();

    const auto my_own_assets =
        spark::CSparkState::GetState()->GetSpatsManager()
            .registry()
            .get_assets_administered_by(my_public_address);

    my_own_assets_map_.clear();

    auto &table_widget = *ui->tableMyCreated;
    table_widget.clearContents();
    table_widget.setRowCount(static_cast<int>(my_own_assets.size()));

    int row = 0;
    for (const auto &asset : my_own_assets) {
        const spats::SparkAssetDisplayAttributes a(asset);

        my_own_assets_map_.emplace(
            spats::universal_asset_id_t{ spats::asset_type_t{ a.asset_type },
                                         spats::identifier_t{ a.identifier } },
            asset);

        table_widget.setItem(row, ColumnAssetType,
                             new QTableWidgetItem(QString::number(a.asset_type)));
        table_widget.setItem(row, ColumnIdentifier,
                             new QTableWidgetItem(QString::number(a.identifier)));
        table_widget.setItem(row, ColumnSymbol,
                             new QTableWidgetItem(QString::fromStdString(a.symbol)));
        table_widget.setItem(row, ColumnName,
                             new QTableWidgetItem(QString::fromStdString(a.name)));
        table_widget.setItem(row, ColumnDescription,
                             new QTableWidgetItem(QString::fromStdString(a.description)));
        table_widget.setItem(row, ColumnTotalSupply,
                             new QTableWidgetItem(QString::fromStdString(a.total_supply)));
        table_widget.setItem(row, ColumnFungible,
                             new QTableWidgetItem(a.fungible ? tr("Yes") : tr("No")));
        table_widget.setItem(row, ColumnResupplyable,
                             new QTableWidgetItem(a.resupplyable ? tr("Yes") : tr("No")));
        table_widget.setItem(row, ColumnPrecision,
                             new QTableWidgetItem(QString::number(a.precision)));
        table_widget.setItem(row, ColumnMetadata,
                             new QTableWidgetItem(QString::fromStdString(a.metadata)));

        for (int col = ColumnAssetType; col < ColumnCount; ++col) {
            auto *item = table_widget.item(row, col);
            if (!item) continue;
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        }

        ++row;
    }

    ui->labelMyAssetsTitle->setText(
        tr("My Created Assets (%1)").arg(static_cast<int>(my_own_assets.size())));

    updateButtonStates();
}

NewSparkAssetCreationContext SparkAssetsPage::make_new_asset_creation_context() const
{
    const auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    const auto lowest_available_asset_type_for_new_fungible_asset =
        registry.get_lowest_available_asset_type_for_new_fungible_asset();
    if (!lowest_available_asset_type_for_new_fungible_asset) [[unlikely]]
        throw std::domain_error(
            "No available fungible asset type values left, all possible values are taken!");
    const auto lowest_available_asset_type_for_new_nft_line =
        registry.get_lowest_available_asset_type_for_new_nft_line();
    if (!lowest_available_asset_type_for_new_nft_line) [[unlikely]]
        throw std::domain_error(
            "No available NFT line asset type values left, all possible values are taken!");
    return NewSparkAssetCreationContext{
        wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin(),
        utils::to_underlying(*lowest_available_asset_type_for_new_fungible_asset),
        utils::to_underlying(*lowest_available_asset_type_for_new_nft_line)
    };
}

static spats::supply_amount_t convert_to_supply_amount(double value, unsigned precision)
{
    const double scaled_value =
        value * utils::math::integral_power(std::uintmax_t(10), precision);

    const spats::supply_amount_t a{
        boost::numeric_cast<std::uint64_t>(std::round(scaled_value)),
        precision
    };

    return a;
}

void SparkAssetsPage::onCreateButtonClicked()
{
    assert(wallet_model_);

    try
    {
        const bool fungible = ui->chkFungible->isChecked();

        QString name        = ui->editName->text().trimmed();
        QString symbol      = ui->editSymbol->text().trimmed();
        QString description = ui->editDescription->toPlainText().trimmed();
        QString metadata    = ui->editMetadata->toPlainText().trimmed();
        QString supplyStr   = ui->editSupply->text().trimmed();
        QString idStr       = ui->editIdentifier->text().trimmed();
        QString typeStr     = ui->editAssetType->text().trimmed();

        if (name.isEmpty())
            throw std::runtime_error("Name cannot be empty.");

        if (symbol.isEmpty())
            throw std::runtime_error("Symbol cannot be empty.");

        if (typeStr.isEmpty())
            throw std::runtime_error("Asset type not assigned.");

        const uint64_t asset_type = typeStr.toULongLong();

        uint64_t identifier = 0;
        if (!fungible)
        {
            if (idStr.isEmpty())
                throw std::runtime_error("Identifier cannot be empty for NFT.");

            identifier = idStr.toULongLong();
        }

        double total_supply = 0;
        unsigned precision = 0;
        bool resupplyable = false;

        if (fungible)
        {
            if (supplyStr.isEmpty())
                throw std::runtime_error("Total supply cannot be empty.");

            total_supply = supplyStr.toDouble();
            precision    = ui->comboPrecision->currentText().toUInt();
            resupplyable = (ui->comboResupply->currentText() == "Yes");
        }

        auto admin_addr =
            wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();

        spats::AssetNaming naming(
            spats::asset_name_t(name.toStdString()),
            spats::asset_symbol_t(symbol.toStdString()),
            description.toStdString()
        );

        std::optional<spats::SparkAsset> created;

        if (fungible)
        {
            const auto supply_amount =
                convert_to_supply_amount(total_supply, precision);

            spats::FungibleSparkAsset a(
                spats::asset_type_t(asset_type),
                naming,
                metadata.toStdString(),
                admin_addr,
                supply_amount,
                resupplyable
            );

            created = a;
        }
        else
        {
            spats::NonfungibleSparkAsset a(
                spats::asset_type_t(asset_type),
                spats::identifier_t(identifier),
                naming,
                metadata.toStdString(),
                admin_addr
            );

            created = a;
        }

        if (!created.has_value())
            throw std::runtime_error("Internal error: asset creation failed.");

      
        wallet_model_->getWallet()->CreateNewSparkAsset(
            *created,
            admin_addr,
            MakeSpatsUserConfirmationCallback(*wallet_model_, this)
        );

        QMessageBox::information(this, tr("Success"),
                                 tr("Spark Asset successfully created."));

        ui->editName->clear();
        ui->editSymbol->clear();
        ui->editDescription->clear();
        ui->editMetadata->clear();
        ui->editSupply->clear();
        ui->editIdentifier->clear();

        display_my_own_spats();
        ui->btnMyCreations->click();
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to create asset:\n%1").arg(e.what()));
    }
}

void SparkAssetsPage::onMintButtonClicked()
{
    assert(wallet_model_);
    if (const auto row = get_the_selected_row()) {
        try {
            const bool resupplyable =
                ui->tableMyCreated->item(*row, ColumnResupplyable)->text() == tr("Yes");
            if (!resupplyable)
                throw std::domain_error("Cannot mint for a non-resupplyable asset!");

            const spats::asset_type_t asset_type{
                ui->tableMyCreated->item(*row, ColumnAssetType)->text().toULongLong()
            };
            assert(is_fungible_asset_type(asset_type));
            const auto &asset =
                my_own_assets_map_.at(spats::universal_asset_id_t{ asset_type, {} });
            const auto &fungible_asset = std::get<spats::FungibleSparkAsset>(asset);
            assert(fungible_asset.resupplyable());

            SpatsMintDialog dialog(platform_style_, fungible_asset, this);
            if (dialog.exec() == QDialog::Accepted) {
                wallet_model_->getWallet()->MintSparkAssetSupply(
                    asset_type,
                    dialog.getNewSupply(),
                    dialog.getRecipient(),
                    nullptr,
                    MakeSpatsUserConfirmationCallback(*wallet_model_, this));
            }
        } catch (const std::exception &e) {
            QMessageBox::critical(this, tr("Error"),
                                  tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
                              tr("Please select an asset to mint for."));
    }
}

void SparkAssetsPage::onModifyButtonClicked()
{
    assert(wallet_model_);
    if (const auto row = get_the_selected_row()) {
        try {
            const spats::asset_type_t asset_type{
                ui->tableMyCreated->item(*row, ColumnAssetType)->text().toULongLong()
            };
            spats::identifier_t identifier{0};
            if (!is_fungible_asset_type(asset_type)) {
                identifier = spats::identifier_t{
                    ui->tableMyCreated->item(*row, ColumnIdentifier)->text().toULongLong()
                };
            }
            const auto &existing_asset =
                my_own_assets_map_.at(spats::universal_asset_id_t{ asset_type, identifier });

            SparkAssetDialog dialog(platform_style_, existing_asset, this);
            if (dialog.exec() == QDialog::Accepted) {
                wallet_model_->getWallet()->ModifySparkAsset(
                    existing_asset,
                    *dialog.getResultAsset(),
                    MakeSpatsUserConfirmationCallback(*wallet_model_, this));
            }
        } catch (const std::exception &e) {
            QMessageBox::critical(this, tr("Error"),
                                  tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
                              tr("Please select an asset to modify."));
    }
}

void SparkAssetsPage::onUnregisterButtonClicked()
{
    assert(wallet_model_);
    if (const auto row = get_the_selected_row()) {
        try {
            const spats::asset_type_t asset_type{
                ui->tableMyCreated->item(*row, ColumnAssetType)->text().toULongLong()
            };
            std::optional<spats::identifier_t> identifier;

            if (!is_fungible_asset_type(asset_type)) {
                identifier = spats::identifier_t{
                    ui->tableMyCreated->item(*row, ColumnIdentifier)->text().toULongLong()
                };

                if (any_other_nfts_within_same_line(asset_type, *identifier)) {
                    const QMessageBox::StandardButton reply =
                        QMessageBox::question(
                            this,
                            tr("Unregister NFT"),
                            tr("Would you like to unregister the whole NFT line or just this "
                               "specific NFT?"),
                            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel,
                            QMessageBox::Cancel);

                    switch (reply) {
                    case QMessageBox::Yes:
                        identifier.reset();
                        break;
                    case QMessageBox::No:
                        break;
                    case QMessageBox::Cancel:
                    default:
                        return;
                    }
                }
            }

            wallet_model_->getWallet()->UnregisterSparkAsset(
                asset_type,
                identifier,
                MakeSpatsUserConfirmationCallback(*wallet_model_, this));
        } catch (const std::exception &e) {
            QMessageBox::critical(this, tr("Error"),
                                  tr("An error occurred: %1").arg(e.what()));
        }
    } else {
        QMessageBox::critical(this, tr("Error"),
                              tr("Please select an asset to unregister."));
    }
}

void SparkAssetsPage::onBurnButtonClicked()
{
    assert(wallet_model_);

    const auto row = get_the_selected_row();
    if (!row) {
        QMessageBox::warning(this, tr("Error"), tr("Please select an asset to burn."));
        return;
    }

    try {
        const spats::asset_type_t asset_type{
            ui->tableMyCreated->item(*row, ColumnAssetType)->text().toULongLong()
        };

        if (!is_fungible_asset_type(asset_type)) {
            throw std::domain_error("Burn is available only for fungible assets.");
        }

        const auto &asset_variant =
            my_own_assets_map_.at(spats::universal_asset_id_t{ asset_type, {} });

        const auto &asset = std::get<spats::FungibleSparkAsset>(asset_variant);

        const spats::supply_amount_t max_allowed = asset.total_supply();
        if (max_allowed == spats::supply_amount_t(0, asset.precision()))
            throw std::domain_error("Cannot burn: supply is zero.");

        SpatsBurnDialog dialog(
            platform_style_,
            asset_type,
            asset.naming().symbol.get(),
            max_allowed,
            this
        );

        if (dialog.exec() != QDialog::Accepted)
            return;

        const auto burn_amount = dialog.getBurnAmount();
        const spats::asset_symbol_t& symbol = asset.naming().symbol;

        wallet_model_->getWallet()->BurnSparkAssetSupply(
            asset_type,
            asset.naming().symbol,
            burn_amount,
            MakeSpatsUserConfirmationCallback(*wallet_model_, this)
        );

        QMessageBox::information(this, tr("Success"), tr("Burn transaction sent."));
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to burn supply:\n%1").arg(e.what()));
    }
}

void SparkAssetsPage::updateButtonStates()
{
    const auto selected_row = get_the_selected_row();
    const bool row_selected = selected_row.has_value();

    ui->btnMetadata->setEnabled(row_selected);
    ui->btnResupply->setEnabled(row_selected);
    ui->btnRevoke->setEnabled(row_selected);

    bool can_mint = false;
    if (row_selected) {
        auto *item = ui->tableMyCreated->item(*selected_row, ColumnResupplyable);
        if (item && item->text() == tr("Yes"))
            can_mint = true;
    }
    ui->btnMint->setEnabled(can_mint);
}

std::optional<int> SparkAssetsPage::get_the_selected_row() const
{
    const auto selection = ui->tableMyCreated->selectionModel()->selectedRows();
    return selection.size() == 1
               ? std::optional<int>{selection.front().row()}
               : std::optional<int>{};
}

bool SparkAssetsPage::any_other_nfts_within_same_line(spats::asset_type_t asset_type,
                                                      spats::identifier_t identifier) const
{
    assert(!is_fungible_asset_type(asset_type));
    assert(asset_type <= spats::max_allowed_asset_type_value);

    return std::ranges::any_of(
        my_own_assets_map_,
        [&](const auto &kv) {
            return kv.first.first == asset_type && kv.first.second != identifier;
        });
}

void SparkAssetsPage::process_spats_registry_changed(
    const admin_addresses_set_t &affected_asset_admin_addresses,
    const asset_ids_set_t & /*affected_asset_ids*/)
{
    if (!wallet_model_)
        return;

    const auto &my_public_address =
        wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();

    if (std::ranges::any_of(
            affected_asset_admin_addresses,
            [&my_public_address](const auto &admin_address) {
                return admin_address == my_public_address || admin_address.empty();
            })) {
        Q_EMIT displayMyOwnSpatsSignal();
    }
}

void SparkAssetsPage::updateAssetTypeField()
{
    if (!wallet_model_)
        return;

    auto ctx = make_new_asset_creation_context();

    if (ui->chkFungible->isChecked())
        ui->editAssetType->setText(
            QString::number(ctx.lowest_available_asset_type_for_new_fungible_asset));
    else
        ui->editAssetType->setText(
            QString::number(ctx.lowest_available_asset_type_for_new_nft_line));
}

void SparkAssetsPage::display_all_assets()
{
    if (!wallet_model_)
        return;

    const auto &balances = wallet_model_->getSpatsBalances();

    auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
    std::vector<spats::SparkAssetDisplayAttributes> list;

    {
        std::shared_lock lock(registry.mutex_);
        for (const auto &p : registry.fungible_assets_) {
            list.emplace_back(p.second);
        }

        for (const auto &line : registry.nft_lines_) {
            for (const auto &kv : line.second) {
                list.emplace_back(kv.second);
            }
        }
    }

    QTableWidget *table = ui->tableAssets;
    if (!table)
        return;

    const int COL_ID        = 0;
    const int COL_NAME      = 1;
    const int COL_AVAILABLE = 2;

    table->setColumnCount(3);
    table->clearContents();
    table->setRowCount(static_cast<int>(list.size()));

    table->setHorizontalHeaderLabels({ "Asset ID", "Name", "Available" });

    int row = 0;

    for (const auto &a : list)
    {
        QString idText;
        if (a.fungible)
            idText = QString("%1:0").arg(a.asset_type);
        else
            idText = QString("%1:%2").arg(a.asset_type).arg(a.identifier);

        table->setItem(row, COL_ID, new QTableWidgetItem(idText));
        table->setItem(
            row, COL_NAME,
            new QTableWidgetItem(QString::fromStdString(a.name))
        );

        spats::identifier_t ident =
            a.fungible ? spats::identifier_t{} : spats::identifier_t{ a.identifier };

        spats::universal_asset_id_t uid{
            spats::asset_type_t(a.asset_type),
            ident
        };

        QString availableText = "0";

        auto it = balances.find(uid);
        if (it != balances.end()) {
            availableText = QString::number(it->second.available.raw());
        }

        table->setItem(row, COL_AVAILABLE, new QTableWidgetItem(availableText));

        for (int col = 0; col < 3; col++) {
            auto *it = table->item(row, col);
            if (it)
                it->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        }

        row++;
    }
    ui->labelAssets->setText(tr("Assets (%1)").arg(list.size()));
}

void SparkAssetsPage::filterPortfolioTable(const QString &query)
{
    QString q = query.trimmed().toLower();

    QTableWidget *table = ui->tableAssets;
    if (!table)
        return;

    for (int row = 0; row < table->rowCount(); ++row) {
        bool match = false;

        if (table->item(row, 0)->text().toLower().contains(q))
            match = true;

        if (table->item(row, 1)->text().toLower().contains(q))
            match = true;

        if (table->item(row, 2)->text().toLower().contains(q))
            match = true;

        table->setRowHidden(row, !match);
    }
}

void SparkAssetsPage::onRefreshButtonClicked()
{
    display_all_assets();
    filterPortfolioTable(ui->searchAssets->text());
    updateButtonStates();
}

void SparkAssetsPage::onClearCreateForm()
{
    ui->editName->clear();
    ui->editSymbol->clear();
    ui->editDescription->clear();
    ui->editMetadata->clear();
    ui->editSupply->clear();
    ui->editIdentifier->clear();

    ui->chkFungible->setChecked(true);
    ui->comboPrecision->setCurrentIndex(0);
    ui->comboResupply->setCurrentIndex(0);
    updateAssetTypeField();
    ui->editName->setFocus();
}

void SparkAssetsPage::onSendButtonClicked()
{
    int row = ui->tableAssets->currentRow();
    if (row < 0)
        return;
    SpatsSendDialog dialog(platform_style_, this);
    dialog.exec();
}

}