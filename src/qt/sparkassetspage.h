#ifndef SPARK_ASSET_PAGE_H
#define SPARK_ASSET_PAGE_H

#include <QWidget>
#include <QResizeEvent>
#include <map>
#include <optional>

#include "../spats/manager.hpp"
#include "platformstyle.h"

namespace Ui {
class SparkAssetsPage;
}

class ClientModel;
class WalletModel;
struct NewSparkAssetCreationContext;

namespace spats {
class SparkAssetsPage : public QWidget, public spats::UpdatesObserver
{
    Q_OBJECT

public:
    explicit SparkAssetsPage(const PlatformStyle *platform_style, QWidget *parent = nullptr);
    ~SparkAssetsPage() override;
    void setClientModel(ClientModel *client_model);
    void setWalletModel(WalletModel *wallet_model);
    void adjustTextSize(int width, int height);
    void display_all_assets();
    void filterPortfolioTable(const QString &query);

protected:
    void resizeEvent(QResizeEvent *event) override;

private Q_SLOTS:
    void onCreateButtonClicked();
    void onMintButtonClicked();
    void onModifyButtonClicked();
    void onUnregisterButtonClicked();
    void handleDisplayMyOwnSpatsSignal() { display_my_own_spats(); }
    void updateButtonStates();
    void onAssetRowClicked();
    void onBurnButtonClicked();
    void onRefreshButtonClicked();
    void onClearCreateForm();

Q_SIGNALS:
    void displayMyOwnSpatsSignal();

private:
    void process_spats_registry_changed(const admin_addresses_set_t &affected_asset_admin_addresses,
                                        const asset_ids_set_t &affected_asset_ids) override;

    void display_my_own_spats();
    NewSparkAssetCreationContext make_new_asset_creation_context() const;
    std::optional<int> get_the_selected_row() const;
    bool any_other_nfts_within_same_line(spats::asset_type_t asset_type,
                                         spats::identifier_t identifier) const;

    // === UI helpers ===
    void addShadow(QWidget *w);
    void setupMyCreatedTableColumns();
    void updateAssetTypeField();

    void showAssetDetails(const spats::SparkAssetDisplayAttributes& d);
    void updateAssetDetails(const spats::SparkAssetDisplayAttributes& d);

private:
    const PlatformStyle *platform_style_;
    Ui::SparkAssetsPage *ui;
    ClientModel *client_model_{};
    WalletModel *wallet_model_{};
    std::map<spats::universal_asset_id_t, spats::SparkAsset> my_own_assets_map_;
};
}
#endif // SPARK_ASSET_PAGE_H
