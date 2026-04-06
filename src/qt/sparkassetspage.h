#ifndef SPARK_ASSET_PAGE_H
#define SPARK_ASSET_PAGE_H

#include <QWidget>
#include <QFrame>
#include <QResizeEvent>

#include <map>
#include <optional>
#include <vector>

#include "../spats/manager.hpp"
#include "../spats/spark_asset.hpp"
#include "platformstyle.h"


class QEvent;
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
    void showPortfolioTabOnEntry();
    void adjustTextSize(int width, int height);
    void display_all_assets();
    void filterPortfolioTable(const QString &query);

protected:
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

private Q_SLOTS:
    void onCreateButtonClicked();
    void onMintButtonClicked();
    void onModifyButtonClicked();
    void onUnregisterButtonClicked();
    void updateButtonStates();
    void onBurnButtonClicked();
    void onRefreshButtonClicked();
    void onClearCreateForm();
    void onExportButtonClicked();
    void onSendButtonClicked();
    void onCopyButtonClicked();
    void onReceiveButtonClicked();
    void onRemoveButtonClicked();
    void refreshMyCreationsDeferred();

private:
    void process_spats_registry_changed(const admin_addresses_set_t &affected_asset_admin_addresses,
                                        const asset_ids_set_t &affected_asset_ids) override;

    void display_my_own_spats();
    NewSparkAssetCreationContext make_new_asset_creation_context() const;
    bool any_other_nfts_within_same_line(spats::asset_type_t asset_type,
                                         spats::identifier_t identifier) const;

    // === UI helpers ===
    void addShadow(QWidget *w);
    void updateAssetTypeField();

    void showAssetDetails(const spats::SparkAssetDisplayAttributes& d);
    void updateAssetDetails(const spats::SparkAssetDisplayAttributes& d);
    void switchToPortfolioTab();

    enum class PortfolioFilterKind { All, Held, WatchOnly };
    void onPortfolioCardClicked(QFrame* frame);
    void applyPortfolioCardChrome(QFrame* frame, bool selected) const;
    void setPortfolioFilter(PortfolioFilterKind kind);
    void refreshPortfolioCardsVisibility();
    std::optional<std::pair<spats::asset_type_t, spats::identifier_t>> getSelectedPortfolioAssetUID() const
    {
        return selected_portfolio_uid_;
    }

private:
    const PlatformStyle *platform_style_;
    Ui::SparkAssetsPage *ui;
    ClientModel *client_model_{};
    WalletModel *wallet_model_{};
    std::map<spats::universal_asset_id_t, spats::SparkAsset> my_own_assets_map_;

    std::optional<std::pair<spats::asset_type_t, spats::identifier_t>> selected_portfolio_uid_;
    QFrame* selected_portfolio_card_{nullptr};
    PortfolioFilterKind portfolio_filter_{PortfolioFilterKind::All};

    std::optional<spats::universal_asset_id_t> selected_my_creation_uid_;
    QFrame* selected_my_creation_card_{nullptr};

    std::vector<spats::SparkAsset> pending_local_created_assets_;

    void applyMyCreationCardChrome(QFrame* frame, bool selected) const;
    void onMyCreationCardClicked(QFrame* frame);
    std::optional<spats::universal_asset_id_t> getSelectedMyCreationUid() const
    {
        return selected_my_creation_uid_;
    }
};
}
#endif // SPARK_ASSET_PAGE_H
